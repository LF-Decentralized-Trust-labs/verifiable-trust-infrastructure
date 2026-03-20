use std::time::Duration;

use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

#[cfg(feature = "encryption")]
mod encryption;

/// Timeout for blocking fjall operations. Prevents indefinite hangs if the
/// store deadlocks or I/O stalls.
const STORE_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run a blocking operation with timeout.
async fn blocking_with_timeout<F, T>(f: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::time::timeout(
        STORE_OP_TIMEOUT,
        tokio::task::spawn_blocking(f),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(AppError::Internal(format!("blocking task panicked: {e}"))),
        Err(_) => Err(AppError::Internal(format!(
            "store operation timed out after {}s",
            STORE_OP_TIMEOUT.as_secs()
        ))),
    }
}

/// A key-value pair of raw bytes from a prefix scan.
pub type RawKvPair = (Vec<u8>, Vec<u8>);

#[derive(Clone)]
pub struct Store {
    db: fjall::Database,
}

/// Handle to a fjall keyspace with optional transparent encryption.
///
/// When an encryption key is set (via `with_encryption`), all **values**
/// are AES-256-GCM encrypted before writing and decrypted after reading.
/// Keys are stored in plaintext so prefix scans still work.
///
/// When no encryption key is set, all operations pass through unchanged.
#[derive(Clone)]
pub struct KeyspaceHandle {
    keyspace: fjall::Keyspace,
    #[cfg(feature = "encryption")]
    encryption_key: Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

impl Store {
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;

        info!(path = %config.data_dir.display(), "opening store");

        let db = fjall::Database::builder(&config.data_dir).open()?;

        Ok(Self { db })
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let keyspace = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        Ok(KeyspaceHandle {
            keyspace,
            #[cfg(feature = "encryption")]
            encryption_key: None,
        })
    }

    pub async fn persist(&self) -> Result<(), AppError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.persist(PersistMode::SyncAll))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }
}

impl KeyspaceHandle {
    /// Return a clone of this handle with AES-256-GCM encryption enabled.
    ///
    /// All subsequent `insert`/`get`/`insert_raw`/`get_raw`/`prefix_iter_raw`/`swap`
    /// operations will transparently encrypt values before writing and decrypt
    /// after reading. Keys remain in plaintext.
    ///
    /// Each encrypted value has the format:
    ///   `[12-byte random nonce][ciphertext][16-byte GCM auth tag]`
    #[cfg(feature = "encryption")]
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(key)));
        self
    }

    /// Returns true if this handle has encryption enabled.
    pub fn is_encrypted(&self) -> bool {
        #[cfg(feature = "encryption")]
        { self.encryption_key.is_some() }
        #[cfg(not(feature = "encryption"))]
        { false }
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(bytes)?;
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.insert(key, bytes)?)).await
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || {
            match ks.get(key)? {
                Some(bytes) => {
                    #[cfg(feature = "encryption")]
                    let bytes = {
                        let k = enc_key.as_ref().map(|arc| &***arc);
                        encryption::maybe_decrypt_bytes(k, &bytes)?
                    };
                    #[cfg(not(feature = "encryption"))]
                    let bytes = bytes.to_vec();
                    Ok(Some(serde_json::from_slice(&bytes)?))
                }
                None => Ok(None),
            }
        })
        .await
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.remove(key)?)).await
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        let key = key.into();
        let value = self.maybe_encrypt(value.into())?;
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.insert(key, value)?)).await
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || {
            match ks.get(key)? {
                Some(bytes) => {
                    #[cfg(feature = "encryption")]
                    let bytes = {
                        let k = enc_key.as_ref().map(|arc| &***arc);
                        encryption::maybe_decrypt_bytes(k, &bytes)?
                    };
                    #[cfg(not(feature = "encryption"))]
                    let bytes = bytes.to_vec();
                    Ok(Some(bytes))
                }
                None => Ok(None),
            }
        })
        .await
    }

    /// Iterate all key-value pairs whose key starts with `prefix`.
    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let prefix = prefix.into();
        let ks = self.keyspace.clone();
        #[cfg(feature = "encryption")]
        let enc_key = self.encryption_key.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, value) = guard.into_inner()?;
                #[cfg(feature = "encryption")]
                let value = {
                    let k = enc_key.as_ref().map(|arc| &***arc);
                    encryption::maybe_decrypt_bytes(k, &value)?
                };
                #[cfg(not(feature = "encryption"))]
                let value = value.to_vec();
                results.push((key.to_vec(), value));
            }
            Ok(results)
        })
        .await
    }

    /// Iterate all keys (without values) whose key starts with `prefix`.
    pub async fn prefix_keys(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, AppError> {
        let prefix = prefix.into();
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, _value) = guard.into_inner()?;
                results.push(key.to_vec());
            }
            Ok(results)
        })
        .await
    }

    /// Returns the approximate number of items in the keyspace.
    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.approximate_len())).await
    }

    /// Atomically check that `new_key` doesn't exist, insert `value` at `new_key`,
    /// and remove `old_key` in a single blocking operation.
    pub async fn swap<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        let old_key = old_key.into();
        let new_key = new_key.into();
        let bytes = serde_json::to_vec(value)?;
        let bytes = self.maybe_encrypt(bytes)?;
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || {
            if ks.contains_key(&new_key)? {
                return Ok(false);
            }
            ks.insert(&new_key, bytes)?;
            ks.remove(&old_key)?;
            Ok(true)
        })
        .await
    }

    /// Encrypt bytes if encryption is enabled, otherwise return unchanged.
    fn maybe_encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, AppError> {
        #[cfg(feature = "encryption")]
        {
            match self.encryption_key.as_ref().map(|arc| &***arc) {
                Some(key) => encryption::encrypt_value(key, &plaintext),
                None => Ok(plaintext),
            }
        }
        #[cfg(not(feature = "encryption"))]
        { Ok(plaintext) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("failed to open store");
        (store, dir)
    }

    #[tokio::test]
    async fn test_basic_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestRecord {
            id: String,
            value: u64,
        }

        let record = TestRecord {
            id: "test-1".into(),
            value: 42,
        };

        ks.insert("key:test-1", &record).await.unwrap();
        let got: TestRecord = ks.get("key:test-1").await.unwrap().unwrap();
        assert_eq!(got, record);
    }

    #[tokio::test]
    async fn test_prefix_iter() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        for i in 0..5 {
            ks.insert_raw(format!("prefix:{i}"), format!("value-{i}").into_bytes())
                .await
                .unwrap();
        }

        let raw = ks.prefix_iter_raw("prefix:").await.unwrap();
        assert_eq!(raw.len(), 5);
    }

    #[tokio::test]
    async fn test_remove() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        ks.insert_raw("key", b"value".to_vec()).await.unwrap();
        assert!(ks.get_raw("key").await.unwrap().is_some());

        ks.remove("key").await.unwrap();
        assert!(ks.get_raw("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_swap() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();

        ks.insert("old", &"value").await.unwrap();
        let swapped = ks.swap("old", "new", &"value").await.unwrap();
        assert!(swapped);
        assert!(ks.get::<String>("old").await.unwrap().is_none());
        assert!(ks.get::<String>("new").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_passthrough_mode_no_encryption() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("plain").unwrap();
        assert!(!ks.is_encrypted());

        ks.insert_raw("test", b"visible".to_vec()).await.unwrap();
        let raw = ks.get_raw("test").await.unwrap().unwrap();
        assert_eq!(raw, b"visible");
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn test_encrypted_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store
            .keyspace("encrypted")
            .unwrap()
            .with_encryption([0xAB; 32]);

        assert!(ks.is_encrypted());

        // Raw bytes roundtrip
        ks.insert_raw("raw:test", b"hello world".to_vec())
            .await
            .unwrap();
        let raw = ks.get_raw("raw:test").await.unwrap().unwrap();
        assert_eq!(raw, b"hello world");

        // JSON roundtrip
        ks.insert("json:test", &"encrypted value").await.unwrap();
        let got: String = ks.get("json:test").await.unwrap().unwrap();
        assert_eq!(got, "encrypted value");
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn test_encrypted_data_is_actually_encrypted_on_disk() {
        let (store, _dir) = temp_store();
        let enc_key = [0x42; 32];

        // Write with encryption
        let ks_enc = store
            .keyspace("secrets")
            .unwrap()
            .with_encryption(enc_key);
        ks_enc
            .insert_raw("test", b"plaintext secret".to_vec())
            .await
            .unwrap();

        // Read the same keyspace WITHOUT encryption — should get raw ciphertext
        let ks_raw = store.keyspace("secrets").unwrap();
        let on_disk = ks_raw.get_raw("test").await.unwrap().unwrap();

        // The on-disk value should NOT be the plaintext
        assert_ne!(on_disk, b"plaintext secret");
        // It should be nonce (12) + ciphertext + tag (16) = at least 28 + plaintext len
        assert!(on_disk.len() >= 12 + 16 + 16);

        // But reading with the correct encryption key should work
        let decrypted = ks_enc.get_raw("test").await.unwrap().unwrap();
        assert_eq!(decrypted, b"plaintext secret");
    }
}
