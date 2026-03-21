use std::time::Duration;

use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

#[cfg(feature = "encryption")]
pub(crate) mod encryption;

#[cfg(feature = "vsock-store")]
pub mod vsock;

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

// ===========================================================================
// Store — dispatches to local (fjall) or vsock backend
// ===========================================================================

/// Persistent key-value store.
///
/// Wraps either a local fjall database or a vsock-proxied store on the parent
/// EC2 instance. All consumers use this type uniformly.
#[derive(Clone)]
pub enum Store {
    /// Local fjall database (standard mode).
    Local(LocalStore),
    /// Vsock-proxied store on the parent (Nitro Enclave mode).
    #[cfg(feature = "vsock-store")]
    Vsock(vsock::VsockStore),
}

impl Store {
    /// Open a local fjall-backed store.
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        Ok(Store::Local(LocalStore::open(config)?))
    }

    /// Connect to the parent's vsock storage proxy.
    #[cfg(feature = "vsock-store")]
    pub async fn connect_vsock(port: Option<u32>) -> Result<Self, AppError> {
        Ok(Store::Vsock(vsock::VsockStore::connect(port).await?))
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        match self {
            Store::Local(s) => Ok(KeyspaceHandle::Local(s.keyspace(name)?)),
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => Ok(KeyspaceHandle::Vsock(s.keyspace(name)?)),
        }
    }

    pub async fn persist(&self) -> Result<(), AppError> {
        match self {
            Store::Local(s) => s.persist().await,
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => s.persist().await,
        }
    }

    /// Read a file from persistent storage.
    /// In vsock mode, reads from the parent's EBS via the storage proxy.
    /// In local mode, reads from the local filesystem.
    pub async fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, AppError> {
        match self {
            Store::Local(_) => {
                match std::fs::read(path) {
                    Ok(data) => Ok(Some(data)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(AppError::Io(e)),
                }
            }
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => vsock::file_read(s, path).await,
        }
    }

    /// Write a file to persistent storage.
    /// In vsock mode, writes to the parent's EBS via the storage proxy.
    /// In local mode, writes to the local filesystem (creating dirs as needed).
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AppError> {
        match self {
            Store::Local(_) => {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(parent).map_err(AppError::Io)?;
                }
                std::fs::write(path, data).map_err(AppError::Io)
            }
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => vsock::file_write(s, path, data).await,
        }
    }

    /// Check if a file exists on persistent storage.
    pub async fn file_exists(&self, path: &str) -> Result<bool, AppError> {
        match self {
            Store::Local(_) => Ok(std::path::Path::new(path).exists()),
            #[cfg(feature = "vsock-store")]
            Store::Vsock(s) => vsock::file_exists(s, path).await,
        }
    }
}

// ===========================================================================
// KeyspaceHandle — dispatches to local (fjall) or vsock backend
// ===========================================================================

/// Handle to a keyspace with optional transparent encryption.
///
/// Wraps either a local fjall keyspace or a vsock-proxied keyspace.
/// Encryption is always applied locally (before data leaves the enclave).
#[derive(Clone)]
pub enum KeyspaceHandle {
    Local(LocalKeyspaceHandle),
    #[cfg(feature = "vsock-store")]
    Vsock(vsock::VsockKeyspaceHandle),
}

impl KeyspaceHandle {
    #[cfg(feature = "encryption")]
    pub fn with_encryption(self, key: [u8; 32]) -> Self {
        match self {
            KeyspaceHandle::Local(h) => KeyspaceHandle::Local(h.with_encryption(key)),
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => KeyspaceHandle::Vsock(h.with_encryption(key)),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        match self {
            KeyspaceHandle::Local(h) => h.is_encrypted(),
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.is_encrypted(),
        }
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.insert(key, value).await,
        }
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.get(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.get(key).await,
        }
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.remove(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.remove(key).await,
        }
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.insert_raw(key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.insert_raw(key, value).await,
        }
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.get_raw(key).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.get_raw(key).await,
        }
    }

    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.prefix_iter_raw(prefix).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.prefix_iter_raw(prefix).await,
        }
    }

    pub async fn prefix_keys(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.prefix_keys(prefix).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.prefix_keys(prefix).await,
        }
    }

    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.approximate_len().await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.approximate_len().await,
        }
    }

    pub async fn swap<V: Serialize>(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<bool, AppError> {
        match self {
            KeyspaceHandle::Local(h) => h.swap(old_key, new_key, value).await,
            #[cfg(feature = "vsock-store")]
            KeyspaceHandle::Vsock(h) => h.swap(old_key, new_key, value).await,
        }
    }
}

// ===========================================================================
// LocalStore — fjall-backed implementation (original code)
// ===========================================================================

#[derive(Clone)]
pub struct LocalStore {
    db: fjall::Database,
}

#[derive(Clone)]
pub struct LocalKeyspaceHandle {
    keyspace: fjall::Keyspace,
    #[cfg(feature = "encryption")]
    encryption_key: Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

impl LocalStore {
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;
        info!(path = %config.data_dir.display(), "opening store");
        let db = fjall::Database::builder(&config.data_dir).open()?;
        Ok(Self { db })
    }

    pub fn keyspace(&self, name: &str) -> Result<LocalKeyspaceHandle, AppError> {
        let keyspace = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        Ok(LocalKeyspaceHandle {
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

impl LocalKeyspaceHandle {
    #[cfg(feature = "encryption")]
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(key)));
        self
    }

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

    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        let ks = self.keyspace.clone();
        blocking_with_timeout(move || Ok(ks.approximate_len())).await
    }

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
