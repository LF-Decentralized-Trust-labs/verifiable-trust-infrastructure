use std::time::Duration;

use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

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
    /// Optional AES-256-GCM encryption key for value-level encryption.
    /// When `Some`, all values are encrypted/decrypted transparently.
    encryption_key: Option<[u8; 32]>,
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
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Returns true if this handle has encryption enabled.
    pub fn is_encrypted(&self) -> bool {
        self.encryption_key.is_some()
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
        let enc_key = self.encryption_key;
        blocking_with_timeout(move || {
            match ks.get(key)? {
                Some(bytes) => {
                    let bytes = maybe_decrypt_bytes(enc_key.as_ref(), &bytes)?;
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
        let enc_key = self.encryption_key;
        blocking_with_timeout(move || {
            match ks.get(key)? {
                Some(bytes) => Ok(Some(maybe_decrypt_bytes(enc_key.as_ref(), &bytes)?)),
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
        let enc_key = self.encryption_key;
        blocking_with_timeout(move || {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, value) = guard.into_inner()?;
                let value = maybe_decrypt_bytes(enc_key.as_ref(), &value)?;
                results.push((key.to_vec(), value));
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
        match self.encryption_key {
            Some(ref key) => encrypt_value(key, &plaintext),
            None => Ok(plaintext),
        }
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM encryption helpers
// ---------------------------------------------------------------------------

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypt plaintext with AES-256-GCM.
/// Output: `[12-byte random nonce][ciphertext + 16-byte auth tag]`
fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("AES key error: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Internal(format!("AES-GCM encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt AES-256-GCM encrypted value.
/// Input: `[12-byte nonce][ciphertext + 16-byte auth tag]`
fn decrypt_value(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::Internal(
            "encrypted value too short (missing nonce or auth tag)".into(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("AES key error: {e}")))?;

    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let ciphertext = &data[NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::Internal(format!("AES-GCM decryption failed (data may be corrupt or key mismatch): {e}")))
}

/// Decrypt bytes if an encryption key is provided, otherwise return a copy.
fn maybe_decrypt_bytes(key: Option<&[u8; 32]>, data: &[u8]) -> Result<Vec<u8>, AppError> {
    match key {
        Some(k) => decrypt_value(k, data),
        None => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyRecord, KeyStatus, KeyType};
    use chrono::Utc;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("failed to open store");
        (store, dir)
    }

    fn make_key_record(id: &str, label: &str, path: &str) -> KeyRecord {
        let now = Utc::now();
        KeyRecord {
            key_id: id.to_string(),
            derivation_path: path.to_string(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: format!("z6Mk{id}"),
            label: Some(label.to_string()),
            context_id: None,
            seed_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn test_prefix_iter_returns_all_keys() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("keys").unwrap();

        // Insert 5 keys (matching typical setup)
        let keys = vec![
            ("id-1", "Mediator signing key", "m/44'/4'/0'"),
            ("id-2", "Mediator key-agreement key", "m/44'/4'/1'"),
            ("id-3", "VTA signing key", "m/44'/0'/0'"),
            ("id-4", "VTA key-agreement key", "m/44'/0'/1'"),
            ("id-5", "Admin did:key", "m/44'/5'/2'"),
        ];

        for (id, label, path) in &keys {
            let record = make_key_record(id, label, path);
            let store_key = format!("key:{id}");
            ks.insert(store_key, &record).await.unwrap();
        }

        // Prefix scan should return all 5
        let raw = ks.prefix_iter_raw("key:").await.unwrap();
        assert_eq!(
            raw.len(),
            5,
            "expected 5 entries from prefix scan, got {}",
            raw.len()
        );

        // Verify each is deserializable
        for (_key, value) in &raw {
            let _record: KeyRecord = serde_json::from_slice(value).unwrap();
        }
    }

    #[tokio::test]
    async fn test_prefix_iter_after_persist_and_reopen() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let data_dir = dir.path().to_path_buf();

        // Phase 1: write keys and persist (simulates setup)
        {
            let config = StoreConfig {
                data_dir: data_dir.clone(),
            };
            let store = Store::open(&config).unwrap();
            let ks = store.keyspace("keys").unwrap();

            for i in 0..5 {
                let id = format!("key-{i}");
                let record = make_key_record(&id, &format!("Key {i}"), &format!("m/44'/0'/{i}'"));
                ks.insert(format!("key:{id}"), &record).await.unwrap();
            }

            store.persist().await.unwrap();
            // Store is dropped here
        }

        // Phase 2: reopen database and verify keys survive (simulates server start)
        {
            let config = StoreConfig {
                data_dir: data_dir.clone(),
            };
            let store = Store::open(&config).unwrap();
            let ks = store.keyspace("keys").unwrap();

            let raw = ks.prefix_iter_raw("key:").await.unwrap();
            assert_eq!(
                raw.len(),
                5,
                "expected 5 entries after reopen, got {}",
                raw.len()
            );

            // Verify approximate_len is reasonable
            let approx = ks.approximate_len().await.unwrap();
            assert!(approx >= 5, "approximate_len should be >= 5, got {approx}");
        }
    }

    #[tokio::test]
    async fn test_prefix_iter_without_persist() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let data_dir = dir.path().to_path_buf();

        // Phase 1: write keys WITHOUT persist (simulates old setup bug)
        {
            let config = StoreConfig {
                data_dir: data_dir.clone(),
            };
            let store = Store::open(&config).unwrap();
            let ks = store.keyspace("keys").unwrap();

            for i in 0..5 {
                let id = format!("key-{i}");
                let record = make_key_record(&id, &format!("Key {i}"), &format!("m/44'/0'/{i}'"));
                ks.insert(format!("key:{id}"), &record).await.unwrap();
            }

            // NO persist call - store is dropped
        }

        // Phase 2: reopen and check what survived
        {
            let config = StoreConfig {
                data_dir: data_dir.clone(),
            };
            let store = Store::open(&config).unwrap();
            let ks = store.keyspace("keys").unwrap();

            let raw = ks.prefix_iter_raw("key:").await.unwrap();
            // Without persist, some or all keys may be lost.
            // This test documents the behavior.
            println!("Without persist: {} of 5 keys survived reopen", raw.len());
        }
    }

    #[tokio::test]
    async fn test_encrypted_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store
            .keyspace("encrypted")
            .unwrap()
            .with_encryption([0xAB; 32]);

        // Insert a JSON value
        let record = make_key_record("enc-1", "Encrypted key", "m/44'/0'/0'");
        ks.insert("key:enc-1", &record).await.unwrap();

        // Read it back
        let got: KeyRecord = ks.get("key:enc-1").await.unwrap().unwrap();
        assert_eq!(got.key_id, "enc-1");
        assert_eq!(got.label.as_deref(), Some("Encrypted key"));

        // Raw bytes roundtrip
        ks.insert_raw("raw:test", b"hello world".to_vec())
            .await
            .unwrap();
        let raw = ks.get_raw("raw:test").await.unwrap().unwrap();
        assert_eq!(raw, b"hello world");

        // Prefix scan returns decrypted values
        let all = ks.prefix_iter_raw("key:").await.unwrap();
        assert_eq!(all.len(), 1);
        let _: KeyRecord = serde_json::from_slice(&all[0].1).unwrap();
    }

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
        assert!(on_disk.len() >= 12 + 16 + 16); // nonce + tag + "plaintext secret"

        // But reading with the correct encryption key should work
        let decrypted = ks_enc.get_raw("test").await.unwrap().unwrap();
        assert_eq!(decrypted, b"plaintext secret");
    }

    #[tokio::test]
    async fn test_passthrough_mode_no_encryption() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("plain").unwrap();
        assert!(!ks.is_encrypted());

        ks.insert_raw("test", b"visible".to_vec()).await.unwrap();
        let raw = ks.get_raw("test").await.unwrap().unwrap();
        assert_eq!(raw, b"visible"); // Not encrypted
    }
}
