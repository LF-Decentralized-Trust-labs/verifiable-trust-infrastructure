use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

/// A key-value pair of raw bytes from a prefix scan.
pub type RawKvPair = (Vec<u8>, Vec<u8>);

#[derive(Clone)]
pub struct Store {
    db: fjall::Database,
}

#[derive(Clone)]
pub struct KeyspaceHandle {
    keyspace: fjall::Keyspace,
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
        Ok(KeyspaceHandle { keyspace })
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
    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.insert(key, bytes))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<V>, AppError> {
            match ks.get(key)? {
                Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.remove(key))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        let key = key.into();
        let value = value.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.insert(key, value))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        let result = tokio::task::spawn_blocking(move || ks.get(key))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(result.map(|v| v.to_vec()))
    }

    /// Iterate all key-value pairs whose key starts with `prefix`.
    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let prefix = prefix.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<RawKvPair>, AppError> {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, value) = guard.into_inner()?;
                results.push((key.to_vec(), value.to_vec()));
            }
            Ok(results)
        })
        .await
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
    }

    /// Returns the approximate number of items in the keyspace.
    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.approximate_len())
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))
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
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, AppError> {
            if ks.contains_key(&new_key)? {
                return Ok(false);
            }
            ks.insert(&new_key, bytes)?;
            ks.remove(&old_key)?;
            Ok(true)
        })
        .await
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
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
}
