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

#[allow(dead_code)]
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
