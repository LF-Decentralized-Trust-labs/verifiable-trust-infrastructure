//! KMS TEE seed store — holds the bootstrapped seed in TEE memory.
//!
//! The seed was bootstrapped from KMS during enclave startup. The ciphertext
//! is stored in the "bootstrap" keyspace of the persistent store (not files).
//! The `get` method returns a clone of the in-memory seed. The `set` method
//! updates the in-memory seed (full re-encryption requires a restart).

use std::sync::Mutex;

use crate::error::AppError;

use super::{BoxFuture, SeedStore};

/// Seed store backed by a KMS-bootstrapped seed held in TEE memory.
pub struct KmsTeeSeedStore {
    /// The plaintext seed, held only in enclave memory.
    seed: Mutex<Option<Vec<u8>>>,
    /// KMS key ARN (for reference / future re-encryption).
    _key_arn: String,
    /// AWS region (for reference / future re-encryption).
    _region: String,
}

impl KmsTeeSeedStore {
    pub fn new(seed: Vec<u8>, key_arn: String, region: String) -> Self {
        Self {
            seed: Mutex::new(Some(seed)),
            _key_arn: key_arn,
            _region: region,
        }
    }
}

impl SeedStore for KmsTeeSeedStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async {
            let guard = self
                .seed
                .lock()
                .map_err(|e| AppError::SecretStore(format!("seed lock poisoned: {e}")))?;
            Ok(guard.clone())
        })
    }

    fn set(&self, seed: &[u8]) -> BoxFuture<'_, Result<(), AppError>> {
        let seed = seed.to_vec();
        Box::pin(async move {
            // Update in-memory seed. The new ciphertext will be persisted
            // to the bootstrap keyspace on the next restart via KMS bootstrap.
            tracing::warn!(
                "seed updated in memory — restart the enclave to re-encrypt \
                 and persist the new seed via KMS bootstrap"
            );
            let mut guard = self
                .seed
                .lock()
                .map_err(|e| AppError::SecretStore(format!("seed lock poisoned: {e}")))?;
            *guard = Some(seed);
            Ok(())
        })
    }
}
