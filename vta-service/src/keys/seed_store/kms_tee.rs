//! KMS TEE seed store — holds the bootstrapped seed in TEE memory.
//!
//! This is a simple in-memory wrapper: the seed was bootstrapped from KMS
//! during enclave startup and exists only in TEE memory. The `get` method
//! returns a clone of the in-memory seed. The `set` method re-encrypts
//! the new seed with KMS and updates the ciphertext file.

use std::sync::Mutex;

use crate::error::AppError;

use super::{BoxFuture, SeedStore};

/// Seed store backed by a KMS-bootstrapped seed held in TEE memory.
pub struct KmsTeeSeedStore {
    /// The plaintext seed, held only in enclave memory.
    seed: Mutex<Option<Vec<u8>>>,
    /// KMS key ARN for re-encrypting on set().
    key_arn: String,
    /// AWS region.
    region: String,
    /// Path to the ciphertext file on external storage.
    ciphertext_path: String,
}

impl KmsTeeSeedStore {
    pub fn new(
        seed: Vec<u8>,
        key_arn: String,
        region: String,
        ciphertext_path: String,
    ) -> Self {
        Self {
            seed: Mutex::new(Some(seed)),
            key_arn,
            region,
            ciphertext_path,
        }
    }
}

impl SeedStore for KmsTeeSeedStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async {
            let guard = self.seed.lock().map_err(|e| {
                AppError::SecretStore(format!("seed lock poisoned: {e}"))
            })?;
            Ok(guard.clone())
        })
    }

    fn set(&self, seed: &[u8]) -> BoxFuture<'_, Result<(), AppError>> {
        let seed = seed.to_vec();
        Box::pin(async move {
            // Re-encrypt the new seed with KMS and write to external storage
            let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(self.region.clone()))
                .load()
                .await;

            let client = aws_sdk_kms::Client::new(&sdk_config);

            let resp = client
                .encrypt()
                .key_id(&self.key_arn)
                .plaintext(aws_sdk_kms::primitives::Blob::new(seed.clone()))
                .send()
                .await
                .map_err(|e| AppError::SecretStore(format!("KMS Encrypt failed: {e}")))?;

            let ciphertext = resp
                .ciphertext_blob()
                .ok_or_else(|| AppError::SecretStore("KMS Encrypt returned no ciphertext".into()))?;

            std::fs::write(&self.ciphertext_path, ciphertext.as_ref()).map_err(|e| {
                AppError::SecretStore(format!("failed to write seed ciphertext: {e}"))
            })?;

            // Update in-memory seed
            let mut guard = self.seed.lock().map_err(|e| {
                AppError::SecretStore(format!("seed lock poisoned: {e}"))
            })?;
            *guard = Some(seed);

            tracing::info!("seed re-encrypted with KMS and stored");
            Ok(())
        })
    }
}
