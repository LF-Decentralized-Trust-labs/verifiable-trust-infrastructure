use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tracing::warn;

use crate::error::AppError;

/// Plaintext file-based seed store (NOT secure — use only for development).
///
/// The seed is stored as a hex-encoded string in a plaintext file.
/// A warning is emitted on every access.
pub struct PlaintextSeedStore {
    path: PathBuf,
}

impl PlaintextSeedStore {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            path: data_dir.join("seed.plaintext"),
        }
    }
}

impl super::SeedStore for PlaintextSeedStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            warn!(
                path = %self.path.display(),
                "reading seed from PLAINTEXT file — this is NOT secure for production use"
            );
            match std::fs::read_to_string(&self.path) {
                Ok(hex_seed) => {
                    let bytes = hex::decode(hex_seed.trim()).map_err(|e| {
                        AppError::SeedStore(format!(
                            "failed to decode hex seed from plaintext file: {e}"
                        ))
                    })?;
                    Ok(Some(bytes))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(AppError::SeedStore(format!(
                    "failed to read plaintext seed file: {e}"
                ))),
            }
        })
    }

    fn set(&self, seed: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_seed = hex::encode(seed);
        Box::pin(async move {
            warn!(
                path = %self.path.display(),
                "writing seed to PLAINTEXT file — this is NOT secure for production use"
            );
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AppError::SeedStore(format!(
                        "failed to create directory for plaintext seed: {e}"
                    ))
                })?;
            }
            std::fs::write(&self.path, hex_seed).map_err(|e| {
                AppError::SeedStore(format!("failed to write plaintext seed file: {e}"))
            })?;
            Ok(())
        })
    }
}
