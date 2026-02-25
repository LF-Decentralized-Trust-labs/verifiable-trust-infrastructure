use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tracing::warn;

use crate::error::AppError;

/// Plaintext file-based secret store (NOT secure — use only for development).
///
/// The VTC key material is stored as a hex-encoded string in a plaintext file.
/// A warning is emitted on every access.
pub struct PlaintextSecretStore {
    path: PathBuf,
}

impl PlaintextSecretStore {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            path: data_dir.join("secret.plaintext"),
        }
    }
}

impl super::SecretStore for PlaintextSecretStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            warn!(
                path = %self.path.display(),
                "reading secret from PLAINTEXT file — this is NOT secure for production use"
            );
            match std::fs::read_to_string(&self.path) {
                Ok(hex_val) => {
                    let bytes = hex::decode(hex_val.trim()).map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to decode hex secret from plaintext file: {e}"
                        ))
                    })?;
                    Ok(Some(bytes))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(AppError::SecretStore(format!(
                    "failed to read plaintext secret file: {e}"
                ))),
            }
        })
    }

    fn set(
        &self,
        secret: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let hex_val = hex::encode(secret);
        Box::pin(async move {
            warn!(
                path = %self.path.display(),
                "writing secret to PLAINTEXT file — this is NOT secure for production use"
            );
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AppError::SecretStore(format!(
                        "failed to create directory for plaintext secret: {e}"
                    ))
                })?;
            }
            std::fs::write(&self.path, hex_val).map_err(|e| {
                AppError::SecretStore(format!("failed to write plaintext secret file: {e}"))
            })?;
            Ok(())
        })
    }
}
