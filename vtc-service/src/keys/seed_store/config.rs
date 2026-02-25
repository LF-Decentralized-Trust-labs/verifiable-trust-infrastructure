use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;
use tracing::debug;

/// Secret store that reads hex-encoded VTC key material from the config.
///
/// Initialized from `[secrets] secret` in the config file. The secret is
/// read-only at runtime — to change it, update the config and restart.
pub struct ConfigSecretStore {
    hex_secret: String,
}

impl ConfigSecretStore {
    pub fn new(hex_secret: String) -> Self {
        Self { hex_secret }
    }
}

impl super::SecretStore for ConfigSecretStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        Box::pin(async {
            let bytes = hex::decode(&self.hex_secret).map_err(|e| {
                AppError::SecretStore(format!("failed to decode hex secret from config: {e}"))
            })?;
            debug!("secret loaded from config");
            Ok(Some(bytes))
        })
    }

    fn set(
        &self,
        _secret: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            Err(AppError::SecretStore(
                "config-secret backend is read-only at runtime; update [secrets] secret in config.toml"
                    .into(),
            ))
        })
    }
}
