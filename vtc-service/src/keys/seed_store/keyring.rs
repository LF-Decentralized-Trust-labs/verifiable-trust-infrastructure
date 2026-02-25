use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;
use tracing::debug;

pub struct KeyringSecretStore {
    service: String,
    user: String,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }
}

impl super::SecretStore for KeyringSecretStore {
    fn get(&self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.get_password() {
                    Ok(hex_secret) => {
                        let bytes = hex::decode(&hex_secret).map_err(|e| {
                            AppError::SecretStore(format!("failed to decode secret: {e}"))
                        })?;
                        debug!("secret loaded from keyring");
                        Ok(Some(bytes))
                    }
                    Err(keyring::Error::NoEntry) => {
                        debug!("no secret found in keyring");
                        Ok(None)
                    }
                    Err(e) => Err(AppError::SecretStore(format!("failed to read secret: {e}"))),
                }
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn set(
        &self,
        secret: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        let hex_secret = hex::encode(secret);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                entry
                    .set_password(&hex_secret)
                    .map_err(|e| AppError::SecretStore(format!("failed to store secret: {e}")))?;
                debug!("secret stored in keyring");
                Ok(())
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn delete(&self) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.delete_credential() {
                    Ok(()) => {
                        debug!("secret deleted from keyring");
                        Ok(())
                    }
                    Err(keyring::Error::NoEntry) => Ok(()),
                    Err(e) => Err(AppError::SecretStore(format!(
                        "failed to delete secret from keyring: {e}"
                    ))),
                }
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }
}
