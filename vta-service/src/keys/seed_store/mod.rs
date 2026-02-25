#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "azure-secrets")]
mod azure;
#[cfg(feature = "config-seed")]
mod config;
#[cfg(feature = "gcp-secrets")]
mod gcp;
#[cfg(feature = "keyring")]
mod keyring;
mod plaintext;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSeedStore;
#[cfg(feature = "azure-secrets")]
pub use azure::AzureSeedStore;
#[cfg(feature = "config-seed")]
pub use config::ConfigSeedStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSeedStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSeedStore;
pub use plaintext::PlaintextSeedStore;

use std::future::Future;
use std::pin::Pin;

use crate::config::AppConfig;
use crate::error::AppError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait SeedStore: Send + Sync {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;
    fn set(&self, seed: &[u8]) -> BoxFuture<'_, Result<(), AppError>>;
}

/// Create a seed store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `secrets.azure_vault_url` set)
/// 4. Config file seed (if `config-seed` compiled + `secrets.seed` set)
/// 5. OS keyring (if `keyring` compiled — the default)
/// 6. Plaintext file (always available — NOT secure)
#[allow(unused_variables)]
pub fn create_seed_store(config: &AppConfig) -> Result<Box<dyn SeedStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if config.secrets.aws_secret_name.is_some() {
        let store = AwsSeedStore::new(
            config.secrets.aws_secret_name.clone().unwrap(),
            config.secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "gcp-secrets")]
    if config.secrets.gcp_secret_name.is_some() {
        let project = config.secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSeedStore::new(project, config.secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "azure-secrets")]
    if config.secrets.azure_vault_url.is_some() {
        let vault_url = config.secrets.azure_vault_url.clone().unwrap();
        let secret_name = config
            .secrets
            .azure_secret_name
            .clone()
            .unwrap_or_else(|| "vta-master-seed".to_string());
        let store = AzureSeedStore::new(vault_url, secret_name);
        return Ok(Box::new(store));
    }

    #[cfg(feature = "config-seed")]
    if config.secrets.seed.is_some() {
        let store = ConfigSeedStore::new(config.secrets.seed.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSeedStore::new(&config.secrets.keyring_service, "master_seed");
        return Ok(Box::new(store));
    }

    #[allow(unreachable_code)]
    {
        tracing::warn!(
            "no secure seed store backend available — falling back to plaintext file storage"
        );
        let store = PlaintextSeedStore::new(&config.store.data_dir);
        Ok(Box::new(store))
    }
}
