//! Unified VTA integration for service startup.
//!
//! Provides a single startup pattern for any service that manages its DID and
//! secrets through a VTA:
//!
//! 1. Authenticate to the VTA (lightweight REST, with session-based fallback).
//! 2. Fetch the latest [`DidSecretsBundle`] from the VTA context.
//! 3. Cache the bundle locally for offline resilience.
//! 4. If the VTA is unreachable, load the last cached bundle.
//!
//! # Usage
//!
//! ```ignore
//! use vta_sdk::integration::{startup, VtaServiceConfig, SecretCache};
//!
//! // Implement SecretCache for your storage backend (keyring, AWS, etc.)
//! struct MyCache { /* ... */ }
//! impl SecretCache for MyCache { /* ... */ }
//!
//! let config = VtaServiceConfig {
//!     credential: loaded_credential_string,
//!     context: "my-service".into(),
//!     url_override: None,
//! };
//! let cache = MyCache::new();
//!
//! let result = startup(&config, &cache).await?;
//! // result.did — the service's DID
//! // result.bundle.secrets — Vec<SecretEntry> for DIDComm/signing
//! // result.source — whether secrets came from VTA or cache
//! ```

pub mod auth;
pub mod cache;

pub use auth::authenticate;
pub use cache::SecretCache;

use crate::did_secrets::DidSecretsBundle;
use crate::error::VtaError;
use std::time::Duration;

/// Default timeout for the entire VTA startup flow (auth + secret fetch).
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for connecting a service to its VTA context.
///
/// The `credential` field should contain the already-loaded base64url credential
/// string. How the credential is loaded (from a config file, AWS Secrets Manager,
/// OS keyring, etc.) is left to the calling service.
#[derive(Clone, Debug)]
pub struct VtaServiceConfig {
    /// Base64url-encoded VTA credential bundle.
    pub credential: String,
    /// VTA context ID that holds this service's DID and keys.
    pub context: String,
    /// Optional REST URL override. When set, bypasses the URL embedded in the
    /// credential (useful for VTARest service discovery or dev/testing).
    pub url_override: Option<String>,
    /// Timeout for the VTA startup flow (auth + secret fetch).
    /// Defaults to 30 seconds if `None`.
    pub timeout: Option<Duration>,
}

/// Whether secrets were loaded live from the VTA or from the local cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// Fresh secrets fetched from the VTA.
    Vta,
    /// Stale secrets loaded from the local cache (VTA was unreachable).
    Cache,
}

/// Successful result from [`startup`].
pub struct StartupResult {
    /// The service's DID, as recorded in the VTA context.
    pub did: String,
    /// The full secrets bundle (DID + all private keys).
    pub bundle: DidSecretsBundle,
    /// Where the secrets came from.
    pub source: SecretSource,
    /// The authenticated VTA client, if secrets were fetched live.
    /// `None` when secrets came from the local cache.
    /// Services can use this for additional VTA calls (e.g., health checks).
    pub client: Option<crate::client::VtaClient>,
}

/// Errors from the VTA integration startup flow.
#[derive(Debug)]
pub enum VtaIntegrationError {
    /// VTA is unreachable and no locally cached secrets exist.
    /// This typically means the service has never successfully contacted the VTA.
    NoCachedSecrets,
    /// The VTA context returned zero secrets. This is a configuration error —
    /// the context must have at least one key (signing or key agreement) provisioned.
    EmptySecretsBundle(String),
    /// The local secret cache could not be read or written.
    CacheError(String),
    /// An error from the VTA SDK (authentication or secret fetch).
    Vta(VtaError),
}

impl std::fmt::Display for VtaIntegrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCachedSecrets => write!(
                f,
                "VTA is unreachable and no cached secrets exist. \
                 Run the setup wizard or ensure the VTA is accessible for the first startup."
            ),
            Self::EmptySecretsBundle(ctx) => write!(
                f,
                "VTA context '{ctx}' returned zero secrets. \
                 Provision keys via the setup wizard or VTA admin tools."
            ),
            Self::CacheError(e) => write!(f, "secret cache error: {e}"),
            Self::Vta(e) => write!(f, "VTA error: {e}"),
        }
    }
}

impl std::error::Error for VtaIntegrationError {}

impl From<VtaError> for VtaIntegrationError {
    fn from(e: VtaError) -> Self {
        Self::Vta(e)
    }
}

/// Main entry point for VTA-integrated service startup.
///
/// Attempts to fetch fresh secrets from the VTA and cache them locally.
/// If the VTA is unreachable, falls back to the last cached bundle.
///
/// Returns a [`StartupResult`] containing the service DID, secrets bundle,
/// and whether the secrets are fresh or cached.
pub async fn startup(
    config: &VtaServiceConfig,
    cache: &(impl SecretCache + ?Sized),
) -> Result<StartupResult, VtaIntegrationError> {
    let timeout = config.timeout.unwrap_or(DEFAULT_STARTUP_TIMEOUT);

    let vta_result = tokio::time::timeout(timeout, async {
        let client = authenticate(config).await?;
        let bundle = client
            .fetch_did_secrets_bundle(&config.context)
            .await
            .map_err(VtaIntegrationError::from)?;
        Ok::<_, VtaIntegrationError>((client, bundle))
    })
    .await;

    match vta_result {
        Ok(Ok((client, bundle))) => {
            if bundle.secrets.is_empty() {
                return Err(VtaIntegrationError::EmptySecretsBundle(
                    config.context.clone(),
                ));
            }
            if let Err(e) = cache.store(&bundle).await {
                tracing::warn!("Failed to cache VTA secrets locally: {e}");
            }
            tracing::info!(
                context = config.context,
                secrets = bundle.secrets.len(),
                "Loaded fresh secrets from VTA",
            );
            Ok(StartupResult {
                did: bundle.did.clone(),
                bundle,
                source: SecretSource::Vta,
                client: Some(client),
            })
        }
        Ok(Err(e)) => {
            tracing::warn!("VTA startup failed: {e}");
            load_from_cache(cache, &config.context).await
        }
        Err(_elapsed) => {
            tracing::warn!(
                "VTA startup timed out after {}s, falling back to cached secrets",
                timeout.as_secs()
            );
            load_from_cache(cache, &config.context).await
        }
    }
}

async fn load_from_cache(
    cache: &(impl SecretCache + ?Sized),
    context: &str,
) -> Result<StartupResult, VtaIntegrationError> {
    match cache.load().await {
        Ok(Some(bundle)) => {
            if bundle.secrets.is_empty() {
                return Err(VtaIntegrationError::EmptySecretsBundle(context.to_string()));
            }
            tracing::warn!(
                context = context,
                secrets = bundle.secrets.len(),
                "Using CACHED secrets — keys may be stale",
            );
            Ok(StartupResult {
                did: bundle.did.clone(),
                bundle,
                source: SecretSource::Cache,
                client: None,
            })
        }
        Ok(None) => Err(VtaIntegrationError::NoCachedSecrets),
        Err(e) => Err(VtaIntegrationError::CacheError(e.to_string())),
    }
}
