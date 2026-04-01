use crate::did_secrets::DidSecretsBundle;

/// Local cache for VTA secrets, enabling offline startup when VTA is unreachable.
///
/// Services implement this trait to persist [`DidSecretsBundle`] using their
/// preferred storage backend (keyring, AWS Secrets Manager, GCP Secret Manager, etc.).
///
/// The bundle's [`encode()`](DidSecretsBundle::encode) and
/// [`decode()`](DidSecretsBundle::decode) methods produce/consume a base64url
/// JSON string — most backends only need to store and retrieve that single string.
pub trait SecretCache: Send + Sync {
    /// Persist a secrets bundle for offline recovery.
    fn store(
        &self,
        bundle: &DidSecretsBundle,
    ) -> impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send;

    /// Load the last cached secrets bundle, if any.
    ///
    /// Returns `Ok(None)` when no cached data exists (first run before VTA contact).
    fn load(
        &self,
    ) -> impl Future<
        Output = Result<Option<DidSecretsBundle>, Box<dyn std::error::Error + Send + Sync>>,
    > + Send;
}

use std::future::Future;
