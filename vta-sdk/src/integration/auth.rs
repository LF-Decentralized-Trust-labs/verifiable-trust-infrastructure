use crate::client::VtaClient;
use crate::credentials::CredentialBundle;
use crate::error::VtaError;

use super::VtaServiceConfig;

/// Authenticate to VTA using a two-tier strategy:
///
/// 1. **Lightweight REST auth** via [`VtaClient::from_credential`] — works when the
///    VTA DID is `did:key`. Enables automatic token refresh.
/// 2. **Session-based challenge-response** via [`crate::session::challenge_response`] —
///    fallback for VTAs using `did:web`, `did:webvh`, or other non-`did:key` methods.
///
/// Network errors are returned immediately (no fallback attempt) since the VTA
/// is genuinely unreachable.
pub async fn authenticate(config: &VtaServiceConfig) -> Result<VtaClient, VtaError> {
    let url_override = config.url_override.as_deref();

    match VtaClient::from_credential(&config.credential, url_override).await {
        Ok(client) => {
            tracing::info!(
                "Authenticated to VTA at '{}' (REST, auto-refresh enabled)",
                client.base_url()
            );
            Ok(client)
        }
        Err(e) if e.is_network() => Err(e),
        Err(e) => {
            tracing::debug!("Lightweight VTA auth failed ({e}), trying session auth");

            let credential = CredentialBundle::decode(&config.credential)?;

            let vta_url = url_override
                .or(credential.vta_url.as_deref())
                .ok_or_else(|| {
                    VtaError::Validation("VTA URL not found in credential or url_override".into())
                })?;

            let token_result = crate::session::challenge_response(
                vta_url,
                &credential.did,
                &credential.private_key_multibase,
                &credential.vta_did,
            )
            .await?;

            let client = VtaClient::new(vta_url);
            client.set_token_async(token_result.access_token).await;

            tracing::info!("Authenticated to VTA at '{vta_url}' (REST, session auth)");
            Ok(client)
        }
    }
}
