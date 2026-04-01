use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::debug;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::tee::TeeState;
use crate::tee::types::{AttestationResponse, TeeStatus};

/// Get the cached TEE detection status.
pub fn get_tee_status(tee_state: &TeeState) -> TeeStatus {
    tee_state.status.clone()
}

/// Generate a fresh attestation report binding the VTA DID and client nonce.
pub async fn generate_attestation_report(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
    nonce: &str,
) -> Result<AttestationResponse, AppError> {
    // Validate nonce: must be hex-encoded, 1-64 bytes
    let nonce_bytes = hex::decode(nonce)
        .map_err(|e| AppError::Validation(format!("nonce must be hex-encoded: {e}")))?;
    if nonce_bytes.is_empty() || nonce_bytes.len() > 64 {
        return Err(AppError::Validation(
            "nonce must be 1-64 bytes (2-128 hex chars)".into(),
        ));
    }

    // Read VTA DID from config
    let vta_did = config.read().await.vta_did.clone();
    let user_data = vta_did.as_deref().unwrap_or("").as_bytes();

    debug!(
        nonce_len = nonce_bytes.len(),
        "generating attestation report"
    );

    // Generate the report via the platform provider
    let mut report = tee_state.provider.attest(user_data, &nonce_bytes)?;
    report.vta_did = vta_did;

    // Self-verify
    let self_verified = tee_state.provider.verify(&report)?;

    Ok(AttestationResponse {
        report,
        self_verified,
    })
}

/// Get a cached attestation report (no client nonce — uses a timestamp-based nonce).
pub async fn get_cached_report(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
) -> Result<AttestationResponse, AppError> {
    // Use a deterministic nonce derived from the current time bucket
    let cache_ttl = {
        #[cfg(feature = "tee")]
        {
            config.read().await.tee.attestation_cache_ttl
        }
        #[cfg(not(feature = "tee"))]
        {
            let _ = config;
            300u64
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_bucket = now / cache_ttl;
    let nonce = hex::encode(time_bucket.to_be_bytes());

    generate_attestation_report(tee_state, config, &nonce).await
}
