use axum::Json;
use axum::extract::State;

use crate::auth::SuperAdminAuth;
use crate::error::{AppError, tee_attestation_error};
use crate::operations;
use crate::server::AppState;
use crate::tee::mnemonic_guard::{MnemonicExportResponse, MnemonicExportStatus};
use crate::tee::types::{AttestationRequest, AttestationResponse, TeeStatus};

/// GET /attestation/status — TEE detection status (unauthenticated).
pub async fn status(State(state): State<AppState>) -> Result<Json<TeeStatus>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    Ok(Json(operations::attestation::get_tee_status(tee_state)))
}

/// POST /attestation/report — Generate a fresh attestation report with a client nonce (unauthenticated).
pub async fn generate_report(
    State(state): State<AppState>,
    Json(body): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    let response =
        operations::attestation::generate_attestation_report(tee_state, &state.config, &body.nonce)
            .await?;

    Ok(Json(response))
}

/// GET /attestation/report — Return a cached attestation report (unauthenticated).
pub async fn cached_report(
    State(state): State<AppState>,
) -> Result<Json<AttestationResponse>, AppError> {
    let tee_state = state
        .tee
        .as_ref()
        .map(|tc| &tc.state)
        .ok_or_else(|| tee_attestation_error("TEE attestation is not enabled on this VTA"))?;

    let response = operations::attestation::get_cached_report(tee_state, &state.config).await?;

    Ok(Json(response))
}

/// GET /attestation/did-log — Return the auto-generated did.jsonl (unauthenticated).
///
/// The DID log is public data (it's published to a web server). This endpoint
/// is only available when the VTA auto-generated a did:webvh identity on first boot.
pub async fn did_log(State(state): State<AppState>) -> Result<String, AppError> {
    let log_bytes = state.keys_ks.get_raw("tee:did_log").await?.ok_or_else(|| {
        AppError::NotFound(
            "no auto-generated DID log found — the VTA may not have \
                 been configured with a vta_did_template"
                .into(),
        )
    })?;

    String::from_utf8(log_bytes)
        .map_err(|e| AppError::Internal(format!("DID log is not valid UTF-8: {e}")))
}

/// GET /attestation/admin-credential — Return and delete the bootstrapped admin credential.
///
/// Unauthenticated, one-time retrieval. The credential is deleted from the
/// store after the first successful read to prevent repeated access. Subsequent
/// calls return 404.
///
/// Only available when the VTA auto-bootstrapped a super-admin credential
/// on first boot via `admin_bootstrap::maybe_bootstrap_admin()`.
pub async fn admin_credential(State(state): State<AppState>) -> Result<String, AppError> {
    let cred_bytes = state
        .keys_ks
        .get_raw("tee:admin_credential")
        .await?
        .ok_or_else(|| {
            AppError::NotFound(
                "no bootstrapped admin credential found — already retrieved or \
                 VTA was not configured with KMS bootstrap"
                    .into(),
            )
        })?;

    let credential = String::from_utf8(cred_bytes)
        .map_err(|e| AppError::Internal(format!("admin credential is not valid UTF-8: {e}")))?;

    // Delete from encrypted store after retrieval (one-time access)
    let _ = state.keys_ks.remove("tee:admin_credential").await;
    tracing::info!("admin credential retrieved and deleted from store");

    Ok(credential)
}

/// GET /attestation/mnemonic — Check mnemonic export window status (super admin only).
pub async fn mnemonic_status(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<MnemonicExportStatus>, AppError> {
    let guard = state
        .tee
        .as_ref()
        .and_then(|tc| tc.mnemonic_guard.as_ref())
        .ok_or_else(|| {
            tee_attestation_error(
                "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
            )
        })?;

    Ok(Json(guard.status()))
}

/// POST /attestation/mnemonic — Export the BIP-39 mnemonic (super admin only, time-limited).
///
/// Requirements:
/// - VTA must have been started with `VTA_MNEMONIC_EXPORT_WINDOW=<seconds>`
/// - Must be within the export window since boot
/// - Caller must be a super admin (JWT-authenticated)
/// - One-time operation: after successful export, the entropy is zeroed
pub async fn mnemonic_export(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<MnemonicExportResponse>, AppError> {
    let guard = state
        .tee
        .as_ref()
        .and_then(|tc| tc.mnemonic_guard.as_ref())
        .ok_or_else(|| {
            tee_attestation_error(
                "mnemonic export not available (TEE mode not active or no KMS bootstrap)",
            )
        })?;

    let response = guard.export()?;
    Ok(Json(response))
}
