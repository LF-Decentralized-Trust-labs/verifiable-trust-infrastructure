use axum::Json;
use axum::extract::State;

use crate::auth::extractor::SuperAdminAuth;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;
use crate::tee::mnemonic_guard::{MnemonicExportResponse, MnemonicExportStatus};
use crate::tee::types::{AttestationRequest, AttestationResponse, TeeStatus};

/// GET /attestation/status — TEE detection status (unauthenticated).
pub async fn status(State(state): State<AppState>) -> Result<Json<TeeStatus>, AppError> {
    let tee_state = state.tee_state.as_ref().ok_or_else(|| {
        AppError::TeeAttestation("TEE attestation is not enabled on this VTA".into())
    })?;

    Ok(Json(operations::attestation::get_tee_status(tee_state)))
}

/// POST /attestation/report — Generate a fresh attestation report with a client nonce (unauthenticated).
pub async fn generate_report(
    State(state): State<AppState>,
    Json(body): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, AppError> {
    let tee_state = state.tee_state.as_ref().ok_or_else(|| {
        AppError::TeeAttestation("TEE attestation is not enabled on this VTA".into())
    })?;

    let response =
        operations::attestation::generate_attestation_report(tee_state, &state.config, &body.nonce)
            .await?;

    Ok(Json(response))
}

/// GET /attestation/report — Return a cached attestation report (unauthenticated).
pub async fn cached_report(
    State(state): State<AppState>,
) -> Result<Json<AttestationResponse>, AppError> {
    let tee_state = state.tee_state.as_ref().ok_or_else(|| {
        AppError::TeeAttestation("TEE attestation is not enabled on this VTA".into())
    })?;

    let response = operations::attestation::get_cached_report(tee_state, &state.config).await?;

    Ok(Json(response))
}

/// GET /attestation/mnemonic — Check mnemonic export window status (super admin only).
pub async fn mnemonic_status(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<MnemonicExportStatus>, AppError> {
    let guard = state.mnemonic_guard.as_ref().ok_or_else(|| {
        AppError::TeeAttestation("mnemonic export not available (TEE mode not active or no KMS bootstrap)".into())
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
    let guard = state.mnemonic_guard.as_ref().ok_or_else(|| {
        AppError::TeeAttestation("mnemonic export not available (TEE mode not active or no KMS bootstrap)".into())
    })?;

    let response = guard.export()?;
    Ok(Json(response))
}
