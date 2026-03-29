use axum::Json;
use axum::extract::State;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

use vta_sdk::protocols::backup_management::types::{
    BackupEnvelope, ExportRequest, ImportRequest, ImportResult,
};

/// POST /backup/export — export VTA state to an encrypted backup.
pub async fn export(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<BackupEnvelope>, AppError> {
    let config = state.config.read().await;
    let envelope = operations::backup::export_backup(
        &state.keys_ks,
        &state.acl_ks,
        &state.contexts_ks,
        &state.audit_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &*state.seed_store,
        &config,
        &auth,
        &req.password,
        req.include_audit,
    )
    .await?;

    let _ = crate::audit::record(
        &state.audit_ks,
        "backup.export",
        &auth.did,
        None,
        "success",
        Some("rest"),
        None,
    )
    .await;

    Ok(Json(envelope))
}

/// POST /backup/import — import VTA state from an encrypted backup.
pub async fn import(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResult>, AppError> {
    auth.require_admin()?;

    // Preview mode: decrypt and return summary without modifying state
    if !req.confirm {
        let (_payload, preview) =
            operations::backup::preview_import(&req.backup, &req.password).await?;
        return Ok(Json(preview));
    }

    // Full import
    let (payload, _preview) =
        operations::backup::preview_import(&req.backup, &req.password).await?;

    let result = operations::backup::apply_import(
        &payload,
        &state.keys_ks,
        &state.acl_ks,
        &state.contexts_ks,
        &state.audit_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &state.seed_store,
        &state.config,
        None, // Store passed for TEE re-encryption (REST has no store access; handled on restart)
    )
    .await?;

    let _ = crate::audit::record(
        &state.audit_ks,
        "backup.import",
        &auth.did,
        payload.config.vta_did.as_deref(),
        "success",
        Some("rest"),
        None,
    )
    .await;

    // Trigger soft restart after response is sent
    let restart_tx = state.restart_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = restart_tx.send(true);
    });

    Ok(Json(result))
}
