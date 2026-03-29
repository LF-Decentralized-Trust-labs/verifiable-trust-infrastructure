use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

#[derive(Serialize)]
pub struct RestartResponse {
    status: &'static str,
}

/// Trigger a soft restart of the VTA.
///
/// All service threads (REST, DIDComm, storage) are shut down and
/// re-initialized with the current config and seed. Admin role required.
pub async fn restart(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<RestartResponse>, AppError> {
    auth.require_admin()?;

    // Log the restart request before triggering
    let _ = crate::audit::record(
        &state.audit_ks,
        "vta.restart",
        &auth.did,
        None,
        "success",
        Some("rest"),
        None,
    )
    .await;

    // Signal the restart after a short delay so the response can be sent first
    let restart_tx = state.restart_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = restart_tx.send(true);
    });

    Ok(Json(RestartResponse {
        status: "restarting",
    }))
}
