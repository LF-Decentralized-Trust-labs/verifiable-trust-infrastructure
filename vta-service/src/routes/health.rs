use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// Minimal health response for load balancers and monitoring.
/// Returned by the unauthenticated `GET /health` endpoint.
/// Does NOT expose deployment details to unauthenticated callers.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Detailed health response with deployment information.
/// Returned by the authenticated `GET /health/details` endpoint.
#[derive(Serialize)]
pub struct HealthDetailsResponse {
    status: &'static str,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mediator_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mediator_did: Option<String>,
    #[cfg(feature = "tee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tee_status: Option<crate::tee::types::TeeStatus>,
    sealed: bool,
    storage_encrypted: bool,
}

/// Minimal health check — no authentication required.
/// Returns only `{"status": "ok"}` to avoid leaking deployment details.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Detailed health check — requires authentication.
/// Exposes version, TEE status, seal state, and mediator configuration.
pub async fn health_details(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<HealthDetailsResponse>, AppError> {
    let config = state.config.read().await;
    let (mediator_url, mediator_did) = config
        .messaging
        .as_ref()
        .map(|m| (Some(m.mediator_url.clone()), Some(m.mediator_did.clone())))
        .unwrap_or((None, None));

    // Check seal status
    let sealed = crate::seal::get_seal(&state.acl_ks)
        .await
        .ok()
        .flatten()
        .is_some();

    // Check if storage encryption is active
    let storage_encrypted = state.keys_ks.is_encrypted();

    Ok(Json(HealthDetailsResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        mediator_url,
        mediator_did,
        #[cfg(feature = "tee")]
        tee_status: state.tee_state.as_ref().map(|ts| ts.status.clone()),
        sealed,
        storage_encrypted,
    }))
}
