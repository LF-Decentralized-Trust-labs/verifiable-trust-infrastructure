use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::server::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
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

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
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

    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        mediator_url,
        mediator_did,
        #[cfg(feature = "tee")]
        tee_status: state.tee_state.as_ref().map(|ts| ts.status.clone()),
        sealed,
        storage_encrypted,
    })
}
