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
}

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let config = state.config.read().await;
    let (mediator_url, mediator_did) = config
        .messaging
        .as_ref()
        .map(|m| (Some(m.mediator_url.clone()), Some(m.mediator_did.clone())))
        .unwrap_or((None, None));
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        mediator_url,
        mediator_did,
    })
}
