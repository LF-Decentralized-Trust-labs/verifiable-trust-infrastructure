use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use vta_sdk::protocols::vta_management::get_config::GetConfigResultBody;

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    pub vta_did: Option<String>,
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
}

pub async fn get_config(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<GetConfigResultBody>, AppError> {
    let result = operations::config::get_config(&state.config, &auth, "rest").await?;
    Ok(Json(result))
}

pub async fn update_config(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<GetConfigResultBody>, AppError> {
    let result = operations::config::update_config(
        &state.config,
        &auth.0,
        operations::config::UpdateConfigParams {
            vta_did: req.vta_did,
            vta_name: req.vta_name,
            public_url: req.public_url,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}
