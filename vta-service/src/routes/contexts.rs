use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::context_management::{
    create::CreateContextResultBody, list::ListContextsResultBody,
};

use crate::auth::{AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateContextRequest {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateContextRequest {
    pub name: Option<String>,
    pub did: Option<String>,
    pub description: Option<String>,
}

pub async fn list_contexts_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ListContextsResultBody>, AppError> {
    let result = operations::contexts::list_contexts(&state.contexts_ks, &auth, "rest").await?;
    Ok(Json(result))
}

pub async fn create_context_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateContextRequest>,
) -> Result<(StatusCode, Json<CreateContextResultBody>), AppError> {
    let result = operations::contexts::create_context(
        &state.contexts_ks,
        &auth.0,
        &req.id,
        req.name,
        req.description,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub async fn get_context_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<CreateContextResultBody>, AppError> {
    let result =
        operations::contexts::get_context_op(&state.contexts_ks, &auth, &id, "rest").await?;
    Ok(Json(result))
}

pub async fn update_context_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateContextRequest>,
) -> Result<Json<CreateContextResultBody>, AppError> {
    let result = operations::contexts::update_context(
        &state.contexts_ks,
        &auth.0,
        &id,
        operations::contexts::UpdateContextParams {
            name: req.name,
            did: req.did,
            description: req.description,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

pub async fn delete_context_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::contexts::delete_context(&state.contexts_ks, &auth.0, &id, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}
