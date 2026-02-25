use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::did_management::{
    create::CreateDidWebvhResultBody,
    list::ListDidsWebvhResultBody,
    servers::{AddWebvhServerResultBody, ListWebvhServersResultBody, UpdateWebvhServerResultBody},
};
use vta_sdk::webvh::WebvhDidRecord;

use crate::auth::{AdminAuth, AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct AddServerRequest {
    pub id: String,
    pub did: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDidRequest {
    pub context_id: String,
    pub server_id: String,
    pub path: Option<String>,
    pub label: Option<String>,
    #[serde(default = "default_true")]
    pub portable: bool,
    #[serde(default)]
    pub add_mediator_service: bool,
    pub additional_services: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub pre_rotation_count: u32,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ListDidsQuery {
    pub context_id: Option<String>,
    pub server_id: Option<String>,
}

// -- Server routes --

pub async fn add_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<AddServerRequest>,
) -> Result<(StatusCode, Json<AddWebvhServerResultBody>), AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let result = operations::did_webvh::add_webvh_server(
        &state.webvh_ks,
        &auth.0,
        &req.id,
        &req.did,
        req.label,
        did_resolver,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub async fn list_servers_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ListWebvhServersResultBody>, AppError> {
    let result = operations::did_webvh::list_webvh_servers(&state.webvh_ks, &auth, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct UpdateServerRequest {
    pub label: Option<String>,
}

pub async fn update_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateServerRequest>,
) -> Result<Json<UpdateWebvhServerResultBody>, AppError> {
    let result = operations::did_webvh::update_webvh_server(
        &state.webvh_ks,
        &auth.0,
        &id,
        req.label,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

pub async fn remove_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::did_webvh::remove_webvh_server(&state.webvh_ks, &auth.0, &id, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}

// -- DID routes --

pub async fn create_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateDidRequest>,
) -> Result<(StatusCode, Json<CreateDidWebvhResultBody>), AppError> {
    let config = state.config.read().await;
    let params = operations::did_webvh::CreateDidWebvhParams {
        context_id: req.context_id,
        server_id: req.server_id,
        path: req.path,
        label: req.label,
        portable: req.portable,
        add_mediator_service: req.add_mediator_service,
        additional_services: req.additional_services,
        pre_rotation_count: req.pre_rotation_count,
    };
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let result = operations::did_webvh::create_did_webvh(
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &*state.seed_store,
        &config,
        &auth.0,
        params,
        did_resolver,
        &state.didcomm_bridge,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub async fn list_dids_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListDidsQuery>,
) -> Result<Json<ListDidsWebvhResultBody>, AppError> {
    let result = operations::did_webvh::list_dids_webvh(
        &state.webvh_ks,
        &auth,
        query.context_id.as_deref(),
        query.server_id.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

pub async fn get_did_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<WebvhDidRecord>, AppError> {
    let result = operations::did_webvh::get_did_webvh(&state.webvh_ks, &auth, &did, "rest").await?;
    Ok(Json(result))
}

pub async fn delete_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    let config = state.config.read().await;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    operations::did_webvh::delete_did_webvh(
        &state.webvh_ks,
        &state.keys_ks,
        &*state.seed_store,
        &config,
        &auth.0,
        &did,
        did_resolver,
        &state.didcomm_bridge,
        "rest",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
