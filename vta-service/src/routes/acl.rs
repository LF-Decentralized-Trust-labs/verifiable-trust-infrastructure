use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::acl_management::{create::CreateAclResultBody, list::ListAclResultBody};

use crate::acl::Role;
use crate::auth::ManageAuth;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct ListAclQuery {
    pub context: Option<String>,
}

pub async fn list_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Query(query): Query<ListAclQuery>,
) -> Result<Json<ListAclResultBody>, AppError> {
    let result =
        operations::acl::list_acl(&state.acl_ks, &auth.0, query.context.as_deref(), "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
}

pub async fn create_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<CreateAclResultBody>), AppError> {
    let result = operations::acl::create_acl(
        &state.acl_ks,
        &auth.0,
        &req.did,
        req.role,
        req.label,
        req.allowed_contexts,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub async fn get_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<CreateAclResultBody>, AppError> {
    let result = operations::acl::get_acl(&state.acl_ks, &auth.0, &did, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
}

pub async fn update_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<CreateAclResultBody>, AppError> {
    let result = operations::acl::update_acl(
        &state.acl_ks,
        &auth.0,
        &did,
        operations::acl::UpdateAclParams {
            role: req.role,
            label: req.label,
            allowed_contexts: req.allowed_contexts,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

pub async fn delete_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::acl::delete_acl(&state.acl_ks, &auth.0, &did, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}
