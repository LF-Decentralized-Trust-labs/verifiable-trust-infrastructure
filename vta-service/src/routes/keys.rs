use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody, list::ListKeysResultBody, rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody, secret::GetKeySecretResultBody,
    sign::{SignAlgorithm, SignResultBody},
};
use vta_sdk::protocols::seed_management::{
    list::ListSeedsResultBody, rotate::RotateSeedResultBody,
};

use crate::auth::{AdminAuth, AuthClaims};
use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::KeyStatus;
use crate::keys::KeyType;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    pub derivation_path: Option<String>,
    pub key_id: Option<String>,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

pub async fn create_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResultBody>), AppError> {
    let result = operations::keys::create_key(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        operations::keys::CreateKeyParams {
            key_type: req.key_type,
            derivation_path: req.derivation_path,
            key_id: req.key_id,
            mnemonic: req.mnemonic,
            label: req.label,
            context_id: req.context_id,
        },
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub async fn get_key_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<GetKeySecretResultBody>, AppError> {
    let result = operations::keys::get_key_secret(
        &state.keys_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        &key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

pub async fn get_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyRecord>, AppError> {
    let result = operations::keys::get_key(&state.keys_ks, &auth, &key_id, "rest").await?;
    Ok(Json(result))
}

pub async fn invalidate_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<RevokeKeyResultBody>, AppError> {
    let result = operations::keys::revoke_key(&state.keys_ks, &state.audit_ks, &auth.0, &key_id, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

pub async fn rename_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResultBody>, AppError> {
    let result =
        operations::keys::rename_key(&state.keys_ks, &state.audit_ks, &auth.0, &key_id, &req.key_id, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<KeyStatus>,
    pub context_id: Option<String>,
}

pub async fn list_keys(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<ListKeysResultBody>, AppError> {
    let result = operations::keys::list_keys(
        &state.keys_ks,
        &auth,
        operations::keys::ListKeysParams {
            offset: query.offset,
            limit: query.limit,
            status: query.status,
            context_id: query.context_id,
        },
        "rest",
    )
    .await?;
    Ok(Json(result))
}

// ── Seed endpoints ────────────────────────────────────────────────

pub async fn list_seeds(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ListSeedsResultBody>, AppError> {
    let result = operations::seeds::list_seeds(&state.keys_ks, "rest").await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct RotateSeedRequest {
    pub mnemonic: Option<String>,
}

pub async fn rotate_seed(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RotateSeedRequest>,
) -> Result<Json<RotateSeedResultBody>, AppError> {
    let result = operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.seed_store,
        &state.audit_ks,
        &_auth.0.did,
        req.mnemonic.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

// ── Sign endpoint ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub payload: String,
    pub algorithm: SignAlgorithm,
}

pub async fn sign_with_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResultBody>, AppError> {
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .map_err(|e| AppError::Validation(format!("invalid base64url payload: {e}")))?;

    let result = operations::keys::sign_payload(
        &state.keys_ks,
        &state.seed_store,
        &auth,
        &key_id,
        &payload,
        &req.algorithm,
        "rest",
    )
    .await?;
    Ok(Json(result))
}
