use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody,
    list::ListKeysResultBody,
    rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody,
    secret::GetKeySecretResultBody,
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

/// POST /keys — create a new key record. Auth: Admin or Initiator. Context-scoped.
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

/// GET /keys/{key_id}/secret — retrieve private key material. Auth: Admin or Initiator.
pub async fn get_key_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<GetKeySecretResultBody>, AppError> {
    let result = operations::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        &key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// GET /keys/{key_id} — retrieve a single key record. Auth: any authenticated user.
pub async fn get_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyRecord>, AppError> {
    let result = operations::keys::get_key(&state.keys_ks, &auth, &key_id, "rest").await?;
    Ok(Json(result))
}

/// DELETE /keys/{key_id} — revoke/invalidate a key. Auth: Admin or Initiator.
pub async fn invalidate_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<RevokeKeyResultBody>, AppError> {
    let result = operations::keys::revoke_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        &auth.0,
        &key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

/// PATCH /keys/{key_id} — rename a key's identifier. Auth: Admin or Initiator.
pub async fn rename_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResultBody>, AppError> {
    let result = operations::keys::rename_key(
        &state.keys_ks,
        &state.audit_ks,
        &auth.0,
        &key_id,
        &req.key_id,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<KeyStatus>,
    pub context_id: Option<String>,
}

/// GET /keys — list key records with optional filters. Auth: any authenticated user. Context-scoped.
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

/// GET /keys/seeds — list all seed records. Auth: Admin or Initiator.
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

/// POST /keys/seeds/rotate — rotate the active seed, optionally supplying a mnemonic. Auth: Admin or Initiator.
pub async fn rotate_seed(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RotateSeedRequest>,
) -> Result<Json<RotateSeedResultBody>, AppError> {
    let result = operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.imported_ks,
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

/// POST /keys/{key_id}/sign — sign a base64url payload with the specified key. Auth: Application or higher.
pub async fn sign_with_key(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResultBody>, AppError> {
    auth.require_write()?;
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .map_err(|e| AppError::Validation(format!("invalid base64url payload: {e}")))?;

    let result = operations::keys::sign_payload(
        &state.keys_ks,
        &state.imported_ks,
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

// ── Import key endpoints ─────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct WrappingKeyResponse {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
}

/// GET /keys/import/wrapping-key — get an ephemeral X25519 public key for REST key wrapping.
pub async fn get_wrapping_key(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<WrappingKeyResponse>, AppError> {
    let (kid, x) = state.wrapping_cache.generate().await;
    Ok(Json(WrappingKeyResponse {
        kid,
        kty: "OKP".into(),
        crv: "X25519".into(),
        x,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ImportKeyRestRequest {
    pub key_type: KeyType,
    /// JWE compact serialization of the private key (REST transport).
    pub private_key_jwe: Option<String>,
    /// Multibase-encoded private key (DIDComm transport — should not be used via REST).
    pub private_key_multibase: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

/// POST /keys/import — import an externally-created private key. Auth: Admin only.
pub async fn import_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ImportKeyRestRequest>,
) -> Result<(StatusCode, Json<CreateKeyResultBody>), AppError> {
    // Unwrap the private key based on transport
    let private_key_bytes = if let Some(jwe) = req.private_key_jwe {
        state.wrapping_cache.unwrap_jwe(&jwe).await?
    } else if let Some(ref mb) = req.private_key_multibase {
        let (_, bytes) = multibase::decode(mb)
            .map_err(|e| AppError::Validation(format!("invalid multibase private key: {e}")))?;
        bytes
    } else {
        return Err(AppError::Validation(
            "either private_key_jwe or private_key_multibase is required".into(),
        ));
    };

    let result = operations::keys::import_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.0,
        operations::keys::ImportKeyParams {
            key_type: req.key_type,
            private_key_bytes,
            label: req.label,
            context_id: req.context_id,
        },
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
