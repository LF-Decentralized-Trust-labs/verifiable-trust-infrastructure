use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use tracing::info;

use crate::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification,
};
use crate::auth::ManageAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;

// ---------- GET /acl ----------

#[derive(Debug, Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
}

impl From<AclEntry> for AclEntryResponse {
    fn from(e: AclEntry) -> Self {
        AclEntryResponse {
            did: e.did,
            role: e.role,
            label: e.label,
            allowed_contexts: e.allowed_contexts,
            created_at: e.created_at,
            created_by: e.created_by,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListAclQuery {
    pub context: Option<String>,
}

pub async fn list_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Query(query): Query<ListAclQuery>,
) -> Result<Json<AclListResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let all_entries = list_acl_entries(&acl).await?;
    let entries: Vec<AclEntryResponse> = all_entries
        .into_iter()
        .filter(|e| is_acl_entry_visible(&auth.0, e))
        .filter(|e| match &query.context {
            Some(ctx) => e.allowed_contexts.contains(ctx),
            None => true,
        })
        .map(AclEntryResponse::from)
        .collect();
    info!(caller = %auth.0.did, count = entries.len(), "ACL listed");
    Ok(Json(AclListResponse { entries }))
}

// ---------- POST /acl ----------

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
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    validate_acl_modification(&auth.0, &req.allowed_contexts)?;

    let acl = state.acl_ks.clone();

    // Check if entry already exists
    if get_acl_entry(&acl, &req.did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {}",
            req.did
        )));
    }

    let entry = AclEntry {
        did: req.did,
        role: req.role,
        label: req.label,
        allowed_contexts: req.allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.0.did,
    };

    store_acl_entry(&acl, &entry).await?;

    info!(caller = %entry.created_by, did = %entry.did, role = %entry.role, "ACL entry created");
    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(entry))))
}

// ---------- GET /acl/{did} ----------

pub async fn get_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(&auth.0, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }
    info!(did = %did, "ACL entry retrieved");
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- PATCH /acl/{did} ----------

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
) -> Result<Json<AclEntryResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let mut entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    // Context admins can only modify entries they can see
    if !is_acl_entry_visible(&auth.0, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    if let Some(role) = req.role {
        entry.role = role;
    }
    if let Some(label) = req.label {
        entry.label = Some(label);
    }
    if let Some(allowed_contexts) = req.allowed_contexts {
        // Validate the new contexts before applying
        validate_acl_modification(&auth.0, &allowed_contexts)?;
        entry.allowed_contexts = allowed_contexts;
    }

    store_acl_entry(&acl, &entry).await?;

    info!(did = %did, "ACL entry updated");
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /acl/{did} ----------

pub async fn delete_acl(
    auth: ManageAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    // Prevent self-deletion
    if auth.0.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let acl = state.acl_ks.clone();

    // Verify entry exists and is visible to the caller
    let entry = get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(&auth.0, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    delete_acl_entry(&acl, &did).await?;

    info!(caller = %auth.0.did, did = %did, "ACL entry deleted");
    Ok(StatusCode::NO_CONTENT)
}
