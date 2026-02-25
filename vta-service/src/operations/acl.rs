use tracing::info;

use vta_sdk::protocols::acl_management::{
    create::CreateAclResultBody, delete::DeleteAclResultBody, list::ListAclResultBody,
};

use crate::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, is_acl_entry_visible, list_acl_entries,
    store_acl_entry, validate_acl_modification,
};
use crate::auth::extractor::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub struct UpdateAclParams {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub allowed_contexts: Option<Vec<String>>,
}

fn to_result_body(e: &AclEntry) -> CreateAclResultBody {
    CreateAclResultBody {
        did: e.did.clone(),
        role: e.role.to_string(),
        label: e.label.clone(),
        allowed_contexts: e.allowed_contexts.clone(),
        created_at: e.created_at,
        created_by: e.created_by.clone(),
    }
}

pub async fn create_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    role: Role,
    label: Option<String>,
    allowed_contexts: Vec<String>,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;
    validate_acl_modification(auth, &allowed_contexts)?;

    if get_acl_entry(acl_ks, did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {did}"
        )));
    }

    let entry = AclEntry {
        did: did.to_string(),
        role,
        label,
        allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.did.clone(),
    };

    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, caller = %auth.did, did = %entry.did, role = %entry.role, "ACL entry created");
    Ok(to_result_body(&entry))
}

pub async fn get_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;

    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }
    info!(channel, did = %did, "ACL entry retrieved");
    Ok(to_result_body(&entry))
}

pub async fn list_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_filter: Option<&str>,
    channel: &str,
) -> Result<ListAclResultBody, AppError> {
    auth.require_manage()?;

    let all_entries = list_acl_entries(acl_ks).await?;
    let entries: Vec<CreateAclResultBody> = all_entries
        .iter()
        .filter(|e| is_acl_entry_visible(auth, e))
        .filter(|e| match context_filter {
            Some(ctx) => e.allowed_contexts.contains(&ctx.to_string()),
            None => true,
        })
        .map(to_result_body)
        .collect();
    info!(channel, caller = %auth.did, count = entries.len(), "ACL listed");
    Ok(ListAclResultBody { entries })
}

pub async fn update_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    params: UpdateAclParams,
    channel: &str,
) -> Result<CreateAclResultBody, AppError> {
    auth.require_manage()?;

    let mut entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    if let Some(role) = params.role {
        entry.role = role;
    }
    if let Some(label) = params.label {
        entry.label = Some(label);
    }
    if let Some(allowed_contexts) = params.allowed_contexts {
        validate_acl_modification(auth, &allowed_contexts)?;
        entry.allowed_contexts = allowed_contexts;
    }

    store_acl_entry(acl_ks, &entry).await?;

    info!(channel, did = %did, "ACL entry updated");
    Ok(to_result_body(&entry))
}

pub async fn delete_acl(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<DeleteAclResultBody, AppError> {
    auth.require_manage()?;

    if auth.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;
    if !is_acl_entry_visible(auth, &entry) {
        return Err(AppError::NotFound(format!(
            "ACL entry not found for DID: {did}"
        )));
    }

    delete_acl_entry(acl_ks, did).await?;

    info!(channel, caller = %auth.did, did = %did, "ACL entry deleted");
    Ok(DeleteAclResultBody {
        did: did.to_string(),
        deleted: true,
    })
}
