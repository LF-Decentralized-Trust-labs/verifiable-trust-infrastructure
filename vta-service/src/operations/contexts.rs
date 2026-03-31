use chrono::Utc;
use tracing::info;

use vta_sdk::protocols::context_management::{
    create::CreateContextResultBody,
    delete::{DeleteContextPreviewResultBody, DeleteContextResultBody},
    list::ListContextsResultBody,
};

use crate::auth::AuthClaims;
use crate::contexts::{
    ContextRecord, allocate_context_index, delete_context as delete_context_store, get_context,
    list_contexts as list_contexts_store, store_context,
};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub struct UpdateContextParams {
    pub name: Option<String>,
    pub did: Option<String>,
    pub description: Option<String>,
}

fn validate_slug(id: &str) -> Result<(), AppError> {
    if id.is_empty() {
        return Err(AppError::Validation("context id cannot be empty".into()));
    }
    if id.len() > 64 {
        return Err(AppError::Validation(
            "context id must be 64 characters or fewer".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::Validation(
            "context id must contain only lowercase alphanumeric characters and hyphens".into(),
        ));
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err(AppError::Validation(
            "context id must not start or end with a hyphen".into(),
        ));
    }
    Ok(())
}

fn to_result_body(r: &ContextRecord) -> CreateContextResultBody {
    CreateContextResultBody {
        id: r.id.clone(),
        name: r.name.clone(),
        did: r.did.clone(),
        description: r.description.clone(),
        base_path: r.base_path.clone(),
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

pub async fn create_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    name: String,
    description: Option<String>,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_super_admin()?;
    validate_slug(id)?;

    if get_context(contexts_ks, id).await?.is_some() {
        return Err(AppError::Conflict(format!("context already exists: {id}")));
    }

    let (index, base_path) = allocate_context_index(contexts_ks).await?;

    let now = Utc::now();
    let record = ContextRecord {
        id: id.to_string(),
        name,
        did: None,
        description,
        base_path,
        index,
        created_at: now,
        updated_at: now,
    };

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %record.id, index, "context created");
    Ok(to_result_body(&record))
}

pub async fn get_context_op(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_context(id)?;
    let record = get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;
    info!(channel, id = %id, "context retrieved");
    Ok(to_result_body(&record))
}

pub async fn list_contexts(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    channel: &str,
) -> Result<ListContextsResultBody, AppError> {
    let records = list_contexts_store(contexts_ks).await?;
    let contexts: Vec<CreateContextResultBody> = records
        .iter()
        .filter(|r| auth.has_context_access(&r.id))
        .map(to_result_body)
        .collect();
    info!(channel, caller = %auth.did, count = contexts.len(), "contexts listed");
    Ok(ListContextsResultBody { contexts })
}

pub async fn update_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    params: UpdateContextParams,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_super_admin()?;

    let mut record = get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    if let Some(name) = params.name {
        record.name = name;
    }
    if let Some(did) = params.did {
        record.did = Some(did);
    }
    if let Some(description) = params.description {
        record.description = Some(description);
    }
    record.updated_at = Utc::now();

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %id, "context updated");
    Ok(to_result_body(&record))
}

/// Update the DID for a context. Requires Admin role with access to the context
/// (context-scoped admins can update DIDs on their own contexts).
pub async fn update_context_did(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    did: String,
    channel: &str,
) -> Result<CreateContextResultBody, AppError> {
    auth.require_admin()?;
    auth.require_context(id)?;

    let mut record = get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    record.did = Some(did);
    record.updated_at = Utc::now();

    store_context(contexts_ks, &record).await?;

    info!(channel, id = %id, did = ?record.did, "context DID updated");
    Ok(to_result_body(&record))
}

/// Collect a preview of all resources associated with a context.
pub async fn preview_delete_context(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<DeleteContextPreviewResultBody, AppError> {
    auth.require_super_admin()?;

    get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    let preview = collect_context_resources(
        keys_ks,
        acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        id,
    )
    .await?;

    info!(channel, id = %id, keys = preview.keys.len(), dids = preview.webvh_dids.len(), "context delete preview");
    Ok(preview)
}

pub async fn delete_context(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    force: bool,
    channel: &str,
) -> Result<DeleteContextResultBody, AppError> {
    auth.require_super_admin()?;

    get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    let preview = collect_context_resources(
        keys_ks,
        acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        id,
    )
    .await?;

    let has_resources = !preview.keys.is_empty()
        || !preview.webvh_dids.is_empty()
        || !preview.acl_entries_removed.is_empty()
        || !preview.acl_entries_updated.is_empty();

    if has_resources && !force {
        return Err(AppError::Validation(
            "context has associated resources; use force=true to delete, or preview first".into(),
        ));
    }

    // Delete keys
    for key_id in &preview.keys {
        keys_ks
            .remove(crate::keys::store_key(key_id))
            .await?;
    }

    // Delete WebVH DIDs and their logs
    #[cfg(feature = "webvh")]
    for did in &preview.webvh_dids {
        crate::webvh_store::delete_did(webvh_ks, did).await?;
        // Remove the log entry (best-effort, may not exist for serverless DIDs)
        let _ = webvh_ks.remove(format!("log:{did}")).await;
    }

    // Remove or update ACL entries
    for did in &preview.acl_entries_removed {
        crate::acl::delete_acl_entry(acl_ks, did).await?;
    }
    for did in &preview.acl_entries_updated {
        if let Some(mut entry) = crate::acl::get_acl_entry(acl_ks, did).await? {
            entry.allowed_contexts.retain(|c| c != id);
            crate::acl::store_acl_entry(acl_ks, &entry).await?;
        }
    }

    // Delete the context record itself
    delete_context_store(contexts_ks, id).await?;

    info!(
        channel,
        id = %id,
        keys_removed = preview.keys.len(),
        dids_removed = preview.webvh_dids.len(),
        acl_removed = preview.acl_entries_removed.len(),
        acl_updated = preview.acl_entries_updated.len(),
        "context deleted with cascade"
    );
    Ok(DeleteContextResultBody {
        id: id.to_string(),
        deleted: true,
    })
}

/// Scan all keyspaces and collect resources associated with a context.
async fn collect_context_resources(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<DeleteContextPreviewResultBody, AppError> {
    use crate::keys::KeyRecord;

    let mut preview = DeleteContextPreviewResultBody {
        id: context_id.to_string(),
        ..Default::default()
    };

    // Keys
    let raw_keys = keys_ks.prefix_iter_raw("key:").await?;
    for (_key, value) in raw_keys {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if record.context_id.as_deref() == Some(context_id) {
            preview.keys.push(record.key_id);
        }
    }

    // WebVH DIDs
    #[cfg(feature = "webvh")]
    {
        use vta_sdk::webvh::WebvhDidRecord;
        let raw_dids = webvh_ks.prefix_iter_raw("did:").await?;
        for (_key, value) in raw_dids {
            let record: WebvhDidRecord = serde_json::from_slice(&value)?;
            if record.context_id == context_id {
                preview.webvh_dids.push(record.did);
            }
        }
    }

    // ACL entries
    let raw_acl = acl_ks.prefix_iter_raw("acl:").await?;
    for (_key, value) in raw_acl {
        let entry: crate::acl::AclEntry = serde_json::from_slice(&value)?;
        if entry.allowed_contexts.contains(&context_id.to_string()) {
            if entry.allowed_contexts.len() == 1 {
                // This entry only has this context — it will be deleted entirely
                preview.acl_entries_removed.push(entry.did);
            } else {
                // This entry has other contexts — just remove this one from the list
                preview.acl_entries_updated.push(entry.did);
            }
        }
    }

    Ok(preview)
}
