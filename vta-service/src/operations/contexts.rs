use chrono::Utc;
use tracing::info;

use vta_sdk::protocols::context_management::{
    create::CreateContextResultBody, delete::DeleteContextResultBody, list::ListContextsResultBody,
};

use crate::auth::extractor::AuthClaims;
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

pub async fn delete_context(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<DeleteContextResultBody, AppError> {
    auth.require_super_admin()?;

    get_context(contexts_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {id}")))?;

    delete_context_store(contexts_ks, id).await?;

    info!(channel, id = %id, "context deleted");
    Ok(DeleteContextResultBody {
        id: id.to_string(),
        deleted: true,
    })
}
