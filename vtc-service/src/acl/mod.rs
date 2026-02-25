use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth::extractor::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Roles that determine endpoint access permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Initiator,
    Application,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Initiator => write!(f, "initiator"),
            Role::Application => write!(f, "application"),
        }
    }
}

impl Role {
    /// Parse a role from its string representation.
    pub fn from_str(s: &str) -> Result<Self, AppError> {
        match s {
            "admin" => Ok(Role::Admin),
            "initiator" => Ok(Role::Initiator),
            "application" => Ok(Role::Application),
            _ => Err(AppError::Internal(format!("unknown role: {s}"))),
        }
    }
}

/// An entry in the Access Control List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
}

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Retrieve an ACL entry by DID.
pub async fn get_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<Option<AclEntry>, AppError> {
    acl.get(acl_key(did)).await
}

/// Store (create or overwrite) an ACL entry.
pub async fn store_acl_entry(acl: &KeyspaceHandle, entry: &AclEntry) -> Result<(), AppError> {
    acl.insert(acl_key(&entry.did), entry).await
}

/// Delete an ACL entry by DID.
pub async fn delete_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    acl.remove(acl_key(did)).await
}

/// List all ACL entries.
pub async fn list_acl_entries(acl: &KeyspaceHandle) -> Result<Vec<AclEntry>, AppError> {
    let raw = acl.prefix_iter_raw("acl:").await?;
    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let entry: AclEntry = serde_json::from_slice(&value)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Check whether a DID is in the ACL and return its role.
///
/// Returns `Forbidden` if the DID is not found.
pub async fn check_acl(acl: &KeyspaceHandle, did: &str) -> Result<Role, AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) => Ok(entry.role),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Check whether a DID is in the ACL and return its role and allowed contexts.
///
/// Returns `Forbidden` if the DID is not found.
pub async fn check_acl_full(
    acl: &KeyspaceHandle,
    did: &str,
) -> Result<(Role, Vec<String>), AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) => Ok((entry.role, entry.allowed_contexts)),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Validate that the caller is allowed to create or modify an ACL entry
/// with the given `target_contexts`.
///
/// - Super admins can do anything.
/// - Context admins cannot create entries with empty `allowed_contexts`
///   (that would grant super admin access) and can only assign contexts
///   they themselves have access to.
pub fn validate_acl_modification(
    caller: &AuthClaims,
    target_contexts: &[String],
) -> Result<(), AppError> {
    if caller.is_super_admin() {
        return Ok(());
    }
    if target_contexts.is_empty() {
        return Err(AppError::Forbidden(
            "only super admin can create unrestricted accounts".into(),
        ));
    }
    for ctx in target_contexts {
        caller.require_context(ctx)?;
    }
    Ok(())
}

/// Check whether an ACL entry is visible to the caller.
///
/// Super admins see all entries. Context admins only see entries whose
/// `allowed_contexts` overlap with their own.
pub fn is_acl_entry_visible(caller: &AuthClaims, entry: &AclEntry) -> bool {
    if caller.is_super_admin() {
        return true;
    }
    entry
        .allowed_contexts
        .iter()
        .any(|ctx| caller.has_context_access(ctx))
}
