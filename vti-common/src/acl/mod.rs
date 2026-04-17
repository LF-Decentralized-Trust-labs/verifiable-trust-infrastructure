use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth::extractor::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub mod pending_bootstrap;
pub use pending_bootstrap::{
    PendingBootstrap, consume_pending_bootstrap, delete_pending_bootstrap,
    get_pending_bootstrap_by_hash, get_pending_bootstrap_by_token, list_pending_bootstraps,
    store_pending_bootstrap,
};

/// Roles that determine endpoint access permissions.
///
/// Hierarchy (most to least privileged):
/// - **Admin** — full management access, can assign any role
/// - **Initiator** — can manage ACL entries and application contexts
/// - **Application** — standard API access (sign, cache write) within allowed contexts
/// - **Reader** — read-only access to keys, contexts, DIDs within allowed contexts
/// - **Monitor** — infrastructure-only: metrics and health endpoints
/// - **Bootstrap** — one-shot, non-composable. Holds no standing permissions;
///   exists only as a marker for an in-flight sealed-bootstrap swap and is
///   never reachable via `check_acl`. Assigning it through any normal route
///   is rejected by [`validate_role_assignment`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Initiator,
    Application,
    Reader,
    Monitor,
    Bootstrap,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Initiator => write!(f, "initiator"),
            Role::Application => write!(f, "application"),
            Role::Reader => write!(f, "reader"),
            Role::Monitor => write!(f, "monitor"),
            Role::Bootstrap => write!(f, "bootstrap"),
        }
    }
}

impl Role {
    /// Parse a role from its string representation.
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "admin" => Ok(Role::Admin),
            "initiator" => Ok(Role::Initiator),
            "application" => Ok(Role::Application),
            "reader" => Ok(Role::Reader),
            "monitor" => Ok(Role::Monitor),
            "bootstrap" => Ok(Role::Bootstrap),
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
    /// Unix-epoch seconds at which this entry expires and should be pruned by
    /// the background sweeper. `None` is permanent (existing pre-Phase-2
    /// behavior; entries serialized before this field existed deserialize with
    /// this default).
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl AclEntry {
    /// Returns true if this entry has passed its configured `expires_at`.
    /// Permanent entries (no `expires_at`) never expire.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self.expires_at {
            Some(deadline) => now_unix >= deadline,
            None => false,
        }
    }
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

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check whether a DID is in the ACL and return its role.
///
/// Returns `Forbidden` if the DID is not found, if its entry has expired, or
/// if the stored role is `Bootstrap` (which is never a valid authenticated
/// identity — it only marks an in-flight sealed-bootstrap swap).
pub async fn check_acl(acl: &KeyspaceHandle, did: &str) -> Result<Role, AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) if entry.is_expired(now_epoch()) => {
            Err(AppError::Forbidden(format!("ACL entry expired: {did}")))
        }
        Some(entry) if entry.role == Role::Bootstrap => Err(AppError::Forbidden(format!(
            "bootstrap-role DID cannot authenticate: {did}"
        ))),
        Some(entry) => Ok(entry.role),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Check whether a DID is in the ACL and return its role and allowed contexts.
///
/// Returns `Forbidden` under the same conditions as [`check_acl`].
pub async fn check_acl_full(
    acl: &KeyspaceHandle,
    did: &str,
) -> Result<(Role, Vec<String>), AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) if entry.is_expired(now_epoch()) => {
            Err(AppError::Forbidden(format!("ACL entry expired: {did}")))
        }
        Some(entry) if entry.role == Role::Bootstrap => Err(AppError::Forbidden(format!(
            "bootstrap-role DID cannot authenticate: {did}"
        ))),
        Some(entry) => Ok((entry.role, entry.allowed_contexts)),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Validate that the caller is allowed to assign the given role.
///
/// - Only Admins can assign the Admin role.
/// - Reader, Application, Monitor, and Bootstrap roles cannot assign any role.
/// - No one can assign the Bootstrap role through a normal ACL route — it
///   exists only as a marker for an in-flight sealed-bootstrap swap and is
///   never persisted to an `AclEntry` via operator-facing endpoints.
pub fn validate_role_assignment(caller: &AuthClaims, target_role: &Role) -> Result<(), AppError> {
    if matches!(
        caller.role,
        Role::Monitor | Role::Reader | Role::Application | Role::Bootstrap
    ) {
        return Err(AppError::Forbidden(
            "insufficient role to assign roles".into(),
        ));
    }
    if *target_role == Role::Bootstrap {
        return Err(AppError::Forbidden(
            "the bootstrap role cannot be assigned directly".into(),
        ));
    }
    if *target_role == Role::Admin && caller.role != Role::Admin {
        return Err(AppError::Forbidden(
            "only admins can assign the admin role".into(),
        ));
    }
    Ok(())
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
