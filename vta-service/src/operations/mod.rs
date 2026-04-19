pub mod acl;
#[cfg(feature = "tee")]
pub mod attestation;
pub mod audit;
pub mod backup;
pub mod cache;
pub mod config;
pub mod contexts;
#[cfg(feature = "webvh")]
pub mod did_webvh;
pub mod keys;
pub mod seeds;

use crate::store::KeyspaceHandle;

/// Shared keyspace handles passed to operations that need multiple keyspaces.
pub struct Keyspaces<'a> {
    pub keys: &'a KeyspaceHandle,
    pub acl: &'a KeyspaceHandle,
    pub contexts: &'a KeyspaceHandle,
    pub audit: &'a KeyspaceHandle,
    pub imported: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh: &'a KeyspaceHandle,
}

impl<'a> Keyspaces<'a> {
    /// Borrow keyspaces from an `AppState`.
    pub fn from_app_state(s: &'a crate::server::AppState) -> Self {
        Self {
            keys: &s.keys_ks,
            acl: &s.acl_ks,
            contexts: &s.contexts_ks,
            audit: &s.audit_ks,
            imported: &s.imported_ks,
            #[cfg(feature = "webvh")]
            webvh: &s.webvh_ks,
        }
    }

    /// Borrow keyspaces from a `VtaState` (DIDComm handlers).
    #[cfg(feature = "didcomm")]
    pub fn from_vta_state(s: &'a crate::messaging::router::VtaState) -> Self {
        Self {
            keys: &s.keys_ks,
            acl: &s.acl_ks,
            contexts: &s.contexts_ks,
            audit: &s.audit_ks,
            imported: &s.imported_ks,
            #[cfg(feature = "webvh")]
            webvh: &s.webvh_ks,
        }
    }
}
