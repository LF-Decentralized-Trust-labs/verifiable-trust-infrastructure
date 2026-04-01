use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use tracing::warn;

use crate::acl::Role;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{SessionState, get_session};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Trait that each service's `AppState` implements to provide the data
/// needed by the auth extractors.
pub trait AuthState: Clone + Send + Sync + 'static {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>>;
    fn sessions_ks(&self) -> &KeyspaceHandle;
}

/// Extracted from a valid JWT Bearer token on protected routes.
///
/// Add this as a handler parameter to require authentication:
/// ```ignore
/// async fn handler(_auth: AuthClaims, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AuthClaims {
    pub did: String,
    pub role: Role,
    pub allowed_contexts: Vec<String>,
}

impl<S: AuthState> FromRequestParts<S> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract Bearer token from Authorization header
        let TypedHeader(auth) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    warn!("auth rejected: missing or invalid Authorization header");
                    AppError::Unauthorized("missing or invalid Authorization header".into())
                })?;

        let token = auth.token();

        // Decode and validate JWT
        let jwt_keys = state
            .jwt_keys()
            .ok_or_else(|| AppError::Unauthorized("auth not configured".into()))?;

        let claims = jwt_keys.decode(token)?;

        // Verify session exists and is authenticated
        let session = get_session(state.sessions_ks(), &claims.session_id)
            .await?
            .ok_or_else(|| {
                warn!(session_id = %claims.session_id, "auth rejected: session not found");
                AppError::Unauthorized("session not found".into())
            })?;

        if session.state != SessionState::Authenticated {
            warn!(session_id = %claims.session_id, "auth rejected: session not in authenticated state");
            return Err(AppError::Unauthorized("session not authenticated".into()));
        }

        let role = Role::parse(&claims.role)?;

        Ok(AuthClaims {
            did: claims.sub,
            role,
            allowed_contexts: claims.contexts,
        })
    }
}

impl AuthClaims {
    /// Returns `true` if the caller is an admin with unrestricted access
    /// (empty `allowed_contexts`).
    pub fn is_super_admin(&self) -> bool {
        self.role == Role::Admin && self.allowed_contexts.is_empty()
    }

    /// Returns `true` if the caller has access to the given context,
    /// either as a super admin or by explicit context assignment.
    pub fn has_context_access(&self, context_id: &str) -> bool {
        self.is_super_admin() || self.allowed_contexts.iter().any(|c| c == context_id)
    }

    /// Check that the caller has access to the given context.
    ///
    /// Admins with an empty `allowed_contexts` list have unrestricted access.
    pub fn require_context(&self, context_id: &str) -> Result<(), AppError> {
        if self.has_context_access(context_id) {
            return Ok(());
        }
        Err(AppError::Forbidden(format!(
            "no access to context: {context_id}"
        )))
    }

    /// If the caller has exactly one allowed context, return it.
    pub fn default_context(&self) -> Option<&str> {
        if self.allowed_contexts.len() == 1 {
            Some(&self.allowed_contexts[0])
        } else {
            None
        }
    }

    /// Require at least Reader role (all roles except Monitor).
    ///
    /// Use for read-only endpoints that access business data (keys, contexts, DIDs).
    /// Monitor can only see metrics and health.
    pub fn require_read(&self) -> Result<(), AppError> {
        if self.role == Role::Monitor {
            return Err(AppError::Forbidden("reader role or higher required".into()));
        }
        Ok(())
    }

    /// Require at least Application role (Admin, Initiator, or Application).
    ///
    /// Use for write operations: signing, cache writes, and other actions that
    /// produce artifacts or modify state.
    pub fn require_write(&self) -> Result<(), AppError> {
        if matches!(self.role, Role::Admin | Role::Initiator | Role::Application) {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "application role or higher required".into(),
        ))
    }

    /// Require the caller to have Admin role.
    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.role == Role::Admin {
            return Ok(());
        }
        Err(AppError::Forbidden("admin role required".into()))
    }

    /// Require the caller to have Admin or Initiator role.
    pub fn require_manage(&self) -> Result<(), AppError> {
        if self.role == Role::Admin || self.role == Role::Initiator {
            return Ok(());
        }
        Err(AppError::Forbidden(
            "admin or initiator role required".into(),
        ))
    }

    /// Require the caller to be a super admin (Admin + unrestricted).
    pub fn require_super_admin(&self) -> Result<(), AppError> {
        if self.is_super_admin() {
            return Ok(());
        }
        Err(AppError::Forbidden("super admin required".into()))
    }
}

/// Extractor that requires the caller to have Admin or Initiator role.
///
/// Use on endpoints that manage ACL entries and other management tasks:
/// ```ignore
/// async fn handler(auth: ManageAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct ManageAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for ManageAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator => Ok(ManageAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin or initiator role required");
                Err(AppError::Forbidden(
                    "admin or initiator role required".into(),
                ))
            }
        }
    }
}

/// Extractor that requires the caller to have Admin role.
///
/// Use on endpoints that modify configuration, create/delete keys, etc.:
/// ```ignore
/// async fn handler(auth: AdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin => Ok(AdminAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin role required");
                Err(AppError::Forbidden("admin role required".into()))
            }
        }
    }
}

/// Extractor that requires the caller to be a super admin (Admin role with
/// empty `allowed_contexts`).
///
/// Use on endpoints that only unrestricted administrators should access,
/// such as creating/deleting contexts or modifying global configuration:
/// ```ignore
/// async fn handler(auth: SuperAdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct SuperAdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for SuperAdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        if !claims.is_super_admin() {
            warn!(did = %claims.did, "auth rejected: super admin required");
            return Err(AppError::Forbidden("super admin required".into()));
        }

        Ok(SuperAdminAuth(claims))
    }
}

/// Extractor that requires the caller to have at least Application role
/// (Admin, Initiator, or Application).
///
/// Use on endpoints that perform write operations — signing, cache writes,
/// and other actions that produce artifacts or modify state:
/// ```ignore
/// async fn handler(auth: WriteAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct WriteAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for WriteAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin | Role::Initiator | Role::Application => Ok(WriteAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: application role or higher required");
                Err(AppError::Forbidden(
                    "application role or higher required".into(),
                ))
            }
        }
    }
}
