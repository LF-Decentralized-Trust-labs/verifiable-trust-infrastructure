//! Structured error type for VTA SDK operations.

/// Errors returned by VTA SDK client operations.
#[derive(Debug, thiserror::Error)]
pub enum VtaError {
    /// Network-level error (connection refused, timeout, DNS failure).
    #[cfg(feature = "client")]
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Authentication failed (401) or token expired.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Resource not found (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Request validation error (400).
    #[error("validation error: {0}")]
    Validation(String),

    /// Permission denied (403).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Conflict (409) — e.g. duplicate key ID.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Server error (5xx).
    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    /// Protocol error (e.g. unexpected DIDComm message type).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

impl VtaError {
    /// Create from an HTTP response status and error body.
    #[cfg(feature = "client")]
    pub(crate) fn from_http(status: reqwest::StatusCode, body: String) -> Self {
        match status.as_u16() {
            401 => Self::Auth(body),
            403 => Self::Forbidden(body),
            404 => Self::NotFound(body),
            400 | 422 => Self::Validation(body),
            409 => Self::Conflict(body),
            s if s >= 500 => Self::Server { status: s, body },
            s => Self::Other(format!("{s}: {body}")),
        }
    }

    /// Returns true if this is an authentication/authorization error.
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_) | Self::Forbidden(_))
    }

    /// Returns true if this is a network-level error (retryable).
    pub fn is_network(&self) -> bool {
        #[cfg(feature = "client")]
        if matches!(self, Self::Network(_)) {
            return true;
        }
        false
    }

    /// Returns true if the resource was not found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

impl From<String> for VtaError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for VtaError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

// Allow converting from Box<dyn Error> for backward compat during migration
impl From<Box<dyn std::error::Error>> for VtaError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<crate::credentials::CredentialBundleError> for VtaError {
    fn from(e: crate::credentials::CredentialBundleError) -> Self {
        Self::Validation(e.to_string())
    }
}

impl From<crate::did_key::DidKeyError> for VtaError {
    fn from(e: crate::did_key::DidKeyError) -> Self {
        Self::Other(e.to_string())
    }
}
