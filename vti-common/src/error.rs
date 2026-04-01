use affinidi_tdk::secrets_resolver::errors::SecretsResolverError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("store error: {0}")]
    Store(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("secret store error: {0}")]
    SecretStore(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("secrets error: {0}")]
    Secrets(#[from] SecretsResolverError),

    #[error("authentication error: {0}")]
    Authentication(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("validation error: {0}")]
    Validation(String),

    /// Catch-all for service-specific errors (e.g., KeyDerivation, BadGateway, TeeAttestation).
    /// Services create helper functions to construct these with appropriate status codes.
    #[error("{message}")]
    ServiceError { status: StatusCode, message: String },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SecretStore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Secrets(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::ServiceError { status, .. } => *status,
        };

        if status.is_server_error() {
            warn!(status = %status.as_u16(), error = %self, "server error");
        } else {
            debug!(status = %status.as_u16(), error = %self, "client error");
        }

        let body = serde_json::json!({ "error": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}

/// Helper to create a service-specific error for key derivation failures.
pub fn key_derivation_error(msg: impl Into<String>) -> AppError {
    AppError::ServiceError {
        status: StatusCode::BAD_REQUEST,
        message: format!("key derivation error: {}", msg.into()),
    }
}

/// Helper to create a service-specific error for bad gateway responses.
pub fn bad_gateway_error(msg: impl Into<String>) -> AppError {
    AppError::ServiceError {
        status: StatusCode::BAD_GATEWAY,
        message: format!("bad gateway: {}", msg.into()),
    }
}

/// Helper to create a service-specific error for TEE attestation failures.
pub fn tee_attestation_error(msg: impl Into<String>) -> AppError {
    AppError::ServiceError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: format!("TEE attestation error: {}", msg.into()),
    }
}
