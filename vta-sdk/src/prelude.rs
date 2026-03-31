//! Convenience re-exports for the most commonly used VTA SDK types.
//!
//! ```ignore
//! use vta_sdk::prelude::*;
//! ```

// Error
pub use crate::error::VtaError;

// Keys
pub use crate::keys::{KeyRecord, KeyStatus, KeyType};

// Contexts
pub use crate::contexts::ContextRecord;

// Credentials
pub use crate::credentials::CredentialBundle;

// DID secrets
pub use crate::did_secrets::{DidSecretsBundle, SecretEntry};

// Client (feature-gated)
#[cfg(feature = "client")]
pub use crate::client::{
    AclEntryResponse, AclListResponse, ConfigResponse, ContextListResponse, ContextResponse,
    CreateAclRequest, CreateContextRequest, CreateKeyRequest, CreateKeyResponse,
    GenerateCredentialsRequest, GenerateCredentialsResponse, GetKeySecretResponse,
    HealthResponse, ImportKeyRequest, ImportKeyResponse, InvalidateKeyResponse,
    ListKeysResponse, RenameKeyResponse, SignResponse, UpdateAclRequest, UpdateConfigRequest,
    UpdateContextDidRequest, VtaClient, WrappingKeyResponse,
};

// DID key utilities
pub use crate::did_key::{decode_private_key_multibase, ed25519_multibase_pubkey};

#[cfg(feature = "client")]
pub use crate::did_key::secret_from_key_response;

// Protocols — commonly used request/response bodies
pub use crate::protocols::audit_management::list::ListAuditLogsBody;
