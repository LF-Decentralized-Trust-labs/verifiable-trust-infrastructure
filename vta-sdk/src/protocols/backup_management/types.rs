use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::contexts::ContextRecord;
use crate::keys::KeyRecord;
use crate::protocols::audit_management::list::AuditLogEntry;
use crate::webvh::{WebvhDidRecord, WebvhServerRecord};

// ── Backup envelope (outer, unencrypted metadata) ──────────────────

/// The on-disk `.vtabak` file format.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub version: u32,
    pub format: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    pub source_version: String,
    pub kdf: KdfParams,
    pub encryption: EncryptionParams,
    pub includes_audit: bool,
    /// Base64url-encoded AES-256-GCM ciphertext of the serialized `BackupPayload`.
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String, // base64url
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionParams {
    pub algorithm: String,
    pub nonce: String, // base64url
}

// ── Backup payload (inner, encrypted) ──────────────────────────────

/// All VTA state, serialized as JSON then encrypted.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Hex-encoded active seed bytes (32 bytes → 64 hex chars).
    pub active_seed_hex: String,
    /// Active seed generation ID.
    pub active_seed_id: u32,
    /// Retired seed records (contain hex-encoded seed bytes).
    #[serde(default)]
    pub seed_records: Vec<SeedRecordBackup>,
    /// Base64url-encoded JWT signing key (32 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_signing_key: Option<String>,
    /// All key records.
    pub key_records: Vec<KeyRecord>,
    /// All context records.
    pub context_records: Vec<ContextRecord>,
    /// Context counter (next index).
    pub context_counter: u32,
    /// All ACL entries.
    pub acl_entries: Vec<AclEntryBackup>,
    /// Seal record (if VTA is sealed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealRecordBackup>,
    /// WebVH server records.
    #[serde(default)]
    pub webvh_servers: Vec<WebvhServerRecord>,
    /// WebVH DID records.
    #[serde(default)]
    pub webvh_dids: Vec<WebvhDidRecord>,
    /// WebVH DID logs (keyed by DID).
    #[serde(default)]
    pub webvh_logs: Vec<WebvhLogBackup>,
    /// VTA identity and messaging config.
    pub config: BackupConfig,
    /// Audit logs (optional, may be empty).
    #[serde(default)]
    pub audit_logs: Vec<AuditLogEntry>,
    /// Imported (non-derived) secrets. Plaintext inside the encrypted envelope.
    #[serde(default)]
    pub imported_secrets: Vec<ImportedSecretBackup>,
    /// Hex-encoded KEK salt for imported secret encryption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_kek_salt: Option<String>,
}

/// An imported secret included in the backup payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportedSecretBackup {
    pub key_id: String,
    /// Hex-encoded raw private key bytes.
    pub private_key_hex: String,
}

/// Seed record for backup (mirrors SeedRecord from vta-service).
#[derive(Debug, Serialize, Deserialize)]
pub struct SeedRecordBackup {
    pub id: u32,
    pub seed_hex: Option<String>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// ACL entry for backup (mirrors AclEntry from vti-common).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntryBackup {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
}

/// Seal record for backup.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealRecordBackup {
    pub sealed_by: String,
    pub sealed_at: DateTime<Utc>,
    pub reason: String,
}

/// WebVH DID log entry for backup.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebvhLogBackup {
    pub did: String,
    pub log_json: String,
}

/// Subset of VTA config that should be backed up.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
}

// ── Request/response types ─────────────────────────────────────────

/// Export request body (REST + DIDComm).
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportRequest {
    pub password: String,
    #[serde(default)]
    pub include_audit: bool,
}

/// Import request body (REST + DIDComm).
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportRequest {
    pub backup: BackupEnvelope,
    pub password: String,
    /// If false, returns a preview without modifying state.
    #[serde(default = "default_true")]
    pub confirm: bool,
}

fn default_true() -> bool {
    true
}

/// Import preview/result response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    pub key_count: usize,
    pub acl_count: usize,
    pub context_count: usize,
    pub audit_count: usize,
    #[serde(default)]
    pub imported_secret_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
