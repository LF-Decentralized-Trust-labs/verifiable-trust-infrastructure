use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidWebvhBody {
    pub context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_mediator_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_services: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_rotation_count: Option<u32>,
    /// Client-provided DID Document template. When set, the VTA uses this
    /// instead of building the document internally. `{DID}` placeholders are
    /// resolved by `didwebvh-rs`. Mutually exclusive with `did_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    /// Complete, pre-signed did.jsonl log entry. When set, the VTA publishes
    /// it as-is without deriving keys or creating a log entry. Mutually
    /// exclusive with `did_document`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    /// Whether to set this DID as the primary DID for the context.
    /// Defaults to `true` for backwards compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_primary: Option<bool>,
    /// Use an existing key as the signing (Ed25519) verification method.
    /// When set, the VTA skips key derivation and uses this key instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    /// Use an existing key as the key-agreement (X25519) verification method.
    /// Required when the DID document includes DIDCommMessaging services.
    /// Requires `signing_key_id` to also be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ka_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidWebvhResultBody {
    pub did: String,
    pub context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    pub scid: String,
    pub portable: bool,
    pub signing_key_id: String,
    pub ka_key_id: String,
    pub pre_rotation_key_count: u32,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_entry: Option<String>,
}
