use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidWebvhBody {
    pub context_id: String,
    pub server_id: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidWebvhResultBody {
    pub did: String,
    pub context_id: String,
    pub server_id: String,
    pub mnemonic: String,
    pub scid: String,
    pub portable: bool,
    pub signing_key_id: String,
    pub ka_key_id: String,
    pub pre_rotation_key_count: u32,
    pub created_at: DateTime<Utc>,
}
