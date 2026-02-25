use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::{KeyStatus, KeyType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyBody {
    pub key_type: KeyType,
    pub derivation_path: String,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyResultBody {
    pub key_id: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}
