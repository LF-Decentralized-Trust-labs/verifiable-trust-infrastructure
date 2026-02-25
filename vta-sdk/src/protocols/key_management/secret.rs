use serde::{Deserialize, Serialize};

use crate::keys::KeyType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeySecretBody {
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeySecretResultBody {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key_multibase: String,
    pub private_key_multibase: String,
}
