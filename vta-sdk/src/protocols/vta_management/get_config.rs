use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetConfigBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConfigResultBody {
    pub vta_did: Option<String>,
    pub vta_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}
