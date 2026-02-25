use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAclBody {
    pub did: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAclResultBody {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
}
