use serde::{Deserialize, Serialize};

use crate::webvh::WebvhDidRecord;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListDidsWebvhBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDidsWebvhResultBody {
    pub dids: Vec<WebvhDidRecord>,
}
