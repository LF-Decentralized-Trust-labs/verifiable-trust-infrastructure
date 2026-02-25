use serde::{Deserialize, Serialize};

use crate::webvh::WebvhServerRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddWebvhServerBody {
    pub id: String,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub type AddWebvhServerResultBody = WebvhServerRecord;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListWebvhServersBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListWebvhServersResultBody {
    pub servers: Vec<WebvhServerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateWebvhServerBody {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub type UpdateWebvhServerResultBody = WebvhServerRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveWebvhServerBody {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveWebvhServerResultBody {
    pub id: String,
    pub removed: bool,
}
