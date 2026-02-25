use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRecord {
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    pub base_path: String,
    pub index: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
