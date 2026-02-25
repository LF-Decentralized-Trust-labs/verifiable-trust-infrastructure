use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDidWebvhBody {
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDidWebvhResultBody {
    pub did: String,
    pub deleted: bool,
}
