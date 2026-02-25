use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAclBody {
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAclResultBody {
    pub did: String,
    pub deleted: bool,
}
