use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContextBody {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContextResultBody {
    pub id: String,
    pub deleted: bool,
}
