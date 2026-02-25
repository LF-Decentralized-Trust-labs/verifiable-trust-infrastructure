use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContextBody {
    pub id: String,
}

pub type GetContextResultBody = CreateContextResultBody;
