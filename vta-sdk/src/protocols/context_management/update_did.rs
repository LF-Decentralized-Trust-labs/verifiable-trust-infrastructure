use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContextDidBody {
    pub id: String,
    pub did: String,
}

pub type UpdateContextDidResultBody = CreateContextResultBody;
