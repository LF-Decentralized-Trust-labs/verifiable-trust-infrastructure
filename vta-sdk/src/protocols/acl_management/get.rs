use serde::{Deserialize, Serialize};

use super::create::CreateAclResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAclBody {
    pub did: String,
}

pub type GetAclResultBody = CreateAclResultBody;
