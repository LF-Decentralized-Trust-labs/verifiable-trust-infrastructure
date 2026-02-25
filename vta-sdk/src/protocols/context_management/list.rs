use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListContextsBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListContextsResultBody {
    pub contexts: Vec<CreateContextResultBody>,
}
