use serde::{Deserialize, Serialize};

use crate::keys::KeyRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeyBody {
    pub key_id: String,
}

pub type GetKeyResultBody = KeyRecord;
