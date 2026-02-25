use serde::{Deserialize, Serialize};

use crate::webvh::WebvhDidRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDidWebvhBody {
    pub did: String,
}

pub type GetDidWebvhResultBody = WebvhDidRecord;
