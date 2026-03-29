use serde::{Deserialize, Serialize};

/// Response body for a VTA restart request.
#[derive(Debug, Serialize, Deserialize)]
pub struct RestartResult {
    pub status: String,
}
