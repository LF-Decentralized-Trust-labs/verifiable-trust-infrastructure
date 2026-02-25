use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RotateSeedBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSeedResultBody {
    pub previous_seed_id: u32,
    pub new_seed_id: u32,
}
