use serde::{Deserialize, Serialize};

/// Request body for updating the audit log retention period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRetentionBody {
    /// Number of days to retain audit logs (minimum 1, maximum 365).
    pub retention_days: u32,
}

/// Response body for get/update retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionResultBody {
    pub retention_days: u32,
}
