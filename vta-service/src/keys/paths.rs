use crate::error::AppError;
use crate::store::KeyspaceHandle;
use tracing::debug;

/// Construct a full derivation path from a base and index.
pub fn path_at(base: &str, index: u32) -> String {
    format!("{base}/{index}'")
}

/// Allocate the next sequential derivation path from a group's counter.
///
/// Reads the current counter for `base` from the keys keyspace,
/// constructs `{base}/{N}'`, increments the counter, and returns the path.
pub async fn allocate_path(keys_ks: &KeyspaceHandle, base: &str) -> Result<String, AppError> {
    let counter_key = format!("path_counter:{base}");
    let current: u32 = match keys_ks.get_raw(counter_key.as_str()).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| AppError::Internal("corrupt path counter".into()))?;
            u32::from_le_bytes(arr)
        }
        None => 0,
    };
    let path = path_at(base, current);
    keys_ks
        .insert_raw(counter_key, (current + 1).to_le_bytes().to_vec())
        .await?;
    debug!(base, path = %path, "derivation path allocated");
    Ok(path)
}
