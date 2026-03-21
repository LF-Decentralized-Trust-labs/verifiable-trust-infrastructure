//! Auto-detect enclave CID from nitro-cli.

use tracing::{info, warn};

/// Auto-detect the CID of a running Nitro Enclave.
///
/// Runs `nitro-cli describe-enclaves` and parses the JSON output.
/// Returns `None` if no running enclave is found or nitro-cli isn't available.
pub fn detect_enclave_cid() -> Option<u32> {
    let output = std::process::Command::new("nitro-cli")
        .arg("describe-enclaves")
        .output()
        .ok()?;

    if !output.status.success() {
        warn!("nitro-cli describe-enclaves failed");
        return None;
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let enclaves = json.as_array()?;

    for enclave in enclaves {
        if enclave.get("State")?.as_str()? == "RUNNING" {
            let cid = enclave.get("EnclaveCID")?.as_u64()? as u32;
            info!(cid, "auto-detected running enclave");
            return Some(cid);
        }
    }

    None
}
