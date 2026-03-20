//! Time-limited mnemonic export guard with secure memory wiping.
//!
//! On first boot, the VTA generates entropy for the BIP-39 mnemonic inside
//! the TEE. The mnemonic is NEVER displayed. Instead, the entropy is held
//! in a `MnemonicExportGuard` that is only active if:
//!
//! 1. The VTA was started with `VTA_MNEMONIC_EXPORT_WINDOW=<seconds>` env var
//! 2. The current time is within the window since boot
//! 3. The requester is a super admin (authenticated via JWT)
//!
//! After the window expires, the entropy is cryptographically zeroed using
//! the `zeroize` crate (prevents compiler optimization of the wipe) and the
//! mnemonic can never be reconstructed.
//!
//! On subsequent boots (not first boot), no entropy exists to export.

use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::error::AppError;

/// Holds the BIP-39 entropy bytes during the export window.
pub struct MnemonicExportGuard {
    inner: Mutex<GuardState>,
}

struct GuardState {
    /// The 32-byte entropy used to generate the BIP-39 mnemonic.
    /// Cryptographically zeroed after export or window expiry.
    entropy: Option<[u8; 32]>,
    /// When the guard was created (boot time).
    created_at: Instant,
    /// How long the export window lasts.
    window_secs: u64,
    /// Whether the mnemonic has been exported (one-time use).
    exported: bool,
}

impl Drop for GuardState {
    fn drop(&mut self) {
        self.wipe_entropy();
    }
}

impl GuardState {
    /// Cryptographically zero the entropy bytes.
    fn wipe_entropy(&mut self) {
        if let Some(ref mut e) = self.entropy {
            e.zeroize();
        }
        self.entropy = None;
    }
}

/// Response from a mnemonic export request.
#[derive(Debug, Serialize)]
pub struct MnemonicExportResponse {
    /// The BIP-39 mnemonic phrase (24 words).
    pub mnemonic: String,
    /// Seconds remaining in the export window when the export was performed.
    pub window_remaining_secs: u64,
}

/// Status of the mnemonic export guard.
#[derive(Debug, Serialize)]
pub struct MnemonicExportStatus {
    /// Whether the export window is currently active.
    pub window_active: bool,
    /// Whether the mnemonic has already been exported.
    pub already_exported: bool,
    /// Whether entropy is available (false on subsequent boots).
    pub entropy_available: bool,
    /// Seconds remaining in the window (0 if expired or not active).
    pub window_remaining_secs: u64,
}

impl MnemonicExportGuard {
    /// Create a new guard holding the entropy bytes.
    ///
    /// The `window_secs` controls how long the entropy remains available.
    /// After the window, `export()` will fail and the entropy is zeroed.
    pub fn new(entropy: [u8; 32], window_secs: u64) -> Self {
        info!(
            window_secs,
            "mnemonic export guard created — window open for {window_secs}s"
        );
        Self {
            inner: Mutex::new(GuardState {
                entropy: Some(entropy),
                created_at: Instant::now(),
                window_secs,
                exported: false,
            }),
        }
    }

    /// Create a guard with no entropy (subsequent boot — export is impossible).
    pub fn empty() -> Self {
        Self {
            inner: Mutex::new(GuardState {
                entropy: None,
                created_at: Instant::now(),
                window_secs: 0,
                exported: false,
            }),
        }
    }

    /// Check the current status of the export guard.
    pub fn status(&self) -> MnemonicExportStatus {
        let guard = self.inner.lock().unwrap();
        let elapsed = guard.created_at.elapsed().as_secs();
        let window_active = guard.entropy.is_some()
            && !guard.exported
            && elapsed < guard.window_secs;
        let remaining = if window_active {
            guard.window_secs.saturating_sub(elapsed)
        } else {
            0
        };

        MnemonicExportStatus {
            window_active,
            already_exported: guard.exported,
            entropy_available: guard.entropy.is_some(),
            window_remaining_secs: remaining,
        }
    }

    /// Export the mnemonic if the window is still open.
    ///
    /// This is a one-time operation: after a successful export, the entropy
    /// is cryptographically zeroed and no further exports are possible.
    ///
    /// Returns `Err` if:
    /// - The export window has expired
    /// - The mnemonic was already exported
    /// - No entropy is available (subsequent boot)
    pub fn export(&self) -> Result<MnemonicExportResponse, AppError> {
        let mut guard = self.inner.lock().unwrap();

        // Check entropy availability
        let entropy = match guard.entropy {
            Some(e) => e,
            None => {
                return Err(AppError::TeeAttestation(
                    "no mnemonic available — entropy only exists on first boot".into(),
                ));
            }
        };

        // Check if already exported
        if guard.exported {
            return Err(AppError::TeeAttestation(
                "mnemonic already exported — one-time operation".into(),
            ));
        }

        // Check window
        let elapsed = guard.created_at.elapsed().as_secs();
        if elapsed >= guard.window_secs {
            // Window expired — securely zero the entropy
            guard.wipe_entropy();
            warn!("mnemonic export attempted after window expired — entropy zeroed");
            return Err(AppError::TeeAttestation(format!(
                "mnemonic export window expired ({elapsed}s elapsed, window was {}s)",
                guard.window_secs
            )));
        }

        // Generate mnemonic from entropy
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| AppError::TeeAttestation(format!("failed to derive mnemonic: {e}")))?;

        let remaining = guard.window_secs.saturating_sub(elapsed);

        // Mark as exported and securely zero the entropy
        guard.exported = true;
        guard.wipe_entropy();

        info!(
            remaining_secs = remaining,
            "mnemonic exported to authenticated super admin — entropy zeroed"
        );

        let mut mnemonic_str = mnemonic.to_string();
        let response = MnemonicExportResponse {
            mnemonic: mnemonic_str.clone(),
            window_remaining_secs: remaining,
        };
        // Zeroize the local copy of the mnemonic string
        mnemonic_str.zeroize();

        Ok(response)
    }
}
