//! Single-use nonce store.
//!
//! The producer records every `bundle_id` it has sealed; sealing the same
//! `bundle_id` twice is rejected. This makes any failure path (network glitch,
//! consumer aborts mid-open) unambiguous: the operator must regenerate the
//! request.
//!
//! Implementations are pluggable. `pnm-cli` will provide a keyring-backed
//! store; tests use [`InMemoryNonceStore`].

use std::collections::HashSet;
use std::sync::Mutex;

use super::error::SealedTransferError;

/// A persistent record of `bundle_id`s that have already been sealed.
pub trait NonceStore: Send + Sync {
    /// Atomically check-and-insert. Returns `Ok(())` on first use,
    /// [`SealedTransferError::NonceReplay`] if the bundle_id has been seen.
    fn check_and_record(&self, bundle_id: &[u8; 16]) -> Result<(), SealedTransferError>;
}

/// In-memory store for tests and single-process producers without persistence.
#[derive(Default)]
pub struct InMemoryNonceStore {
    seen: Mutex<HashSet<[u8; 16]>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_record(&self, bundle_id: &[u8; 16]) -> Result<(), SealedTransferError> {
        let mut set = self
            .seen
            .lock()
            .map_err(|e| SealedTransferError::NonceStore(format!("poisoned mutex: {e}")))?;
        if !set.insert(*bundle_id) {
            return Err(SealedTransferError::NonceReplay);
        }
        Ok(())
    }
}
