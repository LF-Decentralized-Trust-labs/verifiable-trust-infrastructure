//! Single-use nonce store.
//!
//! The producer records every `bundle_id` it has sealed; sealing the same
//! `bundle_id` twice is rejected. This makes any failure path (network glitch,
//! consumer aborts mid-open) unambiguous: the operator must regenerate the
//! request.
//!
//! The trait is async so production implementations can delegate to an
//! existing async storage layer (fjall on a current-thread runtime,
//! vsock-proxied storage in enclave mode) without wrestling with
//! `block_on`.
//!
//! Implementations are pluggable. The vta-service ships a fjall-backed
//! `PersistentNonceStore`; tests use [`InMemoryNonceStore`].

use std::collections::HashSet;
use std::sync::Mutex;

use super::error::SealedTransferError;

/// A persistent record of `bundle_id`s that have already been sealed.
pub trait NonceStore: Send + Sync {
    /// Atomically check-and-insert. Returns `Ok(())` on first use,
    /// [`SealedTransferError::NonceReplay`] if the bundle_id has been seen.
    fn check_and_record<'a>(
        &'a self,
        bundle_id: &'a [u8; 16],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), SealedTransferError>> + Send + 'a>,
    >;
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
    fn check_and_record<'a>(
        &'a self,
        bundle_id: &'a [u8; 16],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), SealedTransferError>> + Send + 'a>,
    > {
        let id = *bundle_id;
        Box::pin(async move {
            let mut set = self
                .seen
                .lock()
                .map_err(|e| SealedTransferError::NonceStore(format!("poisoned mutex: {e}")))?;
            if !set.insert(id) {
                return Err(SealedTransferError::NonceReplay);
            }
            Ok(())
        })
    }
}
