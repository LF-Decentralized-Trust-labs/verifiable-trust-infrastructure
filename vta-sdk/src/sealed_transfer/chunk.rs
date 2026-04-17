//! Chunk wire format and reassembly.
//!
//! Each `ChunkPlaintext` is the input to a single HPKE seal call. Chunk-0 also
//! carries the producer's pubkey + assertion. The chunk header (version,
//! bundle_id, indices) is bound as AEAD AAD so a MITM cannot reshuffle or
//! truncate chunks without detection.

use serde::{Deserialize, Serialize};

use super::bundle::ProducerAssertion;
use super::error::SealedTransferError;

/// The (current) only supported wire-format version.
pub const VERSION: u8 = 1;

/// Maximum payload bytes per chunk before we split. Sized to keep a
/// single-chunk armored bundle reasonable to paste, while leaving room for
/// HPKE/CBOR overhead inside an AEAD tag.
///
/// 32 KiB is conservative — most real payloads (a credential bundle or a
/// per-DID secrets bundle) fit comfortably below this.
pub const MAX_PAYLOAD_FRAGMENT: usize = 32 * 1024;

/// Plaintext layout that gets sealed into a single HPKE ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPlaintext {
    pub version: u8,
    pub bundle_id: [u8; 16],
    pub chunk_index: u16,
    pub total_chunks: u16,
    /// Producer pubkey — present only on chunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_pubkey: Option<[u8; 32]>,
    /// Producer assertion — present only on chunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_assertion: Option<ProducerAssertion>,
    /// CBOR-encoded fragment of the full `SealedPayloadV1`.
    pub payload_fragment: Vec<u8>,
}

impl ChunkPlaintext {
    /// Build the AAD bytes bound to this chunk's AEAD seal.
    ///
    /// Stable serialization: `version || bundle_id || chunk_index_be ||
    /// total_chunks_be || digest_algo_len || digest_algo`.
    /// The digest_algo is included so swapping it across chunks would break
    /// open. The producer_pubkey and assertion are NOT in the AAD because they
    /// are inside the ciphertext only on chunk 0.
    pub fn aad(&self, digest_algo: &str) -> Vec<u8> {
        let algo = digest_algo.as_bytes();
        let mut buf = Vec::with_capacity(1 + 16 + 2 + 2 + 1 + algo.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.bundle_id);
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf.extend_from_slice(&self.total_chunks.to_be_bytes());
        // digest_algo length capped at 255 (sha256/sha512/blake3 all fit).
        let algo_len = u8::try_from(algo.len()).unwrap_or(u8::MAX);
        buf.push(algo_len);
        buf.extend_from_slice(&algo[..algo_len as usize]);
        buf
    }
}

/// In-place sort + duplicate / completeness check, then concatenate the
/// payload fragments in chunk-index order.
pub fn reassemble(mut chunks: Vec<ChunkPlaintext>) -> Result<Vec<u8>, SealedTransferError> {
    if chunks.is_empty() {
        return Err(SealedTransferError::Wire("no chunks supplied".into()));
    }
    let total = chunks[0].total_chunks as usize;
    if total == 0 {
        return Err(SealedTransferError::Wire("total_chunks == 0".into()));
    }
    let bundle_id = chunks[0].bundle_id;
    let version = chunks[0].version;
    if version != VERSION {
        return Err(SealedTransferError::UnsupportedVersion(version));
    }
    for c in &chunks {
        if c.bundle_id != bundle_id {
            return Err(SealedTransferError::ChunkMismatch("bundle_id".into()));
        }
        if c.total_chunks as usize != total {
            return Err(SealedTransferError::ChunkMismatch("total_chunks".into()));
        }
        if c.version != version {
            return Err(SealedTransferError::ChunkMismatch("version".into()));
        }
        if (c.chunk_index as usize) >= total {
            return Err(SealedTransferError::ChunkMismatch(
                "index out of range".into(),
            ));
        }
    }
    chunks.sort_by_key(|c| c.chunk_index);
    for (i, c) in chunks.iter().enumerate() {
        if c.chunk_index as usize != i {
            // Either a missing chunk or a duplicate. Distinguish for a clearer
            // error message.
            if i > 0 && chunks[i - 1].chunk_index == c.chunk_index {
                return Err(SealedTransferError::DuplicateChunk(c.chunk_index));
            }
            return Err(SealedTransferError::MissingChunks {
                have: chunks.len(),
                expected: total,
            });
        }
    }
    if chunks.len() != total {
        return Err(SealedTransferError::MissingChunks {
            have: chunks.len(),
            expected: total,
        });
    }
    let mut out = Vec::new();
    for c in chunks {
        out.extend_from_slice(&c.payload_fragment);
    }
    Ok(out)
}
