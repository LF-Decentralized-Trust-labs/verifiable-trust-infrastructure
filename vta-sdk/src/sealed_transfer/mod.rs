//! Sealed transfer — unified envelope for moving sensitive bundles between
//! workspace tools.
//!
//! See `sealed-bootstrap.md` at the repo root for the full design. The short
//! version: every secret-bearing artifact (admin credentials, context
//! provisioning bundles, DID secret exports, raw key material) is encrypted
//! end-to-end to a recipient-chosen ephemeral X25519 public key using HPKE
//! (RFC 9180), framed in a PGP/SSH-style ASCII armor with strict integrity
//! checks. Producer authenticity is established via one of three assertion
//! types depending on the trust mode (DID-signed, attestation quote, or
//! pinned-pubkey + out-of-band digest).

pub mod armor;
pub mod bundle;
pub mod chunk;
pub mod error;
pub mod hpke;
pub mod nonce;
pub mod request;

pub use bundle::{
    ArmoredChunk, AssertionProof, AttestationQuoteAssertion, DidSignedAssertion, LabeledKey,
    ProducerAssertion, SealedBundle, SealedPayloadV1,
};
pub use chunk::{ChunkPlaintext, MAX_PAYLOAD_FRAGMENT, VERSION};
pub use error::SealedTransferError;
pub use hpke::{HpkeSealed, generate_keypair, open as hpke_open, seal as hpke_seal};
pub use nonce::{InMemoryNonceStore, NonceStore};
pub use request::BootstrapRequest;

use sha2::{Digest, Sha256};

/// Default digest algorithm for new bundles.
pub const DEFAULT_DIGEST_ALGO: &str = "sha256";

/// Compute the canonical bundle digest used for out-of-band verification.
///
/// `sha256(sealed_bytes_chunk_0 || sealed_bytes_chunk_1 || ...)`. The chunks
/// are concatenated in chunk-index order; the digest is over the post-HPKE
/// ciphertexts, so any tamper to the armored bytes invalidates it. Returned as
/// lowercase hex.
pub fn bundle_digest(bundle: &SealedBundle) -> String {
    let mut chunks: Vec<&ArmoredChunk> = bundle.chunks.iter().collect();
    chunks.sort_by_key(|c| c.chunk_index);
    let mut hasher = Sha256::new();
    for c in chunks {
        hasher.update(&c.sealed_bytes);
    }
    format!("{:x}", hasher.finalize())
}

/// Seal a [`SealedPayloadV1`] for delivery to `recipient_pubkey`.
///
/// `bundle_id` should be the consumer's request nonce. The producer's
/// [`NonceStore`] is consulted to enforce single-use semantics: re-sealing the
/// same `bundle_id` returns [`SealedTransferError::NonceReplay`].
pub async fn seal_payload(
    recipient_pubkey: &[u8; 32],
    bundle_id: [u8; 16],
    producer: ProducerAssertion,
    payload: &SealedPayloadV1,
    nonce_store: &dyn NonceStore,
) -> Result<SealedBundle, SealedTransferError> {
    nonce_store.check_and_record(&bundle_id).await?;

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes)
        .map_err(|e| SealedTransferError::CborEncode(e.to_string()))?;

    let producer_pubkey = base64_url_decode_32(&producer.producer_pubkey_b64)?;

    let total_chunks_usize = payload_bytes.len().div_ceil(MAX_PAYLOAD_FRAGMENT).max(1);
    let total_chunks: u16 = total_chunks_usize
        .try_into()
        .map_err(|_| SealedTransferError::Wire("payload too large for u16 chunk count".into()))?;

    let mut chunks: Vec<ArmoredChunk> = Vec::with_capacity(total_chunks_usize);
    for i in 0..total_chunks_usize {
        let start = i * MAX_PAYLOAD_FRAGMENT;
        let end = (start + MAX_PAYLOAD_FRAGMENT).min(payload_bytes.len());
        let fragment = payload_bytes[start..end].to_vec();
        let chunk_index = i as u16;
        let plaintext = ChunkPlaintext {
            version: VERSION,
            bundle_id,
            chunk_index,
            total_chunks,
            producer_pubkey: if i == 0 { Some(producer_pubkey) } else { None },
            producer_assertion: if i == 0 { Some(producer.clone()) } else { None },
            payload_fragment: fragment,
        };
        let aad = plaintext.aad(DEFAULT_DIGEST_ALGO);
        let mut pt_cbor = Vec::new();
        ciborium::ser::into_writer(&plaintext, &mut pt_cbor)
            .map_err(|e| SealedTransferError::CborEncode(e.to_string()))?;
        let sealed = hpke_seal(recipient_pubkey, &pt_cbor, &aad)?;
        let mut sealed_cbor = Vec::new();
        ciborium::ser::into_writer(&sealed, &mut sealed_cbor)
            .map_err(|e| SealedTransferError::CborEncode(e.to_string()))?;
        chunks.push(ArmoredChunk {
            chunk_index,
            total_chunks,
            sealed_bytes: sealed_cbor,
        });
    }

    Ok(SealedBundle {
        bundle_id,
        digest_algo: DEFAULT_DIGEST_ALGO.to_string(),
        chunks,
    })
}

/// The result of opening a sealed bundle: the payload, plus the producer
/// assertion the caller must verify against its trust policy.
#[derive(Debug)]
pub struct OpenedBundle {
    pub payload: SealedPayloadV1,
    pub producer: ProducerAssertion,
    pub bundle_id: [u8; 16],
}

/// Open a [`SealedBundle`] with the recipient's secret. Performs:
///
/// 1. Optional canonical-digest verification when `expect_digest` is `Some`.
/// 2. Per-chunk HPKE open with header AAD binding.
/// 3. Chunk header consistency + reassembly.
/// 4. Extraction of the chunk-0 producer assertion.
///
/// The caller is then responsible for verifying the producer assertion against
/// its trust policy (resolve DID + check signature, validate attestation quote,
/// or compare to a pinned pubkey).
pub fn open_bundle(
    recipient_secret: &[u8; 32],
    bundle: &SealedBundle,
    expect_digest: Option<&str>,
) -> Result<OpenedBundle, SealedTransferError> {
    if let Some(expected) = expect_digest {
        let got = bundle_digest(bundle);
        if !constant_time_eq(expected.as_bytes(), got.as_bytes()) {
            return Err(SealedTransferError::DigestMismatch {
                expected: expected.to_string(),
                got,
            });
        }
    }

    let mut plaintexts: Vec<ChunkPlaintext> = Vec::with_capacity(bundle.chunks.len());
    for chunk in &bundle.chunks {
        let sealed: HpkeSealed = ciborium::de::from_reader(&chunk.sealed_bytes[..])
            .map_err(|e| SealedTransferError::CborDecode(e.to_string()))?;
        // Build the AAD from the *armor-declared* chunk header. If the AEAD
        // open succeeds, the inner header matches the outer (the inner header
        // was the AAD at seal time).
        let header_for_aad = ChunkPlaintext {
            version: VERSION,
            bundle_id: bundle.bundle_id,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
            producer_pubkey: None,
            producer_assertion: None,
            payload_fragment: Vec::new(),
        };
        let aad = header_for_aad.aad(&bundle.digest_algo);
        let pt_bytes = hpke_open(recipient_secret, &sealed, &aad)?;
        let pt: ChunkPlaintext = ciborium::de::from_reader(&pt_bytes[..])
            .map_err(|e| SealedTransferError::CborDecode(e.to_string()))?;
        if pt.bundle_id != bundle.bundle_id
            || pt.chunk_index != chunk.chunk_index
            || pt.total_chunks != chunk.total_chunks
        {
            return Err(SealedTransferError::ChunkMismatch(
                "inner header != armor header".into(),
            ));
        }
        plaintexts.push(pt);
    }

    // Extract chunk-0 assertion before consuming the vec for reassembly.
    let chunk0 = plaintexts
        .iter()
        .find(|p| p.chunk_index == 0)
        .ok_or(SealedTransferError::MissingAssertion)?;
    let producer = chunk0
        .producer_assertion
        .clone()
        .ok_or(SealedTransferError::MissingAssertion)?;
    let declared_pk = chunk0
        .producer_pubkey
        .ok_or(SealedTransferError::MissingAssertion)?;
    let declared_b64 = base64_url_encode(&declared_pk);
    if declared_b64 != producer.producer_pubkey_b64 {
        return Err(SealedTransferError::ProducerMismatch {
            declared: declared_b64,
            expected: producer.producer_pubkey_b64.clone(),
        });
    }

    let payload_bytes = chunk::reassemble(plaintexts)?;
    let payload: SealedPayloadV1 = ciborium::de::from_reader(&payload_bytes[..])
        .map_err(|e| SealedTransferError::CborDecode(e.to_string()))?;

    Ok(OpenedBundle {
        payload,
        producer,
        bundle_id: bundle.bundle_id,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn base64_url_decode_32(s: &str) -> Result<[u8; 32], SealedTransferError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let raw = B64URL
        .decode(s)
        .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
    raw.try_into()
        .map_err(|_| SealedTransferError::Wire("expected 32-byte X25519 pubkey".into()))
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    B64URL.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialBundle;

    fn sample_payload() -> SealedPayloadV1 {
        SealedPayloadV1::AdminCredential(CredentialBundle::new(
            "did:key:z6Mk123",
            "z1234567890",
            "did:key:z6MkVTA",
        ))
    }

    fn sample_assertion(pubkey_b64: String) -> ProducerAssertion {
        ProducerAssertion {
            producer_pubkey_b64: pubkey_b64,
            proof: AssertionProof::PinnedOnly,
        }
    }

    #[tokio::test]
    async fn round_trip_single_chunk() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();
        let bundle_id = [7u8; 16];

        let bundle = seal_payload(&recip_pk, bundle_id, assertion, &sample_payload(), &store)
            .await
            .unwrap();

        assert_eq!(bundle.chunks.len(), 1);

        let opened = open_bundle(&recip_sk, &bundle, None).unwrap();
        assert_eq!(opened.bundle_id, bundle_id);
        match opened.payload {
            SealedPayloadV1::AdminCredential(c) => assert_eq!(c.did, "did:key:z6Mk123"),
            _ => panic!("wrong payload variant"),
        }
    }

    #[tokio::test]
    async fn round_trip_multi_chunk() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();
        let bundle_id = [9u8; 16];

        // Force multi-chunk by stuffing a large LabeledKey set.
        let big_keys: Vec<LabeledKey> = (0..2048)
            .map(|i| LabeledKey {
                label: format!("k-{i}"),
                key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                key_type: Some("ed25519".to_string()),
            })
            .collect();
        let payload = SealedPayloadV1::AdminKeySet(big_keys);

        let bundle = seal_payload(&recip_pk, bundle_id, assertion, &payload, &store)
            .await
            .unwrap();
        assert!(bundle.chunks.len() > 1, "expected multi-chunk bundle");

        let opened = open_bundle(&recip_sk, &bundle, None).unwrap();
        match opened.payload {
            SealedPayloadV1::AdminKeySet(keys) => assert_eq!(keys.len(), 2048),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn replay_rejected_by_nonce_store() {
        let (_recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();
        let bundle_id = [1u8; 16];

        seal_payload(
            &recip_pk,
            bundle_id,
            assertion.clone(),
            &sample_payload(),
            &store,
        )
        .await
        .unwrap();
        let err = seal_payload(&recip_pk, bundle_id, assertion, &sample_payload(), &store)
            .await
            .unwrap_err();
        assert!(matches!(err, SealedTransferError::NonceReplay));
    }

    #[tokio::test]
    async fn digest_mismatch_rejected() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [2u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let err = open_bundle(&recip_sk, &bundle, Some("deadbeef")).unwrap_err();
        assert!(matches!(err, SealedTransferError::DigestMismatch { .. }));
    }

    #[tokio::test]
    async fn digest_match_accepted() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [3u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let digest = bundle_digest(&bundle);
        open_bundle(&recip_sk, &bundle, Some(&digest)).unwrap();
    }

    #[tokio::test]
    async fn armor_round_trip() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [4u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let armored = armor::encode(&bundle);
        assert!(armored.contains("BEGIN VTA SEALED BUNDLE"));
        let parsed = armor::decode(&armored).unwrap();
        assert_eq!(parsed.len(), 1);
        let opened = open_bundle(&recip_sk, &parsed[0], None).unwrap();
        match opened.payload {
            SealedPayloadV1::AdminCredential(c) => assert_eq!(c.did, "did:key:z6Mk123"),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn armor_corruption_caught_by_crc24() {
        let (_recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [5u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        let mut armored = armor::encode(&bundle);
        // Flip one base64 character somewhere in the middle of the body.
        let body_offset = armored.find("\n\n").unwrap() + 2;
        let bytes = unsafe { armored.as_bytes_mut() };
        bytes[body_offset] = if bytes[body_offset] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let err = armor::decode(&armored).unwrap_err();
        assert!(
            matches!(err, SealedTransferError::Crc24Mismatch { .. }),
            "expected Crc24Mismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn aad_tamper_caught_by_aead() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();

        let bundle = seal_payload(&recip_pk, [6u8; 16], assertion, &sample_payload(), &store)
            .await
            .unwrap();
        // Tamper: rewrite the bundle.bundle_id without re-sealing. The inner
        // chunk's AAD will use the new bundle_id, which will not match the AAD
        // used at seal time.
        let mut tampered = bundle.clone();
        tampered.bundle_id = [0xff; 16];
        let err = open_bundle(&recip_sk, &tampered, None).unwrap_err();
        assert!(matches!(err, SealedTransferError::Hpke(_)));
    }

    #[tokio::test]
    async fn missing_chunk_rejected() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (_prod_sk, prod_pk) = generate_keypair();
        let assertion = sample_assertion(base64_url_encode(&prod_pk));
        let store = InMemoryNonceStore::new();
        let big_keys: Vec<LabeledKey> = (0..2048)
            .map(|i| LabeledKey {
                label: format!("k-{i}"),
                key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                key_type: None,
            })
            .collect();
        let payload = SealedPayloadV1::AdminKeySet(big_keys);
        let mut bundle = seal_payload(&recip_pk, [10u8; 16], assertion, &payload, &store)
            .await
            .unwrap();
        assert!(bundle.chunks.len() > 1);
        // Drop the last chunk.
        bundle.chunks.pop();
        let err = open_bundle(&recip_sk, &bundle, None).unwrap_err();
        assert!(
            matches!(err, SealedTransferError::MissingChunks { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn bootstrap_request_round_trip() {
        let (_sk, pk) = generate_keypair();
        let req = BootstrapRequest::new(pk, [42u8; 16], Some("test".into()));
        let json = serde_json::to_string(&req).unwrap();
        let back: BootstrapRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decode_client_pubkey().unwrap(), pk);
        assert_eq!(back.decode_nonce().unwrap(), [42u8; 16]);
    }

    #[test]
    fn bootstrap_request_rejects_unknown_fields() {
        let json = r#"{
            "version": 1,
            "client_pubkey": "AA",
            "nonce": "AA",
            "requested_role": "Admin"
        }"#;
        assert!(serde_json::from_str::<BootstrapRequest>(json).is_err());
    }
}
