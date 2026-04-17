//! `vta bootstrap` — sealed-transfer producer-side commands.
//!
//! Phase 1 only implements `seal` for offline / Mode-C transfer. The producer
//! generates an ephemeral X25519 identity for this seal, embeds the pubkey in
//! the bundle as a `PinnedOnly` assertion, and prints the canonical SHA-256
//! digest. The operator passes the digest to the consumer out-of-band.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1,
    armor, bundle_digest, generate_keypair, seal_payload,
};

pub async fn run_seal(
    request_path: PathBuf,
    payload_path: PathBuf,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
    if request.version != 1 {
        return Err(format!("unsupported request version: {}", request.version).into());
    }

    let recipient_pk = request.decode_client_pubkey()?;
    let bundle_id = request.decode_nonce()?;

    let payload_json = std::fs::read_to_string(&payload_path)
        .map_err(|e| format!("read {}: {e}", payload_path.display()))?;
    let payload: SealedPayloadV1 =
        serde_json::from_str(&payload_json).map_err(|e| format!("parse SealedPayloadV1: {e}"))?;

    // Fresh per-seal producer identity. In Mode C the consumer pins this
    // pubkey out-of-band — it is not tied to the VTA's long-lived DID.
    let (_producer_sk, producer_pk) = generate_keypair();
    let producer = ProducerAssertion {
        producer_pubkey_b64: B64URL.encode(producer_pk),
        proof: AssertionProof::PinnedOnly,
    };

    // Phase 1 uses an in-memory nonce store. The persistent keyring-backed
    // store ships in Phase 2 with the online producer paths.
    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(&recipient_pk, bundle_id, producer, &payload, &nonce_store)?;

    let armored = armor::encode(&bundle);
    std::fs::write(&out_path, armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    let digest = bundle_digest(&bundle);
    eprintln!("Sealed bundle written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:        {}", hex_lower(&bundle.bundle_id));
    eprintln!("  Chunks:           {}", bundle.chunks.len());
    eprintln!("  Producer pubkey:  {}", B64URL.encode(producer_pk));
    eprintln!("  SHA-256 digest:   {digest}");
    eprintln!();
    eprintln!(
        "Communicate the digest to the consumer out-of-band so they can run\n  \
         pnm bootstrap open --bundle <file> --expect-digest {digest}"
    );
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}
