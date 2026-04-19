//! CLI-side producer helper for `vta_sdk::sealed_transfer`.
//!
//! Used by commands that emit sensitive bundles (context provisioning, key
//! bundle export). The CLI sits on the admin's workstation, not inside the
//! VTA, so it has no persistent nonce store and no long-lived producer
//! identity to sign with. We mint a fresh ephemeral keypair per seal and
//! attach a `PinnedOnly` assertion — the operator communicates the producer
//! pubkey + digest out-of-band to the recipient, who verifies by pinning.
//!
//! This mirrors the `vta bootstrap seal` (offline Mode C) pattern from
//! `vta-service/src/bootstrap_cli.rs`; the difference is that context
//! provisioning composes seal + VTA REST calls into a single operator action,
//! whereas Mode C takes a pre-constructed payload file.
//!
//! Call pattern:
//!
//! ```ignore
//! use vta_cli_common::sealed_producer::{SealedRecipient, seal_for_recipient};
//!
//! let recipient = SealedRecipient::from_file(&path)?;  // or ::from_inline(...)
//! let sealed = seal_for_recipient(&recipient, &payload).await?;
//! print!("{}", sealed.armored);
//! eprintln!("SHA-256 digest: {}", sealed.digest);
//! ```

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1,
    armor, bundle_digest, generate_keypair, seal_payload,
};

/// Recipient of a sealed bundle — the X25519 pubkey the AEAD encrypts to,
/// plus the bundle id (the recipient's nonce) that anchors anti-replay.
///
/// Construct via [`Self::from_file`] (standard path: consumer ran
/// `pnm bootstrap request --out <file>`) or [`Self::from_inline`] (fallback:
/// consumer pasted pubkey/nonce over chat, no file transfer available).
#[derive(Debug)]
pub struct SealedRecipient {
    pub pubkey: [u8; 32],
    pub bundle_id: [u8; 16],
    pub label: Option<String>,
}

impl SealedRecipient {
    /// Load from a `BootstrapRequest` JSON file (produced by
    /// `pnm bootstrap request --out <file>`).
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::from_json_str(&json)
            .map_err(|e| format!("parse BootstrapRequest at {}: {e}", path.display()).into())
    }

    /// Parse directly from a JSON string. Useful for tests and non-file
    /// transports (e.g. stdin).
    pub fn from_json_str(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let request: BootstrapRequest =
            serde_json::from_str(json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
        if request.version != 1 {
            return Err(
                format!("unsupported BootstrapRequest version: {}", request.version).into(),
            );
        }
        Ok(Self {
            pubkey: request.decode_client_pubkey()?,
            bundle_id: request.decode_nonce()?,
            label: request.label,
        })
    }

    /// Construct from an inline base64url pubkey and hex nonce.
    ///
    /// `nonce_hex` must be 32 hex characters (16 bytes). Accepts either case.
    pub fn from_inline(
        pubkey_b64: &str,
        nonce_hex: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pk_bytes = B64URL
            .decode(pubkey_b64.trim())
            .map_err(|e| format!("invalid recipient pubkey (base64url): {e}"))?;
        let pubkey: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| "recipient pubkey must be 32 bytes".to_string())?;
        let nonce_bytes = decode_hex(nonce_hex.trim())?;
        let bundle_id: [u8; 16] = nonce_bytes
            .try_into()
            .map_err(|_| "recipient nonce must be 16 bytes (32 hex chars)".to_string())?;
        Ok(Self {
            pubkey,
            bundle_id,
            label: None,
        })
    }
}

/// Output of a successful [`seal_for_recipient`] call.
pub struct SealedOutput {
    /// The armored sealed bundle (caller writes to stdout or file).
    pub armored: String,
    /// SHA-256 digest of the sealed ciphertext (lowercase hex).
    ///
    /// The recipient verifies this out-of-band to defeat producer
    /// impersonation — without it, `PinnedOnly` reduces to trust-on-first-use.
    pub digest: String,
    /// Ephemeral producer pubkey (base64url). Communicated out-of-band
    /// alongside the digest so the recipient can confirm the assertion.
    pub producer_pubkey_b64: String,
    pub bundle_id: [u8; 16],
}

/// Seal a payload for the given recipient with a fresh ephemeral producer
/// keypair and a `PinnedOnly` assertion.
///
/// Uses an [`InMemoryNonceStore`] — the CLI is single-shot, so there is no
/// cross-run replay to defend against on the producer side.
pub async fn seal_for_recipient(
    recipient: &SealedRecipient,
    payload: &SealedPayloadV1,
) -> Result<SealedOutput, Box<dyn std::error::Error>> {
    let (_producer_sk, producer_pk) = generate_keypair();
    let producer_pubkey_b64 = B64URL.encode(producer_pk);
    let producer = ProducerAssertion {
        producer_pubkey_b64: producer_pubkey_b64.clone(),
        proof: AssertionProof::PinnedOnly,
    };
    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(
        &recipient.pubkey,
        recipient.bundle_id,
        producer,
        payload,
        &nonce_store,
    )
    .await?;
    let armored = armor::encode(&bundle);
    let digest = bundle_digest(&bundle);
    Ok(SealedOutput {
        armored,
        digest,
        producer_pubkey_b64,
        bundle_id: recipient.bundle_id,
    })
}

/// Print a standard "sealed output emitted" banner to stderr alongside the
/// digest + producer pubkey. Armor goes to stdout via `println!`.
pub fn emit_sealed_output(sealed: &SealedOutput) {
    let bundle_id_hex = hex_lower(&sealed.bundle_id);
    println!("{}", sealed.armored);
    eprintln!();
    eprintln!("  Bundle-Id:        {bundle_id_hex}");
    eprintln!("  Producer pubkey:  {}", sealed.producer_pubkey_b64);
    eprintln!("  SHA-256 digest:   {}", sealed.digest);
    eprintln!();
    eprintln!(
        "Communicate the digest to the recipient out-of-band so they can run:\n  \
         pnm bootstrap open --bundle <file> --expect-digest {}",
        sealed.digest
    );
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

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string must have even length (got {})", s.len()).into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2])
            .map_err(|e| format!("hex not UTF-8 at offset {i}: {e}"))?;
        let b = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("invalid hex at offset {i} ('{pair}'): {e}"))?;
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::credentials::CredentialBundle;
    use vta_sdk::sealed_transfer::open_bundle;

    fn sample_payload() -> SealedPayloadV1 {
        SealedPayloadV1::AdminCredential(CredentialBundle::new(
            "did:key:z6Mk123",
            "z1234567890",
            "did:key:z6MkVTA",
        ))
    }

    #[test]
    fn hex_roundtrip_16_bytes() {
        let bytes: Vec<u8> = (0..16u8).collect();
        let hex = hex_lower(&bytes);
        assert_eq!(hex.len(), 32);
        let back = decode_hex(&hex).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn decode_hex_rejects_non_hex() {
        assert!(decode_hex("gg").is_err());
    }

    #[test]
    fn recipient_from_inline_validates_sizes() {
        // Valid: 32-byte X25519 pubkey b64url-encoded, 16-byte nonce hex.
        let pk_b64 = B64URL.encode([1u8; 32]);
        let nonce_hex = "00112233445566778899aabbccddeeff";
        let r = SealedRecipient::from_inline(&pk_b64, nonce_hex).unwrap();
        assert_eq!(r.pubkey, [1u8; 32]);
        assert_eq!(
            r.bundle_id,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );

        // Wrong pubkey size.
        let short_pk = B64URL.encode([0u8; 16]);
        assert!(SealedRecipient::from_inline(&short_pk, nonce_hex).is_err());

        // Wrong nonce size.
        assert!(SealedRecipient::from_inline(&pk_b64, "deadbeef").is_err());
    }

    #[tokio::test]
    async fn seal_round_trips_via_armor() {
        // Recipient generates keypair + nonce (simulating `pnm bootstrap request`).
        let (recip_sk, recip_pk) = generate_keypair();
        let bundle_id: [u8; 16] = rand::random();
        let recipient = SealedRecipient {
            pubkey: recip_pk,
            bundle_id,
            label: Some("test".into()),
        };

        // Producer seals.
        let sealed = seal_for_recipient(&recipient, &sample_payload())
            .await
            .unwrap();
        assert!(sealed.armored.contains("BEGIN VTA SEALED BUNDLE"));

        // Recipient opens.
        let parsed = armor::decode(&sealed.armored).unwrap();
        assert_eq!(parsed.len(), 1);
        let opened = open_bundle(&recip_sk, &parsed[0], Some(&sealed.digest)).unwrap();
        assert_eq!(opened.bundle_id, bundle_id);
        match opened.payload {
            SealedPayloadV1::AdminCredential(c) => {
                assert_eq!(c.did, "did:key:z6Mk123");
            }
            _ => panic!("wrong payload variant"),
        }

        // Producer assertion is PinnedOnly and the pubkey matches what we
        // surfaced in the output.
        assert!(matches!(opened.producer.proof, AssertionProof::PinnedOnly));
        assert_eq!(
            opened.producer.producer_pubkey_b64,
            sealed.producer_pubkey_b64
        );
    }

    #[tokio::test]
    async fn seal_recipient_from_json_round_trip() {
        let (recip_sk, recip_pk) = generate_keypair();
        let bundle_id: [u8; 16] = rand::random();
        let request = BootstrapRequest::new(recip_pk, bundle_id, Some("json-test".into()));
        let json = serde_json::to_string(&request).unwrap();

        let recipient = SealedRecipient::from_json_str(&json).unwrap();
        assert_eq!(recipient.pubkey, recip_pk);
        assert_eq!(recipient.bundle_id, bundle_id);
        assert_eq!(recipient.label.as_deref(), Some("json-test"));

        let sealed = seal_for_recipient(&recipient, &sample_payload())
            .await
            .unwrap();
        let parsed = armor::decode(&sealed.armored).unwrap();
        let opened = open_bundle(&recip_sk, &parsed[0], Some(&sealed.digest)).unwrap();
        assert_eq!(opened.bundle_id, bundle_id);
    }

    #[test]
    fn recipient_from_json_rejects_unknown_version() {
        // Manually craft an unsupported version — BootstrapRequest::new always
        // sets version=1, so there's no constructor for this.
        let json = r#"{"version": 99, "client_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "nonce": "AAAAAAAAAAAAAAAAAAAAAA"}"#;
        let err = SealedRecipient::from_json_str(json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("version"), "unexpected error: {err}");
    }
}
