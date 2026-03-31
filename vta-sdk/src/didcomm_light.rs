//! Lightweight DIDComm v2 anonymous encryption (anoncrypt) packer.
//!
//! Produces a JWE (General JSON Serialization) that can be unpacked by any
//! DIDComm v2 implementation (including `affinidi-tdk`'s `ATM::unpack()`).
//!
//! This module avoids the heavyweight ATM/TDK runtime initialization. It only
//! needs the recipient's X25519 public key (derived from their `did:key`).
//!
//! Algorithm: ECDH-ES+A256KW (key agreement) + A256GCM (content encryption).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const GCM_NONCE_LEN: usize = 12;
const AES_KEY_LEN: usize = 32;

// ── DIDComm message builder ─────────────────────────────────────────

/// Build a DIDComm v2 plaintext message JSON.
pub fn build_message(
    msg_type: &str,
    body: serde_json::Value,
    from: &str,
    to: &str,
) -> String {
    serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "typ": "application/didcomm-plain+json",
        "type": msg_type,
        "body": body,
        "from": from,
        "to": [to],
    })
    .to_string()
}

// ── JWE anoncrypt packer ────────────────────────────────────────────

/// Pack a plaintext message as a DIDComm v2 anoncrypt JWE (General JSON).
///
/// Returns the JWE as a JSON string suitable for sending to `POST /auth/`.
pub fn pack_anoncrypt(
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
    recipient_kid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use aes_gcm::aead::rand_core::RngCore;

    // 1. Generate ephemeral X25519 keypair
    let ephemeral_secret = StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);

    // 2. ECDH: shared secret
    let recipient_pub = PublicKey::from(*recipient_x25519_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

    // 3. Build protected header
    let protected = serde_json::json!({
        "typ": "application/didcomm-encrypted+json",
        "alg": "ECDH-ES+A256KW",
        "enc": "A256GCM",
        "apu": B64.encode(b""),
        "apv": B64.encode(Sha256::digest(recipient_kid.as_bytes())),
        "epk": {
            "kty": "OKP",
            "crv": "X25519",
            "x": B64.encode(ephemeral_pub.as_bytes()),
        },
    });
    let protected_b64 = B64.encode(protected.to_string().as_bytes());

    // 4. Derive key-wrapping key via Concat KDF
    let apu = b"";
    let apv = Sha256::digest(recipient_kid.as_bytes());
    let kek = concat_kdf(shared_secret.as_bytes(), "A256KW", apu, &apv)?;

    // 5. Generate random CEK (32 bytes for AES-256-GCM)
    let mut cek = [0u8; AES_KEY_LEN];
    aes_gcm::aead::OsRng.fill_bytes(&mut cek);

    // 6. AES-256 Key Wrap the CEK
    let encrypted_key = aes_key_wrap(&kek, &cek)?;

    // 7. AES-256-GCM encrypt the plaintext with CEK
    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| format!("aes-gcm key: {e}"))?;
    let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD = protected header (base64url encoded)
    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: protected_b64.as_bytes(),
            },
        )
        .map_err(|e| format!("aes-gcm encrypt: {e}"))?;

    // Split ciphertext and tag (last 16 bytes is the GCM tag)
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let tag = &ciphertext_with_tag[tag_start..];

    // 8. Assemble JWE General JSON Serialization
    let jwe = serde_json::json!({
        "protected": protected_b64,
        "recipients": [{
            "header": { "kid": recipient_kid },
            "encrypted_key": B64.encode(&encrypted_key),
        }],
        "iv": B64.encode(nonce_bytes),
        "ciphertext": B64.encode(ciphertext),
        "tag": B64.encode(tag),
    });

    Ok(jwe.to_string())
}

// ── Concat KDF (NIST SP 800-56A, single-pass SHA-256) ──────────────

/// Derive a 256-bit key from ECDH shared secret using Concat KDF.
fn concat_kdf(
    z: &[u8],
    algorithm: &str,
    apu: &[u8],
    apv: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();

    // counter = 00000001
    hasher.update(1u32.to_be_bytes());

    // Z = shared secret
    hasher.update(z);

    // OtherInfo:
    // AlgorithmID = len(4 BE) || algorithm
    hasher.update((algorithm.len() as u32).to_be_bytes());
    hasher.update(algorithm.as_bytes());

    // PartyUInfo = len(4 BE) || apu
    hasher.update((apu.len() as u32).to_be_bytes());
    hasher.update(apu);

    // PartyVInfo = len(4 BE) || apv
    hasher.update((apv.len() as u32).to_be_bytes());
    hasher.update(apv);

    // SuppPubInfo = keydatalen in bits (256) as 32-bit BE
    hasher.update(256u32.to_be_bytes());

    let result = hasher.finalize();
    Ok(result.into())
}

// ── AES-256 Key Wrap (RFC 3394) ─────────────────────────────────────

/// Wrap a key using AES-256 Key Wrap (RFC 3394).
///
/// Input: 32-byte KEK, key to wrap (multiple of 8 bytes).
/// Output: wrapped key (input_len + 8 bytes).
fn aes_key_wrap(kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
    use aes::Aes256;

    if plaintext.len() % 8 != 0 || plaintext.is_empty() {
        return Err("key wrap input must be a non-empty multiple of 8 bytes".into());
    }

    let n = plaintext.len() / 8;
    let cipher = Aes256::new_from_slice(kek)
        .map_err(|e| format!("aes key wrap: {e}"))?;

    // Initialize: A = IV (0xA6 repeated 8 times), R[1..n] = plaintext blocks
    let mut a = [0xA6u8; 8];
    let mut r: Vec<[u8; 8]> = plaintext
        .chunks_exact(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    // Wrap: 6 rounds
    for j in 0..6u64 {
        for i in 0..n {
            let t = (n as u64) * j + (i as u64) + 1;

            // B = AES(K, A || R[i])
            let mut block = aes::Block::default();
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i]);
            cipher.encrypt_block(&mut block);

            // A = MSB(64, B) ^ t
            a.copy_from_slice(&block[..8]);
            let t_bytes = t.to_be_bytes();
            for k in 0..8 {
                a[k] ^= t_bytes[k];
            }

            // R[i] = LSB(64, B)
            r[i].copy_from_slice(&block[8..]);
        }
    }

    // Output: A || R[1] || R[2] || ... || R[n]
    let mut output = Vec::with_capacity(8 + plaintext.len());
    output.extend_from_slice(&a);
    for block in &r {
        output.extend_from_slice(block);
    }
    Ok(output)
}

/// Unwrap a key using AES-256 Key Unwrap (RFC 3394). Used for testing.
#[cfg(test)]
fn aes_key_unwrap(kek: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aes::cipher::{BlockDecrypt, KeyInit as AesKeyInit};
    use aes::Aes256;

    if ciphertext.len() % 8 != 0 || ciphertext.len() < 24 {
        return Err("key unwrap input must be at least 24 bytes and a multiple of 8".into());
    }

    let n = (ciphertext.len() / 8) - 1;
    let cipher = Aes256::new_from_slice(kek)?;

    let mut a = [0u8; 8];
    a.copy_from_slice(&ciphertext[..8]);
    let mut r: Vec<[u8; 8]> = ciphertext[8..]
        .chunks_exact(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;

            let t_bytes = t.to_be_bytes();
            for k in 0..8 {
                a[k] ^= t_bytes[k];
            }

            let mut block = aes::Block::default();
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i]);
            cipher.decrypt_block(&mut block);

            a.copy_from_slice(&block[..8]);
            r[i].copy_from_slice(&block[8..]);
        }
    }

    if a != [0xA6u8; 8] {
        return Err("key unwrap integrity check failed".into());
    }

    let mut output = Vec::with_capacity(n * 8);
    for block in &r {
        output.extend_from_slice(block);
    }
    Ok(output)
}

// ── did:key → X25519 public key conversion ──────────────────────────

/// Extract the Ed25519 public key bytes from a `did:key:z6Mk...` identifier.
pub fn parse_did_key_ed25519(did: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let multibase_part = did
        .strip_prefix("did:key:")
        .ok_or("not a did:key")?;
    let (_, decoded) = multibase::decode(multibase_part)?;
    // Expect 34 bytes: 2-byte multicodec (0xed 0x01) + 32-byte key
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err("invalid did:key: expected Ed25519 multicodec prefix 0xed01".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    Ok(key)
}

/// Convert an Ed25519 public key to an X25519 public key (Edwards → Montgomery).
pub fn ed25519_pub_to_x25519_pub(ed_pub: &[u8; 32]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*ed_pub);
    let edwards = compressed
        .decompress()
        .ok_or("invalid Ed25519 public key: decompression failed")?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// Derive the X25519 key-agreement key ID for a `did:key`.
///
/// Given `did:key:z6Mk...`, returns `did:key:z6Mk...#z6LS...` where the
/// fragment is the X25519 public key encoded with multicodec `0xec01`.
pub fn did_key_agreement_kid(did: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ed_pub = parse_did_key_ed25519(did)?;
    let x_pub = ed25519_pub_to_x25519_pub(&ed_pub)?;
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xec, 0x01]); // x25519-pub multicodec
    buf.extend_from_slice(&x_pub);
    let x_multibase = multibase::encode(multibase::Base::Base58Btc, &buf);
    Ok(format!("{did}#{x_multibase}"))
}

/// Convert an Ed25519 seed (private key) to X25519 static secret bytes.
pub fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    // Standard Ed25519→X25519 conversion: SHA-512(seed)[0..32] with clamping
    let hash = sha2::Sha512::digest(seed);
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);
    // Clamping (applied by StaticSecret::from, but be explicit)
    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;
    x25519_bytes
}

// ── High-level: pack auth message ───────────────────────────────────

/// Pack a DIDComm v2 authenticate message for VTA challenge-response.
///
/// This is the lightweight equivalent of `atm.pack_encrypted()` — it produces
/// a JWE that the server's ATM can unpack, without needing ATM initialization.
pub fn pack_auth_message(
    msg_type: &str,
    body: serde_json::Value,
    client_did: &str,
    vta_did: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let plaintext = build_message(msg_type, body, client_did, vta_did);

    // Get recipient's X25519 public key from their did:key
    let ed_pub = parse_did_key_ed25519(vta_did)?;
    let x_pub = ed25519_pub_to_x25519_pub(&ed_pub)?;
    let kid = did_key_agreement_kid(vta_did)?;

    pack_anoncrypt(plaintext.as_bytes(), &x_pub, &kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_wrap_roundtrip() {
        let kek = [42u8; 32];
        let plaintext = [1u8; 32]; // 32 bytes = 4 blocks of 8

        let wrapped = aes_key_wrap(&kek, &plaintext).unwrap();
        assert_eq!(wrapped.len(), 40); // 32 + 8

        let unwrapped = aes_key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn test_aes_key_wrap_different_keys_different_output() {
        let kek1 = [1u8; 32];
        let kek2 = [2u8; 32];
        let plaintext = [99u8; 32];

        let w1 = aes_key_wrap(&kek1, &plaintext).unwrap();
        let w2 = aes_key_wrap(&kek2, &plaintext).unwrap();
        assert_ne!(w1, w2);
    }

    #[test]
    fn test_concat_kdf_deterministic() {
        let z = [0u8; 32];
        let k1 = concat_kdf(&z, "A256KW", b"", b"recipient").unwrap();
        let k2 = concat_kdf(&z, "A256KW", b"", b"recipient").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_concat_kdf_different_algorithms() {
        let z = [0u8; 32];
        let k1 = concat_kdf(&z, "A256KW", b"", b"x").unwrap();
        let k2 = concat_kdf(&z, "A128KW", b"", b"x").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_parse_did_key_ed25519() {
        // Create a known did:key from a known public key
        let pub_bytes = [42u8; 32];
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&pub_bytes)
        );
        let parsed = parse_did_key_ed25519(&did).unwrap();
        assert_eq!(parsed, pub_bytes);
    }

    #[test]
    fn test_ed25519_to_x25519_conversion() {
        // Generate an Ed25519 key pair and verify conversion produces valid X25519
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let ed_pub = verifying_key.to_bytes();

        let x_pub = ed25519_pub_to_x25519_pub(&ed_pub).unwrap();
        assert_ne!(x_pub, [0u8; 32]); // Should not be all zeros
    }

    #[test]
    fn test_did_key_agreement_kid() {
        let pub_bytes = [42u8; 32];
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&pub_bytes)
        );
        let kid = did_key_agreement_kid(&did).unwrap();
        assert!(kid.starts_with(&did));
        assert!(kid.contains('#'));
        // The fragment should be an X25519 multibase (starts with z after #)
        let fragment = kid.split('#').nth(1).unwrap();
        assert!(fragment.starts_with('z'));
    }

    #[test]
    fn test_pack_anoncrypt_produces_valid_jwe() {
        let recipient_secret = StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
        let recipient_pub = PublicKey::from(&recipient_secret);

        let jwe_str = pack_anoncrypt(
            b"hello world",
            recipient_pub.as_bytes(),
            "did:key:test#key-1",
        )
        .unwrap();

        let jwe: serde_json::Value = serde_json::from_str(&jwe_str).unwrap();
        assert!(jwe["protected"].is_string());
        assert!(jwe["recipients"].is_array());
        assert_eq!(jwe["recipients"].as_array().unwrap().len(), 1);
        assert!(jwe["iv"].is_string());
        assert!(jwe["ciphertext"].is_string());
        assert!(jwe["tag"].is_string());

        // Verify protected header
        let protected_json: serde_json::Value = serde_json::from_slice(
            &B64.decode(jwe["protected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(protected_json["alg"], "ECDH-ES+A256KW");
        assert_eq!(protected_json["enc"], "A256GCM");
        assert_eq!(protected_json["typ"], "application/didcomm-encrypted+json");
    }

    #[test]
    fn test_build_message_structure() {
        let msg = build_message(
            "https://example.com/test",
            serde_json::json!({"foo": "bar"}),
            "did:key:sender",
            "did:key:recipient",
        );
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["type"], "https://example.com/test");
        assert_eq!(parsed["from"], "did:key:sender");
        assert_eq!(parsed["to"][0], "did:key:recipient");
        assert_eq!(parsed["body"]["foo"], "bar");
        assert!(parsed["id"].is_string());
    }
}
