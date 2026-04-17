//! HPKE (RFC 9180) wiring.
//!
//! Suite: `0x0020, 0x0001, 0x0003`
//!   - KEM: DHKEM(X25519, HKDF-SHA256)
//!   - KDF: HKDF-SHA256
//!   - AEAD: ChaCha20-Poly1305
//!
//! Single-shot, base mode (no PSK, no auth-mode KEM). The chunk header is
//! bound as AEAD AAD by the caller.

use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{CryptoRng, RngCore},
    single_shot_open, single_shot_seal,
};
use serde::{Deserialize, Serialize};

use super::error::SealedTransferError;

/// HPKE `info` string. Binds the suite to its purpose so a ciphertext for one
/// purpose cannot be replayed against another.
const HPKE_INFO: &[u8] = b"vta-sealed-transfer/v1";

/// Adapter from `getrandom` to the rand_core trait version that `hpke` 0.13
/// re-exports. We can't use the `rand` crate directly because rand 0.10 /
/// rand_core 0.10 are not compatible with hpke's rand_core 0.9 traits.
struct OsCsprng;

impl RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("OS CSPRNG failed");
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("OS CSPRNG failed");
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS CSPRNG failed");
    }
}

impl CryptoRng for OsCsprng {}

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;

/// Wire layout for one HPKE-sealed chunk. CBOR-encoded into the
/// `ArmoredChunk.sealed_bytes` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeSealed {
    /// X25519 ephemeral public key from the KEM encapsulation (32 bytes).
    pub kem_encap: [u8; 32],
    /// AEAD-sealed bytes (ciphertext || tag).
    pub aead_ciphertext: Vec<u8>,
}

/// Seal a plaintext to `recipient_pubkey` (32-byte X25519 public key), binding
/// `aad` as additional authenticated data.
pub fn seal(
    recipient_pubkey: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<HpkeSealed, SealedTransferError> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pubkey)
        .map_err(SealedTransferError::hpke)?;
    let mut rng = OsCsprng;
    let (encap, ciphertext) = single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        HPKE_INFO,
        plaintext,
        aad,
        &mut rng,
    )
    .map_err(SealedTransferError::hpke)?;
    let encap_bytes = encap.to_bytes();
    let kem_encap: [u8; 32] = encap_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SealedTransferError::Hpke("KEM encap not 32 bytes".into()))?;
    Ok(HpkeSealed {
        kem_encap,
        aead_ciphertext: ciphertext,
    })
}

/// Open an [`HpkeSealed`] using the recipient's 32-byte X25519 secret key.
pub fn open(
    recipient_secret: &[u8; 32],
    sealed: &HpkeSealed,
    aad: &[u8],
) -> Result<Vec<u8>, SealedTransferError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_secret)
        .map_err(SealedTransferError::hpke)?;
    let encap = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed.kem_encap)
        .map_err(SealedTransferError::hpke)?;
    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encap,
        HPKE_INFO,
        &sealed.aead_ciphertext,
        aad,
    )
    .map_err(SealedTransferError::hpke)
}

/// Generate a fresh X25519 keypair (secret, public). The secret is the
/// recipient's input to [`open`]; the public is what they advertise via a
/// [`crate::sealed_transfer::request::BootstrapRequest`].
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = OsCsprng;
    let (sk, pk) = <Kem as KemTrait>::gen_keypair(&mut rng);
    let sk_bytes: [u8; 32] = sk
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("X25519 secret is 32 bytes");
    let pk_bytes: [u8; 32] = pk
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("X25519 public is 32 bytes");
    (sk_bytes, pk_bytes)
}
