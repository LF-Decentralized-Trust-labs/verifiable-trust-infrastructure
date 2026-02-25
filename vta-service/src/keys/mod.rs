pub mod derivation;
pub mod paths;
pub mod seed_store;
pub mod seeds;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use multibase::Base;

use crate::store::KeyspaceHandle;

pub use vta_sdk::keys::{KeyRecord, KeyStatus, KeyType};

pub fn store_key(key_id: &str) -> String {
    format!("key:{key_id}")
}

pub use vta_sdk::did_key::ed25519_multibase_pubkey;

/// Persist a key as a [`KeyRecord`] in the `"keys"` keyspace.
#[allow(clippy::too_many_arguments)]
pub async fn save_key_record(
    keys_ks: &KeyspaceHandle,
    key_id: &str,
    derivation_path: &str,
    key_type: KeyType,
    public_key: &str,
    label: &str,
    context_id: Option<&str>,
    seed_id: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        derivation_path: derivation_path.to_string(),
        key_type,
        status: KeyStatus::Active,
        public_key: public_key.to_string(),
        label: Some(label.to_string()),
        context_id: context_id.map(String::from),
        seed_id,
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(store_key(key_id), &record).await?;
    Ok(())
}

/// Derive an Ed25519 did:key from the BIP-32 seed using a counter-allocated
/// path under `base`, store it as a [`KeyRecord`], and return
/// `(did, private_key_multibase)`.
///
/// The key_id uses the standard did:key fragment format: `{did}#{multibase_pubkey}`.
pub async fn derive_and_store_did_key(
    seed: &[u8],
    base: &str,
    context_id: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
    seed_id: Option<u32>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let dk_path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;
    let derivation_path: DerivationPath = dk_path
        .parse()
        .map_err(|e| format!("Invalid derivation path: {e}"))?;
    let dk_derived = root
        .derive(&derivation_path)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let signing_key = SigningKey::from_bytes(dk_derived.signing_key.as_bytes());
    let public_key = signing_key.verifying_key().to_bytes();

    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let key_id = format!("{did}#{multibase_pubkey}");
    let private_key_multibase =
        multibase::encode(Base::Base58Btc, dk_derived.signing_key.as_bytes());

    save_key_record(
        keys_ks,
        &key_id,
        &dk_path,
        KeyType::Ed25519,
        &multibase_pubkey,
        label,
        Some(context_id),
        seed_id,
    )
    .await?;

    Ok((did, private_key_multibase))
}

/// Derived signing + key-agreement key data, before DID creation.
#[allow(dead_code)]
pub struct DerivedEntityKeys {
    pub signing_secret: Secret,
    pub signing_path: String,
    pub signing_pub: String,
    pub signing_priv: String,
    pub signing_label: String,
    pub ka_secret: Secret,
    pub ka_path: String,
    pub ka_pub: String,
    pub ka_priv: String,
    pub ka_label: String,
}

/// Pre-rotation key data returned from derivation (stored after DID creation).
pub struct PreRotationKeyData {
    pub path: String,
    pub public_key: String,
    pub label: String,
}

/// Derive a signing key (Ed25519) and key-agreement key (X25519) from the
/// BIP-32 seed using counter-allocated paths under `base`.
///
/// Allocates derivation-path counters but does **not** store key records —
/// callers must call [`save_entity_key_records`] after the DID is known.
pub async fn derive_entity_keys(
    seed: &[u8],
    base: &str,
    signing_label: &str,
    ka_label: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<DerivedEntityKeys, Box<dyn std::error::Error>> {
    let signing_path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;
    let ka_path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

    // Signing key (Ed25519)
    let signing_derived = root
        .derive(
            &signing_path
                .parse::<DerivationPath>()
                .map_err(|e| format!("Invalid derivation path: {e}"))?,
        )
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let signing_priv = multibase::encode(Base::Base58Btc, signing_derived.signing_key.as_bytes());
    let signing_secret =
        Secret::generate_ed25519(None, Some(signing_derived.signing_key.as_bytes()));
    let signing_pub = signing_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    // Key-agreement key (X25519)
    let ka_derived = root
        .derive(
            &ka_path
                .parse::<DerivationPath>()
                .map_err(|e| format!("Invalid derivation path: {e}"))?,
        )
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let ka_priv = multibase::encode(Base::Base58Btc, ka_derived.signing_key.as_bytes());
    let ka_secret = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
    let ka_secret = ka_secret
        .to_x25519()
        .map_err(|e| format!("X25519 conversion failed: {e}"))?;
    let ka_pub = ka_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    Ok(DerivedEntityKeys {
        signing_secret,
        signing_path,
        signing_pub,
        signing_priv,
        signing_label: signing_label.to_string(),
        ka_secret,
        ka_path,
        ka_pub,
        ka_priv,
        ka_label: ka_label.to_string(),
    })
}

/// Store entity key records using DID verification method IDs as key_ids.
///
/// Signing key → `{did}#key-0`, key-agreement key → `{did}#key-1`.
pub async fn save_entity_key_records(
    did: &str,
    derived: &DerivedEntityKeys,
    keys_ks: &KeyspaceHandle,
    context_id: Option<&str>,
    seed_id: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    save_key_record(
        keys_ks,
        &format!("{did}#key-0"),
        &derived.signing_path,
        KeyType::Ed25519,
        &derived.signing_pub,
        &derived.signing_label,
        context_id,
        seed_id,
    )
    .await?;
    save_key_record(
        keys_ks,
        &format!("{did}#key-1"),
        &derived.ka_path,
        KeyType::X25519,
        &derived.ka_pub,
        &derived.ka_label,
        context_id,
        seed_id,
    )
    .await?;
    Ok(())
}
