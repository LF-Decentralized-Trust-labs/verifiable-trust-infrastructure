//! `POST /bootstrap/request` — unified sealed-transfer bootstrap endpoint.
//!
//! Two authorization branches, selected by whether a `token` is present:
//!
//! - **Mode A (token)** — Consumer presents a one-time token issued out-of-band
//!   by the operator. Server hashes the token, looks up the stored
//!   [`PendingBootstrap`], atomically consumes it, mints a did:key credential
//!   bound to the stored role/contexts, and returns an HPKE-sealed armored
//!   bundle with a `PinnedOnly` producer assertion.
//! - **Mode B (TEE first-boot)** — No token. Only available on the first
//!   successful request against a TEE VTA that has no admin configured. The
//!   server generates an attestation quote committing to the client pubkey,
//!   nonce, and its own ephemeral producer pubkey, mints an Admin credential,
//!   and closes the carve-out permanently. The bundle's assertion is
//!   `Attested(quote)` so the consumer can verify end-to-end without any
//!   prior shared secret.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[cfg(feature = "tee")]
use sha2::{Digest, Sha256};
use vta_sdk::credentials::CredentialBundle;
#[cfg(feature = "tee")]
use vta_sdk::sealed_transfer::AttestationQuoteAssertion;
use vta_sdk::sealed_transfer::{
    AssertionProof, ProducerAssertion, SealedPayloadV1, armor, bundle_digest, generate_keypair,
    seal_payload,
};

#[cfg(feature = "tee")]
use crate::acl::store_acl_entry;
use crate::acl::{
    AclEntry, PendingBootstrap, Role, consume_pending_bootstrap, get_pending_bootstrap_by_token,
};
use crate::audit::audit;
use crate::auth::credentials::generate_did_key;
use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

/// Request body. `#[serde(deny_unknown_fields)]` so a client cannot smuggle
/// in `requested_role` / `allowed_contexts` — minting parameters are frozen
/// at token issuance time.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequestBody {
    /// Wire-format version. Currently 1.
    pub version: u8,
    /// Consumer's ephemeral X25519 public key (32 bytes), base64url-no-pad.
    pub client_pubkey: String,
    /// Random 16-byte nonce, base64url-no-pad. Becomes the bundle_id.
    pub nonce: String,
    /// One-time bootstrap token. Required for Mode A.
    #[serde(default)]
    pub token: Option<String>,
    /// Optional human-readable label (operator-visible only). Echoed into
    /// server-side audit logs alongside the token hash.
    #[serde(default)]
    pub label: Option<String>,
}

/// Response body — a single armored sealed bundle as UTF-8 text, plus the
/// canonical SHA-256 digest so clients can optionally anchor on it.
#[derive(Debug, Serialize)]
pub struct BootstrapResponseBody {
    pub bundle: String,
    pub digest: String,
}

/// `POST /bootstrap/request`
pub async fn request(
    State(state): State<AppState>,
    Json(req): Json<BootstrapRequestBody>,
) -> Result<Json<BootstrapResponseBody>, AppError> {
    if req.version != 1 {
        return Err(AppError::Validation(format!(
            "unsupported bootstrap request version: {}",
            req.version
        )));
    }

    let client_pubkey = decode_pubkey(&req.client_pubkey)?;
    let bundle_id = decode_nonce(&req.nonce)?;
    let now = now_epoch();

    let bundle = match req.token.as_deref() {
        Some(token) => {
            let pending = get_pending_bootstrap_by_token(&state.acl_ks, token)
                .await?
                .ok_or_else(|| {
                    warn!("bootstrap request: token not found");
                    AppError::Forbidden("invalid or consumed bootstrap token".into())
                })?;
            if pending.is_expired(now) {
                return Err(AppError::Forbidden("bootstrap token expired".into()));
            }
            mint_mode_a(
                &state.acl_ks,
                &state.sealed_nonces_ks,
                &state.config,
                &pending,
                &client_pubkey,
                bundle_id,
                now,
            )
            .await?
        }
        None => {
            #[cfg(feature = "tee")]
            {
                mint_mode_b(&state, &client_pubkey, bundle_id, now).await?
            }
            #[cfg(not(feature = "tee"))]
            {
                return Err(AppError::Forbidden(
                    "bootstrap request requires a token (TEE first-boot is not available \
                     on this VTA build)"
                        .into(),
                ));
            }
        }
    };

    let digest = bundle_digest(&bundle);
    let armored = armor::encode(&bundle);

    info!(
        client_label = ?req.label,
        "bootstrap swap completed"
    );
    audit!(
        "bootstrap.swap",
        actor = "bootstrap-endpoint",
        resource = "bootstrap",
        outcome = "success"
    );
    let _ = crate::audit::record(
        &state.audit_ks,
        "bootstrap.swap",
        "bootstrap-endpoint",
        None,
        "success",
        Some("rest"),
        None,
    )
    .await;

    Ok(Json(BootstrapResponseBody {
        bundle: armored,
        digest,
    }))
}

async fn mint_mode_a(
    acl_ks: &KeyspaceHandle,
    sealed_nonces_ks: &KeyspaceHandle,
    config: &Arc<RwLock<AppConfig>>,
    pending: &PendingBootstrap,
    client_pubkey: &[u8; 32],
    bundle_id: [u8; 16],
    now: u64,
) -> Result<vta_sdk::sealed_transfer::SealedBundle, AppError> {
    // Defense in depth: `PendingBootstrap` issuance already refuses the
    // Bootstrap role, but re-check in case a row was written by a buggy
    // caller or a storage migration.
    if pending.target_role == Role::Bootstrap {
        return Err(AppError::Internal(
            "PendingBootstrap row has Bootstrap role — refusing to mint".into(),
        ));
    }

    let cfg = config.read().await;
    let vta_did = cfg
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    let vta_url = cfg.public_url.clone();
    drop(cfg);

    let (did, private_key_multibase) = generate_did_key();

    let entry = AclEntry {
        did: did.clone(),
        role: pending.target_role.clone(),
        label: pending.label.clone(),
        allowed_contexts: pending.target_contexts.clone(),
        created_at: now,
        created_by: pending.issued_by.clone(),
        expires_at: None,
    };
    // Single-use consumption: delete the token row, then insert the fresh
    // ACL entry. See the design doc for why the sequential form is
    // acceptable here (token pre-image is never persisted, so a replayed
    // token cannot recreate the deleted row).
    consume_pending_bootstrap(acl_ks, &pending.hash_hex(), &entry).await?;

    let credential = CredentialBundle {
        did,
        private_key_multibase,
        vta_did,
        vta_url,
    };

    // Per-request ephemeral producer pubkey. Mode A's integrity anchor is
    // the token plus TLS — the `PinnedOnly` proof is retained for wire-format
    // uniformity; clients that want stronger assurance pin the declared
    // pubkey out-of-band when the token is issued. DidSigned assertions
    // ship in a follow-up increment.
    let (_producer_sk, producer_pk) = generate_keypair();
    let assertion = ProducerAssertion {
        producer_pubkey_b64: B64URL.encode(producer_pk),
        proof: AssertionProof::PinnedOnly,
    };

    // Persistent bundle_id anti-replay log. Token consumption above already
    // prevents cross-restart replay at the policy layer; this is
    // belt-and-suspenders so a malformed caller that reuses a nonce against
    // a freshly-minted token is still rejected.
    let nonce_store = PersistentNonceStore::new(sealed_nonces_ks.clone());
    let payload = SealedPayloadV1::AdminCredential(credential);
    let bundle = seal_payload(client_pubkey, bundle_id, assertion, &payload, &nonce_store)
        .await
        .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
    Ok(bundle)
}

/// Mode B: TEE first-boot sealed bootstrap. No token; the attestation quote
/// is the sole authorization anchor. Gated on `feature = "tee"`.
///
/// On success, closes the first-boot carve-out permanently by writing the
/// `BOOTSTRAP_CARVEOUT_CLOSED_KEY` sentinel. Any subsequent no-token request
/// is rejected.
#[cfg(feature = "tee")]
async fn mint_mode_b(
    state: &AppState,
    client_pubkey: &[u8; 32],
    bundle_id: [u8; 16],
    now: u64,
) -> Result<vta_sdk::sealed_transfer::SealedBundle, AppError> {
    use crate::tee::admin_bootstrap::{BOOTSTRAP_CARVEOUT_CLOSED_KEY, LEGACY_ADMIN_CREDENTIAL_KEY};

    let tee_state =
        state.tee.as_ref().map(|tc| &tc.state).ok_or_else(|| {
            AppError::Forbidden("TEE first-boot is not available on this VTA".into())
        })?;

    // Carve-out active ⇔ neither the closed-sentinel nor the legacy
    // admin-credential row is present. (The latter is a transitional case —
    // startup migration rewrites it into the closed-sentinel before this
    // handler ever runs, but we check here too to keep the handler correct
    // even without startup migration.)
    if state
        .keys_ks
        .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
        .await?
        .is_some()
        || state
            .keys_ks
            .get_raw(LEGACY_ADMIN_CREDENTIAL_KEY)
            .await?
            .is_some()
    {
        return Err(AppError::Forbidden(
            "TEE first-boot carve-out has already been used".into(),
        ));
    }

    let cfg = state.config.read().await;
    let vta_did = cfg
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    let vta_url = cfg.public_url.clone();
    drop(cfg);

    // Per-request ephemeral producer pubkey. The attestation quote binds
    // it into `user_data` alongside the client-provided pubkey and nonce,
    // so the consumer can recompute and verify on open.
    let (_producer_sk, producer_pk) = generate_keypair();

    let mut hasher = Sha256::new();
    hasher.update(client_pubkey);
    hasher.update(&bundle_id);
    hasher.update(&producer_pk);
    let user_data = hasher.finalize();

    // Attestation nonce: reuse the client nonce for freshness.
    let report = tee_state
        .provider
        .attest(user_data.as_slice(), &bundle_id)
        .map_err(|e| AppError::Internal(format!("tee attest failed: {e}")))?;

    // Mint admin credential and insert ACL entry. Carve-out closes atomically
    // with the sentinel write below.
    let (did, private_key_multibase) = crate::auth::credentials::generate_did_key();
    let entry = AclEntry {
        did: did.clone(),
        role: Role::Admin,
        label: Some("TEE first-boot admin".to_string()),
        allowed_contexts: vec![],
        created_at: now,
        created_by: "tee:mode-b".to_string(),
        expires_at: None,
    };
    store_acl_entry(&state.acl_ks, &entry).await?;

    state
        .keys_ks
        .insert_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY, did.as_bytes().to_vec())
        .await?;

    let credential = CredentialBundle {
        did,
        private_key_multibase,
        vta_did,
        vta_url,
    };

    let assertion = ProducerAssertion {
        producer_pubkey_b64: B64URL.encode(producer_pk),
        proof: AssertionProof::Attested(AttestationQuoteAssertion {
            format: format!("{}", report.tee_type),
            quote_b64: report.evidence,
        }),
    };

    let nonce_store = PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let payload = SealedPayloadV1::AdminCredential(credential);
    let bundle = seal_payload(client_pubkey, bundle_id, assertion, &payload, &nonce_store)
        .await
        .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
    info!("TEE first-boot carve-out consumed — closed for good");
    Ok(bundle)
}

fn decode_pubkey(s: &str) -> Result<[u8; 32], AppError> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| AppError::Validation(format!("invalid client_pubkey base64: {e}")))?;
    raw.try_into()
        .map_err(|_| AppError::Validation("client_pubkey must be 32 bytes".into()))
}

fn decode_nonce(s: &str) -> Result<[u8; 16], AppError> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| AppError::Validation(format!("invalid nonce base64: {e}")))?;
    raw.try_into()
        .map_err(|_| AppError::Validation("nonce must be 16 bytes".into()))
}

impl IntoResponse for BootstrapResponseBody {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}
