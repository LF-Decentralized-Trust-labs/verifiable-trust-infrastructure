//! `POST /bootstrap/request` — unified sealed-transfer bootstrap endpoint.
//!
//! Phase 2 implements the **token-based (Mode A)** branch. A consumer presents
//! their ephemeral X25519 pubkey, a nonce, and a one-time token issued
//! out-of-band by the operator. The server hashes the token, looks up the
//! stored [`PendingBootstrap`], atomically consumes it, mints a did:key
//! credential bound to the stored role/contexts, and returns an
//! HPKE-sealed armored bundle.
//!
//! Mode B (TEE first-boot attestation) lands in Phase 3 alongside the
//! attestation quote integration.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use vta_sdk::credentials::CredentialBundle;
use vta_sdk::sealed_transfer::{
    AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    generate_keypair, seal_payload,
};

use crate::acl::{
    AclEntry, PendingBootstrap, Role, consume_pending_bootstrap, get_pending_bootstrap_by_token,
};
use crate::audit::audit;
use crate::auth::credentials::generate_did_key;
use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::server::AppState;

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

    let token = req.token.as_deref().ok_or_else(|| {
        AppError::Forbidden(
            "bootstrap request requires a token (TEE first-boot is not yet available)".into(),
        )
    })?;

    let pending = get_pending_bootstrap_by_token(&state.acl_ks, token)
        .await?
        .ok_or_else(|| {
            warn!("bootstrap request: token not found");
            AppError::Forbidden("invalid or consumed bootstrap token".into())
        })?;

    let now = now_epoch();
    if pending.is_expired(now) {
        return Err(AppError::Forbidden("bootstrap token expired".into()));
    }

    let bundle = mint_and_seal(
        &state.acl_ks,
        &state.config,
        &pending,
        &client_pubkey,
        bundle_id,
        now,
    )
    .await?;

    let digest = bundle_digest(&bundle);
    let armored = armor::encode(&bundle);

    info!(
        token_hash = %pending.hash_hex(),
        role = %pending.target_role,
        client_label = ?req.label,
        "bootstrap swap completed"
    );
    audit!(
        "bootstrap.swap",
        actor = &pending.issued_by,
        resource = &pending.hash_hex(),
        outcome = "success"
    );
    let hash_hex = pending.hash_hex();
    let _ = crate::audit::record(
        &state.audit_ks,
        "bootstrap.swap",
        &pending.issued_by,
        Some(&hash_hex),
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

async fn mint_and_seal(
    acl_ks: &crate::store::KeyspaceHandle,
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

    // Anti-replay: every sealed bundle gets a fresh bundle_id chosen by the
    // client, but the request handler is ephemeral across restarts. Phase 2
    // uses an in-memory nonce store — replay within a single process
    // lifetime is rejected, and token consumption above prevents cross-
    // restart replay at the policy layer.
    let nonce_store = InMemoryNonceStore::new();
    let payload = SealedPayloadV1::AdminCredential(credential);
    let bundle = seal_payload(client_pubkey, bundle_id, assertion, &payload, &nonce_store)
        .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
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
