use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use didwebvh_rs::create::{CreateDIDConfig, create_did};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use serde_json::json;
use tracing::info;
use url::Url;

use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::didcomm_bridge::DIDCommBridge;

use vta_sdk::protocols::did_management::{
    create::{CreateDidWebvhBody, CreateDidWebvhResultBody},
    delete::DeleteDidWebvhResultBody,
    list::ListDidsWebvhResultBody,
    servers::{
        AddWebvhServerResultBody, ListWebvhServersResultBody, RemoveWebvhServerResultBody,
        UpdateWebvhServerResultBody,
    },
};
use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::keys::imported;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyType as SdkKeyType, PreRotationKeyData, encode_private_multibase};
use crate::store::KeyspaceHandle;
use crate::webvh_client::{RequestUriResponse, WebvhClient};
use crate::webvh_didcomm::WebvhDIDCommClient;
use crate::webvh_store;
use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
use zeroize::Zeroize;

use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

pub struct CreateDidWebvhParams {
    pub context_id: String,
    pub server_id: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub label: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    pub additional_services: Option<Vec<serde_json::Value>>,
    pub pre_rotation_count: u32,
    /// Client-provided DID Document template. Mutually exclusive with `did_log`.
    pub did_document: Option<serde_json::Value>,
    /// Complete, pre-signed did.jsonl log entry. Mutually exclusive with `did_document`.
    pub did_log: Option<String>,
    /// Whether to set this DID as the primary DID for the context.
    pub set_primary: bool,
    /// Use an existing key as the signing verification method.
    pub signing_key_id: Option<String>,
    /// Use an existing key as the key-agreement verification method.
    pub ka_key_id: Option<String>,
}

impl From<CreateDidWebvhBody> for CreateDidWebvhParams {
    fn from(body: CreateDidWebvhBody) -> Self {
        Self {
            context_id: body.context_id,
            server_id: body.server_id,
            url: body.url,
            path: body.path,
            label: body.label,
            portable: body.portable.unwrap_or(true),
            add_mediator_service: body.add_mediator_service.unwrap_or(false),
            additional_services: body.additional_services,
            pre_rotation_count: body.pre_rotation_count.unwrap_or(0),
            did_document: body.did_document,
            did_log: body.did_log,
            set_primary: body.set_primary.unwrap_or(true),
            signing_key_id: body.signing_key_id,
            ka_key_id: body.ka_key_id,
        }
    }
}

/// Load an existing key record and return it as a `Secret` for use in DID creation.
///
/// Validates key type, status, and context access. Returns the Secret,
/// public key multibase, and the original KeyRecord.
async fn load_key_as_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    key_id: &str,
    expected_type: KeyType,
    auth: &AuthClaims,
) -> Result<(Secret, String, KeyRecord), AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    // Validate key type
    if record.key_type != expected_type {
        return Err(AppError::Validation(format!(
            "key {key_id} is {} but expected {}",
            record.key_type, expected_type
        )));
    }

    // Validate status
    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(format!(
            "key {key_id} is not active (status: {:?})",
            record.status
        )));
    }

    // Validate context access
    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can use keys without a context".into(),
        ));
    }

    // Load private key material
    let private_key_multibase = match record.origin {
        KeyOrigin::Imported => {
            let seed = load_seed_bytes(keys_ks, seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;
            let priv_mb = encode_private_multibase(&record.key_type, &secret_bytes);
            secret_bytes.zeroize();
            priv_mb
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ExtendedSigningKey::from_seed(&seed).map_err(|e| {
                AppError::Internal(format!("failed to create BIP-32 root key: {e}"))
            })?;
            let derivation_path: DerivationPath = record
                .derivation_path
                .parse()
                .map_err(|e| AppError::Internal(format!("invalid derivation path: {e}")))?;
            let derived_key = bip32
                .derive(&derivation_path)
                .map_err(|e| AppError::Internal(format!("key derivation failed: {e}")))?;
            encode_private_multibase(&KeyType::Ed25519, derived_key.signing_key.as_bytes())
        }
    };

    let secret = Secret::from_multibase(&private_key_multibase, None).map_err(|e| {
        AppError::Internal(format!("failed to construct Secret from key {key_id}: {e}"))
    })?;

    Ok((secret, record.public_key.clone(), record))
}

/// Check whether a DID document (JSON) contains any DIDCommMessaging service.
fn document_has_didcomm_service(doc: &serde_json::Value) -> bool {
    doc.get("service")
        .and_then(|s| s.as_array())
        .is_some_and(|services| {
            services.iter().any(|svc| {
                svc.get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == "DIDCommMessaging")
                    || svc
                        .get("type")
                        .and_then(|t| t.as_array())
                        .is_some_and(|types| {
                            types
                                .iter()
                                .any(|t| t.as_str().is_some_and(|s| s == "DIDCommMessaging"))
                        })
            })
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn create_did_webvh(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
    auth: &AuthClaims,
    params: CreateDidWebvhParams,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    channel: &str,
) -> Result<CreateDidWebvhResultBody, AppError> {
    auth.require_admin()?;
    auth.require_context(&params.context_id)?;

    // Validate did_document and did_log are mutually exclusive
    if params.did_document.is_some() && params.did_log.is_some() {
        return Err(AppError::Validation(
            "did_document and did_log are mutually exclusive".into(),
        ));
    }

    // Validate ka_key_id requires signing_key_id
    if params.ka_key_id.is_some() && params.signing_key_id.is_none() {
        return Err(AppError::Validation(
            "ka_key_id requires signing_key_id".into(),
        ));
    }

    // Validate exactly one of server_id / url is provided
    let serverless = match (&params.server_id, &params.url) {
        (Some(_), Some(_)) => {
            return Err(AppError::Validation(
                "server_id and url are mutually exclusive".into(),
            ));
        }
        (None, None) => {
            return Err(AppError::Validation(
                "either server_id or url is required".into(),
            ));
        }
        (None, Some(_)) => true,
        (Some(_), None) => false,
    };

    // Resolve context
    let mut ctx = crate::contexts::get_context(contexts_ks, &params.context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", params.context_id)))?;

    let now = Utc::now();

    // ── Final mode: client-provided pre-signed log entry ────────────
    if let Some(ref did_log) = params.did_log {
        let log_entry = LogEntry::deserialize_string(did_log, None)
            .map_err(|e| AppError::Validation(format!("invalid did_log: {e}")))?;

        let final_did_document = log_entry.get_did_document().map_err(|e| {
            AppError::Validation(format!("failed to extract DID document from log: {e}"))
        })?;
        let final_did = final_did_document["id"]
            .as_str()
            .ok_or_else(|| AppError::Validation("DID document missing 'id' field".into()))?
            .to_string();
        let scid = log_entry.get_scid().unwrap_or_default().to_string();

        // Publish to server if not serverless
        if !serverless {
            let server_id = params.server_id.as_ref().unwrap();
            let server = webvh_store::get_server(webvh_ks, server_id)
                .await?
                .ok_or_else(|| {
                    AppError::NotFound(format!("webvh server not found: {server_id}"))
                })?;
            let transport =
                WebvhTransport::from_server(&server, did_resolver, didcomm_bridge).await?;
            // Final mode has no mnemonic from a server request — use the SCID as identifier
            transport.publish_did(&scid, did_log).await?;
        }

        // Optionally set as primary DID
        if params.set_primary {
            ctx.did = Some(final_did.clone());
            ctx.updated_at = now;
            crate::contexts::store_context(contexts_ks, &ctx)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
        }

        // Store DID record and log
        let server_id_str = params
            .server_id
            .as_deref()
            .unwrap_or("serverless")
            .to_string();
        let did_record = WebvhDidRecord {
            did: final_did.clone(),
            server_id: server_id_str.clone(),
            mnemonic: String::new(),
            scid: scid.clone(),
            context_id: params.context_id.clone(),
            portable: params.portable,
            log_entry_count: 1,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(webvh_ks, &did_record).await?;
        webvh_store::store_did_log(webvh_ks, &final_did, did_log).await?;

        info!(
            channel,
            did = %final_did,
            context = %params.context_id,
            "did:webvh created (final mode)"
        );

        return Ok(CreateDidWebvhResultBody {
            did: final_did.clone(),
            context_id: params.context_id,
            server_id: if serverless { None } else { params.server_id },
            mnemonic: None,
            scid,
            portable: params.portable,
            signing_key_id: String::new(),
            ka_key_id: String::new(),
            pre_rotation_key_count: 0,
            created_at: now,
            did_document: Some(final_did_document),
            log_entry: Some(did_log.clone()),
        });
    }

    // ── VTA-built or template mode ──────────────────────────────────

    let label = params.label.as_deref().unwrap_or(&params.context_id);

    // Track whether keys were user-specified (affects key record saving)
    let user_specified_keys = params.signing_key_id.is_some();

    // Load or derive entity keys
    let (derived, active_seed_id) = if let Some(ref signing_key_id) = params.signing_key_id {
        // ── User-specified keys ─────────────────────────────────────
        let (mut signing_secret, signing_pub, signing_record) = load_key_as_secret(
            keys_ks,
            imported_ks,
            seed_store,
            signing_key_id,
            KeyType::Ed25519,
            auth,
        )
        .await?;

        // Convert signing key ID to did:key format (required by didwebvh-rs)
        let pub_mb = signing_secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        signing_secret.id = format!("did:key:{pub_mb}#{pub_mb}");

        let (ka_secret, ka_pub, ka_path, ka_label) = if let Some(ref ka_key_id) = params.ka_key_id {
            let (ka_secret, ka_pub, ka_record) = load_key_as_secret(
                keys_ks,
                imported_ks,
                seed_store,
                ka_key_id,
                KeyType::X25519,
                auth,
            )
            .await?;
            (
                ka_secret,
                ka_pub,
                ka_record.derivation_path,
                ka_record
                    .label
                    .unwrap_or_else(|| format!("{label} key-agreement key")),
            )
        } else {
            // No KA key — use dummy values (won't be in the document)
            (
                Secret::generate_ed25519(None, None),
                String::new(),
                String::new(),
                String::new(),
            )
        };

        let derived = keys::DerivedEntityKeys {
            signing_secret,
            signing_path: signing_record.derivation_path.clone(),
            signing_pub,
            signing_priv: String::new(), // Not needed for DID creation
            signing_label: signing_record
                .label
                .unwrap_or_else(|| format!("{label} signing key")),
            ka_secret,
            ka_path,
            ka_pub,
            ka_priv: String::new(),
            ka_label,
        };

        // seed_id from the signing key record (may be None for imported)
        (derived, signing_record.seed_id)
    } else {
        // ── VTA-derived keys ────────────────────────────────────────
        let active_seed_id = get_active_seed_id(keys_ks)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let seed = load_seed_bytes(keys_ks, seed_store, Some(active_seed_id))
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;

        let mut derived = keys::derive_entity_keys(
            &seed,
            &ctx.base_path,
            &format!("{label} signing key"),
            &format!("{label} key-agreement key"),
            keys_ks,
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

        // Convert signing key ID to did:key format (required by didwebvh-rs)
        let pub_mb = derived
            .signing_secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        derived.signing_secret.id = format!("did:key:{pub_mb}#{pub_mb}");

        (derived, Some(active_seed_id))
    };

    // Resolve URL: serverless uses user-provided URL, server-managed requests from server
    let (url_str, mnemonic) = if serverless {
        let url_str = params.url.as_ref().unwrap().clone();
        // Validate the URL
        let parsed_url =
            Url::parse(&url_str).map_err(|e| AppError::Validation(format!("invalid url: {e}")))?;
        WebVHURL::parse_url(&parsed_url)
            .map_err(|e| AppError::Validation(format!("failed to parse WebVH URL: {e}")))?;
        (url_str, None)
    } else {
        let server_id = params.server_id.as_ref().unwrap();
        let server = webvh_store::get_server(webvh_ks, server_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

        let transport = WebvhTransport::from_server(&server, did_resolver, didcomm_bridge).await?;
        let uri_response = transport.request_uri(params.path.as_deref()).await?;

        // Validate the URL
        let parsed_url = Url::parse(&uri_response.did_url)
            .map_err(|e| AppError::Internal(format!("invalid did_url from server: {e}")))?;
        WebVHURL::parse_url(&parsed_url)
            .map_err(|e| AppError::Internal(format!("failed to parse WebVH URL: {e}")))?;
        (uri_response.did_url, Some(uri_response.mnemonic))
    };

    // Build DID document: use client-provided template or build internally
    let has_ka = params.ka_key_id.is_some() || !user_specified_keys;
    let did_document = match params.did_document {
        Some(doc) => doc,
        None if user_specified_keys => {
            // Build document from user-specified keys (signing only, or signing + KA)
            build_did_document_with_options(
                &derived,
                config,
                has_ka,
                params.add_mediator_service,
                &params.additional_services,
            )
        }
        None => build_did_document(
            &derived,
            config,
            params.add_mediator_service,
            &params.additional_services,
        ),
    };

    // Validate DIDComm services require a KA key
    if !has_ka && (params.add_mediator_service || document_has_didcomm_service(&did_document)) {
        return Err(AppError::Validation(
            "DIDCommMessaging services require a key-agreement key (ka_key_id)".into(),
        ));
    }

    // Derive pre-rotation keys (requires seed)
    let seed_for_pre_rotation = if params.pre_rotation_count > 0 {
        let sid = match active_seed_id {
            Some(id) => id,
            None => get_active_seed_id(keys_ks)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?,
        };
        Some(
            load_seed_bytes(keys_ks, seed_store, Some(sid))
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?,
        )
    } else {
        None
    };
    let (next_key_hashes, pre_rotation_keys) = if let Some(ref seed) = seed_for_pre_rotation {
        derive_pre_rotation_keys(
            seed,
            &ctx.base_path,
            label,
            keys_ks,
            params.pre_rotation_count,
        )
        .await?
    } else {
        (vec![], vec![])
    };

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone().into()])),
        portable: Some(params.portable),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(
                next_key_hashes.into_iter().map(Into::into).collect(),
            ))
        },
        ..Default::default()
    };

    // Create the DID
    let create_config = CreateDIDConfig::builder()
        .address(&url_str)
        .authorization_key(derived.signing_secret.clone())
        .did_document(did_document.clone())
        .parameters(parameters)
        .build()
        .map_err(|e| AppError::Internal(format!("failed to build DID config: {e}")))?;

    let result = create_did(create_config)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create DID: {e}")))?;

    let final_did = result.did().to_string();
    let scid = result
        .log_entry()
        .get_scid()
        .unwrap_or_default()
        .to_string();
    let log_content = serde_json::to_string(result.log_entry())
        .map_err(|e| AppError::Internal(format!("failed to serialize DID log: {e}")))?;

    // Save key records
    if !user_specified_keys {
        // VTA-derived: save both signing and KA key records
        keys::save_entity_key_records(
            &final_did,
            &derived,
            keys_ks,
            Some(&params.context_id),
            active_seed_id,
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    } else {
        // User-specified: save key records referencing the user's keys
        keys::save_key_record(
            keys_ks,
            &format!("{final_did}#key-0"),
            &derived.signing_path,
            SdkKeyType::Ed25519,
            &derived.signing_pub,
            &derived.signing_label,
            Some(&params.context_id),
            active_seed_id,
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

        if has_ka {
            keys::save_key_record(
                keys_ks,
                &format!("{final_did}#key-1"),
                &derived.ka_path,
                SdkKeyType::X25519,
                &derived.ka_pub,
                &derived.ka_label,
                Some(&params.context_id),
                active_seed_id,
            )
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        }
    }

    // Save pre-rotation key records
    let pre_rotation_seed_id = active_seed_id.unwrap_or(0);
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            SdkKeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some(&params.context_id),
            Some(pre_rotation_seed_id),
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    // Optionally set as primary DID
    if params.set_primary {
        ctx.did = Some(final_did.clone());
        ctx.updated_at = now;
        crate::contexts::store_context(contexts_ks, &ctx)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    if serverless {
        // Serverless: extract final DID document from log entry, return it + log entry.
        // Skip publish but DO store the DID record and log locally.
        let final_did_document = result
            .log_entry()
            .get_did_document()
            .ok()
            .unwrap_or(did_document);

        // Store DID record and log
        let did_record = WebvhDidRecord {
            did: final_did.clone(),
            server_id: "serverless".to_string(),
            mnemonic: String::new(),
            scid: scid.clone(),
            context_id: params.context_id.clone(),
            portable: params.portable,
            log_entry_count: 1,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(webvh_ks, &did_record).await?;
        webvh_store::store_did_log(webvh_ks, &final_did, &log_content).await?;

        info!(
            channel,
            did = %final_did,
            context = %params.context_id,
            "did:webvh created (serverless)"
        );

        Ok(CreateDidWebvhResultBody {
            did: final_did.clone(),
            context_id: params.context_id,
            server_id: None,
            mnemonic: None,
            scid,
            portable: params.portable,
            signing_key_id: format!("{final_did}#key-0"),
            ka_key_id: format!("{final_did}#key-1"),
            pre_rotation_key_count: pre_rotation_keys.len() as u32,
            created_at: now,
            did_document: Some(final_did_document),
            log_entry: Some(log_content),
        })
    } else {
        // Server-managed: publish, update context, store records
        let server_id = params.server_id.as_ref().unwrap();
        let mnemonic = mnemonic.as_ref().unwrap();

        let server = webvh_store::get_server(webvh_ks, server_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

        let transport = WebvhTransport::from_server(&server, did_resolver, didcomm_bridge).await?;
        transport.publish_did(mnemonic, &log_content).await?;

        // Store DID record and log
        let did_record = WebvhDidRecord {
            did: final_did.clone(),
            server_id: server_id.clone(),
            mnemonic: mnemonic.clone(),
            scid: scid.clone(),
            context_id: params.context_id.clone(),
            portable: params.portable,
            log_entry_count: 1,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(webvh_ks, &did_record).await?;
        webvh_store::store_did_log(webvh_ks, &final_did, &log_content).await?;

        info!(
            channel,
            did = %final_did,
            context = %params.context_id,
            server = %server_id,
            "did:webvh created and published"
        );

        Ok(CreateDidWebvhResultBody {
            did: final_did.clone(),
            context_id: params.context_id,
            server_id: Some(server_id.clone()),
            mnemonic: Some(mnemonic.clone()),
            scid,
            portable: params.portable,
            signing_key_id: format!("{final_did}#key-0"),
            ka_key_id: format!("{final_did}#key-1"),
            pre_rotation_key_count: pre_rotation_keys.len() as u32,
            created_at: now,
            did_document: None,
            log_entry: None,
        })
    }
}

pub async fn get_did_webvh(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<WebvhDidRecord, AppError> {
    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;
    auth.require_context(&record.context_id)?;
    info!(channel, did = %did, "webvh DID retrieved");
    Ok(record)
}

pub async fn get_did_webvh_log(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<GetDidWebvhLogResult, AppError> {
    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;
    auth.require_context(&record.context_id)?;
    let log = webvh_store::get_did_log(webvh_ks, did).await?;
    info!(channel, did = %did, "webvh DID log retrieved");
    Ok(GetDidWebvhLogResult {
        did: did.to_string(),
        log,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct GetDidWebvhLogResult {
    pub did: String,
    pub log: Option<String>,
}

pub async fn list_dids_webvh(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: Option<&str>,
    server_id: Option<&str>,
    channel: &str,
) -> Result<ListDidsWebvhResultBody, AppError> {
    let all = webvh_store::list_dids(webvh_ks).await?;
    let dids: Vec<WebvhDidRecord> = all
        .into_iter()
        .filter(|d| auth.has_context_access(&d.context_id))
        .filter(|d| context_id.is_none_or(|c| d.context_id == c))
        .filter(|d| server_id.is_none_or(|s| d.server_id == s))
        .collect();
    info!(channel, caller = %auth.did, count = dids.len(), "webvh DIDs listed");
    Ok(ListDidsWebvhResultBody { dids })
}

#[allow(clippy::too_many_arguments)]
pub async fn delete_did_webvh(
    webvh_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    _seed_store: &dyn SeedStore,
    _config: &AppConfig,
    auth: &AuthClaims,
    did: &str,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    channel: &str,
) -> Result<DeleteDidWebvhResultBody, AppError> {
    auth.require_admin()?;

    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;

    // Resolve server for remote deletion
    let server = webvh_store::get_server(webvh_ks, &record.server_id).await?;

    if let Some(server) = server {
        match WebvhTransport::from_server(&server, did_resolver, didcomm_bridge).await {
            Ok(transport) => {
                if let Err(e) = transport.delete_did(&record.mnemonic).await {
                    tracing::warn!(did = %did, error = %e, "failed to delete DID from webvh-server (continuing local cleanup)");
                }
            }
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "failed to resolve server endpoint (continuing local cleanup)");
            }
        }
    }

    // Remove local DID record and log
    webvh_store::delete_did(webvh_ks, did).await?;

    // Clean up associated key records (best-effort)
    for key_id in &[format!("{did}#key-0"), format!("{did}#key-1")] {
        let _ = keys_ks.remove(keys::store_key(key_id)).await;
    }
    // Clean up pre-rotation key records
    for i in 0..100u32 {
        let key_id = format!("{did}#pre-rotation-{i}");
        let store_key = keys::store_key(&key_id);
        if keys_ks.get_raw(store_key.clone()).await?.is_none() {
            break;
        }
        let _ = keys_ks.remove(store_key).await;
    }

    info!(channel, did = %did, "webvh DID deleted");
    Ok(DeleteDidWebvhResultBody {
        did: did.to_string(),
        deleted: true,
    })
}

pub async fn add_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    server_did: &str,
    label: Option<String>,
    did_resolver: &DIDCacheClient,
    channel: &str,
) -> Result<AddWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    if webvh_store::get_server(webvh_ks, id).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "webvh server already exists: {id}"
        )));
    }

    // Validate the DID resolves and has a supported WebVH service
    validate_server_did(did_resolver, server_did).await?;

    let now = Utc::now();
    let record = WebvhServerRecord {
        id: id.to_string(),
        did: server_did.to_string(),
        label,
        access_token: None,
        access_expires_at: None,
        refresh_token: None,
        created_at: now,
        updated_at: now,
    };
    webvh_store::store_server(webvh_ks, &record).await?;

    info!(channel, id = %id, did = %server_did, "webvh server added");
    Ok(record)
}

pub async fn list_webvh_servers(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    channel: &str,
) -> Result<ListWebvhServersResultBody, AppError> {
    // Any authenticated user can list servers
    let servers = webvh_store::list_servers(webvh_ks).await?;
    info!(channel, caller = %auth.did, count = servers.len(), "webvh servers listed");
    Ok(ListWebvhServersResultBody { servers })
}

pub async fn update_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    label: Option<String>,
    channel: &str,
) -> Result<UpdateWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    let mut record = webvh_store::get_server(webvh_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {id}")))?;

    if let Some(lbl) = label {
        record.label = if lbl.is_empty() { None } else { Some(lbl) };
    }
    record.updated_at = Utc::now();

    webvh_store::store_server(webvh_ks, &record).await?;

    info!(channel, id = %id, "webvh server updated");
    Ok(record)
}

pub async fn remove_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<RemoveWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    webvh_store::get_server(webvh_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {id}")))?;

    webvh_store::delete_server(webvh_ks, id).await?;

    info!(channel, id = %id, "webvh server removed");
    Ok(RemoveWebvhServerResultBody {
        id: id.to_string(),
        removed: true,
    })
}

// ---------------------------------------------------------------------------
// WebVH transport abstraction
// ---------------------------------------------------------------------------

/// Unified transport for communicating with a WebVH server via REST or DIDComm.
///
/// Owns all necessary state so callers don't need to branch on transport type.
enum WebvhTransport<'a> {
    Rest(WebvhClient),
    DIDComm {
        bridge: &'a DIDCommBridge,
        server_did: String,
    },
}

impl<'a> WebvhTransport<'a> {
    /// Resolve the server DID and construct the appropriate transport.
    ///
    /// Prefers `DIDCommMessaging` and falls back to `WebVHHostingService`.
    async fn from_server(
        server: &WebvhServerRecord,
        did_resolver: &DIDCacheClient,
        didcomm_bridge: &'a Arc<DIDCommBridge>,
    ) -> Result<Self, AppError> {
        let resolved = did_resolver.resolve(&server.did).await.map_err(|e| {
            AppError::Internal(format!("failed to resolve server DID {}: {e}", server.did))
        })?;

        // Check for DIDCommMessaging first
        let has_didcomm = resolved
            .doc
            .service
            .iter()
            .any(|svc| svc.type_.iter().any(|t| t == "DIDCommMessaging"));
        if has_didcomm {
            info!(server_did = %server.did, transport = "didcomm", "resolved webvh server endpoint");
            return Ok(Self::DIDComm {
                bridge: didcomm_bridge,
                server_did: server.did.clone(),
            });
        }

        // Fall back to WebVHHostingService
        for svc in &resolved.doc.service {
            if svc.type_.iter().any(|t| t == "WebVHHostingService")
                && let Some(url) = svc.service_endpoint.get_uri()
            {
                let url = url.trim_matches('"').trim_end_matches('/').to_string();
                info!(server_did = %server.did, transport = "rest", %url, "resolved webvh server endpoint");
                let mut client = WebvhClient::new(&url);
                if let Some(ref token) = server.access_token {
                    client.set_access_token(token.clone());
                }
                return Ok(Self::Rest(client));
            }
        }

        Err(AppError::Internal(format!(
            "server DID {} has no DIDCommMessaging or WebVHHostingService endpoint",
            server.did,
        )))
    }

    async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        match self {
            Self::Rest(c) => c.request_uri(path).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .request_uri(path)
                    .await
            }
        }
    }

    async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.publish_did(mnemonic, log_content).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .publish_did(mnemonic, log_content)
                    .await
            }
        }
    }

    async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.delete_did(mnemonic).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .delete_did(mnemonic)
                    .await
            }
        }
    }
}

/// Validate that a DID resolves and has at least one supported WebVH service.
///
/// Checks for either `DIDCommMessaging` or `WebVHHostingService`.
async fn validate_server_did(
    did_resolver: &DIDCacheClient,
    server_did: &str,
) -> Result<(), AppError> {
    let resolved = did_resolver.resolve(server_did).await.map_err(|e| {
        AppError::Validation(format!("failed to resolve server DID {server_did}: {e}"))
    })?;

    let has_supported_service = resolved.doc.service.iter().any(|svc| {
        svc.type_
            .iter()
            .any(|t| t == "WebVHHostingService" || t == "DIDCommMessaging")
    });

    if !has_supported_service {
        return Err(AppError::Validation(format!(
            "server DID {server_did} has no WebVHHostingService or DIDCommMessaging service endpoint"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a DID document with the given keys.
///
/// When `include_ka` is true (default for VTA-derived keys), adds a
/// keyAgreement verification method. When false (signing-only DID),
/// the document contains only authentication/assertion.
pub fn build_did_document(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        config,
        true,
        add_mediator_service,
        additional_services,
    )
}

/// Build a DID document with optional keyAgreement support.
pub(crate) fn build_did_document_with_options(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    include_ka: bool,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    build_did_document_inner(
        derived,
        config,
        include_ka,
        add_mediator_service,
        additional_services,
    )
}

fn build_did_document_inner(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    include_ka: bool,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    let mut vm = vec![json!({
        "id": "{DID}#key-0",
        "type": "Multikey",
        "controller": "{DID}",
        "publicKeyMultibase": &derived.signing_pub
    })];

    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"]
    });

    if include_ka {
        vm.push(json!({
            "id": "{DID}#key-1",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": &derived.ka_pub
        }));
        did_document["keyAgreement"] = json!(["{DID}#key-1"]);
    }

    did_document["verificationMethod"] = json!(vm);

    // Optionally add mediator DIDComm service
    if add_mediator_service && let Some(ref msg) = config.messaging {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#vta-didcomm",
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": msg.mediator_did
            }]
        }));
    }

    // Append any additional services
    if let Some(svcs) = additional_services {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        for svc in svcs {
            services.as_array_mut().unwrap().push(svc.clone());
        }
    }

    // Add TeeAttestation service when TEE is active and embed_in_did is enabled
    #[cfg(feature = "tee")]
    if config.tee.embed_in_did
        && let Some(ref public_url) = config.public_url
    {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#tee-attestation",
            "type": "TeeAttestation",
            "serviceEndpoint": format!("{}/attestation/report", public_url.trim_end_matches('/'))
        }));
    }

    did_document
}

pub(crate) async fn derive_pre_rotation_keys(
    seed: &[u8],
    base: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
    count: u32,
) -> Result<(Vec<String>, Vec<PreRotationKeyData>), AppError> {
    if count == 0 {
        return Ok((vec![], vec![]));
    }

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| AppError::Internal(format!("failed to create BIP-32 root key: {e}")))?;

    let mut hashes = Vec::with_capacity(count as usize);
    let mut key_data = Vec::with_capacity(count as usize);

    for i in 0..count {
        let path = allocate_path(keys_ks, base)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| AppError::Internal(format!("invalid derivation path: {e}")))?;
        let derived_key = root
            .derive(&derivation_path)
            .map_err(|e| AppError::Internal(format!("key derivation failed: {e}")))?;

        let secret = Secret::generate_ed25519(None, Some(derived_key.signing_key.as_bytes()));
        let pub_mb = secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let hash = secret
            .get_public_keymultibase_hash()
            .map_err(|e| AppError::Internal(format!("{e}")))?;

        key_data.push(PreRotationKeyData {
            path,
            public_key: pub_mb,
            label: format!("{label} pre-rotation key {i}"),
        });

        hashes.push(hash);
    }

    Ok((hashes, key_data))
}
