use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use didwebvh_rs::create::{CreateDIDConfig, create_did};
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use serde_json::json;
use tracing::info;
use url::Url;

use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::didcomm_bridge::DIDCommBridge;

use vta_sdk::protocols::did_management::{
    create::CreateDidWebvhResultBody,
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
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyType as SdkKeyType, PreRotationKeyData};
use crate::store::KeyspaceHandle;
use crate::webvh_client::{RequestUriResponse, WebvhClient};
use crate::webvh_didcomm::WebvhDIDCommClient;
use crate::webvh_store;

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
}

#[allow(clippy::too_many_arguments)]
pub async fn create_did_webvh(
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
    auth: &AuthClaims,
    params: CreateDidWebvhParams,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<OnceLock<DIDCommBridge>>,
    channel: &str,
) -> Result<CreateDidWebvhResultBody, AppError> {
    auth.require_admin()?;
    auth.require_context(&params.context_id)?;

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

    // Load seed
    let active_seed_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(keys_ks, seed_store, Some(active_seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let label = params.label.as_deref().unwrap_or(&params.context_id);

    // Derive entity keys
    let mut derived = keys::derive_entity_keys(
        &seed,
        &ctx.base_path,
        &format!("{label} signing key"),
        &format!("{label} key-agreement key"),
        keys_ks,
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Resolve URL: serverless uses user-provided URL, server-managed requests from server
    let (url_str, mnemonic) = if serverless {
        let url_str = params.url.as_ref().unwrap().clone();
        // Validate the URL
        let parsed_url = Url::parse(&url_str)
            .map_err(|e| AppError::Validation(format!("invalid url: {e}")))?;
        WebVHURL::parse_url(&parsed_url)
            .map_err(|e| AppError::Validation(format!("failed to parse WebVH URL: {e}")))?;
        (url_str, None)
    } else {
        let server_id = params.server_id.as_ref().unwrap();
        let server = webvh_store::get_server(webvh_ks, server_id)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("webvh server not found: {server_id}"))
            })?;

        let transport =
            WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, config).await?;
        let uri_response = transport.request_uri(params.path.as_deref()).await?;

        // Validate the URL
        let parsed_url = Url::parse(&uri_response.did_url)
            .map_err(|e| AppError::Internal(format!("invalid did_url from server: {e}")))?;
        WebVHURL::parse_url(&parsed_url)
            .map_err(|e| AppError::Internal(format!("failed to parse WebVH URL: {e}")))?;
        (uri_response.did_url, Some(uri_response.mnemonic))
    };

    // Convert signing key ID to did:key format (required by didwebvh-rs)
    derived.signing_secret.id = [
        "did:key:",
        &derived
            .signing_secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?,
        "#",
        &derived
            .signing_secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?,
    ]
    .concat();

    // Build DID document
    let did_document = build_did_document(
        &derived,
        config,
        params.add_mediator_service,
        &params.additional_services,
    );

    // Derive pre-rotation keys
    let (next_key_hashes, pre_rotation_keys) = derive_pre_rotation_keys(
        &seed,
        &ctx.base_path,
        label,
        keys_ks,
        params.pre_rotation_count,
    )
    .await?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone().into()])),
        portable: Some(params.portable),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(next_key_hashes.into_iter().map(Into::into).collect()))
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

    let result = create_did(create_config).await
        .map_err(|e| AppError::Internal(format!("failed to create DID: {e}")))?;

    let final_did = result.did().to_string();
    let scid = result.log_entry().get_scid()
        .unwrap_or_default().to_string();
    let log_content = serde_json::to_string(result.log_entry())
        .map_err(|e| AppError::Internal(format!("failed to serialize DID log: {e}")))?;

    // Save key records (common to both paths)
    keys::save_entity_key_records(
        &final_did,
        &derived,
        keys_ks,
        Some(&params.context_id),
        Some(active_seed_id),
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Save pre-rotation key records
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            SdkKeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some(&params.context_id),
            Some(active_seed_id),
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    let now = Utc::now();

    if serverless {
        // Serverless: extract final DID document from log entry, return it + log entry.
        // Skip publish but DO store the DID record and log locally.
        let final_did_document = result
            .log_entry()
            .get_did_document()
            .ok()
            .unwrap_or(did_document);

        // Update context with the new DID
        ctx.did = Some(final_did.clone());
        ctx.updated_at = Utc::now();
        crate::contexts::store_context(contexts_ks, &ctx)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;

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
            .ok_or_else(|| {
                AppError::NotFound(format!("webvh server not found: {server_id}"))
            })?;

        let transport =
            WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, config).await?;
        transport.publish_did(mnemonic, &log_content).await?;

        // Update context with the new DID
        ctx.did = Some(final_did.clone());
        ctx.updated_at = Utc::now();
        crate::contexts::store_context(contexts_ks, &ctx)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;

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
    _keys_ks: &KeyspaceHandle,
    _seed_store: &dyn SeedStore,
    config: &AppConfig,
    auth: &AuthClaims,
    did: &str,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<OnceLock<DIDCommBridge>>,
    channel: &str,
) -> Result<DeleteDidWebvhResultBody, AppError> {
    auth.require_admin()?;

    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;

    // Resolve server for remote deletion
    let server = webvh_store::get_server(webvh_ks, &record.server_id).await?;

    if let Some(server) = server {
        match WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, config).await {
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

    // Remove local records
    webvh_store::delete_did(webvh_ks, did).await?;

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
        vta_did: &'a str,
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
        didcomm_bridge: &'a Arc<OnceLock<DIDCommBridge>>,
        config: &'a AppConfig,
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
            let bridge = didcomm_bridge.get().ok_or_else(|| {
                AppError::Internal(
                    "DIDComm not available — mediator connection not established".into(),
                )
            })?;
            let vta_did = config.vta_did.as_deref().ok_or_else(|| {
                AppError::Internal(
                    "VTA DID not configured — cannot communicate with WebVH server via DIDComm"
                        .into(),
                )
            })?;
            return Ok(Self::DIDComm {
                bridge,
                vta_did,
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

    fn didcomm_client(&self) -> Option<WebvhDIDCommClient<'_>> {
        match self {
            Self::DIDComm {
                bridge,
                vta_did,
                server_did,
            } => Some(WebvhDIDCommClient::new(bridge, vta_did, server_did)),
            _ => None,
        }
    }

    async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        match self {
            Self::Rest(c) => c.request_uri(path).await,
            Self::DIDComm { .. } => self.didcomm_client().unwrap().request_uri(path).await,
        }
    }

    async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.publish_did(mnemonic, log_content).await,
            Self::DIDComm { .. } => {
                self.didcomm_client()
                    .unwrap()
                    .publish_did(mnemonic, log_content)
                    .await
            }
        }
    }

    async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.delete_did(mnemonic).await,
            Self::DIDComm { .. } => self.didcomm_client().unwrap().delete_did(mnemonic).await,
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

pub fn build_did_document(
    derived: &keys::DerivedEntityKeys,
    config: &AppConfig,
    add_mediator_service: bool,
    additional_services: &Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "verificationMethod": [
            {
                "id": "{DID}#key-0",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": &derived.signing_pub
            },
            {
                "id": "{DID}#key-1",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": &derived.ka_pub
            }
        ],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
        "keyAgreement": ["{DID}#key-1"]
    });

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
