use crate::keys::{KeyRecord, KeyStatus, KeyType};
use chrono::{DateTime, Utc};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};

// ── Internal transport ──────────────────────────────────────────────

enum Transport {
    Rest {
        client: Client,
        base_url: String,
        token: Option<String>,
    },
    #[cfg(feature = "session")]
    DIDComm {
        session: crate::didcomm_session::DIDCommSession,
        rest_client: Option<Client>,
        rest_url: Option<String>,
    },
}

/// HTTP/DIDComm client for the VTA service API.
pub struct VtaClient {
    transport: Transport,
}

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    #[serde(default)]
    pub mediator_url: Option<String>,
    #[serde(default)]
    pub mediator_did: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigResponse {
    #[serde(rename = "vta_did")]
    pub community_vta_did: Option<String>,
    #[serde(rename = "vta_name")]
    pub community_vta_name: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

// ── Context types ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CreateContextRequest {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateContextRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContextResponse {
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    pub base_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ContextListResponse {
    pub contexts: Vec<ContextResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct InvalidateKeyResponse {
    pub key_id: String,
    pub status: KeyStatus,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameKeyResponse {
    pub key_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct GetKeySecretResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key_multibase: String,
    pub private_key_multibase: String,
}

#[derive(Debug, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyRecord>,
    pub total: u64,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Seed types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SeedInfoResponse {
    pub id: u32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListSeedsResponse {
    pub seeds: Vec<SeedInfoResponse>,
    pub active_seed_id: u32,
}

#[derive(Debug, Serialize)]
pub struct RotateSeedRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RotateSeedResponse {
    pub previous_seed_id: u32,
    pub new_seed_id: u32,
}

// ── ACL types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
}

#[derive(Debug, Deserialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateAclRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
}

// ── WebVH server types ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AddWebvhServerRequest {
    pub id: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateWebvhServerRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

// ── WebVH DID types ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CreateDidWebvhRequest {
    pub context_id: String,
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_services: Option<Vec<serde_json::Value>>,
    pub pre_rotation_count: u32,
}

// ── Credential types ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GenerateCredentialsRequest {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GenerateCredentialsResponse {
    pub did: String,
    pub credential: String,
    pub role: String,
}

/// Percent-encode characters that are not safe in URL path segments.
///
/// DID verification method IDs contain `#` (fragment delimiter) and potentially
/// `?` (query delimiter) which must be encoded when used in path segments.
/// Derivation paths contain `/` which would be interpreted as path separators.
/// The `:` character is allowed in path segments per RFC 3986.
fn encode_path_segment(s: &str) -> String {
    s.replace('%', "%25")
        .replace('#', "%23")
        .replace('?', "%3F")
        .replace('/', "%2F")
}

// ── REST helpers ────────────────────────────────────────────────────

impl VtaClient {
    /// Attach Bearer token to a request if one is set.
    fn with_auth(req: RequestBuilder, token: &Option<String>) -> RequestBuilder {
        match token {
            Some(token) => req.bearer_auth(token),
            None => req,
        }
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, Box<dyn std::error::Error>> {
        if resp.status().is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }

    async fn handle_delete_response(
        resp: reqwest::Response,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }
}

// ── Client implementation ───────────────────────────────────────────

#[cfg(feature = "session")]
use crate::protocols::{
    acl_management, context_management, credential_management, did_management, key_management,
    seed_management, vta_management,
};

impl VtaClient {
    /// Create a new REST-only client.
    pub fn new(base_url: &str) -> Self {
        Self {
            transport: Transport::Rest {
                client: Client::new(),
                base_url: base_url.trim_end_matches('/').to_string(),
                token: None,
            },
        }
    }

    /// Connect via DIDComm through a mediator.
    ///
    /// `rest_url` is an optional fallback for REST-only operations like `health()`.
    #[cfg(feature = "session")]
    pub async fn connect_didcomm(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
        rest_url: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let session = crate::didcomm_session::DIDCommSession::connect(
            client_did,
            private_key_multibase,
            vta_did,
            mediator_did,
        )
        .await?;

        let rest_client = rest_url.as_ref().map(|_| Client::new());

        Ok(Self {
            transport: Transport::DIDComm {
                session,
                rest_client,
                rest_url: rest_url.map(|u| u.trim_end_matches('/').to_string()),
            },
        })
    }

    /// Set the Bearer token for authenticated requests (REST only, no-op for DIDComm).
    pub fn set_token(&mut self, token: String) {
        if let Transport::Rest { token: t, .. } = &mut self.transport {
            *t = Some(token);
        }
    }

    /// Returns the base URL (REST) or VTA DID (DIDComm).
    pub fn base_url(&self) -> &str {
        match &self.transport {
            Transport::Rest { base_url, .. } => base_url,
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => &session.vta_did,
        }
    }

    /// Gracefully shut down the client (DIDComm only, no-op for REST).
    pub async fn shutdown(&self) {
        #[cfg(feature = "session")]
        if let Transport::DIDComm { session, .. } = &self.transport {
            session.shutdown().await;
        }
    }

    // ── RPC helpers ─────────────────────────────────────────────────

    /// Dispatch an RPC call via REST (using `build_rest`) or DIDComm (using
    /// `msg_type`/`body`/`result_type`), returning a deserialized response.
    #[allow(unused_variables)]
    async fn rpc<T: serde::de::DeserializeOwned>(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        result_type: &str,
        timeout: u64,
        build_rest: impl FnOnce(&Client, &str) -> RequestBuilder,
    ) -> Result<T, Box<dyn std::error::Error>> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                token,
            } => {
                let req = build_rest(client, base_url);
                let resp = Self::with_auth(req, token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                session
                    .send_and_wait(msg_type, body, result_type, timeout)
                    .await
            }
        }
    }

    /// Like [`rpc`](Self::rpc) but for operations that return `()` (e.g. DELETE).
    #[allow(unused_variables)]
    async fn rpc_void(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        result_type: &str,
        timeout: u64,
        build_rest: impl FnOnce(&Client, &str) -> RequestBuilder,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                token,
            } => {
                let req = build_rest(client, base_url);
                let resp = Self::with_auth(req, token).send().await?;
                Self::handle_delete_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { session, .. } => {
                let _: serde_json::Value = session
                    .send_and_wait(msg_type, body, result_type, timeout)
                    .await?;
                Ok(())
            }
        }
    }

    // ── Health ───────────────────────────────────────────────────────

    /// GET /health (always REST)
    pub async fn health(&self) -> Result<HealthResponse, Box<dyn std::error::Error>> {
        match &self.transport {
            Transport::Rest {
                client, base_url, ..
            } => {
                let resp = client.get(format!("{base_url}/health")).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm {
                rest_client,
                rest_url,
                ..
            } => match (rest_client, rest_url) {
                (Some(client), Some(url)) => {
                    let resp = client.get(format!("{url}/health")).send().await?;
                    Self::handle_response(resp).await
                }
                _ => Err("health check not available via DIDComm (no REST URL)".into()),
            },
        }
    }

    // ── Config ──────────────────────────────────────────────────────

    pub async fn get_config(&self) -> Result<ConfigResponse, Box<dyn std::error::Error>> {
        self.rpc(
            vta_management::GET_CONFIG,
            serde_json::json!({}),
            vta_management::GET_CONFIG_RESULT,
            30,
            |c, url| c.get(format!("{url}/config")),
        )
        .await
    }

    pub async fn update_config(
        &self,
        req: UpdateConfigRequest,
    ) -> Result<ConfigResponse, Box<dyn std::error::Error>> {
        self.rpc(
            vta_management::UPDATE_CONFIG,
            serde_json::to_value(&req)?,
            vta_management::UPDATE_CONFIG_RESULT,
            30,
            |c, url| c.patch(format!("{url}/config")).json(&req),
        )
        .await
    }

    // ── Key methods ─────────────────────────────────────────────────

    pub async fn create_key(
        &self,
        req: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, Box<dyn std::error::Error>> {
        self.rpc(
            key_management::CREATE_KEY,
            serde_json::json!({
                "key_type": serde_json::to_value(&req.key_type)?,
                "derivation_path": req.derivation_path.as_deref().unwrap_or_default(),
                "mnemonic": req.mnemonic.as_deref(),
                "label": req.label.as_deref(),
            }),
            key_management::CREATE_KEY_RESULT,
            30,
            |c, url| c.post(format!("{url}/keys")).json(&req),
        )
        .await
    }

    pub async fn list_keys(
        &self,
        offset: u64,
        limit: u64,
        status: Option<&str>,
        context_id: Option<&str>,
    ) -> Result<ListKeysResponse, Box<dyn std::error::Error>> {
        self.rpc(
            key_management::LIST_KEYS,
            serde_json::json!({
                "offset": offset,
                "limit": limit,
                "status": status,
                "context_id": context_id,
            }),
            key_management::LIST_KEYS_RESULT,
            30,
            |c, url| {
                let mut u = format!("{url}/keys?offset={offset}&limit={limit}");
                if let Some(s) = status {
                    u.push_str(&format!("&status={s}"));
                }
                if let Some(ctx) = context_id {
                    u.push_str(&format!("&context_id={ctx}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_key(&self, key_id: &str) -> Result<KeyRecord, Box<dyn std::error::Error>> {
        self.rpc(
            key_management::GET_KEY,
            serde_json::json!({ "key_id": key_id }),
            key_management::GET_KEY_RESULT,
            30,
            |c, url| c.get(format!("{url}/keys/{}", encode_path_segment(key_id))),
        )
        .await
    }

    pub async fn get_key_secret(
        &self,
        key_id: &str,
    ) -> Result<GetKeySecretResponse, Box<dyn std::error::Error>> {
        self.rpc(
            key_management::GET_KEY_SECRET,
            serde_json::json!({ "key_id": key_id }),
            key_management::GET_KEY_SECRET_RESULT,
            30,
            |c, url| c.get(format!("{url}/keys/{}/secret", encode_path_segment(key_id))),
        )
        .await
    }

    pub async fn invalidate_key(
        &self,
        key_id: &str,
    ) -> Result<InvalidateKeyResponse, Box<dyn std::error::Error>> {
        self.rpc(
            key_management::REVOKE_KEY,
            serde_json::json!({ "key_id": key_id }),
            key_management::REVOKE_KEY_RESULT,
            30,
            |c, url| c.delete(format!("{url}/keys/{}", encode_path_segment(key_id))),
        )
        .await
    }

    pub async fn rename_key(
        &self,
        key_id: &str,
        new_key_id: &str,
    ) -> Result<RenameKeyResponse, Box<dyn std::error::Error>> {
        self.rpc(
            key_management::RENAME_KEY,
            serde_json::json!({ "key_id": key_id, "new_key_id": new_key_id }),
            key_management::RENAME_KEY_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/keys/{}", encode_path_segment(key_id)))
                    .json(&RenameKeyRequest {
                        key_id: new_key_id.to_string(),
                    })
            },
        )
        .await
    }

    // ── Seed methods ────────────────────────────────────────────────

    pub async fn list_seeds(&self) -> Result<ListSeedsResponse, Box<dyn std::error::Error>> {
        self.rpc(
            seed_management::LIST_SEEDS,
            serde_json::json!({}),
            seed_management::LIST_SEEDS_RESULT,
            30,
            |c, url| c.get(format!("{url}/keys/seeds")),
        )
        .await
    }

    pub async fn rotate_seed(
        &self,
        mnemonic: Option<String>,
    ) -> Result<RotateSeedResponse, Box<dyn std::error::Error>> {
        let body = RotateSeedRequest {
            mnemonic: mnemonic.clone(),
        };
        self.rpc(
            seed_management::ROTATE_SEED,
            serde_json::json!({ "mnemonic": mnemonic }),
            seed_management::ROTATE_SEED_RESULT,
            30,
            |c, url| c.post(format!("{url}/keys/seeds/rotate")).json(&body),
        )
        .await
    }

    // ── ACL methods ─────────────────────────────────────────────────

    pub async fn list_acl(
        &self,
        context: Option<&str>,
    ) -> Result<AclListResponse, Box<dyn std::error::Error>> {
        self.rpc(
            acl_management::LIST_ACL,
            serde_json::json!({ "context": context }),
            acl_management::LIST_ACL_RESULT,
            30,
            |c, url| {
                let mut u = format!("{url}/acl");
                if let Some(ctx) = context {
                    u.push_str(&format!("?context={ctx}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_acl(&self, did: &str) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        self.rpc(
            acl_management::GET_ACL,
            serde_json::json!({ "did": did }),
            acl_management::GET_ACL_RESULT,
            30,
            |c, url| c.get(format!("{url}/acl/{}", encode_path_segment(did))),
        )
        .await
    }

    pub async fn create_acl(
        &self,
        req: CreateAclRequest,
    ) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        self.rpc(
            acl_management::CREATE_ACL,
            serde_json::to_value(&req)?,
            acl_management::CREATE_ACL_RESULT,
            30,
            |c, url| c.post(format!("{url}/acl")).json(&req),
        )
        .await
    }

    pub async fn update_acl(
        &self,
        did: &str,
        req: UpdateAclRequest,
    ) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        self.rpc(
            acl_management::UPDATE_ACL,
            serde_json::json!({
                "did": did,
                "role": &req.role,
                "label": &req.label,
                "allowed_contexts": &req.allowed_contexts,
            }),
            acl_management::UPDATE_ACL_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/acl/{}", encode_path_segment(did)))
                    .json(&req)
            },
        )
        .await
    }

    pub async fn delete_acl(&self, did: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.rpc_void(
            acl_management::DELETE_ACL,
            serde_json::json!({ "did": did }),
            acl_management::DELETE_ACL_RESULT,
            30,
            |c, url| c.delete(format!("{url}/acl/{}", encode_path_segment(did))),
        )
        .await
    }

    // ── Credential methods ──────────────────────────────────────────

    pub async fn generate_credentials(
        &self,
        req: GenerateCredentialsRequest,
    ) -> Result<GenerateCredentialsResponse, Box<dyn std::error::Error>> {
        self.rpc(
            credential_management::GENERATE_CREDENTIALS,
            serde_json::to_value(&req)?,
            credential_management::GENERATE_CREDENTIALS_RESULT,
            30,
            |c, url| c.post(format!("{url}/auth/credentials")).json(&req),
        )
        .await
    }

    // ── Context methods ──────────────────────────────────────────────

    pub async fn list_contexts(&self) -> Result<ContextListResponse, Box<dyn std::error::Error>> {
        self.rpc(
            context_management::LIST_CONTEXTS,
            serde_json::json!({}),
            context_management::LIST_CONTEXTS_RESULT,
            30,
            |c, url| c.get(format!("{url}/contexts")),
        )
        .await
    }

    pub async fn get_context(
        &self,
        id: &str,
    ) -> Result<ContextResponse, Box<dyn std::error::Error>> {
        self.rpc(
            context_management::GET_CONTEXT,
            serde_json::json!({ "id": id }),
            context_management::GET_CONTEXT_RESULT,
            30,
            |c, url| c.get(format!("{url}/contexts/{}", encode_path_segment(id))),
        )
        .await
    }

    pub async fn create_context(
        &self,
        req: CreateContextRequest,
    ) -> Result<ContextResponse, Box<dyn std::error::Error>> {
        self.rpc(
            context_management::CREATE_CONTEXT,
            serde_json::to_value(&req)?,
            context_management::CREATE_CONTEXT_RESULT,
            30,
            |c, url| c.post(format!("{url}/contexts")).json(&req),
        )
        .await
    }

    pub async fn update_context(
        &self,
        id: &str,
        req: UpdateContextRequest,
    ) -> Result<ContextResponse, Box<dyn std::error::Error>> {
        self.rpc(
            context_management::UPDATE_CONTEXT,
            serde_json::json!({
                "id": id,
                "name": &req.name,
                "did": &req.did,
                "description": &req.description,
            }),
            context_management::UPDATE_CONTEXT_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/contexts/{}", encode_path_segment(id)))
                    .json(&req)
            },
        )
        .await
    }

    pub async fn delete_context(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.rpc_void(
            context_management::DELETE_CONTEXT,
            serde_json::json!({ "id": id }),
            context_management::DELETE_CONTEXT_RESULT,
            30,
            |c, url| c.delete(format!("{url}/contexts/{}", encode_path_segment(id))),
        )
        .await
    }

    // ── WebVH server methods ──────────────────────────────────────────

    pub async fn add_webvh_server(
        &self,
        req: AddWebvhServerRequest,
    ) -> Result<crate::webvh::WebvhServerRecord, Box<dyn std::error::Error>> {
        self.rpc(
            did_management::ADD_WEBVH_SERVER,
            serde_json::to_value(&req)?,
            did_management::ADD_WEBVH_SERVER_RESULT,
            30,
            |c, url| c.post(format!("{url}/webvh/servers")).json(&req),
        )
        .await
    }

    pub async fn list_webvh_servers(
        &self,
    ) -> Result<
        crate::protocols::did_management::servers::ListWebvhServersResultBody,
        Box<dyn std::error::Error>,
    > {
        self.rpc(
            did_management::LIST_WEBVH_SERVERS,
            serde_json::json!({}),
            did_management::LIST_WEBVH_SERVERS_RESULT,
            30,
            |c, url| c.get(format!("{url}/webvh/servers")),
        )
        .await
    }

    pub async fn update_webvh_server(
        &self,
        id: &str,
        req: UpdateWebvhServerRequest,
    ) -> Result<crate::webvh::WebvhServerRecord, Box<dyn std::error::Error>> {
        self.rpc(
            did_management::UPDATE_WEBVH_SERVER,
            serde_json::json!({ "id": id, "label": &req.label }),
            did_management::UPDATE_WEBVH_SERVER_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/webvh/servers/{}", encode_path_segment(id)))
                    .json(&req)
            },
        )
        .await
    }

    pub async fn remove_webvh_server(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.rpc_void(
            did_management::REMOVE_WEBVH_SERVER,
            serde_json::json!({ "id": id }),
            did_management::REMOVE_WEBVH_SERVER_RESULT,
            30,
            |c, url| c.delete(format!("{url}/webvh/servers/{}", encode_path_segment(id))),
        )
        .await
    }

    // ── WebVH DID methods ──────────────────────────────────────────

    pub async fn create_did_webvh(
        &self,
        req: CreateDidWebvhRequest,
    ) -> Result<
        crate::protocols::did_management::create::CreateDidWebvhResultBody,
        Box<dyn std::error::Error>,
    > {
        self.rpc(
            did_management::CREATE_DID_WEBVH,
            serde_json::to_value(&req)?,
            did_management::CREATE_DID_WEBVH_RESULT,
            60,
            |c, url| c.post(format!("{url}/webvh/dids")).json(&req),
        )
        .await
    }

    pub async fn list_dids_webvh(
        &self,
        context_id: Option<&str>,
        server_id: Option<&str>,
    ) -> Result<
        crate::protocols::did_management::list::ListDidsWebvhResultBody,
        Box<dyn std::error::Error>,
    > {
        self.rpc(
            did_management::LIST_DIDS_WEBVH,
            serde_json::json!({
                "context_id": context_id,
                "server_id": server_id,
            }),
            did_management::LIST_DIDS_WEBVH_RESULT,
            30,
            |c, url| {
                let mut u = format!("{url}/webvh/dids");
                let mut sep = '?';
                if let Some(ctx) = context_id {
                    u.push_str(&format!("{sep}context_id={ctx}"));
                    sep = '&';
                }
                if let Some(srv) = server_id {
                    u.push_str(&format!("{sep}server_id={srv}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_did_webvh(
        &self,
        did: &str,
    ) -> Result<crate::webvh::WebvhDidRecord, Box<dyn std::error::Error>> {
        self.rpc(
            did_management::GET_DID_WEBVH,
            serde_json::json!({ "did": did }),
            did_management::GET_DID_WEBVH_RESULT,
            30,
            |c, url| c.get(format!("{url}/webvh/dids/{}", encode_path_segment(did))),
        )
        .await
    }

    pub async fn delete_did_webvh(&self, did: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.rpc_void(
            did_management::DELETE_DID_WEBVH,
            serde_json::json!({ "did": did }),
            did_management::DELETE_DID_WEBVH_RESULT,
            60,
            |c, url| c.delete(format!("{url}/webvh/dids/{}", encode_path_segment(did))),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── encode_path_segment ─────────────────────────────────────────

    #[test]
    fn test_encode_hash_in_did_fragment() {
        assert_eq!(
            encode_path_segment("did:key:z6Mk123#z6Mk123"),
            "did:key:z6Mk123%23z6Mk123"
        );
    }

    #[test]
    fn test_encode_question_mark() {
        assert_eq!(encode_path_segment("foo?bar"), "foo%3Fbar");
    }

    #[test]
    fn test_encode_percent_is_escaped_first() {
        assert_eq!(encode_path_segment("100%#done"), "100%25%23done");
    }

    #[test]
    fn test_encode_colon_preserved() {
        assert_eq!(encode_path_segment("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn test_encode_plain_string_unchanged() {
        assert_eq!(encode_path_segment("simple-id"), "simple-id");
    }

    #[test]
    fn test_encode_multiple_hashes() {
        assert_eq!(encode_path_segment("a#b#c"), "a%23b%23c");
    }

    #[test]
    fn test_encode_slash_in_derivation_path() {
        assert_eq!(
            encode_path_segment("m/44'/0'/0'/0"),
            "m%2F44'%2F0'%2F0'%2F0"
        );
    }

    // ── VtaClient::new ──────────────────────────────────────────────

    #[test]
    fn test_new_strips_trailing_slash() {
        let client = VtaClient::new("http://localhost:3000/");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_strips_multiple_trailing_slashes() {
        let client = VtaClient::new("http://localhost:3000///");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_no_trailing_slash_unchanged() {
        let client = VtaClient::new("http://localhost:3000");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_token_initially_none() {
        let client = VtaClient::new("http://example.com");
        match &client.transport {
            Transport::Rest { token, .. } => assert!(token.is_none()),
            #[cfg(feature = "session")]
            _ => panic!("expected REST transport"),
        }
    }

    #[test]
    fn test_set_token() {
        let mut client = VtaClient::new("http://example.com");
        client.set_token("my-jwt".to_string());
        match &client.transport {
            Transport::Rest { token, .. } => assert_eq!(token.as_deref(), Some("my-jwt")),
            #[cfg(feature = "session")]
            _ => panic!("expected REST transport"),
        }
    }

    // ── Request/Response serialization ──────────────────────────────

    #[test]
    fn test_update_config_skips_none_fields() {
        let req = UpdateConfigRequest {
            vta_did: None,
            vta_name: Some("Test".into()),
            public_url: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(!json.as_object().unwrap().contains_key("vta_did"));
        assert_eq!(json["vta_name"], "Test");
        assert!(!json.as_object().unwrap().contains_key("public_url"));
    }

    #[test]
    fn test_create_key_request_serialization() {
        let req = CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("test key".into()),
            context_id: Some("vta".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(!json.as_object().unwrap().contains_key("derivation_path"));
        assert!(!json.as_object().unwrap().contains_key("key_id"));
        assert!(!json.as_object().unwrap().contains_key("mnemonic"));
        assert_eq!(json["label"], "test key");
        assert_eq!(json["context_id"], "vta");
    }

    #[test]
    fn test_create_acl_request_serialization() {
        let req = CreateAclRequest {
            did: "did:key:z6Mk123".into(),
            role: "admin".into(),
            label: None,
            allowed_contexts: vec!["vta".into()],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["did"], "did:key:z6Mk123");
        assert_eq!(json["role"], "admin");
        assert!(!json.as_object().unwrap().contains_key("label"));
        assert_eq!(json["allowed_contexts"], serde_json::json!(["vta"]));
    }

    #[test]
    fn test_update_acl_request_all_none() {
        let req = UpdateAclRequest {
            role: None,
            label: None,
            allowed_contexts: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.is_empty(), "all-None request should serialize to {{}}");
    }

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{"status":"ok","version":"0.1.0"}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.version, "0.1.0");
    }

    #[test]
    fn test_error_response_deserialization() {
        let json = r#"{"error":"not found"}"#;
        let resp: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "not found");
    }

    #[test]
    fn test_list_keys_response_deserialization() {
        let json = r#"{"keys":[],"total":0}"#;
        let resp: ListKeysResponse = serde_json::from_str(json).unwrap();
        assert!(resp.keys.is_empty());
        assert_eq!(resp.total, 0);
    }

    #[test]
    fn test_generate_credentials_response_deserialization() {
        let json = r#"{"did":"did:key:z6Mk123","credential":"abc123","role":"admin"}"#;
        let resp: GenerateCredentialsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.did, "did:key:z6Mk123");
        assert_eq!(resp.credential, "abc123");
        assert_eq!(resp.role, "admin");
    }

    #[test]
    fn test_acl_list_response_deserialization() {
        let json = r#"{"entries":[{"did":"did:key:z6Mk1","role":"admin","label":null,"allowed_contexts":[],"created_at":1700000000,"created_by":"setup"}]}"#;
        let resp: AclListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].did, "did:key:z6Mk1");
        assert_eq!(resp.entries[0].role, "admin");
        assert!(resp.entries[0].allowed_contexts.is_empty());
    }

    #[test]
    fn test_context_response_deserialization() {
        let json = r#"{"id":"vta","name":"Verified Trust Agent","did":null,"description":null,"base_path":"m/26'/2'/0'","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let resp: ContextResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "vta");
        assert_eq!(resp.name, "Verified Trust Agent");
        assert!(resp.did.is_none());
        assert_eq!(resp.base_path, "m/26'/2'/0'");
    }
}
