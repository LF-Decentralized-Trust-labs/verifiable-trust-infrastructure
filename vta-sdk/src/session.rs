use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use serde::{Deserialize, Serialize};
use serde_json;
use tracing::debug;

use crate::credentials::CredentialBundle;
use crate::protocols::auth::{AuthenticateResponse, ChallengeRequest, ChallengeResponse};

// ── Session (internal) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    client_did: String,
    private_key: String,
    vta_did: String,
    #[serde(default)]
    vta_url: Option<String>,
    access_token: Option<String>,
    access_expires_at: Option<u64>,
}

// ── Public types ────────────────────────────────────────────────────

/// Loaded session info exposed for health/diagnostics.
pub struct SessionInfo {
    pub client_did: String,
    pub vta_did: String,
    pub private_key_multibase: String,
}

/// Status of a stored session.
pub struct SessionStatus {
    pub client_did: String,
    pub vta_did: String,
    pub vta_url: Option<String>,
    pub token_status: TokenStatus,
}

/// Current state of a cached access token.
pub enum TokenStatus {
    Valid { expires_in_secs: u64 },
    Expired,
    None,
}

/// Result of a successful login.
pub struct LoginResult {
    pub client_did: String,
    pub vta_did: String,
    pub vta_url: Option<String>,
}

pub struct TokenResult {
    pub access_token: String,
    pub access_expires_at: u64,
}

// ── SessionBackend trait ────────────────────────────────────────────

/// Pluggable storage backend for VTA session credentials.
///
/// Implement this trait to store VTA sessions in a custom backend
/// (e.g., the same secrets store your application already uses).
///
/// The `key` parameter identifies the session (e.g., "default", "setup").
/// The `value` is a JSON-serialized session blob containing credentials
/// and cached tokens.
pub trait SessionBackend: Send + Sync {
    /// Load a session by key. Returns `None` if not found.
    fn load(&self, key: &str) -> Option<String>;
    /// Store a session. The value is JSON-serialized session data.
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>>;
    /// Remove a session by key.
    fn clear(&self, key: &str);
}

// ── Built-in backends ───────────────────────────────────────────────

/// OS keyring backend (requires `keyring` feature).
#[cfg(feature = "keyring")]
struct KeyringBackend {
    service_name: String,
}

#[cfg(feature = "keyring")]
impl SessionBackend for KeyringBackend {
    fn load(&self, key: &str) -> Option<String> {
        let entry = keyring::Entry::new(&self.service_name, key).ok()?;
        match entry.get_password() {
            Ok(v) => Some(v),
            Err(keyring::Error::NoEntry) => None,
            Err(e) => {
                eprintln!("Warning: keyring read error: {e}");
                None
            }
        }
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| format!("keyring entry error: {e}"))?;
        entry
            .set_password(value)
            .map_err(|e| format!("failed to store session in keyring: {e}"))?;
        Ok(())
    }

    fn clear(&self, key: &str) {
        if let Ok(entry) = keyring::Entry::new(&self.service_name, key) {
            let _ = entry.delete_credential();
        }
    }
}

/// Local JSON file backend (requires `config-session` feature, or used
/// as plaintext fallback when no secure backend is compiled in).
struct FileBackend {
    sessions_dir: PathBuf,
    warn: bool,
}

impl FileBackend {
    fn sessions_path(&self) -> PathBuf {
        self.sessions_dir.join("sessions.json")
    }

    fn load_map(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let path = self.sessions_path();
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return std::collections::HashMap::new(),
        };
        serde_json::from_str(&data).unwrap_or_default()
    }

    fn save_map(
        &self,
        map: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.sessions_path();
        let json = serde_json::to_string_pretty(map)?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

impl SessionBackend for FileBackend {
    fn load(&self, key: &str) -> Option<String> {
        if self.warn {
            eprintln!("WARNING: No secure session store — using plaintext file storage");
        }
        let map = self.load_map();
        map.get(key).map(|v| v.to_string())
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.warn {
            eprintln!("WARNING: No secure session store — using plaintext file storage");
        }
        if let Some(parent) = self.sessions_dir.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::create_dir_all(&self.sessions_dir).ok();
        let mut map = self.load_map();
        let parsed: serde_json::Value = serde_json::from_str(value)?;
        map.insert(key.to_string(), parsed);
        self.save_map(&map)
    }

    fn clear(&self, key: &str) {
        let mut map = self.load_map();
        map.remove(key);
        let _ = self.save_map(&map);
    }
}

/// Azure Key Vault backend (requires `azure-secrets` feature).
#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
struct AzureBackend {
    vault_url: String,
    secret_prefix: String,
}

#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
impl AzureBackend {
    fn secret_name(&self, key: &str) -> String {
        format!("{}-{}", self.secret_prefix, key)
    }
}

#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
impl SessionBackend for AzureBackend {
    fn load(&self, key: &str) -> Option<String> {
        use azure_identity::DeveloperToolsCredential;
        use azure_security_keyvault_secrets::SecretClient;

        let credential = DeveloperToolsCredential::new(None).ok()?;
        let client = SecretClient::new(&self.vault_url, credential, None).ok()?;
        let secret_name = self.secret_name(key);

        let result = tokio::runtime::Handle::current()
            .block_on(async { client.get_secret(&secret_name, None).await });

        match result {
            Ok(response) => {
                let model = response.into_model().ok()?;
                model.value
            }
            Err(_) => None,
        }
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        use azure_identity::DeveloperToolsCredential;
        use azure_security_keyvault_secrets::SecretClient;

        let credential = DeveloperToolsCredential::new(None)
            .map_err(|e| format!("Azure credential error: {e}"))?;
        let client = SecretClient::new(&self.vault_url, credential, None)
            .map_err(|e| format!("Azure client error: {e}"))?;
        let secret_name = self.secret_name(key);

        let params = azure_security_keyvault_secrets::models::SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };

        tokio::runtime::Handle::current().block_on(async {
            let body = params
                .try_into()
                .map_err(|e| format!("Azure request error: {e}"))?;
            client
                .set_secret(&secret_name, body, None)
                .await
                .map_err(|e| format!("failed to store session in Azure Key Vault: {e}"))?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }

    fn clear(&self, key: &str) {
        use azure_identity::DeveloperToolsCredential;
        use azure_security_keyvault_secrets::SecretClient;

        let Ok(credential) = DeveloperToolsCredential::new(None) else {
            return;
        };
        let Ok(client) = SecretClient::new(&self.vault_url, credential, None) else {
            return;
        };
        let secret_name = self.secret_name(key);

        let _ = tokio::runtime::Handle::current()
            .block_on(async { client.delete_secret(&secret_name, None).await });
    }
}

/// Create the default session backend based on compiled features.
///
/// Priority: keyring → azure-secrets → config-session → plaintext fallback.
fn default_backend(service_name: &str, sessions_dir: PathBuf) -> Box<dyn SessionBackend> {
    let _ = service_name;
    let _ = &sessions_dir;

    #[cfg(feature = "keyring")]
    {
        return Box::new(KeyringBackend {
            service_name: service_name.to_string(),
        });
    }

    #[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
    {
        return Box::new(AzureBackend {
            vault_url: std::env::var("AZURE_KEYVAULT_URL").unwrap_or_default(),
            secret_prefix: service_name.to_string(),
        });
    }

    #[cfg(all(
        feature = "config-session",
        not(feature = "keyring"),
        not(feature = "azure-secrets")
    ))]
    {
        return Box::new(FileBackend {
            sessions_dir,
            warn: false,
        });
    }

    #[allow(unreachable_code)]
    Box::new(FileBackend {
        sessions_dir,
        warn: true,
    })
}

// ── SessionStore ────────────────────────────────────────────────────

/// Reusable session storage for VTA authentication.
///
/// Uses a pluggable [`SessionBackend`] for credential persistence.
/// By default, the backend is selected based on compiled features
/// (keyring → azure → config-file → plaintext). Consumers can
/// provide their own backend via [`SessionStore::with_backend`].
pub struct SessionStore {
    backend: Box<dyn SessionBackend>,
}

impl SessionStore {
    /// Create a new session store with the default backend.
    ///
    /// The backend is selected based on compiled features:
    /// - `keyring` → OS keyring (uses `service_name`)
    /// - `azure-secrets` → Azure Key Vault (uses `service_name` as prefix)
    /// - `config-session` → local JSON file (uses `sessions_dir`)
    /// - fallback → plaintext JSON file with warning
    pub fn new(service_name: &str, sessions_dir: PathBuf) -> Self {
        Self {
            backend: default_backend(service_name, sessions_dir),
        }
    }

    /// Create a session store with a custom backend.
    ///
    /// Use this to integrate with your application's existing secrets
    /// storage (e.g., AWS Secrets Manager, GCP Secret Manager, etc.).
    pub fn with_backend(backend: Box<dyn SessionBackend>) -> Self {
        Self { backend }
    }

    // ── Internal session serialization ───────────────────────────────

    fn load_session(&self, key: &str) -> Option<Session> {
        let json = self.backend.load(key)?;
        serde_json::from_str(&json).ok()
    }

    fn save_session(
        &self,
        key: &str,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(session)?;
        self.backend.save(key, &json)
    }

    fn clear_session(&self, key: &str) {
        self.backend.clear(key);
    }

    // ── Public API ──────────────────────────────────────────────────

    /// Returns true if a session exists for the given key.
    pub fn has_session(&self, key: &str) -> bool {
        self.load_session(key).is_some()
    }

    /// Import a base64-encoded credential and authenticate.
    ///
    /// Returns `LoginResult` on success (no printing).
    pub async fn login(
        &self,
        credential_b64: &str,
        base_url: &str,
        key: &str,
    ) -> Result<LoginResult, Box<dyn std::error::Error>> {
        debug!("decoding credential bundle");
        let bundle = CredentialBundle::decode(credential_b64)
            .map_err(|e| format!("invalid credential: {e}"))?;

        debug!(
            client_did = %bundle.did,
            vta_did = %bundle.vta_did,
            vta_url = ?bundle.vta_url,
            "credential decoded"
        );

        let mut session = Session {
            client_did: bundle.did.clone(),
            private_key: bundle.private_key_multibase.clone(),
            vta_did: bundle.vta_did.clone(),
            vta_url: bundle.vta_url.clone(),
            access_token: None,
            access_expires_at: None,
        };
        self.save_session(key, &session)?;
        debug!(keyring_key = key, "session saved");

        // Perform authentication
        let token = challenge_response(
            base_url,
            &bundle.did,
            &bundle.private_key_multibase,
            &bundle.vta_did,
        )
        .await?;

        session.access_token = Some(token.access_token);
        session.access_expires_at = Some(token.access_expires_at);
        self.save_session(key, &session)?;

        Ok(LoginResult {
            client_did: bundle.did,
            vta_did: bundle.vta_did,
            vta_url: bundle.vta_url,
        })
    }

    /// Store a session directly (without performing authentication).
    pub fn store_direct(
        &self,
        key: &str,
        did: &str,
        private_key: &str,
        vta_did: &str,
        vta_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session = Session {
            client_did: did.to_string(),
            private_key: private_key.to_string(),
            vta_did: vta_did.to_string(),
            vta_url: Some(vta_url.to_string()),
            access_token: None,
            access_expires_at: None,
        };
        self.save_session(key, &session)
    }

    /// Clear stored credentials and cached tokens.
    pub fn logout(&self, key: &str) {
        self.clear_session(key);
    }

    /// Load the stored session for diagnostics (DID resolution, etc.).
    pub fn loaded_session(&self, key: &str) -> Option<SessionInfo> {
        self.load_session(key).map(|s| SessionInfo {
            client_did: s.client_did,
            vta_did: s.vta_did,
            private_key_multibase: s.private_key,
        })
    }

    /// Get the status of a stored session.
    pub fn session_status(&self, key: &str) -> Option<SessionStatus> {
        let session = self.load_session(key)?;
        let token_status = match (session.access_token, session.access_expires_at) {
            (Some(_), Some(exp)) => {
                let now = now_epoch();
                if exp > now {
                    TokenStatus::Valid {
                        expires_in_secs: exp - now,
                    }
                } else {
                    TokenStatus::Expired
                }
            }
            _ => TokenStatus::None,
        };
        Some(SessionStatus {
            client_did: session.client_did,
            vta_did: session.vta_did,
            vta_url: session.vta_url,
            token_status,
        })
    }

    /// Ensure we have a valid access token. Returns the token string.
    ///
    /// If no credentials are stored, returns an error.
    /// If a cached token is still valid (>30s remaining), returns it.
    /// Otherwise, performs a full challenge-response authentication.
    pub async fn ensure_authenticated(
        &self,
        base_url: &str,
        key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        debug!(base_url, keyring_key = key, "ensuring authentication");

        let mut session = self.load_session(key).ok_or(
            "Not authenticated.\n\nTo authenticate, import a credential:\n  <cli> auth login <credential-string>",
        )?;

        debug!(
            client_did = %session.client_did,
            vta_did = %session.vta_did,
            "session loaded"
        );

        // Check cached token
        if let (Some(token), Some(expires_at)) = (&session.access_token, session.access_expires_at)
            && now_epoch() + 30 < expires_at
        {
            debug!(expires_in = expires_at - now_epoch(), "using cached token");
            return Ok(token.clone());
        }

        debug!("cached token expired or missing, performing challenge-response");

        // Full challenge-response
        let result = challenge_response(
            base_url,
            &session.client_did,
            &session.private_key,
            &session.vta_did,
        )
        .await?;

        let token = result.access_token.clone();
        session.access_token = Some(result.access_token);
        session.access_expires_at = Some(result.access_expires_at);
        self.save_session(key, &session)?;
        debug!("new token cached");

        Ok(token)
    }

    /// Connect to a VTA using the preferred transport (DIDComm or REST).
    ///
    /// 1. Loads session from store (client DID, private key, VTA DID).
    /// 2. If `url_override` is provided, uses REST directly.
    /// 3. Otherwise resolves the VTA DID to discover DIDComm or REST endpoints.
    /// 4. For DIDComm: encryption provides auth (no JWT needed).
    /// 5. For REST: performs challenge-response to obtain a JWT.
    pub async fn connect(
        &self,
        key: &str,
        url_override: Option<&str>,
    ) -> Result<crate::client::VtaClient, Box<dyn std::error::Error>> {
        let session = self.load_session(key).ok_or(
            "Not authenticated.\n\nTo authenticate, import a credential:\n  <cli> auth login <credential-string>",
        )?;

        // URL override: always use REST
        if let Some(url) = url_override {
            debug!(url, "using REST transport (URL override)");
            let token = self.ensure_authenticated(url, key).await?;
            let mut client = crate::client::VtaClient::new(url);
            client.set_token(token);
            return Ok(client);
        }

        // Resolve VTA DID for transport selection
        match resolve_vta_endpoint(&session.vta_did).await? {
            VtaEndpoint::DIDComm {
                vta_did,
                mediator_did,
                rest_url,
            } => {
                debug!("connecting via DIDComm");
                let client = crate::client::VtaClient::connect_didcomm(
                    &session.client_did,
                    &session.private_key,
                    &vta_did,
                    &mediator_did,
                    rest_url,
                )
                .await?;
                Ok(client)
            }
            VtaEndpoint::Rest { url } => {
                debug!(url = %url, "connecting via REST");
                let token = self.ensure_authenticated(&url, key).await?;
                let mut client = crate::client::VtaClient::new(&url);
                client.set_token(token);
                Ok(client)
            }
        }
    }
}

// ── Challenge-response auth ─────────────────────────────────────────

/// Perform DIDComm challenge-response authentication against a VTA.
pub async fn challenge_response(
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult, Box<dyn std::error::Error>> {
    debug!(
        base_url,
        client_did, vta_did, "starting challenge-response auth"
    );
    let http = reqwest::Client::new();

    // Step 1: Request challenge
    let challenge_url = format!("{base_url}/auth/challenge");
    debug!(url = %challenge_url, did = client_did, "requesting challenge");
    let challenge_resp = http
        .post(&challenge_url)
        .json(&ChallengeRequest {
            did: client_did.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {challenge_url}: {e}"))?;

    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let body = challenge_resp.text().await.unwrap_or_default();
        return Err(format!("challenge request failed ({status}): {body}").into());
    }

    let challenge_text = challenge_resp
        .text()
        .await
        .map_err(|e| format!("failed to read challenge response from VTA: {e}"))?;
    let challenge: ChallengeResponse = serde_json::from_str(&challenge_text).map_err(|e| {
        format!("unexpected response from VTA at {challenge_url} (is this a VTA server?): {e}")
    })?;
    debug!(
        session_id = %challenge.session_id,
        challenge = %challenge.data.challenge,
        "challenge received"
    );

    // Step 2: Build DIDComm message
    debug!("initializing DID resolver and ATM for message packing");

    use std::sync::Arc;
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;

    let tdk = TDKSharedState::new(TDKConfig::builder().build()
        .map_err(|e| format!("TDK config build failed: {e}"))?)
        .await
        .map_err(|e| format!("TDK init failed: {e}"))?;

    // Build DIDComm secrets from the private key
    let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
    let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;
    debug!(signing_id = %secrets.signing.id, ka_id = %secrets.key_agreement.id, "inserting DIDComm secrets");
    tdk.secrets_resolver.insert(secrets.signing).await;
    tdk.secrets_resolver.insert(secrets.key_agreement).await;

    let atm = ATM::new(ATMConfig::builder().build()
        .map_err(|e| format!("ATM config build failed: {e}"))?,
        Arc::new(tdk),
    ).await
    .map_err(|e| format!("ATM init failed: {e}"))?;

    // Build the authenticate message
    debug!(
        from = client_did,
        to = vta_did,
        "building DIDComm authenticate message"
    );
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://affinidi.com/atm/1.0/authenticate".to_string(),
        serde_json::json!({
            "challenge": challenge.data.challenge,
            "session_id": challenge.session_id,
        }),
    )
    .from(client_did.to_string())
    .to(vta_did.to_string())
    .finalize();

    // Pack the message (encrypted)
    let (packed, _metadata) = atm
        .pack_encrypted(&msg, vta_did, Some(client_did), None)
        .await
        .map_err(|e| format!("DIDComm pack failed: {e}"))?;

    debug!(packed_len = packed.len(), "message packed");

    // Step 3: Authenticate
    let auth_url = format!("{base_url}/auth/");
    debug!(url = %auth_url, "sending packed message");
    let auth_resp = http
        .post(&auth_url)
        .header("content-type", "text/plain")
        .body(packed)
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {auth_url}: {e}"))?;

    let status = auth_resp.status();
    debug!(status = %status, "auth response received");

    if !status.is_success() {
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(format!("authentication failed ({status}): {body}").into());
    }

    let auth_text = auth_resp
        .text()
        .await
        .map_err(|e| format!("failed to read auth response from VTA: {e}"))?;
    let auth_data: AuthenticateResponse = serde_json::from_str(&auth_text).map_err(|e| {
        format!("unexpected response from VTA at {auth_url} (is this a VTA server?): {e}")
    })?;
    debug!(
        expires_at = auth_data.data.access_expires_at,
        "authentication successful"
    );

    Ok(TokenResult {
        access_token: auth_data.data.access_token,
        access_expires_at: auth_data.data.access_expires_at,
    })
}

// ── DIDComm-preferred connection ─────────────────────────────────────

/// Result of resolving a VTA DID's service endpoints.
pub enum VtaEndpoint {
    /// REST-only (no DIDCommMessaging service found).
    Rest { url: String },
    /// DIDComm preferred, with optional REST fallback.
    DIDComm {
        vta_did: String,
        mediator_did: String,
        rest_url: Option<String>,
    },
}

/// Resolve a VTA DID to discover available transport endpoints.
///
/// Performs a single DID resolution and extracts:
/// - `DIDCommMessaging` service → mediator DID (preferred transport)
/// - `#vta-rest` service → REST URL (fallback)
///
/// Returns `VtaEndpoint::DIDComm` if a mediator is found, otherwise `VtaEndpoint::Rest`.
pub async fn resolve_vta_endpoint(
    vta_did: &str,
) -> Result<VtaEndpoint, Box<dyn std::error::Error>> {
    debug!(vta_did, "resolving VTA DID for transport selection");

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;

    let resolved = match did_resolver.resolve(vta_did).await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "DID resolution failed, falling back to URL parsing");
            let url = url_from_did(vta_did)
                .ok_or_else(|| format!("Could not determine VTA URL from DID: {vta_did}"))?;
            return Ok(VtaEndpoint::Rest { url });
        }
    };

    // Look for #vta-rest service endpoint
    let rest_url = resolved
        .doc
        .find_service("vta-rest")
        .and_then(|svc| svc.service_endpoint.get_uri())
        .map(|u| u.trim_matches('"').trim_end_matches('/').to_string());

    // Look for DIDCommMessaging service with a DID-based endpoint (mediator)
    let mediator_did = resolved
        .doc
        .service
        .iter()
        .filter(|svc| svc.type_.iter().any(|t| t == "DIDCommMessaging"))
        .flat_map(|svc| svc.service_endpoint.get_uris())
        .map(|u| u.trim_matches('"').to_string())
        .find(|u| u.starts_with("did:"));

    if let Some(mediator_did) = mediator_did {
        debug!(mediator_did = %mediator_did, rest_url = ?rest_url, "DIDComm endpoint found");
        Ok(VtaEndpoint::DIDComm {
            vta_did: vta_did.to_string(),
            mediator_did,
            rest_url,
        })
    } else if let Some(url) = rest_url {
        debug!(url = %url, "REST-only endpoint found");
        Ok(VtaEndpoint::Rest { url })
    } else {
        // Last resort: parse URL from DID string
        let url = url_from_did(vta_did)
            .ok_or_else(|| format!("Could not determine VTA URL from DID: {vta_did}"))?;
        debug!(url = %url, "falling back to URL from DID string");
        Ok(VtaEndpoint::Rest { url })
    }
}

/// Resolve a VTA DID to discover its service URL.
///
/// Resolves the DID document and looks for the `#vta-rest` service endpoint.
/// Falls back to parsing the domain from `did:web:` or `did:webvh:` DID strings.
pub async fn resolve_vta_url(vta_did: &str) -> Result<String, Box<dyn std::error::Error>> {
    debug!(vta_did, "resolving VTA DID to discover service URL");

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;

    match did_resolver.resolve(vta_did).await {
        Ok(resolved) => {
            if let Some(svc) = resolved.doc.find_service("vta-rest") {
                if let Some(url) = svc.service_endpoint.get_uri() {
                    let url = url.trim_matches('"').trim_end_matches('/').to_string();
                    debug!(url = %url, "found VTA URL from #vta-rest service endpoint");
                    return Ok(url);
                }
            }
            debug!("no #vta-rest service found in DID document, falling back to DID parsing");
        }
        Err(e) => {
            debug!(error = %e, "DID resolution failed, falling back to DID parsing");
        }
    }

    // Fallback: parse domain from did:web or did:webvh DID strings
    url_from_did(vta_did)
        .ok_or_else(|| format!("Could not determine VTA URL from DID: {vta_did}").into())
}

/// Extract the base URL from a `did:web:` or `did:webvh:` DID string.
fn url_from_did(did: &str) -> Option<String> {
    let domain = if let Some(rest) = did.strip_prefix("did:web:") {
        // did:web:domain.com or did:web:domain.com%3A8100
        rest.split(':').next()
    } else if let Some(rest) = did.strip_prefix("did:webvh:") {
        // did:webvh:SCID:domain.com or did:webvh:SCID:domain.com%3A8100
        rest.split(':').nth(1)
    } else {
        None
    }?;

    let decoded = domain.replace("%3A", ":").replace("%3a", ":");
    Some(format!("https://{decoded}"))
}

/// Send a DIDComm trust-ping to the mediator using the client's `did:key`
/// credentials, and return latency in milliseconds.
pub async fn send_trust_ping(
    client_did: &str,
    private_key_multibase: &str,
    mediator_did: &str,
    target_did: Option<&str>,
) -> Result<u128, Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Instant;

    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;

    let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
    let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

    let tdk = TDKSharedState::default().await;
    tdk.secrets_resolver.insert(secrets.signing).await;
    tdk.secrets_resolver.insert(secrets.key_agreement).await;

    let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

    let profile = ATMProfile::new(
        &atm,
        None,
        client_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await?;
    let profile = Arc::new(profile);

    atm.profile_enable_websocket(&profile).await?;

    let start = Instant::now();
    TrustPing::default()
        .send_ping(
            &atm,
            &profile,
            target_did.unwrap_or(mediator_did),
            true,
            true,
            true,
        )
        .await?;
    let elapsed = start.elapsed().as_millis();

    atm.graceful_shutdown().await;
    Ok(elapsed)
}

/// Resolve the VTA DID document and extract the mediator DID from the
/// `DIDCommMessaging` service endpoint.
pub async fn resolve_mediator_did(
    vta_did: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| format!("DID resolver init failed: {e}"))?;
    resolve_mediator_did_with_resolver(vta_did, &did_resolver).await
}

/// Resolve the mediator DID using an existing resolver (avoids re-creating one).
pub async fn resolve_mediator_did_with_resolver(
    vta_did: &str,
    resolver: &DIDCacheClient,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let resolved = resolver
        .resolve(vta_did)
        .await
        .map_err(|e| format!("DID resolution failed: {e}"))?;

    for svc in &resolved.doc.service {
        if svc.type_.iter().any(|t| t == "DIDCommMessaging") {
            if let Some(did) = svc
                .service_endpoint
                .get_uris()
                .into_iter()
                .map(|u| u.trim_matches('"').to_string())
                .find(|u| u.starts_with("did:"))
            {
                return Ok(Some(did));
            }
        }
    }

    Ok(None)
}

/// A reusable DIDComm session for sending multiple trust-pings through
/// the same ATM + WebSocket connection.
///
/// Eliminates per-ping overhead of TDK init, ATM creation, profile setup,
/// and WebSocket handshake (~4 seconds saved per additional ping).
pub struct TrustPingSession {
    atm: affinidi_tdk::messaging::ATM,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    mediator_did: String,
}

impl TrustPingSession {
    /// Create a new session connected to the mediator via WebSocket.
    pub async fn new(
        client_did: &str,
        private_key_multibase: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use std::sync::Arc;
        use affinidi_tdk::common::TDKSharedState;
        use affinidi_tdk::messaging::ATM;
        use affinidi_tdk::messaging::config::ATMConfig;
        use affinidi_tdk::messaging::profiles::ATMProfile;

        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        let tdk = TDKSharedState::default().await;
        tdk.secrets_resolver.insert(secrets.signing).await;
        tdk.secrets_resolver.insert(secrets.key_agreement).await;

        let atm = ATM::new(ATMConfig::builder().build()?, Arc::new(tdk)).await?;

        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        atm.profile_enable_websocket(&profile).await?;

        Ok(Self {
            atm,
            profile,
            mediator_did: mediator_did.to_string(),
        })
    }

    /// Send a trust-ping to a target (or the mediator if `target_did` is None).
    /// Returns latency in milliseconds.
    pub async fn ping(
        &self,
        target_did: Option<&str>,
    ) -> Result<u128, Box<dyn std::error::Error>> {
        use std::time::Instant;
        use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;

        let target = target_did.unwrap_or(&self.mediator_did);
        let start = Instant::now();
        TrustPing::default()
            .send_ping(&self.atm, &self.profile, target, true, true, true)
            .await?;
        Ok(start.elapsed().as_millis())
    }

    /// Gracefully shut down the ATM connection.
    pub async fn shutdown(self) {
        self.atm.graceful_shutdown().await;
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_round_trip() {
        let session = Session {
            client_did: "did:key:z6Mk1".into(),
            private_key: "z_seed".into(),
            vta_did: "did:key:z6MkVTA".into(),
            vta_url: Some("https://vta.example.com".into()),
            access_token: Some("tok123".into()),
            access_expires_at: Some(1700000000),
        };
        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.client_did, session.client_did);
        assert_eq!(restored.private_key, session.private_key);
        assert_eq!(restored.vta_did, session.vta_did);
        assert_eq!(restored.vta_url, session.vta_url);
        assert_eq!(restored.access_token, session.access_token);
        assert_eq!(restored.access_expires_at, session.access_expires_at);
    }

    #[test]
    fn test_session_vta_url_defaults_to_none() {
        let json = r#"{
            "client_did": "did:key:z6Mk1",
            "private_key": "z_seed",
            "vta_did": "did:key:z6MkVTA",
            "access_token": null,
            "access_expires_at": null
        }"#;
        let session: Session = serde_json::from_str(json).unwrap();
        assert!(session.vta_url.is_none());
    }

    #[test]
    fn test_now_epoch_is_recent() {
        let epoch = now_epoch();
        assert!(epoch > 1704067200, "epoch {epoch} should be after 2024");
        assert!(epoch < 4102444800, "epoch {epoch} should be before 2100");
    }

    #[test]
    fn test_url_from_did_web() {
        assert_eq!(
            url_from_did("did:web:vta.example.com"),
            Some("https://vta.example.com".to_string())
        );
    }

    #[test]
    fn test_url_from_did_web_with_port() {
        assert_eq!(
            url_from_did("did:web:localhost%3A8100"),
            Some("https://localhost:8100".to_string())
        );
    }

    #[test]
    fn test_url_from_did_webvh() {
        assert_eq!(
            url_from_did("did:webvh:QmSCID123:vta.example.com"),
            Some("https://vta.example.com".to_string())
        );
    }

    #[test]
    fn test_url_from_did_webvh_with_port() {
        assert_eq!(
            url_from_did("did:webvh:QmSCID123:localhost%3A8100"),
            Some("https://localhost:8100".to_string())
        );
    }

    #[test]
    fn test_url_from_did_key_returns_none() {
        assert_eq!(url_from_did("did:key:z6MkTest"), None);
    }

    #[test]
    fn test_in_memory_backend() {
        use std::collections::HashMap;
        use std::sync::Mutex;

        struct InMemoryBackend {
            data: Mutex<HashMap<String, String>>,
        }

        impl SessionBackend for InMemoryBackend {
            fn load(&self, key: &str) -> Option<String> {
                self.data.lock().unwrap().get(key).cloned()
            }
            fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
                self.data.lock().unwrap().insert(key.to_string(), value.to_string());
                Ok(())
            }
            fn clear(&self, key: &str) {
                self.data.lock().unwrap().remove(key);
            }
        }

        let backend = InMemoryBackend {
            data: Mutex::new(HashMap::new()),
        };
        let store = SessionStore::with_backend(Box::new(backend));

        assert!(!store.has_session("test"));

        store.store_direct("test", "did:key:z6Mk1", "zSeed", "did:key:zVTA", "https://vta.example.com").unwrap();
        assert!(store.has_session("test"));

        let info = store.loaded_session("test").unwrap();
        assert_eq!(info.client_did, "did:key:z6Mk1");
        assert_eq!(info.vta_did, "did:key:zVTA");

        store.logout("test");
        assert!(!store.has_session("test"));
    }
}
