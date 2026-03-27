use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use ed25519_dalek_bip32::ExtendedSigningKey;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::auth::AuthState;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
#[cfg(feature = "didcomm")]
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::derivation::Bip32Extension;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::load_seed_bytes;
#[cfg(feature = "didcomm")]
use crate::messaging;
#[cfg(feature = "rest")]
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::{RwLock, watch};
#[cfg(feature = "rest")]
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info, warn};

/// TEE context passed by the caller (main.rs or vta-enclave).
/// None when running outside a TEE.
///
/// When the `tee` feature is not compiled in, this is a unit struct
/// that is never constructed — callers pass `None::<TeeContext>`.
#[derive(Clone)]
#[cfg(feature = "tee")]
pub struct TeeContext {
    pub state: crate::tee::TeeState,
    pub mnemonic_guard: Option<Arc<crate::tee::mnemonic_guard::MnemonicExportGuard>>,
}

/// Stub type when TEE is not compiled in. Never constructed.
#[derive(Clone)]
#[cfg(not(feature = "tee"))]
pub struct TeeContext(());


#[derive(Clone)]
pub struct AppState {
    pub keys_ks: KeyspaceHandle,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    pub config: Arc<RwLock<AppConfig>>,
    pub seed_store: Arc<dyn SeedStore>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    #[cfg(feature = "didcomm")]
    pub didcomm_bridge: Arc<tokio::sync::RwLock<Option<DIDCommBridge>>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub atm: Option<ATM>,
    pub tee: Option<TeeContext>,
}

impl AuthState for AppState {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
        self.jwt_keys.as_ref()
    }
    fn sessions_ks(&self) -> &KeyspaceHandle {
        &self.sessions_ks
    }
}

/// Build the shared application state from config, store, and TEE context.
///
/// Use this to construct `AppState` without the full thread orchestration
/// of `run()`. Useful for non-axum front-ends (e.g., Lambda handlers)
/// that need the state but manage their own request loop.
pub async fn build_app_state(
    config: AppConfig,
    store: &Store,
    seed_store: Arc<dyn SeedStore>,
    storage_encryption_key: Option<[u8; 32]>,
    tee_context: Option<TeeContext>,
) -> Result<AppState, AppError> {
    let apply_encryption = |ks: KeyspaceHandle| -> KeyspaceHandle {
        if let Some(key) = storage_encryption_key {
            ks.with_encryption(key)
        } else {
            ks
        }
    };

    let keys_ks = apply_encryption(store.keyspace("keys")?);
    let sessions_ks = apply_encryption(store.keyspace("sessions")?);
    let acl_ks = apply_encryption(store.keyspace("acl")?);
    let contexts_ks = apply_encryption(store.keyspace("contexts")?);
    let audit_ks = apply_encryption(store.keyspace("audit")?);
    #[cfg(feature = "webvh")]
    let webvh_ks = apply_encryption(store.keyspace("webvh")?);

    let (did_resolver, secrets_resolver, jwt_keys, atm) =
        init_auth(&config, &*seed_store, &keys_ks).await;

    Ok(AppState {
        keys_ks,
        sessions_ks,
        acl_ks,
        contexts_ks,
        audit_ks,
        #[cfg(feature = "webvh")]
        webvh_ks,
        config: Arc::new(RwLock::new(config)),
        seed_store,
        did_resolver,
        secrets_resolver,
        #[cfg(feature = "didcomm")]
        didcomm_bridge: Arc::new(tokio::sync::RwLock::new(None)),
        jwt_keys,
        atm,
        tee: tee_context,
    })
}

pub async fn run(
    config: AppConfig,
    store: Store,
    seed_store: Arc<dyn SeedStore>,
    storage_encryption_key: Option<[u8; 32]>,
    tee_context: Option<TeeContext>,
) -> Result<(), AppError> {
    // Determine which services will actually start (feature flag AND config)
    let rest_enabled = cfg!(feature = "rest") && config.services.rest;
    let didcomm_enabled = cfg!(feature = "didcomm") && config.services.didcomm;

    if !rest_enabled && !didcomm_enabled {
        return Err(AppError::Config(
            "no services enabled — enable at least one of REST or DIDComm \
             (check [services] config and compile-time features)"
                .into(),
        ));
    }

    // Open cached keyspace handles with optional encryption.
    let apply_encryption = |ks: KeyspaceHandle| -> KeyspaceHandle {
        match storage_encryption_key {
            Some(key) => {
                info!("storage encryption enabled for keyspace");
                ks.with_encryption(key)
            }
            None => ks,
        }
    };

    let keys_ks = apply_encryption(store.keyspace("keys")?);
    let sessions_ks = apply_encryption(store.keyspace("sessions")?);
    let acl_ks = apply_encryption(store.keyspace("acl")?);
    let contexts_ks = apply_encryption(store.keyspace("contexts")?);
    let audit_ks = apply_encryption(store.keyspace("audit")?);
    #[cfg(feature = "webvh")]
    let webvh_ks = apply_encryption(store.keyspace("webvh")?);

    // Initialize auth infrastructure
    let (did_resolver, secrets_resolver, jwt_keys, atm) =
        init_auth(&config, &*seed_store, &keys_ks).await;

    // In TEE required mode, warn if auth isn't initialized.
    #[cfg(feature = "tee")]
    if config.tee.mode == crate::config::TeeMode::Required && jwt_keys.is_none() {
        warn!(
            "TEE mode is 'required' but authentication is not initialized \
             (vta_did not configured). The VTA will start but authenticated \
             endpoints will return 401."
        );
    }

    // Bind TCP listener only if REST is enabled
    #[cfg(feature = "rest")]
    let std_listener = if config.services.rest {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("server listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    // Shutdown coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn signal handler on the main tokio runtime
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        }
    });

    // Gather storage thread inputs
    let storage_sessions_ks = sessions_ks.clone();
    let storage_audit_ks = audit_ks.clone();
    let storage_audit_config = config.audit.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    // Shared DIDComm bridge (set by the DIDComm thread once ATM is ready)
    #[cfg(feature = "didcomm")]
    let didcomm_bridge: Arc<tokio::sync::RwLock<Option<DIDCommBridge>>> = Arc::new(tokio::sync::RwLock::new(None));

    // Clone handles for DIDComm before REST takes ownership
    #[cfg(feature = "didcomm")]
    let didcomm_state = if config.services.didcomm {
        Some(messaging::DidcommState {
            keys_ks: keys_ks.clone(),
            acl_ks: acl_ks.clone(),
            contexts_ks: contexts_ks.clone(),
            audit_ks: audit_ks.clone(),
            #[cfg(feature = "webvh")]
            webvh_ks: webvh_ks.clone(),
            seed_store: seed_store.clone(),
            config: Arc::new(RwLock::new(config.clone())),
            did_resolver: did_resolver.clone(),
            didcomm_bridge: didcomm_bridge.clone(),
            #[cfg(feature = "tee")]
            tee_state: tee_context.as_ref().and_then(|tc| Some(tc.state.clone())),
        })
    } else {
        None
    };

    // Spawn REST thread (conditional)
    #[cfg(feature = "rest")]
    let rest_handle = if let Some(listener) = std_listener {
        // Build AppState for the REST thread
        let state = AppState {
            keys_ks,
            sessions_ks,
            acl_ks,
            contexts_ks,
            audit_ks,
            #[cfg(feature = "webvh")]
            webvh_ks,
            config: Arc::new(RwLock::new(config.clone())),
            seed_store,
            did_resolver,
            secrets_resolver: secrets_resolver.clone(),
            #[cfg(feature = "didcomm")]
            didcomm_bridge: didcomm_bridge.clone(),
            jwt_keys,
            atm,
            tee: tee_context.clone(),
        };
        let mut rest_shutdown_rx = shutdown_rx.clone();
        Some(
            std::thread::Builder::new()
                .name("vta-rest".into())
                .spawn(move || run_rest_thread(listener, state, &mut rest_shutdown_rx))
                .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?,
        )
    } else {
        None
    };
    #[cfg(not(feature = "rest"))]
    let rest_handle: Option<std::thread::JoinHandle<()>> = None;

    // Spawn DIDComm thread (conditional)
    #[cfg(feature = "didcomm")]
    let didcomm_handle = if let Some(didcomm_state) = didcomm_state {
        let didcomm_secrets = secrets_resolver;
        let didcomm_vta_did = config.vta_did.clone();
        let mut didcomm_shutdown_rx = shutdown_rx.clone();
        let didcomm_bridge_lock = didcomm_bridge;
        Some(
            std::thread::Builder::new()
                .name("vta-didcomm".into())
                .spawn(move || {
                    run_didcomm_thread(
                        didcomm_secrets,
                        didcomm_vta_did,
                        didcomm_state,
                        &mut didcomm_shutdown_rx,
                        didcomm_bridge_lock,
                    )
                })
                .map_err(|e| AppError::Internal(format!("failed to spawn DIDComm thread: {e}")))?,
        )
    } else {
        None
    };
    #[cfg(not(feature = "didcomm"))]
    let didcomm_handle: Option<std::thread::JoinHandle<()>> = None;

    // Storage thread always runs
    let mut storage_shutdown_rx = shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("vta-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_audit_ks,
                storage_audit_config,
                storage_auth_config,
                has_auth,
                &mut storage_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Join service threads
    let mut any_panic = false;

    if let Some(handle) = rest_handle {
        match tokio::task::spawn_blocking(move || handle.join()).await {
            Ok(Ok(())) => info!("REST thread stopped"),
            Ok(Err(_panic)) => {
                error!("REST thread panicked");
                any_panic = true;
            }
            Err(e) => {
                error!("failed to join REST thread: {e}");
                any_panic = true;
            }
        }
    }

    if let Some(handle) = didcomm_handle {
        match tokio::task::spawn_blocking(move || handle.join()).await {
            Ok(Ok(())) => info!("DIDComm thread stopped"),
            Ok(Err(_panic)) => {
                error!("DIDComm thread panicked");
                any_panic = true;
            }
            Err(e) => {
                error!("failed to join DIDComm thread: {e}");
                any_panic = true;
            }
        }
    }

    if any_panic {
        let _ = shutdown_tx.send(true);
    }

    // Join storage last — guarantees all writes flushed before database closes
    match storage_handle.join() {
        Ok(()) => info!("storage thread stopped"),
        Err(_panic) => {
            error!("storage thread panicked");
            any_panic = true;
        }
    }

    if any_panic {
        return Err(AppError::Internal("one or more threads panicked".into()));
    }

    info!("server shut down");
    Ok(())
}

/// Storage thread: runs session cleanup loop and persists the store on shutdown.
fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
    audit_ks: KeyspaceHandle,
    audit_config: crate::config::AuditConfig,
    auth_config: AuthConfig,
    has_auth: bool,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");

        if has_auth {
            let interval = Duration::from_secs(auth_config.session_cleanup_interval);
            let mut timer = tokio::time::interval(interval);
            // First tick completes immediately; skip it so cleanup doesn't run at startup
            timer.tick().await;

            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                            warn!("session cleanup error: {e}");
                        }
                        // Also clean up expired audit logs
                        let audit_retention = audit_config.retention_days;
                        if let Err(e) = crate::audit::cleanup_expired_logs(&audit_ks, audit_retention).await {
                            warn!("audit cleanup error: {e}");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        info!("storage thread shutting down");
                        break;
                    }
                }
            }
        } else {
            // No auth — just wait for shutdown
            let _ = shutdown_rx.changed().await;
            info!("storage thread shutting down");
        }

        // Persist store before closing
        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

/// REST thread: serves the Axum HTTP server.
#[cfg(feature = "rest")]
fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        info!("REST thread started");

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        let traced_routes = routes::router().with_state(state.clone()).layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        );
        let app = traced_routes.merge(routes::health_router().with_state(state));

        let shutdown_rx = shutdown_rx.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let mut rx = shutdown_rx;
                let _ = rx.changed().await;
            })
            .await
            .expect("axum serve failed");

        info!("REST thread shutting down");
    });
}

/// DIDComm thread: connects to the mediator and processes inbound messages.
///
/// Retries with exponential backoff (5 s -> 60 s cap) when the mediator
/// connection fails or drops. The bridge is cleared while reconnecting so
/// REST handlers can report the correct status.
#[cfg(feature = "didcomm")]
fn run_didcomm_thread(
    secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    vta_did: Option<String>,
    state: messaging::DidcommState,
    shutdown_rx: &mut watch::Receiver<bool>,
    bridge_lock: Arc<tokio::sync::RwLock<Option<DIDCommBridge>>>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build DIDComm runtime");

    rt.block_on(async {
        info!("DIDComm thread started");

        let (sr, did) = match (&secrets_resolver, &vta_did) {
            (Some(sr), Some(did)) => (sr, did.as_str()),
            _ => {
                info!("DIDComm not configured — thread idle");
                let _ = shutdown_rx.changed().await;
                info!("DIDComm thread shutting down (idle)");
                return;
            }
        };

        let state = Arc::new(state);
        let mut delay_secs: u64 = 5;
        let max_delay_secs: u64 = 60;
        let mut attempt: u32 = 0;

        loop {
            // Read fresh config each attempt (in case it changed)
            let config = state.config.read().await.clone();

            // Try to initialize the DIDComm connection
            let (atm, profile) = match messaging::init_didcomm_connection(&config, sr, did).await {
                Some(handles) => {
                    if attempt > 0 {
                        info!("DIDComm connection established after {attempt} retries");
                    } else {
                        info!("DIDComm connection established");
                    }
                    delay_secs = 5; // Reset backoff on success
                    attempt = 0;
                    handles
                }
                None => {
                    attempt += 1;
                    warn!(
                        attempt,
                        retry_in_secs = delay_secs,
                        "DIDComm connection failed — retrying"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {
                            delay_secs = (delay_secs * 2).min(max_delay_secs);
                            continue;
                        }
                        _ = shutdown_rx.changed() => {
                            info!("DIDComm thread shutting down");
                            return;
                        }
                    }
                }
            };

            // Publish bridge for REST/WebVH handlers
            let bridge = DIDCommBridge::new(atm.clone(), profile.clone());
            *bridge_lock.write().await = Some(bridge);

            // Run the message loop — get a fresh reference from the lock
            {
                let guard = bridge_lock.read().await;
                let bridge = guard.as_ref().unwrap();
                messaging::run_didcomm_loop(bridge, did, Arc::clone(&state), shutdown_rx).await;
            }

            // Message loop exited — connection lost
            // Clear bridge so REST handlers know we're reconnecting
            *bridge_lock.write().await = None;

            // Graceful ATM shutdown
            atm.graceful_shutdown().await;

            // Check if this is a shutdown or a reconnect
            if *shutdown_rx.borrow() {
                info!("DIDComm thread shutting down");
                return;
            }

            attempt += 1;
            warn!(
                retry_in_secs = delay_secs,
                "DIDComm connection lost — reconnecting"
            );
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(delay_secs)) => {
                    delay_secs = (delay_secs * 2).min(max_delay_secs);
                }
                _ = shutdown_rx.changed() => {
                    info!("DIDComm thread shutting down");
                    return;
                }
            }
        }
    });
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the VTA DID is not configured (server still starts
/// so the setup wizard can be run first).
async fn init_auth(
    config: &AppConfig,
    seed_store: &dyn SeedStore,
    keys_ks: &KeyspaceHandle,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
    Option<Arc<JwtKeys>>,
    Option<ATM>,
) {
    let vta_did = match &config.vta_did {
        Some(did) => did.clone(),
        None => {
            warn!("vta_did not configured — auth endpoints will not work (run setup first)");
            return (None, None, None, None);
        }
    };

    // Look up VTA key paths from stored key records
    let (signing_path, ka_path, vta_seed_id) = match find_vta_key_paths(&vta_did, keys_ks).await {
        Ok(paths) => paths,
        Err(e) => {
            warn!(
                "failed to find VTA key records: {e} — auth endpoints will not work (run setup first)"
            );
            return (None, None, None, None);
        }
    };

    // Load seed for VTA keys (uses the seed generation from the key record)
    let seed = match load_seed_bytes(keys_ks, seed_store, vta_seed_id).await {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to load seed: {e} — auth endpoints will not work");
            return (None, None, None, None);
        }
    };

    let root = match ExtendedSigningKey::from_seed(&seed) {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create BIP-32 root key: {e} — auth endpoints will not work");
            return (None, None, None, None);
        }
    };

    // 1. DID resolver (network mode if resolver_url is set, local mode otherwise)
    let resolver_config = {
        let mut builder = DIDCacheConfigBuilder::default();
        if let Some(ref url) = config.resolver_url {
            info!(url = %url, "DID resolver using network mode (remote resolver)");
            builder = builder.with_network_mode(url);
        } else {
            info!("DID resolver using local mode");
        }
        builder.build()
    };
    let did_resolver = match DIDCacheClient::new(resolver_config).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return (None, None, None, None);
        }
    };

    // 2. Secrets resolver with VTA's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Load stored key records for validation
    let stored_signing: Option<KeyRecord> = keys_ks
        .get(crate::keys::store_key(&format!("{vta_did}#key-0")))
        .await
        .ok()
        .flatten();
    let stored_ka: Option<KeyRecord> = keys_ks
        .get(crate::keys::store_key(&format!("{vta_did}#key-1")))
        .await
        .ok()
        .flatten();

    // Derive and insert VTA signing secret (Ed25519)
    match root.derive_ed25519(&signing_path) {
        Ok(mut signing_secret) => {
            // Validate: runtime key must match what was stored at DID creation time
            if let Some(ref record) = stored_signing {
                match signing_secret.get_public_keymultibase() {
                    Ok(runtime_pub) if runtime_pub != record.public_key => {
                        error!(
                            key_id = %format!("{vta_did}#key-0"),
                            stored = %record.public_key,
                            runtime = %runtime_pub,
                            "SIGNING KEY MISMATCH: runtime-derived Ed25519 public key does not match \
                             the key stored in the key record (and published in the DID document). \
                             DIDComm message signing/verification will fail. \
                             This likely means the DID was created with different code or seed."
                        );
                    }
                    Ok(runtime_pub) => {
                        info!(key_id = %format!("{vta_did}#key-0"), pub_key = %runtime_pub, "signing key validated");
                    }
                    Err(e) => warn!("could not extract signing public key for validation: {e}"),
                }
            }
            signing_secret.id = format!("{vta_did}#key-0");
            secrets_resolver.insert(signing_secret).await;
        }
        Err(e) => warn!("failed to derive VTA signing key: {e}"),
    }

    // Derive and insert VTA key-agreement secret (X25519)
    match root.derive_x25519(&ka_path) {
        Ok(mut ka_secret) => {
            // Validate: runtime key must match what was stored at DID creation time
            if let Some(ref record) = stored_ka {
                match ka_secret.get_public_keymultibase() {
                    Ok(runtime_pub) if runtime_pub != record.public_key => {
                        error!(
                            key_id = %format!("{vta_did}#key-1"),
                            stored = %record.public_key,
                            runtime = %runtime_pub,
                            "KEY-AGREEMENT KEY MISMATCH: runtime-derived X25519 public key does not match \
                             the key stored in the key record (and published in the DID document). \
                             DIDComm encryption/decryption will fail. Others will encrypt to the DID \
                             document key but this VTA holds a different private key. \
                             The DID document must be updated or the VTA identity must be regenerated."
                        );
                    }
                    Ok(runtime_pub) => {
                        info!(key_id = %format!("{vta_did}#key-1"), pub_key = %runtime_pub, "key-agreement key validated");
                    }
                    Err(e) => warn!("could not extract KA public key for validation: {e}"),
                }
            }
            ka_secret.id = format!("{vta_did}#key-1");
            secrets_resolver.insert(ka_secret).await;
        }
        Err(e) => warn!("failed to derive VTA key-agreement key: {e}"),
    }

    // 3. JWT signing key from config (random key, not BIP-32 derived)
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None, None);
            }
        },
        None => {
            warn!(
                "auth.jwt_signing_key not configured — auth endpoints will not work (run setup first)"
            );
            return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None, None);
        }
    };

    // 4. Build ATM for DIDComm message unpacking (used by auth endpoints)
    let secrets_resolver = Arc::new(secrets_resolver);
    let atm = {
        let tdk_config = TDKConfig::builder()
            .with_did_resolver(did_resolver.clone())
            .with_secrets_resolver((*secrets_resolver).clone())
            .with_load_environment(false)
            .build();
        match tdk_config {
            Ok(cfg) => match TDKSharedState::new(cfg).await {
                Ok(tdk) => match ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk)).await {
                    Ok(a) => Some(a),
                    Err(e) => {
                        warn!("failed to create ATM for auth unpack: {e}");
                        None
                    }
                },
                Err(e) => {
                    warn!("failed to create TDK shared state: {e}");
                    None
                }
            },
            Err(e) => {
                warn!("failed to build TDK config: {e}");
                None
            }
        }
    };

    info!("auth initialized for DID {vta_did}");

    (
        Some(did_resolver),
        Some(secrets_resolver),
        Some(Arc::new(jwt_keys)),
        atm,
    )
}

/// Look up VTA signing and key-agreement derivation paths from stored key records.
///
/// Uses direct lookups by `{vta_did}#key-0` and `{vta_did}#key-1`.
///
/// Returns `(signing_path, ka_path, seed_id)` where `seed_id` comes from
/// the signing key record.
async fn find_vta_key_paths(
    vta_did: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<(String, String, Option<u32>), AppError> {
    let signing_key_id = format!("{vta_did}#key-0");
    let ka_key_id = format!("{vta_did}#key-1");

    let signing: KeyRecord = keys_ks
        .get(crate::keys::store_key(&signing_key_id))
        .await?
        .ok_or_else(|| AppError::NotFound("VTA signing key not found".into()))?;
    let ka: KeyRecord = keys_ks
        .get(crate::keys::store_key(&ka_key_id))
        .await?
        .ok_or_else(|| AppError::NotFound("VTA key-agreement key not found".into()))?;

    debug!(signing_path = %signing.derivation_path, ka_path = %ka.derivation_path, "VTA key paths resolved");
    Ok((signing.derivation_path, ka.derivation_path, signing.seed_id))
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes, "VTA")?;
    debug!("JWT signing key decoded successfully");
    Ok(keys)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}
