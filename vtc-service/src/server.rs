use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::keys::seed_store::SecretStore;
use crate::messaging;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::{RwLock, watch};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
}

pub async fn run(
    config: AppConfig,
    store: Store,
    secret_store: Box<dyn SecretStore>,
) -> Result<(), AppError> {
    // Open cached keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;

    // Initialize auth infrastructure
    let (did_resolver, secrets_resolver, jwt_keys) = init_auth(&config, &*secret_store).await;

    // Bind TCP listener on the main thread for early port validation
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let std_listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
    std_listener.set_nonblocking(true).map_err(AppError::Io)?;
    info!("server listening addr={addr}");

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

    // Gather DIDComm thread inputs
    let didcomm_config = config.clone();
    let didcomm_secrets = secrets_resolver.clone();
    let didcomm_vtc_did = config.vtc_did.clone();

    // Gather storage thread inputs
    let storage_sessions_ks = sessions_ks.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    // Build AppState for the REST thread
    let state = AppState {
        sessions_ks,
        acl_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver,
        secrets_resolver,
        jwt_keys,
    };

    // Spawn three named OS threads
    let mut rest_shutdown_rx = shutdown_rx.clone();
    let rest_handle = std::thread::Builder::new()
        .name("vtc-rest".into())
        .spawn(move || run_rest_thread(std_listener, state, &mut rest_shutdown_rx))
        .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?;

    let mut didcomm_shutdown_rx = shutdown_rx.clone();
    let didcomm_handle = std::thread::Builder::new()
        .name("vtc-didcomm".into())
        .spawn(move || {
            run_didcomm_thread(
                didcomm_config,
                didcomm_secrets,
                didcomm_vtc_did,
                &mut didcomm_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn DIDComm thread: {e}")))?;

    let mut storage_shutdown_rx = shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("vtc-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_auth_config,
                has_auth,
                &mut storage_shutdown_rx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Join REST + DIDComm in parallel, then storage last
    let (rest_result, didcomm_result) = tokio::join!(
        tokio::task::spawn_blocking(move || rest_handle.join()),
        tokio::task::spawn_blocking(move || didcomm_handle.join()),
    );

    // If either thread panicked, trigger shutdown for the remaining threads
    let mut any_panic = false;

    match rest_result {
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

    match didcomm_result {
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

        let app = routes::router()
            .with_state(state)
            .layer(TraceLayer::new_for_http());

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
fn run_didcomm_thread(
    config: AppConfig,
    secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    vtc_did: Option<String>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build DIDComm runtime");

    rt.block_on(async {
        info!("DIDComm thread started");

        let (sr, did) = match (&secrets_resolver, &vtc_did) {
            (Some(sr), Some(did)) => (sr, did.as_str()),
            _ => {
                info!("DIDComm not configured — thread idle");
                let _ = shutdown_rx.changed().await;
                info!("DIDComm thread shutting down (idle)");
                return;
            }
        };

        // Initialize ATM connection
        let (atm, profile) = match messaging::init_didcomm_connection(&config, sr, did).await {
            Some(handles) => handles,
            None => {
                let _ = shutdown_rx.changed().await;
                info!("DIDComm thread shutting down (init failed)");
                return;
            }
        };

        // Run message loop until shutdown
        messaging::run_didcomm_loop(&atm, &profile, did, shutdown_rx).await;

        // Graceful ATM shutdown
        info!("DIDComm thread shutting down");
    });
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the VTC DID is not configured (server still starts
/// so the setup wizard can be run first).
///
/// Loads 64 raw bytes from the secret store: first 32 = Ed25519 signing key,
/// last 32 = X25519 key-agreement key.
async fn init_auth(
    config: &AppConfig,
    secret_store: &dyn SecretStore,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
    Option<Arc<JwtKeys>>,
) {
    let vtc_did = match &config.vtc_did {
        Some(did) => did.clone(),
        None => {
            warn!("vtc_did not configured — auth endpoints will not work (run setup first)");
            return (None, None, None);
        }
    };

    // Load key material from secret store (64 bytes: 32 Ed25519 + 32 X25519)
    let key_material = match secret_store.get().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!("no key material found — auth endpoints will not work (run setup first)");
            return (None, None, None);
        }
        Err(e) => {
            warn!("failed to load key material: {e} — auth endpoints will not work");
            return (None, None, None);
        }
    };

    if key_material.len() != 64 {
        warn!(
            "key material is {} bytes, expected 64 — auth endpoints will not work",
            key_material.len()
        );
        return (None, None, None);
    }

    let ed25519_bytes: &[u8; 32] = key_material[..32].try_into().unwrap();
    let x25519_bytes: &[u8; 32] = key_material[32..].try_into().unwrap();

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return (None, None, None);
        }
    };

    // 2. Secrets resolver with VTC's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    let mut signing_secret = Secret::generate_ed25519(None, Some(ed25519_bytes));
    signing_secret.id = format!("{vtc_did}#key-0");
    secrets_resolver.insert(signing_secret).await;

    match Secret::generate_x25519(None, Some(x25519_bytes)) {
        Ok(mut ka_secret) => {
            ka_secret.id = format!("{vtc_did}#key-1");
            secrets_resolver.insert(ka_secret).await;
        }
        Err(e) => warn!("failed to create VTC key-agreement secret: {e}"),
    }

    // 3. JWT signing key from config (random key, not derived from VTC keys)
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None);
            }
        },
        None => {
            warn!(
                "auth.jwt_signing_key not configured — auth endpoints will not work (run setup first)"
            );
            return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None);
        }
    };

    info!("auth initialized for DID {vtc_did}");

    (
        Some(did_resolver),
        Some(Arc::new(secrets_resolver)),
        Some(Arc::new(jwt_keys)),
    )
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes)?;
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
