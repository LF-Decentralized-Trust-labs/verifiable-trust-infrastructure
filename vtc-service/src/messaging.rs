use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, ListenerEvent,
    MESSAGE_PICKUP_STATUS_TYPE, RestartPolicy, RetryConfig, Router, TRUST_PING_TYPE, handler_fn,
    ignore_handler, trust_ping_handler,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::AppConfig;

/// Start the DIDComm service and block until shutdown.
///
/// Uses `DIDCommService` for automatic mediator connection management,
/// reconnection with backoff, and typed message routing.
pub async fn run_didcomm_service(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vtc_did: &str,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mediator_did = match &config.messaging {
        Some(m) => &m.mediator_did,
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Collect secrets for the TDKProfile
    let signing_id = format!("{vtc_did}#key-0");
    let ka_id = format!("{vtc_did}#key-1");
    let mut secrets = Vec::new();
    if let Some(s) = secrets_resolver.get_secret(&signing_id).await {
        secrets.push(s);
    } else {
        warn!("VTC signing secret not found — messaging disabled");
        let _ = shutdown_rx.changed().await;
        return;
    }
    if let Some(s) = secrets_resolver.get_secret(&ka_id).await {
        secrets.push(s);
    }

    let profile = TDKProfile::new("VTC", vtc_did, Some(mediator_did), secrets);

    let service_config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: "vtc-main".into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig {
                    initial_delay_secs: 5,
                    max_delay_secs: 60,
                },
            },
            ..Default::default()
        }],
    };

    // Build a minimal router: trust-ping + ignore message-pickup-status
    let router = match Router::new()
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))
        .and_then(|r| r.route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler)))
    {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to build DIDComm router: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    let shutdown_token = CancellationToken::new();
    let service = match DIDCommService::start(service_config, router, shutdown_token.clone()).await
    {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to start DIDComm service: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Wait for the mediator connection
    if let Err(e) = service
        .wait_connected("vtc-main", Duration::from_secs(30))
        .await
    {
        warn!("DIDComm listener not connected after 30s: {e}");
    }

    // Log lifecycle events in background
    let mut event_rx = service.subscribe();
    let event_task = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(ListenerEvent::Connected { listener_id }) => {
                    info!(listener = %listener_id, "DIDComm listener connected");
                }
                Ok(ListenerEvent::Disconnected { listener_id, error }) => {
                    warn!(
                        listener = %listener_id,
                        error = error.as_deref().unwrap_or("none"),
                        "DIDComm listener disconnected"
                    );
                }
                Ok(ListenerEvent::Restarting {
                    listener_id,
                    attempt,
                    delay,
                }) => {
                    info!(
                        listener = %listener_id,
                        attempt,
                        delay_secs = delay.as_secs(),
                        "DIDComm listener restarting"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "DIDComm event logger lagged");
                }
            }
        }
    });

    info!("DIDComm service started");

    // Block until shutdown
    let _ = shutdown_rx.changed().await;

    // Graceful shutdown
    service.shutdown().await;
    event_task.abort();
    info!("DIDComm service stopped");
}
