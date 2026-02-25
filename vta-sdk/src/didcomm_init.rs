use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use tracing::{info, warn};

/// Initialize a DIDComm connection to a mediator.
///
/// Connects over WebSocket and returns the ATM and profile handles needed
/// for inbound/outbound messaging. The `service_label` is used in log messages
/// (e.g. `"VTA"` or `"VTC"`).
pub async fn init_didcomm_connection(
    mediator_did: &str,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    service_did: &str,
    service_label: &str,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    // Create TDK shared state and copy secrets from the shared resolver
    let tdk = TDKSharedState::default().await;

    let signing_id = format!("{service_did}#key-0");
    let ka_id = format!("{service_did}#key-1");

    if let Some(secret) = secrets_resolver.get_secret(&signing_id).await {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("{service_label} signing secret not found — messaging disabled");
        return None;
    }

    if let Some(secret) = secrets_resolver.get_secret(&ka_id).await {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("{service_label} key-agreement secret not found — messaging disabled");
        return None;
    }

    // Build ATM with inbound message channel
    let atm_config = match ATMConfig::builder()
        .with_inbound_message_channel(100)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to build ATM config: {e} — messaging disabled");
            return None;
        }
    };

    let atm = match ATM::new(atm_config, Arc::new(tdk)).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e} — messaging disabled");
            return None;
        }
    };

    // Create profile with mediator
    let profile = match ATMProfile::new(
        &atm,
        None,
        service_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!("failed to create ATM profile: {e} — messaging disabled");
            return None;
        }
    };

    // Enable WebSocket (auto-starts live streaming from mediator)
    if let Err(e) = atm.profile_enable_websocket(&profile).await {
        warn!("failed to enable websocket: {e} — messaging disabled");
        return None;
    }

    let atm = Arc::new(atm);

    info!("messaging initialized — connected to mediator");
    Some((atm, profile))
}

/// Handle an inbound trust-ping by sending a pong response.
pub async fn handle_trust_ping(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    service_did: &str,
    ping: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = ping
        .from
        .as_deref()
        .ok_or("trust-ping has no 'from' DID — cannot send pong")?;

    info!(from = sender_did, "received trust-ping");

    let pong = TrustPing::default().generate_pong_message(ping, Some(service_did))?;

    let (packed, _) = atm
        .pack_encrypted(
            &pong,
            sender_did,
            Some(service_did),
            Some(service_did),
            None,
        )
        .await?;

    atm.send_message(profile, &packed, &pong.id, false, false)
        .await?;

    info!(to = sender_did, "sent trust-pong");
    Ok(())
}
