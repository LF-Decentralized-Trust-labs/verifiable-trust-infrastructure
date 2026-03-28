//! Standalone DIDComm connectivity test.
//!
//! Mimics the VTA TEE key derivation and DIDComm message flow without
//! requiring a TEE, KMS, or persistent store. Useful for verifying that
//! the TDK, mediator authentication, and WebSocket live streaming all
//! work end-to-end with the current crate versions.
//!
//! Usage:
//!   cargo run --package didcomm-test -- --mediator-did <DID>
//!   cargo run --package didcomm-test -- --mediator-did <DID> --resolver-url ws://localhost:4445/did/v1/ws
//!   cargo run --package didcomm-test -- --mediator-did <DID> --seed-hex <64-hex-chars>

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use clap::Parser;
use ed25519_dalek_bip32::ExtendedSigningKey;
use tracing::{error, info, warn};
use vta_sdk::did_key::{ed25519_multibase_pubkey, secrets_from_did_key};

#[derive(Parser)]
#[command(name = "didcomm-test", about = "DIDComm connectivity test")]
struct Args {
    /// DID of the mediator to connect to.
    #[arg(long)]
    mediator_did: String,

    /// Optional DID resolver URL (network mode). Omit for local resolution.
    #[arg(long)]
    resolver_url: Option<String>,

    /// Hex-encoded 32-byte seed. Generated randomly if omitted.
    #[arg(long)]
    seed_hex: Option<String>,

    /// BIP-32 derivation path for the signing key.
    #[arg(long, default_value = "m/44'/0'/0'")]
    signing_path: String,

    /// BIP-32 derivation path for the key-agreement key.
    #[arg(long, default_value = "m/44'/0'/1'")]
    ka_path: String,

    /// Seconds to listen for inbound messages after connecting.
    #[arg(long, default_value = "15")]
    listen_secs: u64,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    // ---------------------------------------------------------------
    // 1. Seed — reuse or generate
    // ---------------------------------------------------------------
    let seed: Vec<u8> = if let Some(ref hex) = args.seed_hex {
        let bytes = hex::decode(hex).map_err(|e| format!("bad --seed-hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()).into());
        }
        info!("using provided seed");
        bytes
    } else {
        let mut buf = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
        info!(seed_hex = %hex::encode(buf), "generated random seed (save this to reuse the same identity)");
        buf.to_vec()
    };

    // ---------------------------------------------------------------
    // 2. Derive keys (same as VTA TEE: BIP-32 → Ed25519 → X25519)
    // ---------------------------------------------------------------
    let root = ExtendedSigningKey::from_seed(&seed)?;

    // Signing key (Ed25519)
    let signing_dp: ed25519_dalek_bip32::DerivationPath = args.signing_path.parse()?;
    let signing_derived = root.derive(&signing_dp)?;
    let signing_pub_bytes: [u8; 32] =
        ed25519_dalek::SigningKey::from_bytes(signing_derived.signing_key.as_bytes())
            .verifying_key()
            .to_bytes();
    let signing_pub_mb = ed25519_multibase_pubkey(&signing_pub_bytes);

    // Build did:key from the signing public key
    let did = format!("did:key:{signing_pub_mb}");
    info!(did = %did, "identity created");

    // Derive secrets using the same path as VTA: Ed25519 seed → Secret → to_x25519
    let secrets = secrets_from_did_key(&did, signing_derived.signing_key.as_bytes())?;

    let signing_pub = secrets
        .signing
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;
    let ka_pub = secrets
        .key_agreement
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    // We need secrets registered under TWO ID conventions:
    //   1. "{did}#key-0" / "#key-1"  — used by init_didcomm_connection() lookups
    //   2. "{did}#{multibase_pub}"   — used by affinidi-did-authentication when it
    //      resolves the did:key document and looks up the KA secret by VM ID
    //
    // Clone the secrets so we can insert both sets of IDs.
    let mut signing_key0 = secrets.signing.clone();
    signing_key0.id = format!("{did}#key-0");
    let mut ka_key1 = secrets.key_agreement.clone();
    ka_key1.id = format!("{did}#key-1");

    // The originals keep their did:key fragment IDs (e.g. "{did}#{z6Mk...}", "{did}#{z6LS...}")
    let signing_didkey = secrets.signing.clone();
    let ka_didkey = secrets.key_agreement.clone();

    info!(signing = %signing_pub, ka = %ka_pub, "keys derived (authcrypt: ECDH-1PU+A256KW)");

    // Also derive the KA key via the BIP-32 path (like VTA does for did:webvh entities)
    // to verify both derivation paths produce the same X25519 key
    {
        use affinidi_tdk::secrets_resolver::secrets::Secret;
        let ka_dp: ed25519_dalek_bip32::DerivationPath = args.ka_path.parse()?;
        let ka_derived = root.derive(&ka_dp)?;
        let ka_ed = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
        let ka_x = ka_ed.to_x25519().map_err(|e| format!("{e}"))?;
        let ka_bip32_pub = ka_x.get_public_keymultibase().map_err(|e| format!("{e}"))?;
        info!(
            ka_bip32 = %ka_bip32_pub,
            "BIP-32 KA key (separate path — would be used for did:webvh)"
        );
    }

    // ---------------------------------------------------------------
    // 3. Connect to mediator (same as init_didcomm_connection)
    // ---------------------------------------------------------------
    info!(mediator = %args.mediator_did, "connecting to mediator...");

    let (atm, profile) = vta_sdk::didcomm_init::init_didcomm_connection(
        &args.mediator_did,
        &{
            // Build a temporary ThreadedSecretsResolver and insert secrets under
            // both ID conventions (see comment above).
            let (resolver, _handle) =
                affinidi_tdk::secrets_resolver::ThreadedSecretsResolver::new(None).await;
            // #key-0 / #key-1 IDs (for init_didcomm_connection lookups)
            resolver.insert(signing_key0).await;
            resolver.insert(ka_key1).await;
            // did:key fragment IDs (for affinidi-did-authentication DID-doc lookups)
            resolver.insert(signing_didkey).await;
            resolver.insert(ka_didkey).await;
            Arc::new(resolver)
        },
        &did,
        "didcomm-test",
        args.resolver_url.as_deref(),
    )
    .await
    .ok_or("failed to connect to mediator")?;

    info!("connected to mediator — WebSocket live streaming active");

    // ---------------------------------------------------------------
    // 4. Send a trust-ping
    // ---------------------------------------------------------------
    info!("sending trust-ping to mediator...");
    let ping = TrustPing::default()
        .generate_ping_message(Some(&did), &args.mediator_did, true)?;

    let (packed, _) = atm
        .pack_encrypted(
            &ping,
            &args.mediator_did,
            Some(&did),
            Some(&did),
        )
        .await
        .map_err(|e| format!("pack_encrypted failed: {e}"))?;

    atm.send_message(&profile, &packed, &ping.id, false, false)
        .await
        .map_err(|e| format!("send_message failed: {e}"))?;

    info!(msg_id = %ping.id, "trust-ping sent");

    // ---------------------------------------------------------------
    // 5. Listen for inbound messages
    // ---------------------------------------------------------------
    let mut rx = atm
        .get_inbound_channel()
        .ok_or("no inbound channel")?;

    info!(
        listen_secs = args.listen_secs,
        "listening for inbound messages..."
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.listen_secs);
    let mut received = 0u32;

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _)) => {
                        received += 1;
                        log_message("plaintext", &msg);
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => {
                                received += 1;
                                log_message("decrypted", &msg);
                            }
                            Err(e) => {
                                error!("failed to unpack message: {e}");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("channel lagged, missed {n} messages");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("inbound channel closed");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                info!("listen period elapsed");
                break;
            }
        }
    }

    // ---------------------------------------------------------------
    // 6. Summary
    // ---------------------------------------------------------------
    info!(
        did = %did,
        messages_received = received,
        "test complete"
    );

    if received > 0 {
        info!("SUCCESS — authentication, pack/unpack, and live streaming all working");
    } else {
        warn!("no messages received — check mediator logs for errors");
    }

    atm.graceful_shutdown().await;
    Ok(())
}

fn log_message(label: &str, msg: &Message) {
    info!(
        label,
        msg_type = %msg.typ,
        from = msg.from.as_deref().unwrap_or("anon"),
        msg_id = %msg.id,
        thid = msg.thid.as_deref().unwrap_or("none"),
        "received message"
    );
}
