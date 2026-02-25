use std::path::PathBuf;
use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use dialoguer::{Confirm, Input, Select};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use serde_json::json;

use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::keys::KeyType as SdkKeyType;

use crate::config::AppConfig;
use crate::keys::seed_store::create_secret_store;
use crate::setup;
use crate::store::Store;

pub struct CreateDidWebvhArgs {
    pub config_path: Option<PathBuf>,
    pub label: Option<String>,
}

pub async fn run_create_did_webvh(
    args: CreateDidWebvhArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;

    // Load key material from configured backend (64 bytes: 32 Ed25519 + 32 X25519)
    let secret_store = create_secret_store(&config)?;
    let key_material = secret_store
        .get()
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or("No key material found. Run `vtc setup` first.")?;

    if key_material.len() != 64 {
        return Err(format!(
            "key material is {} bytes, expected 64. Run `vtc setup` to regenerate.",
            key_material.len()
        )
        .into());
    }

    let ed25519_bytes: &[u8; 32] = key_material[..32].try_into().unwrap();
    let x25519_bytes: &[u8; 32] = key_material[32..].try_into().unwrap();

    let label = args.label.as_deref().unwrap_or("VTC");

    // Create secrets from raw key material
    let mut signing_secret = Secret::generate_ed25519(None, Some(ed25519_bytes));
    let signing_pub = signing_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;
    let signing_priv = signing_secret
        .get_private_keymultibase()
        .map_err(|e| format!("{e}"))?;

    let ka_secret = Secret::generate_x25519(None, Some(x25519_bytes))?;
    let ka_pub = ka_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;
    let ka_priv = ka_secret
        .get_private_keymultibase()
        .map_err(|e| format!("{e}"))?;

    // Prompt for URL and convert to WebVHURL
    let webvh_url = setup::prompt_webvh_url(label)?;
    let did_id = webvh_url.to_string();

    // Convert the Signing Key ID to did:key format (required by didwebvh-rs)
    signing_secret.id = [
        "did:key:",
        &signing_secret.get_public_keymultibase().unwrap(),
        "#",
        &signing_secret.get_public_keymultibase().unwrap(),
    ]
    .concat();

    // Build DID document
    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": &did_id,
        "verificationMethod": [
            {
                "id": format!("{did_id}#key-0"),
                "type": "Multikey",
                "controller": &did_id,
                "publicKeyMultibase": &signing_pub
            }
        ],
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")]
    });

    // Add X25519 key agreement method
    did_document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{did_id}#key-1"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": &ka_pub
        }));
    did_document["keyAgreement"] = json!([format!("{did_id}#key-1")]);

    // Optionally add service endpoints
    if let Some(ref msg) = config.messaging {
        let service_options = &[
            "DIDComm endpoint (references mediator DID for routing)",
            "No service endpoints",
        ];
        let service_choice = Select::new()
            .with_prompt("Service endpoints")
            .items(service_options)
            .default(0)
            .interact()?;

        if service_choice == 0 {
            did_document["service"] = json!([
                {
                    "id": format!("{did_id}#didcomm"),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "accept": ["didcomm/v2"],
                        "uri": msg.mediator_did
                    }]
                }
            ]);
        }
    }

    // Add VTC service endpoint if public URL is configured
    if let Some(ref url) = config.public_url {
        let services = did_document
            .get_mut("service")
            .and_then(|s| s.as_array_mut());
        let vtc_service = json!({
            "id": format!("{did_id}#vtc"),
            "type": "VerifiableTrustCommunity",
            "serviceEndpoint": url
        });
        match services {
            Some(arr) => arr.push(vtc_service),
            None => {
                did_document["service"] = json!([vtc_service]);
            }
        }
    }

    eprintln!();
    eprintln!(
        "\x1b[2mDID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&did_document)?
    );
    eprintln!();

    // Portability
    let portable = Confirm::new()
        .with_prompt("Make this DID portable (can move to a different domain later)?")
        .default(true)
        .interact()?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![signing_pub.clone()])),
        portable: Some(portable),
        ..Default::default()
    };

    // Create the log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, &signing_secret)
        .map_err(|e| format!("Failed to create DID log entry: {e}"))?;

    let scid = did_state.scid.clone();
    let log_entry_state = did_state.log_entries.last().unwrap();

    let fallback_did = format!("did:webvh:{scid}:{}", webvh_url.domain);
    let final_did = match log_entry_state.log_entry.get_did_document() {
        Ok(doc) => doc
            .get("id")
            .and_then(|id| id.as_str())
            .map(String::from)
            .unwrap_or(fallback_did),
        Err(_) => fallback_did,
    };

    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Persist store
    store.persist().await?;

    // Save did.jsonl
    let default_file = format!("{label}-did.jsonl");
    let did_file: String = Input::new()
        .with_prompt("Save DID log to file")
        .default(default_file)
        .interact_text()?;

    log_entry_state
        .log_entry
        .save_to_file(&did_file)
        .map_err(|e| format!("Failed to save DID log file: {e}"))?;

    eprintln!("  DID log saved to: {did_file}");

    // Optionally export secrets bundle
    if Confirm::new()
        .with_prompt("Export DID secrets bundle?")
        .default(false)
        .interact()?
    {
        let bundle = DidSecretsBundle {
            did: final_did.clone(),
            secrets: vec![
                SecretEntry {
                    key_id: format!("{final_did}#key-0"),
                    key_type: SdkKeyType::Ed25519,
                    private_key_multibase: signing_priv.clone(),
                },
                SecretEntry {
                    key_id: format!("{final_did}#key-1"),
                    key_type: SdkKeyType::X25519,
                    private_key_multibase: ka_priv.clone(),
                },
            ],
        };
        let encoded = bundle.encode().map_err(|e| format!("{e}"))?;
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: The secrets bundle contains private keys.      ║");
        eprintln!("║  Store it securely and do not share it publicly.         ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        println!("{encoded}");
        eprintln!();
    }

    Ok(())
}
