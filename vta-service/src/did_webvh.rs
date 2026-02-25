use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use dialoguer::{Confirm, Input, Select};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use serde_json::json;

use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};

use crate::config::AppConfig;
use crate::contexts::{self, get_context, store_context};
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyType as SdkKeyType};
use crate::operations::did_webvh as ops;
use crate::setup;
use crate::store::Store;

pub struct CreateDidWebvhArgs {
    pub config_path: Option<PathBuf>,
    pub context: String,
    pub label: Option<String>,
}

pub async fn run_create_did_webvh(
    args: CreateDidWebvhArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let contexts_ks = store.keyspace("contexts")?;

    // Load seed from configured backend using the active generation
    let seed_store = create_seed_store(&config)?;
    let active_seed_id = get_active_seed_id(&keys_ks).await?;
    let seed = load_seed_bytes(&keys_ks, &*seed_store, Some(active_seed_id)).await?;

    // Resolve context
    let mut ctx = match get_context(&contexts_ks, &args.context).await? {
        Some(ctx) => ctx,
        None => {
            eprintln!("Context '{}' does not exist.", args.context);
            let name: String = Input::new()
                .with_prompt("Create it with name")
                .default(args.context.clone())
                .interact_text()?;
            let ctx = contexts::create_context(&contexts_ks, &args.context, &name).await?;
            eprintln!("Created context: {} ({})", ctx.id, ctx.base_path);
            ctx
        }
    };

    let label = args.label.as_deref().unwrap_or(&args.context);

    // Derive entity keys
    let mut derived = keys::derive_entity_keys(
        &seed,
        &ctx.base_path,
        &format!("{label} signing key"),
        &format!("{label} key-agreement key"),
        &keys_ks,
    )
    .await?;

    // Prompt for URL and convert to WebVHURL
    let webvh_url = setup::prompt_webvh_url(label)?;
    let did_id = webvh_url.to_string();

    // Convert the Signing Key ID to did:key format (required by didwebvh-rs)
    derived.signing_secret.id = [
        "did:key:",
        &derived.signing_secret.get_public_keymultibase().unwrap(),
        "#",
        &derived.signing_secret.get_public_keymultibase().unwrap(),
    ]
    .concat();

    // Build base DID document using shared helper (without services)
    let mut did_document = ops::build_did_document(&did_id, &derived, &config, false, &None);

    // Interactive service endpoint selection
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

        match service_choice {
            0 => {
                // Reference the mediator DID for routing
                did_document["service"] = json!([
                    {
                        "id": format!("{did_id}#vta-didcomm"),
                        "type": "DIDCommMessaging",
                        "serviceEndpoint": [{
                            "accept": ["didcomm/v2"],
                            "uri": msg.mediator_did
                        }]
                    }
                ]);
            }
            _ => {} // No service endpoints
        }
    }

    eprintln!();
    eprintln!(
        "\x1b[2mDID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&did_document)?
    );
    eprintln!();

    // Offer to edit in $EDITOR
    if Confirm::new()
        .with_prompt("Edit DID document in your editor?")
        .default(false)
        .interact()?
    {
        did_document = edit_did_document(did_document)?;
    }

    // Portability
    let portable = Confirm::new()
        .with_prompt("Make this DID portable (can move to a different domain later)?")
        .default(true)
        .interact()?;

    // Pre-rotation keys
    let (next_key_hashes, pre_rotation_keys) =
        setup::prompt_pre_rotation_keys(&seed, &ctx.base_path, label, &keys_ks).await?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone()])),
        portable: Some(portable),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(next_key_hashes))
        },
        ..Default::default()
    };

    // Create the log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, &derived.signing_secret)
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

    // Save key records now that we have the final DID
    keys::save_entity_key_records(
        &final_did,
        &derived,
        &keys_ks,
        Some(&ctx.id),
        Some(active_seed_id),
    )
    .await?;

    // Save pre-rotation key records
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            &keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            SdkKeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some(&ctx.id),
            Some(active_seed_id),
        )
        .await?;
    }

    // Update context with the new DID
    ctx.did = Some(final_did.clone());
    ctx.updated_at = Utc::now();
    store_context(&contexts_ks, &ctx)
        .await
        .map_err(|e| format!("{e}"))?;

    // Persist all writes
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
    eprintln!("  Context '{}' updated with DID: {final_did}", ctx.id);

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
                    private_key_multibase: derived.signing_priv.clone(),
                },
                SecretEntry {
                    key_id: format!("{final_did}#key-1"),
                    key_type: SdkKeyType::X25519,
                    private_key_multibase: derived.ka_priv.clone(),
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

fn edit_did_document(
    doc: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::process::Command;

    let json = serde_json::to_string_pretty(&doc)?;

    // Write to a named temp file with .json extension for editor syntax highlighting
    let mut tmp = tempfile::Builder::new().suffix(".json").tempfile()?;
    tmp.write_all(json.as_bytes())?;
    tmp.flush()?;
    let path = tmp.path().to_path_buf();

    // Resolve editor: $VISUAL > $EDITOR > fallback
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    // Open editor and wait
    let status = Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| format!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        return Err(format!("editor exited with {status}").into());
    }

    // Read back and parse
    let edited = std::fs::read_to_string(&path)?;
    let new_doc: serde_json::Value =
        serde_json::from_str(&edited).map_err(|e| format!("invalid JSON from editor: {e}"))?;

    // Basic validation: must be an object with "id" field
    if !new_doc.is_object() || !new_doc.get("id").is_some_and(|v| v.is_string()) {
        return Err("DID document must be a JSON object with an \"id\" field".into());
    }

    // Show the updated document
    eprintln!(
        "\x1b[2mUpdated DID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&new_doc)?
    );

    Ok(new_doc)
}
