use std::path::PathBuf;
use std::sync::Arc;

use affinidi_tdk::{
    affinidi_crypto::ed25519::ed25519_private_to_x25519, secrets_resolver::secrets::Secret,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::{Confirm, Input, Select};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use rand::Rng;
use serde_json::json;
use url::Url;

use didwebvh_rs::url::WebVHURL;
use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::keys::KeyType as SdkKeyType;
use vta_sdk::session::resolve_mediator_did;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::credentials::generate_did_key;
use crate::config::{
    AppConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, SecretsConfig, ServerConfig,
    StoreConfig,
};
use crate::keys::seed_store::create_secret_store;
use crate::store::Store;

/// Prompt for secret store backend configuration based on compiled features.
fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let mut labels: Vec<&str> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();

    #[cfg(feature = "aws-secrets")]
    {
        labels.push("AWS Secrets Manager");
        tags.push("aws");
    }

    #[cfg(feature = "gcp-secrets")]
    {
        labels.push("GCP Secret Manager");
        tags.push("gcp");
    }

    #[cfg(feature = "azure-secrets")]
    {
        labels.push("Azure Key Vault");
        tags.push("azure");
    }

    #[cfg(feature = "config-secret")]
    {
        labels.push("Config file (hex-encoded secret in config.toml)");
        tags.push("config");
    }

    #[cfg(feature = "keyring")]
    {
        labels.push("OS keyring");
        tags.push("keyring");
    }

    labels.push("Plaintext file (NOT recommended)");
    tags.push("plaintext");

    // If only one backend is compiled, use it without prompting
    let choice = if labels.len() == 1 {
        0
    } else {
        Select::new()
            .with_prompt("Secret storage backend")
            .items(&labels)
            .default(0)
            .interact()?
    };

    let tag = tags[choice];

    #[cfg(feature = "aws-secrets")]
    if tag == "aws" {
        return prompt_aws_secrets();
    }

    #[cfg(feature = "gcp-secrets")]
    if tag == "gcp" {
        return prompt_gcp_secrets();
    }

    #[cfg(feature = "azure-secrets")]
    if tag == "azure" {
        return prompt_azure_secrets();
    }

    #[cfg(feature = "config-secret")]
    if tag == "config" {
        // Marker: secret field will be populated with hex after key generation
        return Ok(SecretsConfig {
            secret: Some(String::new()),
            ..Default::default()
        });
    }

    #[cfg(feature = "keyring")]
    if tag == "keyring" {
        return prompt_keyring_service(SecretsConfig::default());
    }

    if tag == "plaintext" {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Plaintext storage is NOT secure.               ║");
        eprintln!("║  Secrets will be stored in a plaintext file on disk.     ║");
        eprintln!("║  Use only for development or testing.                    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        return Ok(SecretsConfig::default());
    }

    unreachable!("selected backend tag does not match any compiled feature")
}

/// Prompt for the OS keyring service name.
#[cfg(feature = "keyring")]
fn prompt_keyring_service(
    mut config: SecretsConfig,
) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let service: String = Input::new()
        .with_prompt("Keyring service name (use a unique name per VTC instance)")
        .default("vtc".into())
        .interact_text()?;
    config.keyring_service = service;
    Ok(config)
}

#[cfg(feature = "aws-secrets")]
fn prompt_aws_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let secret_name: String = Input::new()
        .with_prompt("AWS Secrets Manager secret name")
        .default("vtc-secret".into())
        .interact_text()?;

    let region: String = Input::new()
        .with_prompt("AWS region (leave empty for SDK default)")
        .allow_empty(true)
        .interact_text()?;
    let region = if region.is_empty() {
        None
    } else {
        Some(region)
    };

    Ok(SecretsConfig {
        aws_secret_name: Some(secret_name),
        aws_region: region,
        ..Default::default()
    })
}

#[cfg(feature = "gcp-secrets")]
fn prompt_gcp_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;

    let secret_name: String = Input::new()
        .with_prompt("GCP Secret Manager secret name")
        .default("vtc-secret".into())
        .interact_text()?;

    Ok(SecretsConfig {
        gcp_project: Some(project),
        gcp_secret_name: Some(secret_name),
        ..Default::default()
    })
}

#[cfg(feature = "azure-secrets")]
fn prompt_azure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let vault_url: String = Input::new()
        .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)")
        .interact_text()?;

    let secret_name: String = Input::new()
        .with_prompt("Azure Key Vault secret name")
        .default("vtc-secret".into())
        .interact_text()?;

    Ok(SecretsConfig {
        azure_vault_url: Some(vault_url),
        azure_secret_name: Some(secret_name),
        ..Default::default()
    })
}

/// Generate 64 bytes of VTC key material: 32 random Ed25519 bytes + 32 X25519 bytes
/// derived from the Ed25519 key via clamped SHA-512.
fn generate_key_material() -> [u8; 64] {
    let mut ed25519_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut ed25519_bytes);
    let x25519_bytes = ed25519_private_to_x25519(&ed25519_bytes);
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(&ed25519_bytes);
    material[32..].copy_from_slice(&x25519_bytes);
    material
}

pub async fn run_setup_wizard(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the VTC setup wizard.\n");

    // 1. Config file path
    let default_path = config_path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            std::env::var("VTC_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into())
        });
    let config_path: String = Input::new()
        .with_prompt("Config file path")
        .default(default_path)
        .interact_text()?;
    let config_path = PathBuf::from(&config_path);

    let old_config = if config_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
        // Load existing config so we can clean up old secrets and data
        AppConfig::load(Some(config_path.clone())).ok()
    } else {
        None
    };

    // 2. VTC name
    let vtc_name: String = Input::new()
        .with_prompt("VTC name (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vtc_name = if vtc_name.is_empty() {
        None
    } else {
        Some(vtc_name)
    };

    // 3. VTC description
    let vtc_description: String = Input::new()
        .with_prompt("VTC description (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vtc_description = if vtc_description.is_empty() {
        None
    } else {
        Some(vtc_description)
    };

    // 4. Public URL
    let public_url: String = Input::new()
        .with_prompt("Public URL for this VTC (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let public_url = if public_url.is_empty() {
        None
    } else {
        Some(public_url)
    };

    // 5. Server host
    let host: String = Input::new()
        .with_prompt("Server host")
        .default("0.0.0.0".into())
        .interact_text()?;

    // 6. Server port
    let port: u16 = Input::new()
        .with_prompt("Server port")
        .default(8200u16)
        .interact_text()?;

    // 7. Log level
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".into())
        .interact_text()?;

    // 8. Log format
    let log_format_items = &["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_format_items)
        .default(0)
        .interact()?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 9. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/vtc".into())
        .interact_text()?;

    // 10. Clean up old secrets and data when overwriting
    if let Some(ref old) = old_config {
        // Delete old secrets from the previous backend (best-effort)
        match create_secret_store(old) {
            Ok(store) => {
                if let Err(e) = store.delete().await {
                    eprintln!("  Warning: could not clear old secrets: {e}");
                }
            }
            Err(e) => {
                eprintln!("  Warning: could not access old secret store: {e}");
            }
        }

        // Wipe old data directory if it exists
        if old.store.data_dir.exists() {
            std::fs::remove_dir_all(&old.store.data_dir).ok();
        }
    }

    // Wipe the chosen data directory if it already exists (fresh start)
    let data_dir_path = PathBuf::from(&data_dir);
    if data_dir_path.exists() {
        std::fs::remove_dir_all(&data_dir_path).ok();
    }

    let store = Store::open(&StoreConfig {
        data_dir: data_dir_path,
    })?;

    // 11. Generate VTC key material (32 Ed25519 + 32 X25519)
    let key_material = generate_key_material();

    // Prompt for secret store backend configuration
    let mut secrets_config = configure_secrets()?;

    // Store key material via the configured backend
    if secrets_config.secret.is_some() {
        // config-secret backend: hex-encode into the config (persisted when config is saved)
        secrets_config.secret = Some(hex::encode(key_material));
    } else {
        // All other backends: store via the secret store
        let secret_store = create_secret_store(&AppConfig {
            vtc_did: None,
            vta_did: None,
            vtc_name: None,
            vtc_description: None,
            public_url: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: StoreConfig::default(),
            messaging: None,
            auth: AuthConfig::default(),
            secrets: secrets_config.clone(),
            config_path: config_path.clone(),
        })
        .map_err(|e| format!("{e}"))?;
        secret_store
            .set(&key_material)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    // 12. Generate random JWT signing key
    let mut jwt_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut jwt_key_bytes);
    let jwt_signing_key = BASE64.encode(jwt_key_bytes);

    // 13. VTA DID and DIDComm messaging (mediator DID)
    let vta_did_input: String = Input::new()
        .with_prompt("VTA DID for this community (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vta_did = if vta_did_input.is_empty() {
        None
    } else {
        Some(vta_did_input)
    };

    let messaging = if let Some(ref vta) = vta_did {
        match resolve_mediator_did(vta).await {
            Ok(Some(mediator)) => {
                eprintln!("  Resolved mediator DID: {mediator}");
                let use_it = Confirm::new()
                    .with_prompt("Use this mediator?")
                    .default(true)
                    .interact()?;
                if use_it {
                    Some(MessagingConfig {
                        mediator_url: String::new(),
                        mediator_did: mediator,
                    })
                } else {
                    configure_messaging().await?
                }
            }
            Ok(None) => {
                eprintln!("  No DIDComm mediator found in VTA DID document.");
                configure_messaging().await?
            }
            Err(e) => {
                eprintln!("  Failed to resolve VTA DID: {e}");
                configure_messaging().await?
            }
        }
    } else {
        configure_messaging().await?
    };

    // 14. VTC DID
    let vtc_did = create_vtc_did(&key_material, messaging.as_ref(), &public_url).await?;

    // 15. Bootstrap admin DID in ACL
    let (admin_did, admin_credential) = create_admin_did(&vtc_did, &public_url).await?;

    let acl_ks = store.keyspace("acl")?;
    let admin_entry = AclEntry {
        did: admin_did.clone(),
        role: Role::Admin,
        label: Some("Initial admin".into()),
        allowed_contexts: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        created_by: "setup".into(),
    };
    store_acl_entry(&acl_ks, &admin_entry).await?;
    eprintln!("  Admin DID added to ACL: {admin_did}");

    // Flush all store writes to disk before exiting
    store.persist().await?;

    // 16. Save config
    let config = AppConfig {
        vtc_did,
        vta_did: vta_did.clone(),
        vtc_name,
        vtc_description,
        public_url: public_url.clone(),
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(data_dir),
        },
        messaging,
        auth: AuthConfig {
            jwt_signing_key: Some(jwt_signing_key),
            ..AuthConfig::default()
        },
        secrets: secrets_config,
        config_path: config_path.clone(),
    };
    config.save()?;

    // 17. Summary
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    eprintln!("  Config saved to: {}", config_path.display());
    eprintln!("  Key material stored in configured backend");
    // Print which secret backend was chosen
    {
        let mut _printed = false;
        #[cfg(feature = "aws-secrets")]
        if let Some(ref name) = config.secrets.aws_secret_name {
            let region = config
                .secrets
                .aws_region
                .as_deref()
                .unwrap_or("SDK default");
            eprintln!("  Secret backend: AWS Secrets Manager ({name} in {region})");
            _printed = true;
        }
        #[cfg(feature = "gcp-secrets")]
        if !_printed && let Some(ref name) = config.secrets.gcp_secret_name {
            let project = config.secrets.gcp_project.as_deref().unwrap_or("unknown");
            eprintln!("  Secret backend: GCP Secret Manager ({project}/{name})");
            _printed = true;
        }
        #[cfg(feature = "azure-secrets")]
        if !_printed && let Some(ref url) = config.secrets.azure_vault_url {
            let name = config
                .secrets
                .azure_secret_name
                .as_deref()
                .unwrap_or("vtc-secret");
            eprintln!("  Secret backend: Azure Key Vault ({url}/{name})");
            _printed = true;
        }
        if !_printed && config.secrets.secret.is_some() {
            eprintln!("  Secret backend: config file (hex-encoded in config.toml)");
            _printed = true;
        }
        #[cfg(feature = "keyring")]
        if !_printed {
            eprintln!(
                "  Secret backend: OS keyring (service: \"{}\")",
                config.secrets.keyring_service
            );
        }
    }
    if let Some(name) = &config.vtc_name {
        eprintln!("  VTC Name: {name}");
    }
    if let Some(url) = &config.public_url {
        eprintln!("  Public URL: {url}");
    }
    if let Some(did) = &config.vtc_did {
        eprintln!("  VTC DID: {did}");
    }
    if let Some(did) = &config.vta_did {
        eprintln!("  VTA DID: {did}");
    }
    eprintln!("  Server: {}:{}", config.server.host, config.server.port);
    if let Some(msg) = &config.messaging {
        eprintln!("  Mediator DID: {}", msg.mediator_did);
        if !msg.mediator_url.is_empty() {
            eprintln!("  Mediator URL: {}", msg.mediator_url);
        }
    }
    eprintln!("  Admin DID: {admin_did}");
    if let Some(cred) = &admin_credential {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  REMINDER: Save your admin credential string below.      ║");
        eprintln!("║  You will need it to authenticate with the VTC.          ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        eprintln!("  \x1b[1m{cred}\x1b[0m");
        eprintln!();
    }

    Ok(())
}

/// Guide the user through creating or entering an admin DID.
///
/// Returns `(did, Option<credential_string>)`. The credential string is only
/// produced for the `did:key` option (base64-encoded JSON bundle).
async fn create_admin_did(
    vtc_did: &Option<String>,
    public_url: &Option<String>,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let admin_options = &["Generate a new did:key (Ed25519)", "Enter an existing DID"];
    let choice = Select::new()
        .with_prompt("Admin DID")
        .items(admin_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            let (did, private_key_multibase) = generate_did_key();

            // Build credential bundle (same format as POST /auth/credentials)
            let vtc_did_str = vtc_did.clone().unwrap_or_default();
            let mut bundle = serde_json::json!({
                "did": did,
                "privateKeyMultibase": private_key_multibase,
                "vtaDid": vtc_did_str,
            });
            if let Some(url) = public_url {
                bundle["vtaUrl"] = serde_json::json!(url);
            }
            let bundle_json = serde_json::to_string(&bundle)?;
            let credential = BASE64.encode(bundle_json.as_bytes());

            eprintln!();
            eprintln!("\x1b[1;32mGenerated admin DID:\x1b[0m {did}");
            eprintln!();
            eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
            eprintln!("║  IMPORTANT: Save the credential string below.            ║");
            eprintln!("║  It contains your private key and is the ONLY way to     ║");
            eprintln!("║  authenticate as admin.                                  ║");
            eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
            eprintln!();
            eprintln!("  \x1b[1m{credential}\x1b[0m");
            eprintln!();

            let confirmed = Confirm::new()
                .with_prompt("I have saved the admin credential")
                .default(false)
                .interact()?;
            if !confirmed {
                eprintln!("Setup cancelled — please save your admin credential before proceeding.");
                return Err("Admin credential not saved".into());
            }

            Ok((did, Some(credential)))
        }
        _ => {
            // Enter existing DID
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;
            Ok((did, None))
        }
    }
}

/// Guide the user through creating (or entering) a DID for the VTC.
///
/// Uses raw key material (32 Ed25519 + 32 X25519 bytes) directly.
async fn create_vtc_did(
    key_material: &[u8; 64],
    messaging: Option<&MessagingConfig>,
    public_url: &Option<String>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_options = &[
        "Create a new did:webvh DID",
        "Enter an existing DID",
        "Skip (no VTC DID for now)",
    ];
    let choice = Select::new()
        .with_prompt("VTC DID")
        .items(did_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            let ed25519_bytes: &[u8; 32] = key_material[..32].try_into().unwrap();
            let x25519_bytes: &[u8; 32] = key_material[32..].try_into().unwrap();

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

            let did = create_webvh_did(
                &mut signing_secret,
                &signing_pub,
                &ka_pub,
                &signing_priv,
                &ka_priv,
                "VTC",
                messaging,
                public_url.as_deref(),
            )
            .await?;
            Ok(Some(did))
        }
        1 => {
            let did: String = Input::new().with_prompt("VTC DID").interact_text()?;
            Ok(Some(did))
        }
        _ => Ok(None),
    }
}

/// Guide the user through DIDComm messaging configuration.
///
/// Returns `None` when the user chooses to skip.
async fn configure_messaging() -> Result<Option<MessagingConfig>, Box<dyn std::error::Error>> {
    let options = &[
        "Use an existing mediator DID",
        "Do not use DIDComm messaging",
    ];
    let choice = Select::new()
        .with_prompt("DIDComm messaging")
        .items(options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            let did: String = Input::new().with_prompt("Mediator DID").interact_text()?;

            Ok(Some(MessagingConfig {
                mediator_url: String::new(),
                mediator_did: did,
            }))
        }
        // Skip DIDComm
        _ => Ok(None),
    }
}

/// Prompt the user for a URL and convert it to a [`WebVHURL`].
pub(crate) fn prompt_webvh_url(label: &str) -> Result<WebVHURL, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vtc       -> did:webvh:{{SCID}}:example.com:dids:vtc");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    loop {
        let raw: String = Input::new()
            .with_prompt(format!("{label} DID URL"))
            .default("http://localhost:8000/".into())
            .interact_text()?;

        let parsed = match Url::parse(&raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("\x1b[31mInvalid URL: {e} — please try again.\x1b[0m");
                continue;
            }
        };

        match WebVHURL::parse_url(&parsed) {
            Ok(webvh_url) => {
                let did_display = webvh_url.to_string();
                let http_url = webvh_url.get_http_url(None).map_err(|e| format!("{e}"))?;

                eprintln!("  DID:  {did_display}");
                eprintln!("  URL:  {http_url}");

                if Confirm::new()
                    .with_prompt("Is this correct?")
                    .default(true)
                    .interact()?
                {
                    return Ok(webvh_url);
                }
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mCould not convert to a webvh DID: {e} — please try again.\x1b[0m"
                );
            }
        }
    }
}

/// Interactive did:webvh creation flow for the VTC DID.
///
/// Uses pre-generated keys (from secret store) instead of BIP-32 derivation.
#[allow(clippy::too_many_arguments)]
async fn create_webvh_did(
    signing_secret: &mut Secret,
    signing_pub: &str,
    ka_pub: &str,
    signing_priv: &str,
    ka_priv: &str,
    label: &str,
    messaging: Option<&MessagingConfig>,
    vtc_public_url: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Prompt for URL and convert to WebVHURL
    let webvh_url = prompt_webvh_url(label)?;
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
                "publicKeyMultibase": signing_pub
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
            "publicKeyMultibase": ka_pub
        }));
    did_document["keyAgreement"] = json!([format!("{did_id}#key-1")]);

    // Add service endpoints
    let mut services = Vec::new();

    if let Some(msg) = messaging {
        // VTC DID: add #didcomm referencing the mediator DID
        services.push(json!({
            "id": format!("{did_id}#didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": msg.mediator_did
            }]
        }));
    }

    // Add #vtc service endpoint if a public URL is configured
    if let Some(url) = vtc_public_url {
        services.push(json!({
            "id": format!("{did_id}#vtc"),
            "type": "VerifiableTrustCommunity",
            "serviceEndpoint": url
        }));
    }

    if !services.is_empty() {
        did_document["service"] = serde_json::Value::Array(services);
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
        update_keys: Some(Arc::new(vec![signing_pub.to_string()])),
        portable: Some(portable),
        ..Default::default()
    };

    // Create the log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, signing_secret)
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
                    private_key_multibase: signing_priv.to_string(),
                },
                SecretEntry {
                    key_id: format!("{final_did}#key-1"),
                    key_type: SdkKeyType::X25519,
                    private_key_multibase: ka_priv.to_string(),
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

    Ok(final_did)
}
