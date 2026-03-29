use std::io::{self, BufRead, Write};

use dialoguer::{Input, Select};
use ed25519_dalek::SigningKey;
use rand::Rng;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_key::ed25519_multibase_pubkey;

use crate::auth;
use crate::config::{PnmConfig, VtaConfig, save_config, slugify, vta_keyring_key};

/// Interactive setup for PNM.
///
/// Presents the user with a choice between connecting to an existing VTA
/// (with an admin credential bundle) or preparing a new TEE deployment
/// (generating a did:key for the config).
pub async fn run_setup(
    credential: Option<&str>,
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // If a credential was passed on the CLI, skip the menu
    if let Some(cred) = credential {
        return setup_with_credential(cred, config).await;
    }

    let choices = &[
        "Connect to an existing VTA  — I have an admin credential bundle",
        "Set up a new VTA in a TEE   — generate admin identity for enclave deployment",
    ];

    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(choices)
        .default(0)
        .interact()?;

    match selection {
        0 => {
            eprintln!();
            eprintln!("Paste the base64-encoded admin credential you received from");
            eprintln!("your VTA administrator or from the VTA's bootstrap output.");
            eprintln!();
            eprint!("Admin credential: ");
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                return Err("No credential provided.".into());
            }
            setup_with_credential(&trimmed, config).await
        }
        1 => setup_tee(config).await,
        _ => unreachable!(),
    }
}

/// Connect to an existing VTA using an admin credential bundle.
async fn setup_with_credential(
    credential: &str,
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = CredentialBundle::decode(credential)?;

    // Prompt for a name/slug
    let default_name = if bundle.vta_did.is_empty() {
        "My VTA".to_string()
    } else {
        // Use the last segment of the DID as a reasonable default
        bundle
            .vta_did
            .rsplit(':')
            .next()
            .unwrap_or("my-vta")
            .to_string()
    };

    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default(default_name)
        .interact_text()?;

    let slug = slugify(&name);
    let keyring_key = vta_keyring_key(&slug);

    // Resolve URL from DID
    let url = if let Some(ref url) = bundle.vta_url {
        url.clone()
    } else if !bundle.vta_did.is_empty() {
        eprintln!("Resolving VTA DID: {}", bundle.vta_did);
        vta_sdk::session::resolve_vta_url(&bundle.vta_did).await?
    } else {
        let url: String = Input::new()
            .with_prompt("VTA URL")
            .interact_text()?;
        url
    };
    let url = url.trim_end_matches('/').to_string();

    // Save to config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: Some(url.clone()),
            vta_did: if bundle.vta_did.is_empty() {
                None
            } else {
                Some(bundle.vta_did.clone())
            },
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    // Authenticate
    auth::login(credential, &url, &keyring_key).await?;

    let path = crate::config::config_path()?;
    eprintln!();
    eprintln!("VTA '{slug}' configured.");
    eprintln!("  Config: {}", path.display());
    if config.default_vta.as_deref() == Some(&slug) {
        eprintln!("  Default: yes");
    }

    Ok(())
}

/// Set up a new VTA for TEE deployment.
///
/// Single interactive session:
/// 1. Generate admin did:key (in memory)
/// 2. Print DID for config.toml
/// 3. Wait for operator to deploy + boot VTA
/// 4. Prompt for VTA DID
/// 5. Store credential in keyring, save config
async fn setup_tee(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("This will create an admin identity for a VTA running in a");
    eprintln!("Trusted Execution Environment. The private key stays on this");
    eprintln!("machine and never touches the TEE or the parent instance.");
    eprintln!();

    // 1. Prompt for name
    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default("my-tee-vta".to_string())
        .interact_text()?;
    let slug = slugify(&name);

    // 2. Generate random Ed25519 keypair (in memory only)
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);

    // 3. Print DID for config.toml
    eprintln!();
    eprintln!("Admin identity generated.");
    eprintln!();
    eprintln!("Add this to your VTA's deploy/nitro/config.toml under [tee.kms]:");
    eprintln!();
    println!("  admin_did = \"{did}\"");
    eprintln!();
    eprintln!("Then build the EIF and start the enclave.");

    // 4. Wait for VTA to be running
    eprintln!();
    eprint!("Press Enter once the VTA is running...");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;

    // 5. Prompt for VTA DID
    eprintln!();
    eprintln!("The VTA's DID is shown in its boot logs. You can also retrieve");
    eprintln!("it via: GET /attestation/did-log (if REST is enabled).");
    eprintln!();
    let vta_did: String = Input::new()
        .with_prompt("VTA DID")
        .interact_text()?;

    // 6. Prompt for mediator DID
    let mediator_did: String = Input::new()
        .with_prompt("Mediator DID")
        .interact_text()?;

    // 7. Build credential bundle and store in keyring
    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase: private_key_multibase.clone(),
        vta_did: vta_did.clone(),
        vta_url: None,
    };
    let _credential_b64 = bundle.encode()?;
    let keyring_key = vta_keyring_key(&slug);

    // Store session directly — the VTA may not be reachable for auth yet
    // (DIDComm connections need time to establish)
    auth::store_session(
        &keyring_key,
        &did,
        &private_key_multibase,
        &vta_did,
        "", // No REST URL in TEE mode
    )?;

    // 8. Save to config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: None,
            vta_did: Some(vta_did.clone()),
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    eprintln!();
    eprintln!("VTA '{slug}' configured.");
    eprintln!("  Admin DID:    {did}");
    eprintln!("  VTA DID:      {vta_did}");
    eprintln!("  Mediator DID: {mediator_did}");
    eprintln!("  Credential stored in keyring (key: {keyring_key})");
    if config.default_vta.as_deref() == Some(&slug) {
        eprintln!("  Default: yes");
    }
    eprintln!();
    eprintln!("You can now run commands against this VTA:");
    eprintln!("  pnm health");
    eprintln!("  pnm keys list");

    Ok(())
}
