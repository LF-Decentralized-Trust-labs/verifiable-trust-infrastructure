use std::io::{self, BufRead, Write};

use dialoguer::Select;
use ed25519_dalek::SigningKey;
use rand::Rng;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::resolve_vta_url;

use crate::auth;
use crate::config::{PnmConfig, save_config};

/// Interactive setup for PNM.
///
/// Presents the user with a choice between connecting to an existing VTA
/// (with an admin credential bundle) or preparing a new TEE deployment
/// (generating a did:key for the config).
pub async fn run_setup(credential: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // If a credential was passed on the CLI, skip the menu
    if let Some(cred) = credential {
        return setup_with_credential(cred).await;
    }

    let choices = &[
        "Connect to an existing VTA (I have an admin credential)",
        "Prepare a new VTA for TEE deployment (generate admin identity)",
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
            setup_with_credential(&trimmed).await
        }
        1 => setup_tee_identity().await,
        _ => unreachable!(),
    }
}

/// Connect to an existing VTA using an admin credential bundle.
async fn setup_with_credential(credential: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = CredentialBundle::decode(credential)?;
    eprintln!("Resolving VTA DID: {}", bundle.vta_did);
    let url = resolve_vta_url(&bundle.vta_did).await?;
    let url = url.trim_end_matches('/').to_string();

    let config = PnmConfig {
        url: Some(url.clone()),
    };
    save_config(&config)?;

    let path = crate::config::config_path()?;
    println!("Config saved to: {}", path.display());
    println!("  URL: {url}");
    println!();

    auth::login(credential, &url).await?;

    Ok(())
}

/// Generate a did:key identity for TEE deployment.
///
/// The operator adds the generated DID to the VTA's config.toml as
/// `admin_did` before building the EIF. The private key is saved locally
/// as a credential bundle for later use.
async fn setup_tee_identity() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("Generating a new admin identity for TEE deployment.");
    eprintln!();
    eprintln!("This creates a did:key keypair. The private key stays on this");
    eprintln!("machine and never touches the TEE or the parent EC2 instance.");
    eprintln!();

    // Generate random Ed25519 keypair
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);

    // Build a credential bundle (vta_did and vta_url are empty for now —
    // they'll be set after the VTA boots and generates its DID)
    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase,
        vta_did: String::new(),
        vta_url: None,
    };
    let encoded = bundle.encode()?;

    // Save the credential locally
    let cred_dir = crate::config::config_dir()?;
    let cred_path = cred_dir.join("tee-admin-credential.txt");
    std::fs::write(&cred_path, &encoded)?;

    eprintln!("Admin identity generated:");
    eprintln!();
    println!("  DID: {did}");
    eprintln!();
    eprintln!("Add this to your VTA's deploy/nitro/config.toml under [tee.kms]:");
    eprintln!();
    eprintln!("  admin_did = \"{did}\"");
    eprintln!();
    eprintln!("Then build the EIF and start the enclave. Once the VTA is running,");
    eprintln!("run `pnm setup` again and choose \"Connect to an existing VTA\"");
    eprintln!("with the credential saved at:");
    eprintln!("  {}", cred_path.display());
    eprintln!();
    eprintln!("Credential (save this — it contains your private key):");
    println!("{encoded}");

    Ok(())
}
