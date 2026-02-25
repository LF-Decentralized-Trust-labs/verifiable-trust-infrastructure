use std::io::{self, BufRead, Write};

use vta_sdk::credentials::CredentialBundle;
use vta_sdk::session::resolve_vta_url;

use crate::auth;
use crate::config::{PnmConfig, save_config};

/// Configure PNM with a VTA credential. The VTA service URL is resolved from the
/// VTA DID in the credential bundle.
/// If no credential is provided on the CLI, the user is prompted to paste one interactively.
pub async fn run_setup(credential: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let credential = match credential {
        Some(cred) => cred.to_string(),
        None => {
            eprint!("Paste your VTA admin credential: ");
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                return Err("No credential provided.".into());
            }
            trimmed
        }
    };

    // Decode credential and resolve VTA URL from the DID document
    let bundle = CredentialBundle::decode(&credential)?;
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

    auth::login(&credential, &url).await?;

    Ok(())
}
