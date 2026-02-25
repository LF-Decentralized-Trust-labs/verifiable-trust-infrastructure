use vta_sdk::session::{SessionStore, TokenStatus};

pub use vta_sdk::session::SessionInfo;

use crate::config::SESSION_KEY;

const SERVICE_NAME: &str = "pnm-cli";

fn store() -> SessionStore {
    SessionStore::new(
        SERVICE_NAME,
        crate::config::config_dir().expect("could not determine config directory"),
    )
}

/// Import a base64-encoded credential and authenticate.
pub async fn login(credential_b64: &str, base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    eprintln!(
        "Warning: sessions are stored unprotected on disk (~/.config/pnm/sessions.json).\n         \
         Do not use config-session in production."
    );

    let result = store().login(credential_b64, base_url, SESSION_KEY).await?;

    println!("Credential imported:");
    println!("  Client DID: {}", result.client_did);
    println!("  VTA DID:    {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        println!("  VTA URL:    {url}");
    }
    println!("\nAuthentication successful.");
    Ok(())
}

/// Clear stored credentials and cached tokens.
pub fn logout() {
    store().logout(SESSION_KEY);
    println!("Logged out. Credentials and tokens removed.");
}

/// Load the stored session for diagnostics.
pub fn loaded_session() -> Option<SessionInfo> {
    store().loaded_session(SESSION_KEY)
}

/// Return current session status (for health diagnostics).
pub fn session_status() -> Option<vta_sdk::session::SessionStatus> {
    store().session_status(SESSION_KEY)
}

/// Show current authentication status.
pub fn status() {
    match store().session_status(SESSION_KEY) {
        Some(status) => {
            println!("Client DID: {}", status.client_did);
            println!("VTA DID:    {}", status.vta_did);
            println!(
                "VTA URL:    {}",
                status.vta_url.as_deref().unwrap_or("(not set)")
            );
            match status.token_status {
                TokenStatus::Valid { expires_in_secs } => {
                    println!("Token:      valid (expires in {expires_in_secs}s)");
                }
                TokenStatus::Expired => {
                    println!("Token:      expired");
                }
                TokenStatus::None => {
                    println!("Token:      none (will authenticate on next request)");
                }
            }
        }
        None => {
            println!("Not authenticated.");
            println!("\nTo authenticate, import a credential:");
            println!("  pnm auth login <credential-string>");
        }
    }
}

/// Ensure we have a valid access token. Returns the token string.
pub async fn ensure_authenticated(base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    store().ensure_authenticated(base_url, SESSION_KEY).await
}

/// Connect to the VTA using the preferred transport (DIDComm or REST).
///
/// If `url_override` is provided, always uses REST.
/// Otherwise resolves the VTA DID and prefers DIDComm when available.
pub async fn connect(
    url_override: Option<&str>,
) -> Result<vta_sdk::client::VtaClient, Box<dyn std::error::Error>> {
    store().connect(SESSION_KEY, url_override).await
}
