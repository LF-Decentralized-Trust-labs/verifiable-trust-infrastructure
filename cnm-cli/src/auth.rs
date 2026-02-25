use vta_sdk::session::{SessionStore, TokenStatus};

pub use vta_sdk::session::SessionInfo;

const SERVICE_NAME: &str = "cnm-cli";
/// Legacy keyring key (pre multi-community).
const LEGACY_KEYRING_KEY: &str = "session";

fn store() -> SessionStore {
    SessionStore::new(
        SERVICE_NAME,
        crate::config::config_dir().expect("could not determine config directory"),
    )
}

/// Returns true if the legacy single-session keyring entry exists.
pub fn has_legacy_session() -> bool {
    store().has_session(LEGACY_KEYRING_KEY)
}

/// Import a base64-encoded credential and authenticate.
pub async fn login(
    credential_b64: &str,
    base_url: &str,
    keyring_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(feature = "config-session", not(feature = "keyring")))]
    eprintln!(
        "Warning: sessions are stored unprotected on disk (~/.config/cnm/sessions.json).\n         \
         Do not use config-session in production."
    );

    let result = store().login(credential_b64, base_url, keyring_key).await?;

    println!("Credential imported:");
    println!("  Client DID: {}", result.client_did);
    println!("  VTA DID:    {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        println!("  VTA URL:    {url}");
    }
    println!("\nAuthentication successful.");
    Ok(())
}

/// Store a session directly (without performing authentication).
pub fn store_session_direct(
    keyring_key: &str,
    did: &str,
    private_key: &str,
    vta_did: &str,
    vta_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_direct(keyring_key, did, private_key, vta_did, vta_url)
}

/// Clear stored credentials and cached tokens.
pub fn logout(keyring_key: &str) {
    store().logout(keyring_key);
    println!("Logged out. Credentials and tokens removed.");
}

/// Load the stored session for diagnostics (DID resolution, etc.).
pub fn loaded_session(keyring_key: &str) -> Option<SessionInfo> {
    store().loaded_session(keyring_key)
}

/// Show current authentication status.
pub fn status(keyring_key: &str) {
    match store().session_status(keyring_key) {
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
            println!("\nTo authenticate, import a credential from your VTA administrator:");
            println!("  cnm auth login <credential-string>");
        }
    }
}

/// Ensure we have a valid access token. Returns the token string.
pub async fn ensure_authenticated(
    base_url: &str,
    keyring_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    store().ensure_authenticated(base_url, keyring_key).await
}

/// Connect to the VTA using the preferred transport (DIDComm or REST).
///
/// If `url_override` is provided, always uses REST.
/// Otherwise resolves the VTA DID and prefers DIDComm when available.
pub async fn connect(
    url_override: Option<&str>,
    keyring_key: &str,
) -> Result<vta_sdk::client::VtaClient, Box<dyn std::error::Error>> {
    store().connect(keyring_key, url_override).await
}
