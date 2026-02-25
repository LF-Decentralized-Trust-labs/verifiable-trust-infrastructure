use dialoguer::{Input, Select};

use crate::auth;
use crate::config::{
    CommunityConfig, PERSONAL_KEYRING_KEY, PersonalVtaConfig, community_keyring_key, load_config,
    save_config,
};
use vta_sdk::client::{CreateContextRequest, GenerateCredentialsRequest, VtaClient};

/// Derive a URL-safe slug from a community name.
///
/// Lowercases, replaces whitespace/non-alphanumeric with hyphens, trims hyphens.
fn slugify(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    slug.trim_matches('-')
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Try to resolve a VTA URL from a DID's `#vta-rest` service endpoint.
async fn resolve_vta_url(did: &str) -> Option<String> {
    vta_sdk::session::resolve_vta_url(did).await.ok()
}

/// Prompt for a VTA DID, resolve the `#vta-rest` service URL if possible,
/// then ask for the URL (pre-filled with the discovered value or manual entry).
///
/// `label` is a human-readable prefix like "Personal" or "Community".
/// Returns `(Option<did>, url)`.
async fn prompt_vta_url(
    label: &str,
) -> Result<(Option<String>, String), Box<dyn std::error::Error>> {
    let did: String = Input::new()
        .with_prompt(format!("{label} VTA DID (press Enter to skip)"))
        .allow_empty(true)
        .interact_text()?;

    let (did, discovered_url) = if did.is_empty() {
        (None, None)
    } else {
        eprintln!("Resolving DID...");
        let url = match resolve_vta_url(&did).await {
            Some(url) => {
                eprintln!("  Discovered VTA URL: {url}");
                Some(url)
            }
            None => {
                eprintln!("  No #vta-rest service endpoint found in DID document.");
                None
            }
        };
        (Some(did), url)
    };

    let vta_url: String = if let Some(url) = discovered_url {
        Input::new()
            .with_prompt(format!("{label} VTA URL"))
            .default(url)
            .interact_text()?
    } else {
        Input::new()
            .with_prompt(format!("{label} VTA URL"))
            .interact_text()?
    };

    Ok((did, vta_url))
}

/// Run the interactive setup wizard.
pub async fn run_setup_wizard() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the CNM setup wizard.\n");

    let mut config = load_config()?;

    // ── Personal VTA ────────────────────────────────────────────────
    let (_personal_did, personal_url) = prompt_vta_url("Personal").await?;

    let personal_credential: String = Input::new()
        .with_prompt("Personal VTA credential (base64)")
        .interact_text()?;

    // Authenticate against personal VTA
    eprintln!();
    auth::login(&personal_credential, &personal_url, PERSONAL_KEYRING_KEY).await?;

    config.personal_vta = Some(PersonalVtaConfig {
        url: personal_url.clone(),
    });

    // ── Community ───────────────────────────────────────────────────
    let community_name: String = Input::new().with_prompt("Community name").interact_text()?;

    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    let (community_did, community_url) = prompt_vta_url("Community").await?;

    let join_options = &["Import existing credential", "Generate from personal VTA"];
    let join_choice = Select::new()
        .with_prompt("How do you want to join this community?")
        .items(join_options)
        .default(0)
        .interact()?;

    let mut community_vta_did_for_config: Option<String> = community_did.clone();

    let context_id = match join_choice {
        // Import existing credential
        0 => {
            let credential: String = Input::new()
                .with_prompt("Community admin credential (base64)")
                .interact_text()?;

            let keyring_key = community_keyring_key(&community_slug);
            eprintln!();
            auth::login(&credential, &community_url, &keyring_key).await?;

            None
        }
        // Generate from personal VTA
        _ => {
            let context_slug = format!("cnm-{community_slug}");
            let context_name = format!("CNM - {community_name}");

            // Authenticate personal VTA client
            let mut personal_client = VtaClient::new(&personal_url);
            let token = auth::ensure_authenticated(&personal_url, PERSONAL_KEYRING_KEY).await?;
            personal_client.set_token(token);

            // Create context in personal VTA
            eprintln!("\nCreating context '{context_name}' in personal VTA...");
            let ctx_req = CreateContextRequest {
                id: context_slug.clone(),
                name: context_name,
                description: Some(format!("Community admin identity for {}", community_name)),
            };
            match personal_client.create_context(ctx_req).await {
                Ok(ctx) => {
                    eprintln!("  Context created: {} ({})", ctx.id, ctx.base_path);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("409") || msg.to_lowercase().contains("already exists") {
                        eprintln!("  Context '{context_slug}' already exists, reusing it.");
                    } else {
                        return Err(e);
                    }
                }
            }

            // Generate credential in personal VTA
            eprintln!("Generating community admin credential...");
            let cred_req = GenerateCredentialsRequest {
                role: "admin".into(),
                label: Some(format!("CNM community admin — {community_slug}")),
                allowed_contexts: vec![context_slug.clone()],
            };
            let resp = personal_client.generate_credentials(cred_req).await?;

            // Decode credential to extract the private key
            let bundle = vta_sdk::credentials::CredentialBundle::decode(&resp.credential)
                .map_err(|e| format!("failed to decode credential: {e:?}"))?;
            let private_key = &bundle.private_key_multibase;

            // Ensure we have the community VTA DID (prompt if not provided earlier)
            let community_vta_did = match &community_did {
                Some(did) => did.clone(),
                None => {
                    let did: String = Input::new()
                        .with_prompt("Community VTA DID (required for authentication)")
                        .interact_text()?;
                    community_vta_did_for_config = Some(did.clone());
                    did
                }
            };

            // Store community session so cnm can authenticate automatically
            let keyring_key = community_keyring_key(&community_slug);
            auth::store_session_direct(
                &keyring_key,
                &resp.did,
                private_key,
                &community_vta_did,
                &community_url,
            )?;

            eprintln!();
            eprintln!(
                "\x1b[1;32mGenerated community admin DID:\x1b[0m {}",
                resp.did
            );
            eprintln!();
            eprintln!("Share this DID with the community administrator.");
            eprintln!("They will run:");
            eprintln!("  vta import-did --did {}", resp.did);
            eprintln!();
            eprintln!("Once access is granted, cnm will authenticate automatically.");
            eprintln!();

            Some(context_slug)
        }
    };

    // ── Save config ─────────────────────────────────────────────────
    config.communities.insert(
        community_slug.clone(),
        CommunityConfig {
            name: community_name,
            url: community_url,
            context_id,
            vta_did: community_vta_did_for_config,
        },
    );

    // Set as default if first community
    if config.default_community.is_none() || config.communities.len() == 1 {
        config.default_community = Some(community_slug.clone());
    }

    save_config(&config)?;

    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    let path = crate::config::config_path()?;
    eprintln!("  Config saved to: {}", path.display());
    eprintln!("  Default community: {community_slug}");
    eprintln!();

    Ok(())
}

/// Add a new community interactively.
pub async fn add_community() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    let community_name: String = Input::new().with_prompt("Community name").interact_text()?;

    let default_slug = slugify(&community_name);
    let community_slug: String = Input::new()
        .with_prompt("Community slug (short identifier)")
        .default(default_slug)
        .interact_text()?;

    if config.communities.contains_key(&community_slug) {
        return Err(
            format!("community '{community_slug}' already exists. Use a different slug.").into(),
        );
    }

    let (_community_did, community_url) = prompt_vta_url("Community").await?;

    let credential: String = Input::new()
        .with_prompt("Community admin credential (base64)")
        .interact_text()?;

    let keyring_key = community_keyring_key(&community_slug);
    eprintln!();
    auth::login(&credential, &community_url, &keyring_key).await?;

    config.communities.insert(
        community_slug.clone(),
        CommunityConfig {
            name: community_name,
            url: community_url,
            context_id: None,
            vta_did: None,
        },
    );

    if config.default_community.is_none() {
        config.default_community = Some(community_slug.clone());
    }

    save_config(&config)?;

    eprintln!();
    eprintln!("Community '{community_slug}' added.");
    Ok(())
}

/// Bootstrap a community session from the personal VTA.
///
/// When a community was set up via "Generate from personal VTA" but the session
/// was lost (e.g. setup ran before auto-store was implemented), this function
/// regenerates a credential from the personal VTA and stores it.
///
/// **Note:** This creates a NEW admin DID. The user must run `vta import-did`
/// on the community VTA with the new DID.
pub async fn bootstrap_community_session(
    slug: &str,
    community: &CommunityConfig,
    personal_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let context_id = community
        .context_id
        .as_deref()
        .ok_or("community has no context_id")?;
    let community_vta_did = community
        .vta_did
        .as_deref()
        .ok_or("community has no vta_did in config (setup ran before this feature was added)")?;

    // Authenticate to personal VTA
    let token = auth::ensure_authenticated(personal_url, PERSONAL_KEYRING_KEY).await?;
    let mut personal_client = VtaClient::new(personal_url);
    personal_client.set_token(token);

    // Generate a new credential on the personal VTA
    eprintln!("Bootstrapping community session from personal VTA...");
    let cred_req = GenerateCredentialsRequest {
        role: "admin".into(),
        label: Some(format!("CNM community admin — {slug} (bootstrapped)")),
        allowed_contexts: vec![context_id.to_string()],
    };
    let resp = personal_client.generate_credentials(cred_req).await?;

    // Decode credential to extract the private key
    let bundle = vta_sdk::credentials::CredentialBundle::decode(&resp.credential)
        .map_err(|e| format!("failed to decode credential: {e:?}"))?;
    let private_key = &bundle.private_key_multibase;

    // Store community session
    let keyring_key = community_keyring_key(slug);
    auth::store_session_direct(
        &keyring_key,
        &resp.did,
        private_key,
        community_vta_did,
        &community.url,
    )?;

    eprintln!();
    eprintln!(
        "\x1b[1;32mBootstrapped community session with new DID:\x1b[0m {}",
        resp.did
    );
    eprintln!();
    eprintln!("This is a NEW DID. You must grant it access on the community VTA:");
    eprintln!("  vta import-did --did {}", resp.did);
    eprintln!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify_basic() {
        assert_eq!(slugify("Storm Network"), "storm-network");
    }

    #[test]
    fn test_slugify_special_chars() {
        assert_eq!(slugify("Acme Corp."), "acme-corp");
    }

    #[test]
    fn test_slugify_multiple_spaces() {
        assert_eq!(slugify("  My   Test  Community  "), "my-test-community");
    }

    #[test]
    fn test_slugify_already_slug() {
        assert_eq!(slugify("already-good"), "already-good");
    }

    #[test]
    fn test_slugify_uppercase() {
        assert_eq!(slugify("UPPERCASE"), "uppercase");
    }

    #[test]
    fn test_slugify_numbers() {
        assert_eq!(slugify("Community 42"), "community-42");
    }
}
