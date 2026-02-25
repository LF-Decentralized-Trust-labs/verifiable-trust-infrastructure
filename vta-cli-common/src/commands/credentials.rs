use vta_sdk::client::{GenerateCredentialsRequest, VtaClient};

use super::acl::validate_role;

pub async fn cmd_auth_credential_create(
    client: &VtaClient,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_role(&role)?;
    let req = GenerateCredentialsRequest {
        role,
        label,
        allowed_contexts: contexts,
    };
    let resp = client.generate_credentials(req).await?;
    println!("Credentials generated:");
    println!("  DID:  {}", resp.did);
    println!("  Role: {}", resp.role);
    println!();
    println!("Credential (one-time secret — save this now):");
    println!("{}", resp.credential);
    Ok(())
}
