use vta_sdk::prelude::*;

use super::acl::validate_role;

pub async fn cmd_auth_credential_create(
    client: &VtaClient,
    role: String,
    label: Option<String>,
    contexts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_role(&role)?;
    let mut req = GenerateCredentialsRequest::new(role).contexts(contexts);
    if let Some(l) = label { req = req.label(l); }
    let resp = client.generate_credentials(req).await?;
    println!("Credentials generated:");
    println!("  DID:  {}", resp.did);
    println!("  Role: {}", resp.role);
    println!();
    println!("Credential (one-time secret — save this now):");
    println!("{}", resp.credential);
    Ok(())
}
