use vta_sdk::client::{UpdateConfigRequest, VtaClient};

pub async fn cmd_config_get(
    client: &VtaClient,
    label_prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_config().await?;
    println!(
        "{label_prefix}VTA DID:    {}",
        resp.community_vta_did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "{label_prefix}VTA Name:   {}",
        resp.community_vta_name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "{label_prefix}Public URL: {}",
        resp.public_url.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}

pub async fn cmd_config_update(
    client: &VtaClient,
    label_prefix: &str,
    vta_did: Option<String>,
    vta_name: Option<String>,
    public_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateConfigRequest {
        vta_did,
        vta_name,
        public_url,
    };
    let resp = client.update_config(req).await?;
    println!("Configuration updated:");
    println!(
        "  {label_prefix}VTA DID:    {}",
        resp.community_vta_did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  {label_prefix}VTA Name:   {}",
        resp.community_vta_name.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  {label_prefix}Public URL: {}",
        resp.public_url.as_deref().unwrap_or("(not set)")
    );
    Ok(())
}
