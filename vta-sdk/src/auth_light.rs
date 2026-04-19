//! Lightweight challenge-response authentication for VTA REST clients.
//!
//! This module provides the same DIDComm challenge-response flow as
//! `session::challenge_response()` but without requiring ATM/TDK runtime
//! initialization. It uses the lightweight DIDComm packer from
//! `didcomm_light` to build encrypted auth messages.
//!
//! Feature gate: `client` (not `session`).

use crate::credentials::CredentialBundle;
use crate::didcomm_light;
use crate::protocols::auth::{AuthenticateResponse, ChallengeRequest, ChallengeResponse};
use reqwest::Client;

/// Result of a successful authentication.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
}

/// Perform DIDComm challenge-response authentication without ATM/TDK runtime.
///
/// This is the lightweight equivalent of `session::challenge_response()`.
/// It uses the `didcomm_light` packer to build the encrypted message.
pub async fn challenge_response_light(
    http: &Client,
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<AuthResult, crate::error::VtaError> {
    let _ = private_key_multibase; // Sender identity is in the plaintext `from` field;
    // anoncrypt doesn't use sender's private key for encryption.

    // Step 1: Request challenge
    let challenge_url = format!("{base_url}/auth/challenge");
    let challenge_resp = http
        .post(&challenge_url)
        .json(&ChallengeRequest {
            did: client_did.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {challenge_url}: {e}"))?;

    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let body = challenge_resp.text().await.unwrap_or_default();
        return Err(format!("challenge request failed ({status}): {body}").into());
    }

    let challenge: ChallengeResponse = challenge_resp
        .json()
        .await
        .map_err(|e| format!("unexpected response from VTA: {e}"))?;

    // Step 2: Pack encrypted authenticate message
    let packed = didcomm_light::pack_auth_message(
        "https://affinidi.com/atm/1.0/authenticate",
        serde_json::json!({
            "challenge": challenge.data.challenge,
            "session_id": challenge.session_id,
        }),
        client_did,
        vta_did,
    )?;

    // Step 3: Send packed message
    let auth_url = format!("{base_url}/auth/");
    let auth_resp = http
        .post(&auth_url)
        .header("content-type", "text/plain")
        .body(packed)
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {auth_url}: {e}"))?;

    if !auth_resp.status().is_success() {
        let status = auth_resp.status();
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(format!("authentication failed ({status}): {body}").into());
    }

    let auth_data: AuthenticateResponse = auth_resp
        .json()
        .await
        .map_err(|e| format!("unexpected auth response: {e}"))?;

    Ok(AuthResult {
        access_token: auth_data.data.access_token,
        access_expires_at: auth_data.data.access_expires_at,
        refresh_token: auth_data.data.refresh_token,
        refresh_expires_at: auth_data.data.refresh_expires_at,
    })
}

/// Refresh an access token using the refresh token endpoint.
///
/// Returns a new `AuthResult` with a fresh access token. The refresh token
/// itself remains unchanged.
pub async fn refresh_token_light(
    http: &Client,
    base_url: &str,
    client_did: &str,
    vta_did: &str,
    refresh_token: &str,
) -> Result<AuthResult, crate::error::VtaError> {
    let packed = didcomm_light::pack_auth_message(
        "https://affinidi.com/atm/1.0/authenticate/refresh",
        serde_json::json!({
            "refresh_token": refresh_token,
        }),
        client_did,
        vta_did,
    )?;

    let refresh_url = format!("{base_url}/auth/refresh");
    let resp = http
        .post(&refresh_url)
        .header("content-type", "text/plain")
        .body(packed)
        .send()
        .await
        .map_err(|e| format!("refresh request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("token refresh failed ({status}): {body}").into());
    }

    let auth_data: AuthenticateResponse = resp
        .json()
        .await
        .map_err(|e| format!("unexpected refresh response: {e}"))?;

    Ok(AuthResult {
        access_token: auth_data.data.access_token,
        access_expires_at: auth_data.data.access_expires_at,
        refresh_token: auth_data.data.refresh_token,
        refresh_expires_at: auth_data.data.refresh_expires_at,
    })
}

/// Authenticate using an already-decoded credential bundle, returning an
/// `AuthResult`.
///
/// The second tuple element is a clone of the input bundle, echoed back for
/// callers that want a single expression yielding auth state + identity.
pub async fn authenticate_with_credential(
    credential: &CredentialBundle,
    url_override: Option<&str>,
) -> Result<(AuthResult, CredentialBundle, Client), crate::error::VtaError> {
    let url = url_override
        .or(credential.vta_url.as_deref())
        .ok_or("no VTA URL in credential and no override provided")?;

    let http = Client::new();
    let result = challenge_response_light(
        &http,
        url,
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
    )
    .await?;

    Ok((result, credential.clone(), http))
}
