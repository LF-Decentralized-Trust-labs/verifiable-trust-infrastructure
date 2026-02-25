use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::UnpackOptions;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::protocols::auth::{
    AuthenticateData, AuthenticateResponse, ChallengeData, ChallengeRequest, ChallengeResponse,
};

use crate::acl::{
    AclEntry, Role, check_acl, check_acl_full, store_acl_entry, validate_acl_modification,
};
use crate::auth::credentials::generate_did_key;
use crate::auth::extractor::{AdminAuth, AuthClaims, ManageAuth};
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{
    Session, SessionState, delete_session, get_session, get_session_by_refresh, list_sessions,
    now_epoch, store_refresh_index, store_session, update_session,
};
use crate::error::AppError;
use crate::server::AppState;
use tracing::{info, warn};

// ---------- POST /auth/challenge ----------

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // ACL enforcement: DID must be in the ACL to request a challenge
    let acl = state.acl_ks.clone();
    check_acl(&acl, &req.did).await?;

    let session_id = Uuid::new_v4().to_string();

    // Generate 32-byte random challenge as hex
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);

    let session = Session {
        session_id: session_id.clone(),
        did: req.did,
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
    };

    let sessions = state.sessions_ks.clone();
    store_session(&sessions, &session).await?;

    info!(did = %session.did, session_id = %session.session_id, "auth challenge issued");

    Ok(Json(ChallengeResponse {
        session_id,
        data: ChallengeData { challenge },
    }))
}

// ---------- POST /auth/ ----------

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;
    let secrets_resolver = state
        .secrets_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("secrets resolver not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Unpack the DIDComm message
    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver.as_ref(),
        &UnpackOptions::default(),
    )
    .await
    .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Validate message type
    if msg.type_ != "https://affinidi.com/atm/1.0/authenticate" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.type_
        )));
    }

    // Extract challenge and session_id from body
    let challenge = msg.body["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?;
    let session_id = msg.body["session_id"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?;

    // Validate sender DID
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

    // Look up session and validate
    let sessions = state.sessions_ks.clone();
    let mut session = get_session(&sessions, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::ChallengeSent {
        warn!(session_id, "authentication rejected: session replay");
        return Err(AppError::Authentication(
            "session already authenticated (replay)".into(),
        ));
    }
    if session.challenge != challenge {
        warn!(session_id, "authentication rejected: challenge mismatch");
        return Err(AppError::Authentication("challenge mismatch".into()));
    }
    // Match the DID (compare base DID, ignoring any fragment)
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);
    if session.did != sender_base {
        warn!(session_id, sender = %sender_base, expected = %session.did, "authentication rejected: DID mismatch");
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Check challenge TTL
    {
        let config = state.config.read().await;
        let challenge_ttl = config.auth.challenge_ttl;
        drop(config);
        if now_epoch().saturating_sub(session.created_at) > challenge_ttl {
            warn!(session_id, "authentication rejected: challenge expired");
            return Err(AppError::Authentication("challenge expired".into()));
        }
    }

    // Look up ACL entry to get role and allowed contexts for the token
    let acl = state.acl_ks.clone();
    let (role, allowed_contexts) = check_acl_full(&acl, &session.did).await?;

    // Generate tokens
    let config = state.config.read().await;
    let access_expiry = config.auth.access_token_expiry;
    let refresh_expiry = config.auth.refresh_token_expiry;
    drop(config);

    let claims = JwtKeys::new_claims(
        session.did.clone(),
        session.session_id.clone(),
        role.to_string(),
        allowed_contexts,
        access_expiry,
    );
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;

    // Update session to Authenticated
    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    update_session(&sessions, &session).await?;

    // Store reverse refresh index
    store_refresh_index(&sessions, &refresh_token, &session.session_id).await?;

    info!(did = %session.did, session_id = %session.session_id, "authentication successful");

    Ok(Json(AuthenticateResponse {
        session_id: Some(session.session_id),
        data: AuthenticateData {
            access_token,
            access_expires_at,
            refresh_token: Some(refresh_token),
            refresh_expires_at: Some(refresh_expires_at),
        },
    }))
}

// ---------- POST /auth/refresh ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub session_id: String,
    pub data: RefreshData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshData {
    pub access_token: String,
    pub access_expires_at: u64,
}

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<RefreshResponse>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;
    let secrets_resolver = state
        .secrets_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("secrets resolver not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Unpack the DIDComm message
    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver.as_ref(),
        &UnpackOptions::default(),
    )
    .await
    .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Validate message type
    if msg.type_ != "https://affinidi.com/atm/1.0/authenticate/refresh" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.type_
        )));
    }

    // Extract refresh_token from body
    let refresh_token = msg.body["refresh_token"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?;

    // Look up session by refresh token
    let sessions = state.sessions_ks.clone();
    let session_id = get_session_by_refresh(&sessions, refresh_token)
        .await?
        .ok_or_else(|| AppError::Authentication("refresh token not found".into()))?;

    let session = get_session(&sessions, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::Authenticated {
        return Err(AppError::Authentication("session not authenticated".into()));
    }

    // Verify refresh token hasn't expired
    if let Some(expires_at) = session.refresh_expires_at
        && now_epoch() > expires_at
    {
        return Err(AppError::Authentication("refresh token expired".into()));
    }

    // Look up current ACL role and contexts (propagates changes at refresh time)
    let acl = state.acl_ks.clone();
    let (role, allowed_contexts) = check_acl_full(&acl, &session.did).await?;

    // Generate new access token
    let config = state.config.read().await;
    let access_expiry = config.auth.access_token_expiry;
    drop(config);

    let claims = JwtKeys::new_claims(
        session.did.clone(),
        session.session_id.clone(),
        role.to_string(),
        allowed_contexts,
        access_expiry,
    );
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    info!(did = %session.did, session_id = %session.session_id, "token refreshed");

    Ok(Json(RefreshResponse {
        session_id: session.session_id,
        data: RefreshData {
            access_token,
            access_expires_at,
        },
    }))
}

// ---------- POST /auth/credentials ----------

#[derive(Debug, Deserialize)]
pub struct GenerateCredentialsRequest {
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateCredentialsResponse {
    pub did: String,
    pub credential: String,
    pub role: Role,
}

pub async fn generate_credentials(
    auth: ManageAuth,
    State(state): State<AppState>,
    Json(req): Json<GenerateCredentialsRequest>,
) -> Result<(StatusCode, Json<GenerateCredentialsResponse>), AppError> {
    validate_acl_modification(&auth.0, &req.allowed_contexts)?;

    let config = state.config.read().await;
    let vtc_did = config
        .vtc_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?
        .clone();
    let vtc_url = config.public_url.clone();
    drop(config);

    let (did, private_key_multibase) = generate_did_key();

    // Add the new DID to the ACL
    let acl = state.acl_ks.clone();
    let entry = AclEntry {
        did: did.clone(),
        role: req.role.clone(),
        label: req.label,
        allowed_contexts: req.allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.0.did,
    };
    store_acl_entry(&acl, &entry).await?;

    // Build the credential bundle
    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase,
        vta_did: vtc_did,
        vta_url: vtc_url,
    };
    let credential = bundle
        .encode()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    info!(did = %did, role = %req.role, caller = %entry.created_by, "credentials generated");

    Ok((
        StatusCode::CREATED,
        Json(GenerateCredentialsResponse {
            did,
            credential,
            role: req.role,
        }),
    ))
}

// ---------- GET /auth/sessions ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub session_id: String,
    pub did: String,
    pub state: SessionState,
    pub created_at: u64,
    pub refresh_expires_at: Option<u64>,
}

impl From<Session> for SessionSummary {
    fn from(s: Session) -> Self {
        Self {
            session_id: s.session_id,
            did: s.did,
            state: s.state,
            created_at: s.created_at,
            refresh_expires_at: s.refresh_expires_at,
        }
    }
}

pub async fn session_list(
    _auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionSummary>>, AppError> {
    let sessions = state.sessions_ks.clone();
    let all = list_sessions(&sessions).await?;
    let summaries: Vec<SessionSummary> = all.into_iter().map(SessionSummary::from).collect();
    info!(caller = %_auth.0.did, count = summaries.len(), "sessions listed");
    Ok(Json(summaries))
}

// ---------- DELETE /auth/sessions/{session_id} ----------

pub async fn revoke_session(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let sessions = state.sessions_ks.clone();
    let session = get_session(&sessions, &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("session not found: {session_id}")))?;

    // Allow if caller owns the session or is admin
    if session.did != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "cannot revoke another user's session".into(),
        ));
    }

    delete_session(&sessions, &session_id).await?;
    info!(caller = %auth.did, session_id = %session_id, "session revoked");
    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /auth/sessions?did=X ----------

#[derive(Debug, Deserialize)]
pub struct RevokeByDidQuery {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeByDidResponse {
    pub revoked: u64,
}

pub async fn revoke_sessions_by_did(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<RevokeByDidQuery>,
) -> Result<Json<RevokeByDidResponse>, AppError> {
    let sessions = state.sessions_ks.clone();
    let all = list_sessions(&sessions).await?;
    let mut revoked = 0u64;

    for session in all {
        if session.did == query.did {
            delete_session(&sessions, &session.session_id).await?;
            revoked += 1;
        }
    }

    info!(caller = %_auth.0.did, target_did = %query.did, revoked, "sessions revoked by DID");
    Ok(Json(RevokeByDidResponse { revoked }))
}
