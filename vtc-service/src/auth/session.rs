use crate::error::AppError;
use crate::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Session lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    ChallengeSent,
    Authenticated,
}

/// A session record stored in fjall under `session:{session_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub did: String,
    pub challenge: String,
    pub state: SessionState,
    pub created_at: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
}

fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

fn refresh_key(token: &str) -> String {
    format!("refresh:{token}")
}

/// Store a new session in the `sessions` keyspace.
pub async fn store_session(sessions: &KeyspaceHandle, session: &Session) -> Result<(), AppError> {
    sessions
        .insert(session_key(&session.session_id), session)
        .await?;
    debug!(session_id = %session.session_id, did = %session.did, "session stored");
    Ok(())
}

/// Load a session by session_id.
pub async fn get_session(
    sessions: &KeyspaceHandle,
    session_id: &str,
) -> Result<Option<Session>, AppError> {
    sessions.get(session_key(session_id)).await
}

/// Update an existing session (overwrites).
pub async fn update_session(sessions: &KeyspaceHandle, session: &Session) -> Result<(), AppError> {
    sessions
        .insert(session_key(&session.session_id), session)
        .await
}

/// Store a reverse index from refresh token to session_id.
pub async fn store_refresh_index(
    sessions: &KeyspaceHandle,
    token: &str,
    session_id: &str,
) -> Result<(), AppError> {
    sessions
        .insert_raw(refresh_key(token), session_id.as_bytes().to_vec())
        .await
}

/// Look up a session_id by refresh token.
pub async fn get_session_by_refresh(
    sessions: &KeyspaceHandle,
    token: &str,
) -> Result<Option<String>, AppError> {
    match sessions.get_raw(refresh_key(token)).await? {
        Some(bytes) => {
            let session_id = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid session_id bytes: {e}")))?;
            Ok(Some(session_id))
        }
        None => Ok(None),
    }
}

/// Returns the current UNIX epoch timestamp in seconds.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Delete a single session and its refresh index.
pub async fn delete_session(sessions: &KeyspaceHandle, session_id: &str) -> Result<(), AppError> {
    let session: Option<Session> = sessions.get(session_key(session_id)).await?;
    if let Some(session) = session {
        if let Some(ref token) = session.refresh_token {
            sessions.remove(refresh_key(token)).await?;
        }
        sessions.remove(session_key(session_id)).await?;
        debug!(session_id, "session deleted");
    }
    Ok(())
}

/// List all active sessions.
pub async fn list_sessions(sessions: &KeyspaceHandle) -> Result<Vec<Session>, AppError> {
    let raw = sessions.prefix_iter_raw("session:").await?;
    let mut result = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        if let Ok(session) = serde_json::from_slice::<Session>(&value) {
            result.push(session);
        }
    }
    Ok(result)
}

/// Remove expired sessions from the store.
///
/// - `ChallengeSent` sessions expire after `challenge_ttl` seconds from `created_at`.
/// - `Authenticated` sessions expire when `refresh_expires_at` has passed.
pub async fn cleanup_expired_sessions(
    sessions: &KeyspaceHandle,
    challenge_ttl: u64,
) -> Result<(), AppError> {
    let entries = sessions.prefix_iter_raw("session:").await?;
    let now = now_epoch();
    let mut removed = 0u64;

    for (key, value) in entries {
        let session: Session = match serde_json::from_slice(&value) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let expired = match session.state {
            SessionState::ChallengeSent => now.saturating_sub(session.created_at) > challenge_ttl,
            SessionState::Authenticated => session
                .refresh_expires_at
                .is_none_or(|expires| now > expires),
        };

        if expired {
            sessions.remove(key).await?;
            if let Some(ref token) = session.refresh_token {
                sessions.remove(refresh_key(token)).await?;
            }
            removed += 1;
        }
    }

    debug!(removed, "session cleanup complete");

    Ok(())
}
