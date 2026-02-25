use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn server_key(id: &str) -> String {
    format!("server:{id}")
}

fn did_key(did: &str) -> String {
    format!("did:{did}")
}

fn log_key(did: &str) -> String {
    format!("log:{did}")
}

pub async fn get_server(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<WebvhServerRecord>, AppError> {
    ks.get(server_key(id)).await
}

pub async fn store_server(ks: &KeyspaceHandle, record: &WebvhServerRecord) -> Result<(), AppError> {
    ks.insert(server_key(&record.id), record).await
}

pub async fn delete_server(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(server_key(id)).await
}

pub async fn list_servers(ks: &KeyspaceHandle) -> Result<Vec<WebvhServerRecord>, AppError> {
    let raw = ks.prefix_iter_raw("server:").await?;
    let mut servers = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: WebvhServerRecord = serde_json::from_slice(&value)?;
        servers.push(record);
    }
    Ok(servers)
}

pub async fn get_did(ks: &KeyspaceHandle, did: &str) -> Result<Option<WebvhDidRecord>, AppError> {
    ks.get(did_key(did)).await
}

pub async fn store_did(ks: &KeyspaceHandle, record: &WebvhDidRecord) -> Result<(), AppError> {
    ks.insert(did_key(&record.did), record).await
}

pub async fn delete_did(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.remove(did_key(did)).await
}

pub async fn list_dids(ks: &KeyspaceHandle) -> Result<Vec<WebvhDidRecord>, AppError> {
    let raw = ks.prefix_iter_raw("did:").await?;
    let mut dids = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: WebvhDidRecord = serde_json::from_slice(&value)?;
        dids.push(record);
    }
    Ok(dids)
}

pub async fn store_did_log(
    ks: &KeyspaceHandle,
    did: &str,
    log_content: &str,
) -> Result<(), AppError> {
    ks.insert_raw(log_key(did), log_content.as_bytes().to_vec())
        .await
}

pub async fn get_did_log(ks: &KeyspaceHandle, did: &str) -> Result<Option<String>, AppError> {
    match ks.get_raw(log_key(did)).await? {
        Some(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|e| {
            AppError::Internal(format!("invalid UTF-8 in DID log: {e}"))
        })?)),
        None => Ok(None),
    }
}
