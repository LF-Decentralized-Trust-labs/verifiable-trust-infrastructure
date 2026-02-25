use serde::Deserialize;
use tracing::{debug, info};

use crate::error::AppError;

pub struct WebvhClient {
    http: reqwest::Client,
    server_url: String,
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RequestUriResponse {
    pub did_url: String,
    pub mnemonic: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckPathResponse {
    pub available: bool,
}

impl WebvhClient {
    pub fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            access_token: None,
        }
    }

    pub fn set_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    fn auth_header(&self) -> Option<String> {
        self.access_token.as_ref().map(|t| format!("Bearer {t}"))
    }

    /// POST /api/dids — allocate URI (optional path).
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let mut req = self.http.post(&url);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let body = match path {
            Some(p) => serde_json::json!({ "path": p }),
            None => serde_json::json!({}),
        };
        let resp = req
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "webvh-server POST /api/dids failed ({status}): {text}"
            )));
        }
        debug!(method = "POST", status = 200, "webvh: received via rest");
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// PUT /api/dids/{mnemonic} — publish DID log.
    pub async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        let url = format!("{}/api/dids/{mnemonic}", self.server_url);
        info!(method = "PUT", %url, "webvh: sending via rest");
        let mut req = self.http.put(&url);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req
            .header("Content-Type", "application/jsonl")
            .body(log_content.to_string())
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "webvh-server PUT /api/dids/{mnemonic} failed ({status}): {text}"
            )));
        }
        debug!(method = "PUT", status = 200, "webvh: received via rest");
        Ok(())
    }

    /// DELETE /api/dids/{mnemonic}.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        let url = format!("{}/api/dids/{mnemonic}", self.server_url);
        info!(method = "DELETE", %url, "webvh: sending via rest");
        let mut req = self.http.delete(&url);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "webvh-server DELETE /api/dids/{mnemonic} failed ({status}): {text}"
            )));
        }
        debug!(method = "DELETE", status = 200, "webvh: received via rest");
        Ok(())
    }

    /// POST /api/dids/check — check if a path is available.
    pub async fn check_path(&self, path: &str) -> Result<CheckPathResponse, AppError> {
        let url = format!("{}/api/dids/check", self.server_url);
        let mut req = self.http.post(&url);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req
            .json(&serde_json::json!({ "path": path }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "webvh-server POST /api/dids/check failed ({status}): {text}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }
}
