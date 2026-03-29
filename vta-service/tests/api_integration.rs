//! Integration tests for the VTA REST API.
//!
//! Spins up the axum router with a temp fjall store and tests endpoints
//! with real HTTP requests. JWT tokens are created programmatically and
//! sessions are pre-inserted to bypass the DIDComm challenge-response flow.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::{RwLock, watch};
use tower::ServiceExt;

use vti_common::acl::Role;
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vta_service::config::AppConfig;
use vta_service::routes;
use vta_service::server::AppState;
use vta_service::store::KeyspaceHandle;

// ── Test harness ───────────────────────────────────────────────────

struct TestApp {
    router: axum::Router,
}

impl TestApp {
    async fn new() -> (Self, TestContext) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&store_config).expect("open store");

        let keys_ks = store.keyspace("keys").unwrap();
        let sessions_ks = store.keyspace("sessions").unwrap();
        let acl_ks = store.keyspace("acl").unwrap();
        let contexts_ks = store.keyspace("contexts").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        let cache_ks = store.keyspace("cache").unwrap();
        #[cfg(feature = "webvh")]
        let webvh_ks = store.keyspace("webvh").unwrap();

        let jwt_seed = [0x42u8; 32];
        let jwt_keys = Arc::new(
            JwtKeys::from_ed25519_bytes(&jwt_seed, "VTA").expect("jwt keys"),
        );

        let seed_store: Arc<dyn vta_service::keys::seed_store::SeedStore> = Arc::new(
            TestSeedStore(vec![0xABu8; 32]),
        );

        let mut config: AppConfig = toml::from_str(&format!(
            r#"
            vta_did = "did:key:z6MkTestVTA"
            [store]
            data_dir = "{}"
            [auth]
            jwt_signing_key = "{}"
            "#,
            dir.path().display(),
            BASE64.encode(&jwt_seed),
        ))
        .expect("parse config");
        // Set config_path to a writable location so update_config can persist
        config.config_path = dir.path().join("config.toml");

        let (restart_tx, _rx) = watch::channel(false);

        let state = AppState {
            keys_ks: keys_ks.clone(),
            sessions_ks: sessions_ks.clone(),
            acl_ks: acl_ks.clone(),
            contexts_ks,
            audit_ks: audit_ks.clone(),
            cache_ks,
            #[cfg(feature = "webvh")]
            webvh_ks,
            config: Arc::new(RwLock::new(config)),
            seed_store,
            did_resolver: None,
            secrets_resolver: None,
            #[cfg(feature = "didcomm")]
            didcomm_bridge: Arc::new(tokio::sync::RwLock::new(None)),
            jwt_keys: Some(jwt_keys.clone()),
            atm: None,
            tee: None,
            restart_tx,
            metrics_handle: None,
        };

        let router = routes::router()
            .with_state(state.clone())
            .merge(routes::health_router().with_state(state));

        let ctx = TestContext {
            jwt_keys,
            sessions_ks,
            acl_ks,
            _dir: dir,
        };

        (Self { router }, ctx)
    }

    async fn request(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("request failed");
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
        (status, json)
    }
}

struct TestContext {
    jwt_keys: Arc<JwtKeys>,
    sessions_ks: KeyspaceHandle,
    acl_ks: KeyspaceHandle,
    _dir: tempfile::TempDir,
}

impl TestContext {
    /// Create an authenticated session and return a Bearer token.
    async fn auth_token(&self, did: &str, role: &str, contexts: Vec<String>) -> String {
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        let session = Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
        };
        store_session(&self.sessions_ks, &session)
            .await
            .expect("store session");

        let claims = self.jwt_keys.new_claims(
            did.to_string(),
            session_id,
            role.to_string(),
            contexts,
            900,
            false,
        );
        self.jwt_keys.encode(&claims).expect("encode jwt")
    }

    /// Create an ACL entry for a DID.
    async fn create_acl(&self, did: &str, role: Role, contexts: Vec<String>) {
        let entry = vti_common::acl::AclEntry {
            did: did.to_string(),
            role,
            label: None,
            allowed_contexts: contexts,
            created_at: now_epoch(),
            created_by: "test".to_string(),
        };
        self.acl_ks
            .insert(format!("acl:{did}"), &entry)
            .await
            .expect("insert acl");
    }
}

/// Minimal seed store for tests.
struct TestSeedStore(Vec<u8>);

impl vta_service::keys::seed_store::SeedStore for TestSeedStore {
    fn get(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, vti_common::error::AppError>> + Send + '_>> {
        let seed = self.0.clone();
        Box::pin(async move { Ok(Some(seed)) })
    }
    fn set(&self, _seed: &[u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), vti_common::error::AppError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_auth(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn patch_auth(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn delete_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// ── Health ─────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok_without_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, body) = app.request(get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn health_details_requires_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/health/details")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_details_returns_version_with_auth() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkTest", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/health/details", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
}

// ── Auth: missing/invalid token ────────────────────────────────────

#[tokio::test]
async fn missing_token_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/config")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get_auth("/config", "not-a-jwt")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_session_returns_401() {
    let (app, ctx) = TestApp::new().await;
    // Create a token with a valid JWT but no session in the store
    let claims = ctx.jwt_keys.new_claims(
        "did:key:z6MkGhost".into(),
        "nonexistent-session".into(),
        "admin".into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();
    let (status, _) = app.request(get_auth("/config", &token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ── Role enforcement ───────────────────────────────────────────────

#[tokio::test]
async fn application_role_cannot_access_admin_endpoints() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["ctx1".into()])
        .await;
    // POST /keys requires admin
    let (status, _) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "ctx1"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn initiator_cannot_access_super_admin_endpoints() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkInit", "initiator", vec![])
        .await;
    // PATCH /config requires super admin
    let (status, _) = app
        .request(patch_auth(
            "/config",
            &token,
            json!({"vta_name": "hacked"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_read_config() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/config", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["vta_did"], "did:key:z6MkTestVTA");
}

#[tokio::test]
async fn super_admin_can_update_config() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(patch_auth(
            "/config",
            &token,
            json!({"vta_name": "Updated Name"}),
        ))
        .await;
    assert!(status.is_success(), "update config: {status} {body}");
    assert_eq!(body["vta_name"], "Updated Name");
}

#[tokio::test]
async fn scoped_admin_cannot_update_config() {
    let (app, ctx) = TestApp::new().await;
    // Admin with allowed_contexts is NOT super admin
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(patch_auth(
            "/config",
            &token,
            json!({"vta_name": "nope"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── ACL CRUD ───────────────────────────────────────────────────────

#[tokio::test]
async fn acl_create_and_list() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create
    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({
                "did": "did:key:z6MkNew",
                "role": "application",
                "label": "test app",
                "allowed_contexts": ["ctx1"]
            }),
        ))
        .await;
    assert!(status.is_success(), "create: {body}");

    // List
    let (status, body) = app.request(get_auth("/acl", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries array");
    assert!(
        entries.iter().any(|e| e["did"] == "did:key:z6MkNew"),
        "new entry should be in list"
    );
}

#[tokio::test]
async fn acl_application_cannot_manage() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["ctx1".into()])
        .await;
    let (status, _) = app.request(get_auth("/acl", &token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Context CRUD ───────────────────────────────────────────────────

#[tokio::test]
async fn context_create_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    // Scoped admin → forbidden
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "new-ctx", "name": "New Context"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Super admin → OK
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "new-ctx", "name": "New Context"}),
        ))
        .await;
    assert!(status.is_success(), "create: {body}");
}

// ── Key management ─────────────────────────────────────────────────

#[tokio::test]
async fn key_create_and_list() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create a context first (needed for key creation)
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "test", "name": "Test Context"}),
        ))
        .await;
    assert!(status.is_success());

    // Create key
    let (status, body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "test"}),
        ))
        .await;
    assert!(status.is_success(), "create key: {body}");
    assert!(body["key_id"].is_string());
    assert_eq!(body["key_type"], "ed25519");

    // List keys
    let (status, body) = app.request(get_auth("/keys", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().expect("keys array");
    assert!(!keys.is_empty(), "should have at least one key");
}

// ── Restart requires super admin ───────────────────────────────────

#[tokio::test]
async fn restart_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    // Regular admin with contexts → forbidden
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(post_auth("/vta/restart", &token, json!({})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Initiator → forbidden
    let token = ctx
        .auth_token("did:key:z6MkInit", "initiator", vec![])
        .await;
    let (status, _) = app
        .request(post_auth("/vta/restart", &token, json!({})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Backup requires super admin ────────────────────────────────────

#[tokio::test]
async fn backup_export_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    // Scoped admin → forbidden
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "test-password-12!!", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn backup_export_rejects_short_password() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "short", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "should reject short password: {body}");
}

#[tokio::test]
async fn backup_export_and_import_preview() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Export
    let (status, envelope) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "test-password-12!!", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "export: {envelope}");
    assert_eq!(envelope["format"], "vta-backup-v1");

    // Import preview (confirm=false)
    let (status, preview) = app
        .request(post_auth(
            "/backup/import",
            &token,
            json!({
                "backup": envelope,
                "password": "test-password-12!!",
                "confirm": false
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "preview: {preview}");
    assert_eq!(preview["status"], "preview");
}

// ── Cache ──────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_put_get_delete() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/cache/test-key")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"value":"hello","ttl_secs":60}"#))
        .unwrap();
    let (status, _) = app.request(req).await;
    assert!(status.is_success(), "PUT cache: {status}");

    // GET
    let (status, body) = app.request(get_auth("/cache/test-key", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], "hello");

    // DELETE
    let (status, _) = app
        .request(delete_auth("/cache/test-key", &token))
        .await;
    assert!(status.is_success(), "DELETE cache: {status}");

    // GET again → 404
    let (status, _) = app.request(get_auth("/cache/test-key", &token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Audit ──────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_list_requires_admin() {
    let (app, ctx) = TestApp::new().await;

    // Application → forbidden
    let token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["ctx1".into()])
        .await;
    let (status, _) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin → OK
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["entries"].is_array());
}

// ── Context scoping ────────────────────────────────────────────────

#[tokio::test]
async fn scoped_admin_can_only_access_own_context_keys() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Create two contexts
    app.request(post_auth("/contexts", &super_token, json!({"id": "ctx-a", "name": "A"}))).await;
    app.request(post_auth("/contexts", &super_token, json!({"id": "ctx-b", "name": "B"}))).await;

    // Create a key in ctx-a
    let (status, key_body) = app.request(post_auth(
        "/keys", &super_token, json!({"key_type": "ed25519", "context_id": "ctx-a"}),
    )).await;
    assert!(status.is_success());
    let key_id = key_body["key_id"].as_str().unwrap();

    // Scoped admin for ctx-b cannot get the key in ctx-a (returns 403 or 404 — both are valid)
    let encoded_id = urlencoding::encode(key_id);
    let scoped_b_token = ctx.auth_token("did:key:z6MkB", "admin", vec!["ctx-b".into()]).await;
    let (status, _) = app.request(get_auth(&format!("/keys/{encoded_id}"), &scoped_b_token)).await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "scoped admin should not access other context's key, got {status}"
    );

    // Scoped admin for ctx-a CAN get the key
    let scoped_a_token = ctx.auth_token("did:key:z6MkA", "admin", vec!["ctx-a".into()]).await;
    let (status, body) = app.request(get_auth(&format!("/keys/{encoded_id}"), &scoped_a_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key_id"], key_id);
}

// ── Key lifecycle ──────────────────────────────────────────────────

#[tokio::test]
async fn key_create_revoke_list_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create context + key
    app.request(post_auth("/contexts", &token, json!({"id": "lc", "name": "Lifecycle"}))).await;
    let (_, key_body) = app.request(post_auth(
        "/keys", &token, json!({"key_type": "ed25519", "context_id": "lc"}),
    )).await;
    let key_id = key_body["key_id"].as_str().unwrap();
    assert_eq!(key_body["status"], "active");

    // Revoke the key (key_id may contain slashes from derivation path, URL-encode it)
    let encoded_id = urlencoding::encode(key_id);
    let (status, body) = app.request(delete_auth(&format!("/keys/{encoded_id}"), &token)).await;
    assert!(status.is_success(), "revoke: {status} {body}");

    // Get key — should show revoked status
    let (status, body) = app.request(get_auth(&format!("/keys/{encoded_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "revoked");
}

#[tokio::test]
async fn key_rename() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth("/contexts", &token, json!({"id": "rn", "name": "Rename"}))).await;
    let (_, key_body) = app.request(post_auth(
        "/keys", &token, json!({"key_type": "ed25519", "context_id": "rn", "label": "original"}),
    )).await;
    let key_id = key_body["key_id"].as_str().unwrap();

    // Rename the key (PATCH expects new key_id in body)
    let encoded_id = urlencoding::encode(key_id);
    let (status, body) = app.request(patch_auth(
        &format!("/keys/{encoded_id}"), &token, json!({"key_id": "renamed-key"}),
    )).await;
    assert!(status.is_success(), "rename: {status} {body}");
    assert_eq!(body["key_id"], "renamed-key");
}

// ── Seed management ────────────────────────────────────────────────

#[tokio::test]
async fn seed_list_returns_seeds() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/keys/seeds", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["seeds"].is_array());
}

// ── Audit entries created by operations ────────────────────────────

#[tokio::test]
async fn operations_create_audit_entries() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Perform some operations that create audit entries
    app.request(post_auth("/contexts", &token, json!({"id": "aud", "name": "Audit Test"}))).await;
    app.request(post_auth(
        "/keys", &token, json!({"key_type": "ed25519", "context_id": "aud"}),
    )).await;

    // Check audit logs contain entries
    let (status, body) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries");
    assert!(!entries.is_empty(), "should have at least 1 audit entry, got {}", entries.len());

    // Verify audit entries have expected fields
    let entry = &entries[0];
    assert!(entry["id"].is_string());
    assert!(entry["timestamp"].is_number());
    assert!(entry["action"].is_string());
    assert!(entry["actor"].is_string());
}

// ── Audit retention ────────────────────────────────────────────────

#[tokio::test]
async fn audit_retention_get_and_update() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Get current retention
    let (status, body) = app.request(get_auth("/audit/retention", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["retention_days"].is_number());

    // Update retention
    let (status, body) = app.request(patch_auth(
        "/audit/retention", &token, json!({"retention_days": 90}),
    )).await;
    assert!(status.is_success(), "update retention: {status} {body}");
}

// ── Backup wrong password ──────────────────────────────────────────

#[tokio::test]
async fn backup_import_wrong_password_returns_auth_error() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Export with one password
    let (status, envelope) = app.request(post_auth(
        "/backup/export", &token,
        json!({"password": "correct-password!!", "include_audit": false}),
    )).await;
    assert_eq!(status, StatusCode::OK);

    // Import with wrong password
    let (status, body) = app.request(post_auth(
        "/backup/import", &token,
        json!({"backup": envelope, "password": "wrong-password!!!", "confirm": false}),
    )).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong password should → 401: {body}");
}

// ── ACL CRUD full lifecycle ────────────────────────────────────────

#[tokio::test]
async fn acl_get_update_delete_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create
    app.request(post_auth("/acl", &token, json!({
        "did": "did:key:z6MkTarget",
        "role": "application",
        "label": "test",
        "allowed_contexts": ["ctx1"]
    }))).await;

    // Get
    let (status, body) = app.request(get_auth("/acl/did:key:z6MkTarget", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "application");

    // Update
    let (status, body) = app.request(patch_auth(
        "/acl/did:key:z6MkTarget", &token,
        json!({"role": "initiator", "label": "updated"}),
    )).await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["role"], "initiator");

    // Delete
    let (status, _) = app.request(delete_auth("/acl/did:key:z6MkTarget", &token)).await;
    assert!(status.is_success());

    // Verify deleted
    let (status, _) = app.request(get_auth("/acl/did:key:z6MkTarget", &token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Context lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn context_create_get_update_delete() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Create
    let (status, _) = app.request(post_auth(
        "/contexts", &token, json!({"id": "lifecycle", "name": "Test", "description": "A test context"}),
    )).await;
    assert!(status.is_success());

    // Get
    let (status, body) = app.request(get_auth("/contexts/lifecycle", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Test");
    assert_eq!(body["description"], "A test context");

    // Update
    let (status, body) = app.request(patch_auth(
        "/contexts/lifecycle", &token, json!({"name": "Updated"}),
    )).await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["name"], "Updated");

    // List
    let (status, body) = app.request(get_auth("/contexts", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let contexts = body["contexts"].as_array().expect("contexts");
    assert!(contexts.iter().any(|c| c["id"] == "lifecycle"));

    // Delete
    let (status, _) = app.request(delete_auth("/contexts/lifecycle", &token)).await;
    assert!(status.is_success());
}

// ── Multiple key types ─────────────────────────────────────────────

#[tokio::test]
async fn create_p256_key() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth("/contexts", &token, json!({"id": "p256", "name": "P256 Test"}))).await;

    let (status, body) = app.request(post_auth(
        "/keys", &token, json!({"key_type": "p256", "context_id": "p256"}),
    )).await;
    assert!(status.is_success(), "create p256: {status} {body}");
    assert_eq!(body["key_type"], "p256");
    assert!(body["public_key"].is_string());
}
