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
