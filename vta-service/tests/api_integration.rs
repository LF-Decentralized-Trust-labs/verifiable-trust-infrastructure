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
        let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTA").expect("jwt keys"));

        let seed_store: Arc<dyn vta_service::keys::seed_store::SeedStore> =
            Arc::new(TestSeedStore(vec![0xABu8; 32]));

        let mut config: AppConfig = toml::from_str(&format!(
            r#"
            vta_did = "did:key:z6MkTestVTA"
            [store]
            data_dir = "{}"
            [auth]
            jwt_signing_key = "{}"
            "#,
            dir.path().display(),
            BASE64.encode(jwt_seed),
        ))
        .expect("parse config");
        // Set config_path to a writable location so update_config can persist
        config.config_path = dir.path().join("config.toml");

        let (restart_tx, _rx) = watch::channel(false);

        let imported_ks = store.keyspace("imported_secrets").unwrap();
        let state = AppState {
            keys_ks: keys_ks.clone(),
            sessions_ks: sessions_ks.clone(),
            acl_ks: acl_ks.clone(),
            contexts_ks,
            audit_ks: audit_ks.clone(),
            imported_ks,
            cache_ks,
            #[cfg(feature = "webvh")]
            webvh_ks,
            wrapping_cache: vta_service::keys::wrapping::WrappingKeyCache::new(),
            config: Arc::new(RwLock::new(config)),
            seed_store,
            did_resolver: {
                use affinidi_did_resolver_cache_sdk::{
                    DIDCacheClient, config::DIDCacheConfigBuilder,
                };
                DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                    .await
                    .ok()
            },
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
        let json: Value = serde_json::from_slice(&body)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
        (status, json)
    }
}

struct TestContext {
    jwt_keys: Arc<JwtKeys>,
    sessions_ks: KeyspaceHandle,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    fn get(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, vti_common::error::AppError>>
                + Send
                + '_,
        >,
    > {
        let seed = self.0.clone();
        Box::pin(async move { Ok(Some(seed)) })
    }
    fn set(
        &self,
        _seed: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), vti_common::error::AppError>> + Send + '_>,
    > {
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

fn put_auth(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
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

// ── Capabilities ──────────────────────────────────────────────────

#[tokio::test]
async fn capabilities_requires_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/capabilities")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn capabilities_returns_features() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["any".into()])
        .await;
    let (status, body) = app.request(get_auth("/capabilities", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["version"].as_str().is_some());
    assert!(body["features"].is_object());
    assert!(body["services"].is_object());
    assert!(body["did_creation_modes"].is_array());
    // webvh feature is compiled in for tests
    assert_eq!(body["features"]["webvh"], true);
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
        .request(patch_auth("/config", &token, json!({"vta_name": "hacked"})))
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
        .request(patch_auth("/config", &token, json!({"vta_name": "nope"})))
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "should reject short password: {body}"
    );
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
    let (status, _) = app.request(delete_auth("/cache/test-key", &token)).await;
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
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-a", "name": "A"}),
    ))
    .await;
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-b", "name": "B"}),
    ))
    .await;

    // Create a key in ctx-a
    let (status, key_body) = app
        .request(post_auth(
            "/keys",
            &super_token,
            json!({"key_type": "ed25519", "context_id": "ctx-a"}),
        ))
        .await;
    assert!(status.is_success());
    let key_id = key_body["key_id"].as_str().unwrap();

    // Scoped admin for ctx-b cannot get the key in ctx-a (returns 403 or 404 — both are valid)
    let encoded_id = urlencoding::encode(key_id);
    let scoped_b_token = ctx
        .auth_token("did:key:z6MkB", "admin", vec!["ctx-b".into()])
        .await;
    let (status, _) = app
        .request(get_auth(&format!("/keys/{encoded_id}"), &scoped_b_token))
        .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "scoped admin should not access other context's key, got {status}"
    );

    // Scoped admin for ctx-a CAN get the key
    let scoped_a_token = ctx
        .auth_token("did:key:z6MkA", "admin", vec!["ctx-a".into()])
        .await;
    let (status, body) = app
        .request(get_auth(&format!("/keys/{encoded_id}"), &scoped_a_token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key_id"], key_id);
}

// ── Key lifecycle ──────────────────────────────────────────────────

#[tokio::test]
async fn key_create_revoke_list_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create context + key
    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "lc", "name": "Lifecycle"}),
    ))
    .await;
    let (_, key_body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "lc"}),
        ))
        .await;
    let key_id = key_body["key_id"].as_str().unwrap();
    assert_eq!(key_body["status"], "active");

    // Revoke the key (key_id may contain slashes from derivation path, URL-encode it)
    let encoded_id = urlencoding::encode(key_id);
    let (status, body) = app
        .request(delete_auth(&format!("/keys/{encoded_id}"), &token))
        .await;
    assert!(status.is_success(), "revoke: {status} {body}");

    // Get key — should show revoked status
    let (status, body) = app
        .request(get_auth(&format!("/keys/{encoded_id}"), &token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "revoked");
}

#[tokio::test]
async fn key_rename() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "rn", "name": "Rename"}),
    ))
    .await;
    let (_, key_body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "rn", "label": "original"}),
        ))
        .await;
    let key_id = key_body["key_id"].as_str().unwrap();

    // Rename the key (PATCH expects new key_id in body)
    let encoded_id = urlencoding::encode(key_id);
    let (status, body) = app
        .request(patch_auth(
            &format!("/keys/{encoded_id}"),
            &token,
            json!({"key_id": "renamed-key"}),
        ))
        .await;
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
    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "aud", "name": "Audit Test"}),
    ))
    .await;
    app.request(post_auth(
        "/keys",
        &token,
        json!({"key_type": "ed25519", "context_id": "aud"}),
    ))
    .await;

    // Check audit logs contain entries
    let (status, body) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries");
    assert!(
        !entries.is_empty(),
        "should have at least 1 audit entry, got {}",
        entries.len()
    );

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
    let (status, body) = app
        .request(patch_auth(
            "/audit/retention",
            &token,
            json!({"retention_days": 90}),
        ))
        .await;
    assert!(status.is_success(), "update retention: {status} {body}");
}

// ── Backup wrong password ──────────────────────────────────────────

#[tokio::test]
async fn backup_import_wrong_password_returns_auth_error() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Export with one password
    let (status, envelope) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "correct-password!!", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Import with wrong password
    let (status, body) = app
        .request(post_auth(
            "/backup/import",
            &token,
            json!({"backup": envelope, "password": "wrong-password!!!", "confirm": false}),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong password should → 401: {body}"
    );
}

// ── ACL CRUD full lifecycle ────────────────────────────────────────

#[tokio::test]
async fn acl_get_update_delete_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create
    app.request(post_auth(
        "/acl",
        &token,
        json!({
            "did": "did:key:z6MkTarget",
            "role": "application",
            "label": "test",
            "allowed_contexts": ["ctx1"]
        }),
    ))
    .await;

    // Get
    let (status, body) = app
        .request(get_auth("/acl/did:key:z6MkTarget", &token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "application");

    // Update
    let (status, body) = app
        .request(patch_auth(
            "/acl/did:key:z6MkTarget",
            &token,
            json!({"role": "initiator", "label": "updated"}),
        ))
        .await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["role"], "initiator");

    // Delete
    let (status, _) = app
        .request(delete_auth("/acl/did:key:z6MkTarget", &token))
        .await;
    assert!(status.is_success());

    // Verify deleted
    let (status, _) = app
        .request(get_auth("/acl/did:key:z6MkTarget", &token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Context lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn context_create_get_update_delete() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Create
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "lifecycle", "name": "Test", "description": "A test context"}),
        ))
        .await;
    assert!(status.is_success());

    // Get
    let (status, body) = app.request(get_auth("/contexts/lifecycle", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Test");
    assert_eq!(body["description"], "A test context");

    // Update
    let (status, body) = app
        .request(patch_auth(
            "/contexts/lifecycle",
            &token,
            json!({"name": "Updated"}),
        ))
        .await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["name"], "Updated");

    // List
    let (status, body) = app.request(get_auth("/contexts", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let contexts = body["contexts"].as_array().expect("contexts");
    assert!(contexts.iter().any(|c| c["id"] == "lifecycle"));

    // Delete
    let (status, _) = app
        .request(delete_auth("/contexts/lifecycle", &token))
        .await;
    assert!(status.is_success());
}

// ── Multiple key types ─────────────────────────────────────────────

#[tokio::test]
async fn create_p256_key() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "p256", "name": "P256 Test"}),
    ))
    .await;

    let (status, body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "p256", "context_id": "p256"}),
        ))
        .await;
    assert!(status.is_success(), "create p256: {status} {body}");
    assert_eq!(body["key_type"], "p256");
    assert!(body["public_key"].is_string());
}

// ── Context DID update (context admin) ────────────────────────────

#[tokio::test]
async fn context_admin_can_update_own_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create a context as super admin
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &super_token,
            json!({"id": "myctx", "name": "My Context"}),
        ))
        .await;
    assert!(status.is_success());

    // Context-scoped admin can update DID on their own context
    let scoped_token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["myctx".into()])
        .await;
    let (status, body) = app
        .request(put_auth(
            "/contexts/myctx/did",
            &scoped_token,
            json!({"did": "did:webvh:abc:example.com"}),
        ))
        .await;
    assert!(status.is_success(), "update did: {status} {body}");
    assert_eq!(body["did"], "did:webvh:abc:example.com");
}

#[tokio::test]
async fn context_admin_cannot_update_other_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create two contexts
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-a", "name": "A"}),
    ))
    .await;
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-b", "name": "B"}),
    ))
    .await;

    // Admin scoped to ctx-a cannot update ctx-b's DID
    let scoped_token = ctx
        .auth_token("did:key:z6MkScopedA", "admin", vec!["ctx-a".into()])
        .await;
    let (status, _) = app
        .request(put_auth(
            "/contexts/ctx-b/did",
            &scoped_token,
            json!({"did": "did:webvh:nope:example.com"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn super_admin_can_update_any_context_did() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "anyctx", "name": "Any"}),
    ))
    .await;

    let (status, body) = app
        .request(put_auth(
            "/contexts/anyctx/did",
            &token,
            json!({"did": "did:webvh:xyz:example.com"}),
        ))
        .await;
    assert!(
        status.is_success(),
        "super admin update did: {status} {body}"
    );
    assert_eq!(body["did"], "did:webvh:xyz:example.com");
}

#[tokio::test]
async fn non_admin_cannot_update_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "restricted", "name": "R"}),
    ))
    .await;

    // Application role cannot update DID
    let app_token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["restricted".into()])
        .await;
    let (status, _) = app
        .request(put_auth(
            "/contexts/restricted/did",
            &app_token,
            json!({"did": "did:webvh:bad:example.com"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Reader role tests ──────────────────────────────────────────────

#[tokio::test]
async fn reader_can_list_keys() {
    let (app, ctx) = TestApp::new().await;
    let reader_token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["test-ctx".into()])
        .await;

    let (status, _) = app
        .request(get_auth("/keys?context_id=test-ctx", &reader_token))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn reader_cannot_sign() {
    let (app, ctx) = TestApp::new().await;
    let reader_token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["test-ctx".into()])
        .await;

    let (status, _) = app
        .request(post_auth(
            "/keys/test-key/sign",
            &reader_token,
            json!({"payload": "aGVsbG8", "algorithm": "EdDSA"}),
        ))
        .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 403 or 422, got {status}"
    );
}

#[tokio::test]
async fn reader_cannot_create_key() {
    let (app, ctx) = TestApp::new().await;
    let reader_token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["test-ctx".into()])
        .await;

    let (status, _) = app
        .request(post_auth(
            "/keys",
            &reader_token,
            json!({"key_type": "ed25519", "context_id": "test-ctx"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── WebVH DID creation mode tests ─────────────────────────────────

/// Helper: create a context via the API and return admin token.
async fn setup_webvh_context(app: &TestApp, ctx: &TestContext, context_id: &str) -> String {
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &super_token,
            json!({"id": context_id, "name": context_id}),
        ))
        .await;
    assert!(status.is_success(), "create context: {status}");
    super_token
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_rejects_both_document_and_log() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-reject").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-reject",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "did_document": {"id": "{DID}"},
                "did_log": "{\"some\": \"log\"}"
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400: {body}");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_mode() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-template").await;

    // Client-provided DID document template with {DID} placeholders
    let template = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "verificationMethod": [{
            "id": "{DID}#custom-key",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }],
        "authentication": ["{DID}#custom-key"],
        "assertionMethod": ["{DID}#custom-key"]
    });

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-template",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "did_document": template,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "template create: {status} {body}"
    );
    assert!(body["did"].as_str().is_some(), "response has did");
    assert!(
        body["did_document"].is_object(),
        "response has did_document"
    );
    assert!(
        body["log_entry"].as_str().is_some(),
        "response has log_entry"
    );
    // Verify the template was used (custom key ID present in returned document)
    let doc = &body["did_document"];
    let vm = doc["verificationMethod"]
        .as_array()
        .expect("verificationMethod array");
    assert!(
        vm.iter().any(|v| {
            v["id"]
                .as_str()
                .is_some_and(|id| id.ends_with("#custom-key"))
        }),
        "template's custom key should be in the returned document"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_final_mode_stores_record() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-final").await;

    // First, create a DID via VTA-built mode to get a valid log entry
    let (status, created) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-final",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": false,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap create: {status} {created}"
    );
    let log_entry = created["log_entry"].as_str().expect("log_entry string");

    // Now create another DID using the log entry in final mode, under a new context
    let token2 = setup_webvh_context(&app, &ctx, "test-final-2").await;
    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token2,
            json!({
                "context_id": "test-final-2",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "did_log": log_entry,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "final mode create: {status} {body}"
    );
    let final_did = body["did"].as_str().expect("did in response");
    assert!(!final_did.is_empty());
    // signing_key_id and ka_key_id are empty in final mode (VTA didn't derive keys)
    assert_eq!(body["signing_key_id"].as_str().unwrap(), "");
    assert_eq!(body["ka_key_id"].as_str().unwrap(), "");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_set_primary_false() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-no-primary").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-no-primary",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": false,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Context's primary DID should still be null
    let (status, body) = app
        .request(get_auth("/contexts/test-no-primary", &token))
        .await;
    assert!(status.is_success(), "get context: {status}");
    assert!(
        body["did"].is_null(),
        "context did should be null when set_primary=false"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_set_primary_true() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-primary").await;

    let (status, created) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-primary",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": true,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let created_did = created["did"].as_str().expect("did");

    // Context's primary DID should be set
    let (status, body) = app
        .request(get_auth("/contexts/test-primary", &token))
        .await;
    assert!(status.is_success(), "get context: {status}");
    assert_eq!(
        body["did"].as_str().unwrap(),
        created_did,
        "context did should match created DID"
    );
}

// ── User-specified key tests ──────────────────────────────────────

/// Helper: import an Ed25519 key and return the key_id.
#[cfg(feature = "webvh")]
async fn import_ed25519_key(app: &TestApp, token: &str, label: &str, context_id: &str) -> String {
    // 32 deterministic bytes for the Ed25519 seed (test only)
    let seed_bytes = [0x42u8; 32];
    let mb = multibase::encode(multibase::Base::Base58Btc, seed_bytes);

    let (status, body) = app
        .request(post_auth(
            "/keys/import",
            token,
            json!({
                "key_type": "ed25519",
                "private_key_multibase": mb,
                "label": label,
                "context_id": context_id,
            }),
        ))
        .await;
    assert!(status.is_success(), "import ed25519: {status} {body}");
    body["key_id"].as_str().unwrap().to_string()
}

/// Helper: import an X25519 key and return the key_id.
#[cfg(feature = "webvh")]
async fn import_x25519_key(app: &TestApp, token: &str, label: &str, context_id: &str) -> String {
    // 32 deterministic bytes for the X25519 private key (test only)
    let key_bytes = [0x99u8; 32];
    let mb = multibase::encode(multibase::Base::Base58Btc, key_bytes);

    let (status, body) = app
        .request(post_auth(
            "/keys/import",
            token,
            json!({
                "key_type": "x25519",
                "private_key_multibase": mb,
                "label": label,
                "context_id": context_id,
            }),
        ))
        .await;
    assert!(status.is_success(), "import x25519: {status} {body}");
    body["key_id"].as_str().unwrap().to_string()
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_with_user_signing_key() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-user-sign").await;
    let signing_key = import_ed25519_key(&app, &token, "my-sign", "test-user-sign").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-user-sign",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": signing_key,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "signing-only create: {status} {body}"
    );
    assert!(body["did"].as_str().is_some());
    // Document should have signing key but no keyAgreement
    let doc = &body["did_document"];
    assert!(doc["authentication"].is_array());
    assert!(doc.get("keyAgreement").is_none() || doc["keyAgreement"].is_null());
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_with_user_signing_and_ka_keys() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-user-both").await;
    let signing_key = import_ed25519_key(&app, &token, "my-sign", "test-user-both").await;
    let ka_key = import_x25519_key(&app, &token, "my-ka", "test-user-both").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-user-both",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": signing_key,
                "ka_key_id": ka_key,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "both keys create: {status} {body}"
    );
    let doc = &body["did_document"];
    assert!(doc["keyAgreement"].is_array(), "should have keyAgreement");
    let vm = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(vm.len(), 2, "should have 2 verification methods");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_ka_without_signing_rejected() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-ka-only").await;
    let ka_key = import_x25519_key(&app, &token, "my-ka", "test-ka-only").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-ka-only",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "ka_key_id": ka_key,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_didcomm_requires_ka_key() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-didcomm-ka").await;
    let signing_key = import_ed25519_key(&app, &token, "my-sign", "test-didcomm-ka").await;

    // Signing key only + mediator service → should fail
    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-didcomm-ka",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": signing_key,
                "add_mediator_service": true,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "didcomm without ka: {status} {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_wrong_key_type_rejected() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-wrong-type").await;
    let ka_key = import_x25519_key(&app, &token, "my-ka", "test-wrong-type").await;

    // Use X25519 key as signing key → should fail
    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-wrong-type",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": ka_key,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── Server-managed DID creation tests ─────────────────────────────

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_unknown_server_returns_404() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-no-server").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-no-server",
                "server_id": "nonexistent-server",
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown server_id: {status} {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_server_and_url_mutually_exclusive() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-exclusive").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-exclusive",
                "server_id": "some-server",
                "url": "https://example.com/.well-known/did/did.jsonl",
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_neither_server_nor_url_rejected() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-neither").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-neither",
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
