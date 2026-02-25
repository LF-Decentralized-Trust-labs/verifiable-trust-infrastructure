pub mod acl;
pub mod config;
pub mod contexts;
pub mod credentials;
#[cfg(feature = "webvh")]
pub mod did_webvh;
pub mod keys;
pub mod seeds;

pub type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Generate a DIDComm handler function that follows the standard pattern:
/// authenticate → (optional admin check) → (optional body deser) → call op → send response.
///
/// The closure-like `|state, auth, body|` or `|state, auth|` binds identifiers
/// that are accessible within the `$op` expression.
macro_rules! didcomm_handler {
    // With body, admin auth
    ($name:ident, body: $body_ty:ty, auth: admin, result: $result:expr,
     |$state:ident, $auth:ident, $body:ident| $op:expr) => {
        pub async fn $name(
            $state: &DidcommState,
            ctx: &DIDCommCtx<'_>,
            msg: &Message,
        ) -> HandlerResult {
            let $auth = auth_from_message(msg, &$state.acl_ks).await?;
            $auth.require_admin()?;
            let $body: $body_ty = serde_json::from_value(msg.body.clone())?;
            let result = $op.await?;
            ctx.send_response(&$auth.did, $result, Some(&msg.id), &result)
                .await
        }
    };
    // With body, any auth
    ($name:ident, body: $body_ty:ty, result: $result:expr,
     |$state:ident, $auth:ident, $body:ident| $op:expr) => {
        pub async fn $name(
            $state: &DidcommState,
            ctx: &DIDCommCtx<'_>,
            msg: &Message,
        ) -> HandlerResult {
            let $auth = auth_from_message(msg, &$state.acl_ks).await?;
            let $body: $body_ty = serde_json::from_value(msg.body.clone())?;
            let result = $op.await?;
            ctx.send_response(&$auth.did, $result, Some(&msg.id), &result)
                .await
        }
    };
    // No body, admin auth
    ($name:ident, auth: admin, result: $result:expr,
     |$state:ident, $auth:ident| $op:expr) => {
        pub async fn $name(
            $state: &DidcommState,
            ctx: &DIDCommCtx<'_>,
            msg: &Message,
        ) -> HandlerResult {
            let $auth = auth_from_message(msg, &$state.acl_ks).await?;
            $auth.require_admin()?;
            let result = $op.await?;
            ctx.send_response(&$auth.did, $result, Some(&msg.id), &result)
                .await
        }
    };
    // No body, any auth
    ($name:ident, result: $result:expr,
     |$state:ident, $auth:ident| $op:expr) => {
        pub async fn $name(
            $state: &DidcommState,
            ctx: &DIDCommCtx<'_>,
            msg: &Message,
        ) -> HandlerResult {
            let $auth = auth_from_message(msg, &$state.acl_ks).await?;
            let result = $op.await?;
            ctx.send_response(&$auth.did, $result, Some(&msg.id), &result)
                .await
        }
    };
}

pub(crate) use didcomm_handler;
