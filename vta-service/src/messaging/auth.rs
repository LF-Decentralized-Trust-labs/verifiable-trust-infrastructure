use affinidi_tdk::didcomm::Message;

use crate::acl::get_acl_entry;
use crate::auth::extractor::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Extract sender DID from a DIDComm message and look up their ACL entry,
/// returning unified `AuthClaims`.
pub async fn auth_from_message(
    msg: &Message,
    acl_ks: &KeyspaceHandle,
) -> Result<AuthClaims, AppError> {
    let did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

    // Strip any fragment (e.g. did:key:z6Mk...#z6Mk... → did:key:z6Mk...)
    let base_did = did.split('#').next().unwrap_or(did);

    let entry = get_acl_entry(acl_ks, base_did)
        .await?
        .ok_or_else(|| AppError::Forbidden(format!("DID not in ACL: {base_did}")))?;

    Ok(AuthClaims {
        did: base_did.to_string(),
        role: entry.role,
        allowed_contexts: entry.allowed_contexts,
    })
}
