//! AC-001, AC-002, AC-025: a code yields a scoped token, an expired code is
//! refused without writing a session, and a revoked token stops working.
//!
//! Every store is a tempfile, so these tests never touch the real pairing
//! state under `~/.opencrabs/`.

use crate::remote::pairing::{PairingStore, StoreFile, VerifyError};
use crate::remote::scopes::{SCOPE_READ, SCOPE_SEND, SCOPE_SESSION_SEND};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn store() -> PairingStore {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    PairingStore::new(std::env::temp_dir().join(format!(
        "oc-pairing-test-{}-{}-{n}.json",
        std::process::id(),
        Uuid::new_v4()
    )))
}

#[test]
fn pairing_issues_scoped_token() {
    let store = store();
    let scopes = vec![SCOPE_READ.to_string(), SCOPE_SEND.to_string()];
    let code = store.mint_code(&scopes).expect("mint");

    let (token, session) = store.verify_code(&code, "phone").expect("verify");
    assert!(token.starts_with(crate::remote::pairing::TOKEN_PREFIX));
    assert_eq!(session.scopes, scopes, "the token carries the code's scopes");
    assert_eq!(session.label, "phone");
    assert!(session.revoked_at.is_none());

    let verified = store.verify_token(&token).expect("token resolves");
    assert_eq!(verified.id, session.id);
    assert_eq!(verified.scopes, scopes);
}

#[test]
fn a_code_is_single_use() {
    let store = store();
    let code = store.mint_code(&[SCOPE_READ.to_string()]).expect("mint");
    assert!(store.verify_code(&code, "phone").is_ok());
    assert!(
        matches!(store.verify_code(&code, "laptop"), Err(VerifyError::NoMatch)),
        "a consumed code cannot be replayed"
    );
}

#[test]
fn expired_code_rejected() {
    let store = store();
    let code = store
        .mint_code(&[SCOPE_READ.to_string()])
        .expect("mint the code");

    // Age the pending code past its TTL by rewriting the store, which is
    // cheaper and more precise than sleeping 301 s.
    let raw = std::fs::read_to_string(store.path()).expect("store file exists");
    let mut file: StoreFile = serde_json::from_str(&raw).expect("store parses");
    for pending in &mut file.codes {
        pending.expires_at = 1;
    }
    let rewritten = serde_json::to_string_pretty(&file).expect("store serialises");
    std::fs::write(store.path(), rewritten).expect("store rewritten");

    assert!(
        matches!(store.verify_code(&code, "phone"), Err(VerifyError::NoMatch)),
        "an expired code is indistinguishable from an unknown one"
    );
    assert!(
        store.list_sessions().expect("list").is_empty(),
        "no token row was written"
    );
}

#[test]
fn revoked_token_rejected() {
    let store = store();
    let scopes = vec![SCOPE_READ.to_string(), SCOPE_SESSION_SEND.to_string()];
    let code = store.mint_code(&scopes).expect("mint");
    let (token, session) = store.verify_code(&code, "lost phone").expect("verify");
    assert!(store.verify_token(&token).is_some());

    let revoked = store.revoke(&session.id).expect("revoke");
    assert_eq!(revoked, 1, "exactly one session was revoked");
    assert!(
        store.verify_token(&token).is_none(),
        "the token is dead on its next request"
    );

    let listed = store.list_sessions().expect("list");
    let row = listed
        .iter()
        .find(|s| s.id == session.id)
        .expect("the row is kept for the audit trail");
    assert!(!row.active, "listed as inactive");
    assert_eq!(row.label, "lost phone", "the label survives revocation");
}

#[test]
fn revoking_by_label_works_too() {
    let store = store();
    let code = store.mint_code(&[SCOPE_READ.to_string()]).expect("mint");
    let (token, _) = store.verify_code(&code, "tablet").expect("verify");
    assert_eq!(store.revoke("tablet").expect("revoke by label"), 1);
    assert!(store.verify_token(&token).is_none());
}

#[test]
fn an_unknown_scope_cannot_be_minted() {
    let store = store();
    assert!(
        store.mint_code(&["root:everything".to_string()]).is_err(),
        "a code may only carry a known scope"
    );
    assert!(store.mint_code(&[]).is_err(), "a code needs at least one");
}
