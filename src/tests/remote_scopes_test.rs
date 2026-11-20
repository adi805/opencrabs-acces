use crate::remote::scopes::*;

/// The complete dispatched method surface: dispatch.rs (message/send,
/// tasks/get, tasks/cancel, session/notify, session/notify-status),
/// server.rs SSE (message/stream), and the remote session surface
/// (session/*, fs/*, device/*). Every entry must carry a scope.
const KNOWN_METHODS: &[&str] = &[
    // Classic A2A surface, unchanged by the remote release.
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/cancel",
    "session/notify",
    "session/notify-status",
    // Remote session surface.
    "session/list",
    "session/history",
    "session/attach",
    "session/send",
    "session/interrupt",
    "session/ack",
    "session/approve",
    "session/presence",
    // Client filesystem proxy.
    "fs/list",
    "fs/read",
    "fs/write",
    // Device administration.
    "device/list",
    "device/revoke",
];

#[test]
fn every_dispatched_method_has_a_scope() {
    for m in KNOWN_METHODS {
        assert!(
            scope_for_method(m).is_some(),
            "{m} missing from scope table"
        );
    }
}

#[test]
fn unknown_methods_are_not_gated_here() {
    assert_eq!(scope_for_method("agent/info"), None);
    assert_eq!(scope_for_method("nonexistent/method"), None);
    assert_eq!(scope_for_method(""), None);
}

#[test]
fn scope_assignment_matrix() {
    assert_eq!(scope_for_method("tasks/get"), Some(SCOPE_READ));
    assert_eq!(scope_for_method("session/notify-status"), Some(SCOPE_READ));
    assert_eq!(scope_for_method("message/send"), Some(SCOPE_SEND));
    assert_eq!(scope_for_method("message/stream"), Some(SCOPE_SEND));
    assert_eq!(scope_for_method("tasks/cancel"), Some(SCOPE_SEND));
    assert_eq!(scope_for_method("session/notify"), Some(SCOPE_SEND));
}

#[test]
fn session_scope_matrix() {
    assert_eq!(scope_for_method("session/list"), Some(SCOPE_SESSION_LIST));
    for m in [
        "session/history",
        "session/attach",
        "session/ack",
        "session/presence",
    ] {
        assert_eq!(scope_for_method(m), Some(SCOPE_SESSION_READ), "{m}");
    }
    assert_eq!(scope_for_method("session/send"), Some(SCOPE_SESSION_SEND));
    for m in ["session/interrupt", "session/approve"] {
        assert_eq!(scope_for_method(m), Some(SCOPE_SESSION_CONTROL), "{m}");
    }
}

#[test]
fn fs_and_device_scope_matrix() {
    for m in ["fs/list", "fs/read", "fs/write"] {
        assert_eq!(scope_for_method(m), Some(SCOPE_FS_CLIENT), "{m}");
    }
    for m in ["device/list", "device/revoke"] {
        assert_eq!(scope_for_method(m), Some(SCOPE_DEVICE_ADMIN), "{m}");
    }
}

#[test]
fn known_scopes_validate() {
    assert!(is_known_scope(SCOPE_READ));
    assert!(is_known_scope(SCOPE_SEND));
    assert!(is_known_scope(SCOPE_SESSION_LIST));
    assert!(is_known_scope(SCOPE_SESSION_READ));
    assert!(is_known_scope(SCOPE_SESSION_SEND));
    assert!(is_known_scope(SCOPE_SESSION_CONTROL));
    assert!(is_known_scope(SCOPE_FS_CLIENT));
    assert!(is_known_scope(SCOPE_DEVICE_ADMIN));
    assert!(is_known_scope(SCOPE_ARTIFACT_TRANSFER));
    assert!(!is_known_scope("a2a:admin"));
    assert!(!is_known_scope("a2a:*"));
    assert!(!is_known_scope(""));
    assert!(!is_known_scope("A2A:READ"));
    // No wildcard or hierarchy: a parent string never stands in for a child.
    assert!(!is_known_scope("session:*"));
    assert!(!is_known_scope("session"));
    assert!(!is_known_scope("fs"));
}

#[test]
fn all_scopes_has_no_duplicates_and_every_entry_is_known() {
    for (i, a) in ALL_SCOPES.iter().enumerate() {
        assert!(is_known_scope(a), "{a} listed but not known");
        for b in &ALL_SCOPES[i + 1..] {
            assert_ne!(a, b, "duplicate scope {a}");
        }
    }
    assert_eq!(ALL_SCOPES.len(), 9);
}

#[test]
fn allows_is_exact_membership() {
    let read_only = vec![SCOPE_READ.to_string()];
    let full = vec![SCOPE_READ.to_string(), SCOPE_SEND.to_string()];
    assert!(allows(&read_only, SCOPE_READ));
    assert!(!allows(&read_only, SCOPE_SEND));
    assert!(allows(&full, SCOPE_READ));
    assert!(allows(&full, SCOPE_SEND));
    assert!(!allows(&[], SCOPE_READ));
    // The classic pair does not imply any session capability.
    assert!(!allows(&full, SCOPE_SESSION_READ));
    assert!(!allows(&full, SCOPE_SESSION_SEND));
    assert!(!allows(&full, SCOPE_FS_CLIENT));
}

#[test]
fn allows_any_matches_a_single_held_scope() {
    let granted = vec![SCOPE_SESSION_READ.to_string()];
    assert!(allows_any(
        &granted,
        &[SCOPE_SESSION_READ, SCOPE_SESSION_SEND]
    ));
    assert!(!allows_any(&granted, &[SCOPE_SESSION_SEND]));
    assert!(!allows_any(&[], ALL_SCOPES));
}

#[test]
fn sanitize_drops_unknown_and_dedups() {
    let input = vec![
        SCOPE_SESSION_READ.to_string(),
        "bogus".to_string(),
        SCOPE_SESSION_READ.to_string(),
        SCOPE_ARTIFACT_TRANSFER.to_string(),
    ];
    assert_eq!(
        sanitize(&input),
        vec![
            SCOPE_SESSION_READ.to_string(),
            SCOPE_ARTIFACT_TRANSFER.to_string()
        ]
    );
    assert!(sanitize(&[]).is_empty());
}

#[test]
fn default_pairing_scopes_are_the_classic_pair() {
    assert_eq!(
        default_pairing_scopes(),
        vec![SCOPE_READ.to_string(), SCOPE_SEND.to_string()]
    );
    for s in DEFAULT_PAIRING_SCOPES {
        assert!(is_known_scope(s));
    }
}

#[test]
fn every_known_method_maps_to_a_known_scope() {
    for m in KNOWN_METHODS {
        let s = scope_for_method(m).expect("known method");
        assert!(is_known_scope(s), "{m} maps to unknown scope {s}");
    }
}
