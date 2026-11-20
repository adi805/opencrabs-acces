//! Pre-turn history hygiene, shared by every surface that starts a turn.
//!
//! A turn that was stopped before its first token, or whose provider failed
//! early, leaves a `user` row and an empty `assistant` row behind. Sending the
//! same text again used to append a second copy of the question instead of
//! pairing it with the answer the first attempt never gave (#2697), and a
//! message whose stored form is redacted never matched its outgoing form at
//! all (#2756).
//!
//! The GUI bin has run this walk ahead of every turn since. The remote relay
//! called the agent service directly and skipped it, which brought both bugs
//! back on the remote surface, so the implementation lives here and each
//! surface calls it before the turn's first write.

use crate::services::MessageService;
use crate::utils::sanitize::redact_secrets;
use uuid::Uuid;

/// Drop the provably-unanswered pair a resend would duplicate.
///
/// The pair is cut only when the newest row is an `assistant` row whose
/// content is still empty and the row before it is a `user` row carrying
/// exactly the outgoing text. Anything else ends the walk: a real answer, a
/// turn that ran a tool (tool activity lives on the assistant row, so an empty
/// one answered nothing), or a different question is history, and history is
/// never touched.
///
/// A read or delete failure is logged and the turn proceeds: losing a
/// duplicate row is a cosmetic defect, and refusing the user's message over it
/// would be a worse one.
pub async fn drop_unanswered_duplicate(
    messages: &MessageService,
    session_id: Uuid,
    outgoing: &str,
) {
    let rows = match messages
        .list_recent_messages_for_session(session_id, 2)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(session = %session_id, "turn dedup read failed: {e}");
            return;
        }
    };
    let Some(placeholder) = rows.last() else {
        return;
    };
    if placeholder.role != "assistant" || !placeholder.content.trim().is_empty() {
        return;
    }
    let Some(question) = rows.get(rows.len().saturating_sub(2)) else {
        return;
    };
    if question.role != "user" {
        return;
    }
    // The ledger keeps the redacted form of the text the turn was given.
    let stored = redact_secrets(outgoing);
    if question.content.trim() != stored.trim() {
        return;
    }
    for row in [question, placeholder] {
        if let Err(e) = messages.delete_message(row.id).await {
            tracing::warn!(session = %session_id, "turn dedup delete failed: {e}");
            return;
        }
    }
    tracing::info!(
        session = %session_id,
        "turn dedup: dropped the unanswered pair a resend would have duplicated"
    );
}
