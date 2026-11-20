//! `ProgressEvent` → wire frame mapping.
//!
//! The engine's [`ProgressEvent`] is deliberately not `Serialize`: it is an
//! internal enum carrying provider values, and adding a derive would freeze
//! its shape into a wire contract the PRD explicitly does not want (it reuses
//! the enum "as-is"). So the relay maps it here, once, into the
//! `(kind, payload)` pair a client renders.
//!
//! Every variant maps to a stable `kind` string. Adding a variant to
//! `ProgressEvent` fails the exhaustiveness test below, which is the guard
//! against a silently dropped event type.

use crate::brain::agent::service::ProgressEvent;
use serde_json::{Value, json};

/// One mapped event.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayEvent {
    /// Stable kind string; clients switch on it.
    pub kind: &'static str,
    /// JSON payload. Never contains the provider's raw types.
    pub payload: Value,
}

impl RelayEvent {
    fn new(kind: &'static str, payload: Value) -> Self {
        Self { kind, payload }
    }
}

/// Map one engine progress event to its wire form.
///
/// Durations are milliseconds, percentages are 0..=100, and paths are
/// strings: the payload is JSON, so no binary or provider type crosses.
pub fn map_progress(event: &ProgressEvent) -> RelayEvent {
    match event {
        ProgressEvent::Thinking => RelayEvent::new("thinking", json!({})),
        ProgressEvent::ToolStarted {
            tool_name,
            tool_input,
            tool_call_id,
        } => RelayEvent::new(
            "tool.started",
            json!({
                "tool": tool_name,
                "input": tool_input,
                "call_id": tool_call_id,
            }),
        ),
        ProgressEvent::ToolCompleted {
            tool_name,
            tool_input,
            success,
            summary,
            tool_call_id,
        } => RelayEvent::new(
            "tool.completed",
            json!({
                "tool": tool_name,
                "input": tool_input,
                "success": success,
                "summary": summary,
                "call_id": tool_call_id,
            }),
        ),
        ProgressEvent::DetachedTaskStarted { task_id, label } => RelayEvent::new(
            "task.detached.started",
            json!({ "task_id": task_id, "label": label }),
        ),
        ProgressEvent::DetachedTaskFinished {
            task_id,
            label,
            success,
            elapsed_secs,
        } => RelayEvent::new(
            "task.detached.finished",
            json!({
                "task_id": task_id,
                "label": label,
                "success": success,
                "elapsed_ms": (*elapsed_secs as f64 * 1000.0).round() as u64,
            }),
        ),
        ProgressEvent::IntermediateText { text, reasoning } => RelayEvent::new(
            "text.intermediate",
            json!({ "text": text, "reasoning": reasoning }),
        ),
        ProgressEvent::QueuedUserMessage { text } => {
            RelayEvent::new("user.queued", json!({ "text": text }))
        }
        ProgressEvent::StreamingChunk { text } => {
            RelayEvent::new("text.delta", json!({ "text": text }))
        }
        ProgressEvent::Compacting {
            usage_pct,
            predicted,
        } => RelayEvent::new(
            "context.compacting",
            json!({
                "usage_pct": usage_pct,
                "predicted_ms": predicted.map(|d| d.as_millis() as u64),
            }),
        ),
        ProgressEvent::CompactionSummary {
            summary,
            before_pct,
            after_pct,
            elapsed,
        } => RelayEvent::new(
            "context.compacted",
            json!({
                "summary": summary,
                "before_pct": before_pct,
                "after_pct": after_pct,
                "elapsed_ms": elapsed.as_millis() as u64,
            }),
        ),
        ProgressEvent::BuildLine(line) => RelayEvent::new("build.line", json!({ "line": line })),
        ProgressEvent::RestartReady {
            status,
            binary_path,
        } => RelayEvent::new(
            "build.restart_ready",
            json!({
                "status": status,
                "binary_path": binary_path.as_ref().map(|p| p.display().to_string()),
            }),
        ),
        ProgressEvent::TokenCount(n) => RelayEvent::new("usage.tokens", json!({ "tokens": n })),
        ProgressEvent::ReasoningChunk { text } => {
            RelayEvent::new("reasoning.delta", json!({ "text": text }))
        }
        ProgressEvent::SelfHealingAlert { message } => {
            RelayEvent::new("self_healing", json!({ "message": message }))
        }
        ProgressEvent::StripStreamedContent { bytes, reason } => {
            RelayEvent::new("text.strip", json!({ "bytes": bytes, "reason": reason }))
        }
        ProgressEvent::ProviderSwitched {
            from_name,
            from_model,
            to_name,
            to_model,
            reason,
        } => RelayEvent::new(
            "provider.switched",
            json!({
                "from_name": from_name,
                "from_model": from_model,
                "to_name": to_name,
                "to_model": to_model,
                "reason": reason,
            }),
        ),
        ProgressEvent::RetryAttempt {
            attempt,
            max,
            reason,
        } => RelayEvent::new(
            "provider.retry",
            json!({ "attempt": attempt, "max": max, "reason": reason }),
        ),
        // The suggestion payload is a UI type, not a wire type: the count is
        // enough for a remote client to draw a pick-list placeholder, and the
        // options themselves travel in the turn's final message.
        ProgressEvent::SuggestedOptions(items) => {
            RelayEvent::new("suggested.options", json!({ "count": items.len() }))
        }
        ProgressEvent::PlanCompleted { title, tasks } => {
            RelayEvent::new("plan.completed", json!({ "title": title, "tasks": tasks }))
        }
    }
}

/// Kind used when a turn starts, emitted by the relay rather than the engine.
pub const KIND_TURN_STARTED: &str = "turn.started";
/// Kind used when a turn ends successfully.
pub const KIND_TURN_FINISHED: &str = "turn.finished";
/// Kind used when a turn fails or is interrupted.
pub const KIND_TURN_FAILED: &str = "turn.failed";
/// Kind used when a user message is accepted (carries its own seq).
pub const KIND_USER_MESSAGE: &str = "user.message";
/// Kind used when the engine needs a tool approval decision.
pub const KIND_APPROVAL_REQUESTED: &str = "approval.requested";

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Every `ProgressEvent` variant must map. Constructing each one here
    /// means a new variant breaks this test at compile time.
    fn all_variants() -> Vec<ProgressEvent> {
        vec![
            ProgressEvent::Thinking,
            ProgressEvent::ToolStarted {
                tool_name: "bash".into(),
                tool_input: json!({"command": "ls"}),
                tool_call_id: "c1".into(),
            },
            ProgressEvent::ToolCompleted {
                tool_name: "bash".into(),
                tool_input: json!({"command": "ls"}),
                success: true,
                summary: "ok".into(),
                tool_call_id: "c1".into(),
            },
            ProgressEvent::DetachedTaskStarted {
                task_id: "t1".into(),
                label: "cargo test".into(),
            },
            ProgressEvent::DetachedTaskFinished {
                task_id: "t1".into(),
                label: "cargo test".into(),
                success: true,
                elapsed_secs: 1.5,
            },
            ProgressEvent::IntermediateText {
                text: "mid".into(),
                reasoning: None,
            },
            ProgressEvent::QueuedUserMessage {
                text: "queued".into(),
            },
            ProgressEvent::StreamingChunk {
                text: "hello".into(),
            },
            ProgressEvent::Compacting {
                usage_pct: 81.0,
                predicted: Some(Duration::from_secs(20)),
            },
            ProgressEvent::CompactionSummary {
                summary: "sum".into(),
                before_pct: 81.0,
                after_pct: 20.0,
                elapsed: Duration::from_secs(30),
            },
            ProgressEvent::BuildLine("Compiling".into()),
            ProgressEvent::RestartReady {
                status: "ok".into(),
                binary_path: None,
            },
            ProgressEvent::TokenCount(1234),
            ProgressEvent::ReasoningChunk { text: "why".into() },
            ProgressEvent::SelfHealingAlert {
                message: "recovered".into(),
            },
            ProgressEvent::StripStreamedContent {
                bytes: 12,
                reason: "gaslight".into(),
            },
            ProgressEvent::ProviderSwitched {
                from_name: "a".into(),
                from_model: "m1".into(),
                to_name: "b".into(),
                to_model: "m2".into(),
                reason: "429".into(),
            },
            ProgressEvent::RetryAttempt {
                attempt: 1,
                max: 3,
                reason: "drop".into(),
            },
            ProgressEvent::SuggestedOptions(Vec::new()),
            ProgressEvent::PlanCompleted {
                title: "plan".into(),
                tasks: 3,
            },
        ]
    }

    #[test]
    fn every_variant_maps_to_a_distinct_kind() {
        let events = all_variants();
        let mut kinds: Vec<&str> = events.iter().map(|e| map_progress(e).kind).collect();
        let count = kinds.len();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), count, "two variants share a kind string");
    }

    #[test]
    fn payloads_are_json_objects() {
        for e in all_variants() {
            let mapped = map_progress(&e);
            assert!(
                mapped.payload.is_object(),
                "{} payload is not an object",
                mapped.kind
            );
        }
    }

    #[test]
    fn streaming_chunk_carries_the_text_verbatim() {
        let mapped = map_progress(&ProgressEvent::StreamingChunk {
            text: "partial".into(),
        });
        assert_eq!(mapped.kind, "text.delta");
        assert_eq!(mapped.payload["text"], "partial");
    }

    #[test]
    fn tool_events_carry_the_call_id_for_pairing() {
        let started = map_progress(&ProgressEvent::ToolStarted {
            tool_name: "read_file".into(),
            tool_input: json!({"path": "x"}),
            tool_call_id: "abc".into(),
        });
        let completed = map_progress(&ProgressEvent::ToolCompleted {
            tool_name: "read_file".into(),
            tool_input: json!({"path": "x"}),
            success: false,
            summary: "denied".into(),
            tool_call_id: "abc".into(),
        });
        assert_eq!(started.payload["call_id"], "abc");
        assert_eq!(completed.payload["call_id"], "abc");
        assert_eq!(completed.payload["success"], false);
    }

    #[test]
    fn durations_are_reported_in_milliseconds() {
        let mapped = map_progress(&ProgressEvent::DetachedTaskFinished {
            task_id: "t".into(),
            label: "l".into(),
            success: true,
            elapsed_secs: 2.25,
        });
        assert_eq!(mapped.payload["elapsed_ms"], 2250);
    }
}
