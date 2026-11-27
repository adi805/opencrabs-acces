# Vendored: android-activity 0.6.0 (OC-patched)

Unmodified crate source from crates.io except ONE fix:

`src/game_activity/mod.rs` -> `map_input_state_to_text_event_callback`:
guard NULL/empty `text_UTF8` before `slice::from_raw_parts`. Upstream
0.6.0 and 0.6.1 both panic ("unsafe precondition(s) violated") on the
initial empty GameTextInput state; the panic aborts the app on the first
frame (run 45626319320, tombstone + RustStdoutStderr captured via panic
hook).

Why vendored instead of upstream bump:
- 0.6.1 has the identical bug (its mod.rs:717, no null guard).
- 0.6.1 also ships a newer AGDK C source whose `onTouchEventNative`
  is 17-arg, incompatible with the pinned Java AAR `games-activity
  2.0.2` (3-arg) -> RegisterNatives fatal at load (runs 45593951071,
  45554388812).

Wired via `[patch.crates-io]` in `android/Cargo.toml`.
