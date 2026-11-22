//! One-time pairing codes and scoped session tokens.
//!
//! Flow: `opencrabs connect` (CLI, its own process) mints a short code and
//! prints it beside the tunnel URL. The client POSTs the code to the public
//! `/a2a/pair` endpoint; the daemon verifies it against this store, consumes
//! it (single use) and issues a long-lived session token. Both processes
//! share one JSON file under `state/remote/`, coordinated with an exclusive
//! `flock` and atomic temp+rename writes — that file is the whole IPC.
//!
//! Secrets at rest: codes and tokens are stored only as SHA-256 (base64url).
//! Plaintext exists exactly once, at mint/issue time, in the returning
//! process. Verification hashes the presented secret and compares digests.
//!
//! A code also carries the lifetime of the session it redeems into (#2873):
//! `opencrabs connect` mints the 30-day default, `--ttl` shortens it so a
//! guest can be let in for an hour without holding a month of access. The
//! lifetime travels on the stored code, never on the wire, so the client
//! cannot ask for more than the operator minted.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{now_secs, scopes::is_known_scope};

/// Crockford-flavoured 32-char alphabet: no I, L, O, U. Codes get read
/// aloud from a terminal and typed on a phone.
pub(crate) const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Code length: 32^8 = 2^40 guess space. Brute force is hopeless under the
/// global lockout below plus the server's per-IP rate limit.
pub const CODE_LEN: usize = 8;
/// Code lifetime, seconds.
pub const CODE_TTL_SECS: u64 = 300;
/// Session token lifetime, seconds (30 days).
pub const TOKEN_TTL_SECS: u64 = 30 * 86_400;
/// Guest grant lifetime, seconds (1 hour). A time-boxed link lets someone
/// in for one sitting instead of handing out a month of access (#2873).
pub const GUEST_TTL_SECS: u64 = 3_600;
/// Prefix on every issued token: greppable, recognizable, revocable.
pub const TOKEN_PREFIX: &str = "ocpair_";
/// Consecutive failed verifies before a client locks itself out of pairing.
pub const MAX_FAIL_STREAK: u32 = 10;
/// Lockout duration once tripped, seconds.
pub const LOCKOUT_SECS: u64 = 900;
/// Distinct clients the failure map tracks before the least-recently-seen
/// entries are evicted. Without a cap every spoofed source address would add
/// a permanent entry to the store file.
pub const MAX_TRACKED_CLIENTS: usize = 1024;
/// Attempts to draw a code whose hash no stored code already holds. Two codes
/// with the same text would make `verify_code`'s first match hand out the
/// other code's scopes, so a colliding candidate is redrawn. 40 bits of
/// entropy make one retry essentially unreachable; the bound stops a broken
/// RNG from spinning forever under the store lock.
pub const MINT_RETRIES: u8 = 8;
/// Cap on a persisted client key: it arrives from an HTTP header on the
/// tunnel path, so it is attacker-controlled text.
const MAX_CLIENT_KEY_LEN: usize = 64;
/// Sessions expired/revoked longer than this get swept from the file.
const SESSION_RETENTION_SECS: u64 = 7 * 86_400;
/// Label cap; longer input is truncated, not rejected.
const MAX_LABEL_LEN: usize = 64;

/// SHA-256 of a secret, base64url (43 chars). Storage form for codes+tokens.
pub(crate) fn sha_b64(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// One random candidate pairing code. Kept separate from the mint loop so a
/// test can substitute a fixed sequence and reach the collision branch, which
/// 40 bits of entropy otherwise makes effectively unreachable.
fn draw_code() -> String {
    random_bytes::<8>()
        .iter()
        .map(|b| CODE_ALPHABET[(b & 31) as usize] as char)
        .collect()
}

fn sanitize_label(label: &str) -> String {
    let cleaned: String = label
        .trim()
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_LABEL_LEN)
        .collect();
    if cleaned.is_empty() {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

/// Normalize the caller identity into a stable map key. Two requests from the
/// same source must land on the same bucket, so this only trims and bounds
/// the text: it never rewrites the address itself.
fn sanitize_client(client: &str) -> String {
    let cleaned: String = client
        .trim()
        .chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_CLIENT_KEY_LEN)
        .collect();
    if cleaned.is_empty() {
        "direct".to_string()
    } else {
        cleaned
    }
}

/// Parse a human session lifetime: `900` (seconds), `30m`, `1h`, `7d`.
/// Case-insensitive, one unit only, capped at [`TOKEN_TTL_SECS`] because the
/// longest session the store can issue is the 30-day default (#2873).
pub fn parse_ttl(raw: &str) -> Result<u64> {
    let s = raw.trim().to_ascii_lowercase();
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    let unit: String = s.chars().skip_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        anyhow::bail!("TTL {raw:?} needs a number first, e.g. 1h, 30m, 7d");
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("TTL {raw:?} is out of range"))?;
    let secs = match unit.as_str() {
        "" | "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3_600),
        "d" => n.checked_mul(86_400),
        other => anyhow::bail!("unknown TTL unit {other:?} (expected s, m, h or d)"),
    }
    .ok_or_else(|| anyhow::anyhow!("TTL {raw:?} is out of range"))?;
    if secs == 0 {
        anyhow::bail!("TTL {raw:?} must be at least 1 second");
    }
    if secs > TOKEN_TTL_SECS {
        anyhow::bail!(
            "TTL {raw:?} exceeds the {}-day session maximum",
            TOKEN_TTL_SECS / 86_400
        );
    }
    Ok(secs)
}

/// A minted, not-yet-redeemed pairing code. Only the hash is stored.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingCode {
    pub code_hash: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    /// Lifetime of the session this code mints on redemption, seconds.
    /// A code written before #2873 has no such field on disk; those keep the
    /// full 30-day session they were minted under.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
}

fn default_session_ttl() -> u64 {
    TOKEN_TTL_SECS
}

/// An issued session. The token itself only ever existed at issue time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Stable public identifier: first 12 chars of the token hash.
    pub id: String,
    pub token_hash: String,
    pub label: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

impl Session {
    /// Usable right now: not revoked, not expired.
    pub fn active(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// Owner-facing session summary: no hashes, no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub id: String,
    pub label: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub active: bool,
}

/// Per-client failure state. One entry per distinct caller identity, so the
/// lockout a stranger trips lands on that stranger instead of on the owner.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientFails {
    /// Consecutive failures since this client last succeeded or got locked.
    #[serde(default)]
    pub streak: u32,
    /// Unix seconds until which THIS client is refused.
    #[serde(default)]
    pub locked_until: Option<u64>,
    /// Last attempt, used to evict the coldest entries at the cap.
    #[serde(default)]
    pub last_seen: u64,
}

/// On-disk shape of `state/remote/pairing.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoreFile {
    #[serde(default = "default_version")]
    pub version: u32,
    /// Legacy global streak. Still read so an older file parses, but no
    /// longer incremented: a single counter shared by every caller is what
    /// let ten wrong guesses lock the owner out of their own host.
    #[serde(default)]
    pub fail_streak: u32,
    /// Unix seconds until which ALL pairing is refused. Operator-set, and
    /// still honored as a floor on top of the per-client locks below.
    #[serde(default)]
    pub locked_until: Option<u64>,
    /// Per-client failure state, keyed by the trust-derived client identity.
    #[serde(default)]
    pub fail_streaks: BTreeMap<String, ClientFails>,
    #[serde(default)]
    pub codes: Vec<PendingCode>,
    #[serde(default)]
    pub sessions: Vec<Session>,
}

fn default_version() -> u32 {
    1
}

impl Default for StoreFile {
    fn default() -> Self {
        Self {
            version: 1,
            fail_streak: 0,
            locked_until: None,
            fail_streaks: BTreeMap::new(),
            codes: Vec::new(),
            sessions: Vec::new(),
        }
    }
}

/// Why a code verification failed. The HTTP layer maps these:
/// `Locked` → 429, `NoMatch` → 401, `Storage` → 500.
#[derive(Debug)]
pub enum VerifyError {
    Locked { retry_after_secs: u64 },
    NoMatch,
    Storage(anyhow::Error),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked { retry_after_secs } => {
                write!(
                    f,
                    "pairing locked after repeated failures; retry in {retry_after_secs}s"
                )
            }
            Self::NoMatch => write!(f, "pairing code invalid, expired, or already used"),
            Self::Storage(e) => write!(f, "pairing store error: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// The pairing store: one JSON file + its flock sibling.
///
/// Constructed with an explicit path so tests stay hermetic (tempfile);
/// production uses [`PairingStore::default_path`].
#[derive(Clone)]
pub struct PairingStore {
    path: PathBuf,
}

impl PairingStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `<opencrabs_home>/state/remote/pairing.json`
    pub fn default_path() -> PathBuf {
        crate::config::opencrabs_home()
            .join("state")
            .join("remote")
            .join("pairing.json")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Mint a single-use code carrying `scopes` (validated, deduped) that
    /// redeems into a full-lifetime session.
    /// Returns the plaintext code — the only moment it exists.
    pub fn mint_code(&self, scopes: &[String]) -> Result<String> {
        self.mint_code_with_ttl(scopes, TOKEN_TTL_SECS)
    }

    /// Mint a single-use code whose redeemed session lives `session_ttl_secs`
    /// instead of the 30-day default (#2873). Returns the plaintext code.
    ///
    /// The lifetime is a property of the grant, so it is stored on the code
    /// and applied when the code is redeemed: the client cannot ask for a
    /// longer one, and the server has nothing to recompute. Capped at
    /// [`TOKEN_TTL_SECS`] because a grant must never outlive the session
    /// shape it is issued into, and zero is refused rather than minting a
    /// code that redeems into an already-dead token.
    pub fn mint_code_with_ttl(&self, scopes: &[String], session_ttl_secs: u64) -> Result<String> {
        self.mint_code_drawn(scopes, session_ttl_secs, draw_code)
    }

    /// [`Self::mint_code_with_ttl`] with the candidate source injected.
    /// Production passes [`draw_code`]; a test passes a fixed sequence so the
    /// collision branch is exercised deterministically.
    pub(crate) fn mint_code_drawn(
        &self,
        scopes: &[String],
        session_ttl_secs: u64,
        mut draw: impl FnMut() -> String,
    ) -> Result<String> {
        if scopes.is_empty() {
            anyhow::bail!("a pairing code must carry at least one scope");
        }
        for s in scopes {
            if !is_known_scope(s) {
                anyhow::bail!("unknown scope {s:?}");
            }
        }
        if session_ttl_secs == 0 {
            anyhow::bail!("a session TTL must be at least 1 second");
        }
        if session_ttl_secs > TOKEN_TTL_SECS {
            anyhow::bail!(
                "session TTL {session_ttl_secs}s exceeds the {TOKEN_TTL_SECS}s session maximum"
            );
        }
        let mut dedup = scopes.to_vec();
        dedup.sort();
        dedup.dedup();

        let now = now_secs();

        self.with_locked_store(|st| {
            // Draw under the store lock so the collision check and the insert
            // are one atomic step: a candidate is accepted only when no stored
            // code already holds its hash. Two live codes with the same text
            // would let `verify_code`'s first match redeem the wrong grant.
            let mut drawn: Option<(String, String)> = None;
            for _ in 0..MINT_RETRIES {
                let candidate = draw();
                let candidate_hash = sha_b64(&candidate);
                if !st.codes.iter().any(|c| c.code_hash == candidate_hash) {
                    drawn = Some((candidate, candidate_hash));
                    break;
                }
            }
            let Some((code, hash)) = drawn else {
                anyhow::bail!(
                    "could not draw a pairing code free of collisions in {MINT_RETRIES} attempts"
                );
            };
            st.codes.push(PendingCode {
                code_hash: hash,
                scopes: dedup,
                created_at: now,
                expires_at: now + CODE_TTL_SECS,
                session_ttl_secs,
            });
            Ok(code)
        })
    }

    /// Verify a presented code; on success consume it and issue a session.
    /// Wrong guesses don't reveal which codes exist: every failure is
    /// `NoMatch`, and a fail streak eventually locks pairing for that caller.
    ///
    /// `client` is the trust-derived caller identity (the HTTP layer's
    /// `client_key`: edge IP behind the tunnel, socket peer otherwise). The
    /// streak and the lock it trips are per client, so ten wrong guesses from
    /// a stranger lock the stranger out instead of the owner.
    pub fn verify_code(
        &self,
        code: &str,
        label: &str,
        client: &str,
    ) -> std::result::Result<(String, Session), VerifyError> {
        let now = now_secs();
        let hash = sha_b64(code.trim());
        let label = sanitize_label(label);
        let client = sanitize_client(client);

        self.with_locked_store(
            |st| -> Result<std::result::Result<(String, Session), VerifyError>> {
                if let Some(until) = st.locked_until {
                    if now < until {
                        return Ok(Err(VerifyError::Locked {
                            retry_after_secs: until - now,
                        }));
                    }
                    st.locked_until = None;
                }
                // A file written before this change carries one global streak.
                // Reading it is fine, continuing to count it is the bug, so it
                // is reset here and a lock it already tripped stays enforced
                // through `locked_until` above.
                st.fail_streak = 0;

                // Per-client lock: scoped to its own block so the borrow ends
                // before `st.codes` is touched below.
                let client_locked = {
                    let entry = st.fail_streaks.entry(client.clone()).or_default();
                    // A streak that has gone cold is history. Without this, nine
                    // failures from hours ago plus one new guess would trip the
                    // lock on a client whose count should have started over:
                    // `sweep` would drop the entry, but only once some other
                    // write touches the store, so it cannot be relied on here.
                    if now.saturating_sub(entry.last_seen) > LOCKOUT_SECS {
                        entry.streak = 0;
                    }
                    entry.last_seen = now;
                    match entry.locked_until {
                        Some(until) if now < until => Some(until),
                        Some(_) => {
                            entry.locked_until = None;
                            entry.streak = 0;
                            None
                        }
                        None => None,
                    }
                };
                if let Some(until) = client_locked {
                    return Ok(Err(VerifyError::Locked {
                        retry_after_secs: until - now,
                    }));
                }

                let found = st
                    .codes
                    .iter()
                    .position(|c| c.code_hash == hash && c.expires_at > now);
                let Some(idx) = found else {
                    let entry = st.fail_streaks.entry(client.clone()).or_default();
                    entry.streak += 1;
                    if entry.streak >= MAX_FAIL_STREAK {
                        entry.locked_until = Some(now + LOCKOUT_SECS);
                        entry.streak = 0;
                    }
                    return Ok(Err(VerifyError::NoMatch));
                };
                {
                    let entry = st.fail_streaks.entry(client.clone()).or_default();
                    entry.streak = 0;
                    entry.locked_until = None;
                }
                let pending = st.codes.remove(idx);
                // Clamped at issue time too: the store is owner-writable, and
                // a hand-edited TTL must not mint a session longer than the
                // 30-day shape (#2873).
                let grant_ttl = pending.session_ttl_secs.clamp(1, TOKEN_TTL_SECS);

                let token = format!(
                    "{TOKEN_PREFIX}{}",
                    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
                );
                let token_hash = sha_b64(&token);
                // SHA-256 base64url is ASCII-only, so a 12-char prefix can
                // never split a character — `get` keeps that invariant
                // provable to the byte-slice ratchet (and to the reader).
                let id = token_hash.get(..12).unwrap_or_default().to_string();
                let session = Session {
                    id,
                    token_hash,
                    label,
                    scopes: pending.scopes,
                    created_at: now,
                    expires_at: now + grant_ttl,
                    revoked_at: None,
                };
                st.sessions.push(session.clone());
                Ok(Ok((token, session)))
            },
        )
        .map_err(VerifyError::Storage)?
    }

    /// Hot path for the auth middleware: hash, look up, check liveness.
    /// Read-only (no lock): the writer's atomic rename guarantees a
    /// complete file, and a stale read is corrected by the next request.
    pub fn verify_token(&self, token: &str) -> Option<Session> {
        if !token.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let hash = sha_b64(token);
        let now = now_secs();
        let store = self.load().ok()?;
        store
            .sessions
            .iter()
            .find(|s| s.token_hash == hash && s.active(now))
            .cloned()
    }

    /// Revoke every active session matching an id or label exactly.
    /// Returns how many were revoked.
    pub fn revoke(&self, id_or_label: &str) -> Result<usize> {
        let now = now_secs();
        self.with_locked_store(|st| {
            let mut n = 0;
            for s in st.sessions.iter_mut() {
                if s.active(now) && (s.id == id_or_label || s.label == id_or_label) {
                    s.revoked_at = Some(now);
                    n += 1;
                }
            }
            Ok(n)
        })
    }

    /// All sessions (active and not) as owner-safe views.
    pub fn list_sessions(&self) -> Result<Vec<SessionView>> {
        let now = now_secs();
        let store = self.load()?;
        Ok(store
            .sessions
            .iter()
            .map(|s| SessionView {
                id: s.id.clone(),
                label: s.label.clone(),
                scopes: s.scopes.clone(),
                created_at: s.created_at,
                expires_at: s.expires_at,
                active: s.active(now),
            })
            .collect())
    }

    /// Load → mutate → sweep → atomic-save under the exclusive state lock
    /// (`state_lock`: bounded wait, then a hard error — never a silent
    /// unlocked write, because the lock guards single-use code consumption).
    fn with_locked_store<T>(&self, f: impl FnOnce(&mut StoreFile) -> Result<T>) -> Result<T> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let _lock = super::state_lock::exclusive_wait(&self.lock_path(), super::state_lock::WAIT)?;

        let mut store = self.load()?;
        let out = f(&mut store)?;
        sweep(&mut store, now_secs());
        self.save(&store)?;
        Ok(out)
    }

    fn load(&self) -> Result<StoreFile> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse pairing store {}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreFile::default()),
            Err(e) => {
                Err(anyhow::Error::new(e)).with_context(|| format!("read {}", self.path.display()))
            }
        }
    }

    /// Atomic write: temp file → 0600 → fsync → rename over the target.
    /// A reader never observes a partial file.
    fn save(&self, store: &StoreFile) -> Result<()> {
        let json = serde_json::to_vec_pretty(store).context("serialize pairing store")?;
        let tmp = PathBuf::from(format!("{}.tmp", self.path.display()));
        {
            let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .context("chmod 0600 pairing store")?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }

    fn lock_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.lock", self.path.display()))
    }
}

/// Drop expired codes and long-dead sessions. Runs on every locked write.
fn sweep(store: &mut StoreFile, now: u64) {
    store.codes.retain(|c| c.expires_at > now);
    store.sessions.retain(|s| {
        let dead_since =
            s.revoked_at
                .unwrap_or(0)
                .max(if s.expires_at <= now { s.expires_at } else { 0 });
        dead_since == 0 || now.saturating_sub(dead_since) < SESSION_RETENTION_SECS
    });
    // Client failure state is kept only while it can still refuse someone:
    // an active lock, or a streak young enough to matter. Everything else is
    // dropped, so a scan of random source addresses cannot grow the file.
    store.fail_streaks.retain(|_, e| {
        let lock_live = matches!(e.locked_until, Some(u) if u > now);
        lock_live || (e.streak > 0 && now.saturating_sub(e.last_seen) < LOCKOUT_SECS)
    });
    if store.fail_streaks.len() > MAX_TRACKED_CLIENTS {
        let mut by_age: Vec<(u64, String)> = store
            .fail_streaks
            .iter()
            .map(|(k, v)| (v.last_seen, k.clone()))
            .collect();
        by_age.sort();
        let excess = store.fail_streaks.len() - MAX_TRACKED_CLIENTS;
        for (_, key) in by_age.into_iter().take(excess) {
            store.fail_streaks.remove(&key);
        }
    }
}
