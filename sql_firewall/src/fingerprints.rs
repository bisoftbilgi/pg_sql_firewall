//! Fingerprint identity version 3, using the version 2 canonical token form.
//!
//! The input is the statement text selected in `hooks.rs` (PostgreSQL's span
//! for the statement). It is tokenized by PostgreSQL's own core lexer
//! (`fingerprint_scan.c`); comments and whitespace are not tokens. The
//! canonical form is the token sequence joined by single spaces:
//!
//! | token | canonical form |
//! |---|---|
//! | keyword | upper case: `SELECT` |
//! | identifier | `"name"`, `"` doubled inside. Unquoted names are folded and long names truncated exactly as PostgreSQL does, so `Tbl`, `tbl`, and `"tbl"` are one identifier; `"Tbl"` is another |
//! | `U&"..."` identifier | `U&"raw"`, escapes left undecoded |
//! | parameter | `$n`, number kept |
//! | operator, punctuation, `::` `..` `:=` `=>` `<=` `>=` | as written; `!=` is `<>` (the lexer returns one token for both) |
//! | integer literal within int4 (`5`, `0x1F`, `1_000`) | `?int` |
//! | other numeric literal (`1.5`, `1e3`, `.5`, integers beyond int4) | `?num` |
//! | string: `'...'`, `E'...'`, `$tag$...$tag$` | `?str` |
//! | `U&'...'` string | `?ustr` |
//! | bit string `B'...'` / hex string `X'...'` | `?bits` / `?hex` |
//!
//! A sign is a separate operator token: `-5` is `- ?int`, which differs from
//! `?int`. `N'...'` is the keyword `NCHAR` followed by `?str`. Trailing `;`
//! tokens are dropped; a `;` followed by another token is kept. No semantic
//! rewrite is made (no reordering, no IN-list folding).
//!
//! Literal values are kept, as `'value'`, `U&'raw'`, `B'...'`, `X'...'` or
//! the number as written, in statements whose strings are code or
//! server-side resources: `DO`, `CREATE [OR REPLACE] FUNCTION|PROCEDURE`,
//! `COPY`, and `LOAD` (decided from the leading keywords). Two different
//! function bodies therefore never share an identity; the same body quoted
//! differently (`$$...$$` or `'...'`) does. The string after `UESCAPE` is
//! always kept, because it decides how the preceding `U&` text is decoded.
//!
//! `standard_conforming_strings` decides whether a backslash in a plain
//! `'...'` string escapes the next character, and a statement can be
//! inspected under a setting that differs from the one it was parsed with (a
//! SET earlier in the same message, PREPARE or Parse before a SET). Text
//! without a backslash reads the same either way; `E'...'`, dollar-quoted,
//! and `U&'...'` strings do not depend on the setting. Text with a backslash
//! is read with the setting on and off (backslash_quote on, which accepts
//! everything either setting can accept, so PostgreSQL's reading is always
//! among the accepted ones):
//!
//! - one accepted reading: that is the reading PostgreSQL used;
//! - two accepted readings with equal canonical text: that text;
//! - two accepted readings that differ: `0A000`, the statement is refused.
//!   No reading is chosen and no identity is formed, so no cached or
//!   approved identity can be reused. This restricts plain strings whose
//!   backslashes change the statement's structure, or the value of a literal
//!   kept below, whenever fingerprint processing runs;
//! - no accepted reading: `XX000`.
//!
//! These errors are raised before any cache lookup or queue event. There is
//! no empty, zero, or combined identity.
//!
//! Identity: SHA-256 over [`IDENTITY_DOMAIN`], the installation identity,
//! the complete canonical text and, for a planned statement with dependencies,
//! a tagged sequence of resolved relation OIDs and plan invalidation items. It is
//! shown as 64 hex digits. The domain separates this identity
//! version from the earlier 64-bit identities: an old row is never matched
//! and its approval is never carried over. The digest covers the whole
//! canonical text; `normalized_query` and
//! `sample_query` rows are display text truncated by the queue (1023 and 511
//! bytes).
//!
//! A fingerprint describes the chosen SQL shape and plan dependencies. It is not evidence that
//! every value of a literal, or SQL a function builds from its arguments at
//! run time, is safe. Cryptographic collision resistance does not make
//! normalization itself sensitive to the value of an intentionally replaced
//! literal.

use crate::{
    context::ExecutionContext,
    fingerprint_cache::{self, CacheState, Hit},
    guc::{self, FirewallMode},
    policy_visibility::{self, PolicyTable},
    spi_checks,
};
use pgrx::pg_sys;
use sha2::{Digest, Sha256};

pub const IDENTITY_VERSION: u32 = 3;
pub const IDENTITY_DOMAIN: &[u8] = b"sql_firewall fingerprint v3 sha256\0";
pub type FingerprintId = [u8; 32];

/// Object dependencies resolved by PostgreSQL's planner for this execution.
/// The text shape alone cannot distinguish the same unqualified SQL bound to
/// different relations or user-defined functions after a replan.
#[derive(Default)]
pub struct PlanBindings {
    relations: Vec<u32>,
    invalidation_items: Vec<(i32, u32)>,
}

impl PlanBindings {
    pub fn from_planned(planned: *mut pg_sys::PlannedStmt) -> Self {
        if planned.is_null() {
            return Self::default();
        }
        let relation_list =
            unsafe { pgrx::PgList::<pg_sys::Oid>::from_pg((*planned).relationOids) };
        let mut relations = (0..relation_list.len())
            .filter_map(|index| relation_list.get_oid(index).map(u32::from))
            .collect::<Vec<_>>();
        relations.sort_unstable();
        relations.dedup();

        let item_list =
            unsafe { pgrx::PgList::<pg_sys::PlanInvalItem>::from_pg((*planned).invalItems) };
        let mut invalidation_items = (0..item_list.len())
            .filter_map(|index| item_list.get_ptr(index))
            .filter(|item| !item.is_null())
            .map(|item| unsafe { ((*item).cacheId, (*item).hashValue) })
            .collect::<Vec<_>>();
        invalidation_items.sort_unstable();
        invalidation_items.dedup();
        Self {
            relations,
            invalidation_items,
        }
    }
}

pub struct FingerprintSummary {
    pub normalized: String,
    pub hash: FingerprintId,
    pub sample: String,
}

impl FingerprintSummary {
    pub fn new(query: &str) -> Self {
        Self::with_bindings(query, &PlanBindings::default())
    }

    pub fn with_bindings(query: &str, bindings: &PlanBindings) -> Self {
        let canonical = canonical_form(query);
        let hash = identity_with_bindings(&canonical, bindings);
        let normalized = format!("v{IDENTITY_VERSION}: {canonical}");
        let sample = truncate_query(query, 512);
        Self {
            normalized,
            hash,
            sample,
        }
    }

    pub fn hex(&self) -> String {
        hex_identity(&self.hash)
    }
}

/// The full 256-bit digest is the policy and cache identity. Display text is
/// truncated independently and must not participate in an equality decision.
pub fn identity(canonical: &str) -> FingerprintId {
    identity_with_bindings(canonical, &PlanBindings::default())
}

fn identity_with_bindings(canonical: &str, bindings: &PlanBindings) -> FingerprintId {
    // A logical restore copies policy rows, but creates a new extension in a
    // different database or cluster. Even if PostgreSQL reuses every object
    // OID, the old approval must not authorize that new installation.
    let Some(extension_oid) = crate::pending_approvals::current_extension_oid() else {
        pgrx::error!("sql_firewall: cannot fingerprint without an installed extension");
    };
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(b"\0installation\0");
    hasher.update(unsafe { pg_sys::GetSystemIdentifier() }.to_be_bytes());
    hasher.update(u32::from(unsafe { pg_sys::MyDatabaseId }).to_be_bytes());
    hasher.update(u32::from(extension_oid).to_be_bytes());
    hasher.update(canonical.as_bytes());
    if !bindings.relations.is_empty() || !bindings.invalidation_items.is_empty() {
        hasher.update(b"\0pg_plan_dependencies\0");
        hasher.update((bindings.relations.len() as u32).to_be_bytes());
        for oid in &bindings.relations {
            hasher.update(oid.to_be_bytes());
        }
        hasher.update((bindings.invalidation_items.len() as u32).to_be_bytes());
        for (cache_id, hash_value) in &bindings.invalidation_items {
            hasher.update(cache_id.to_be_bytes());
            hasher.update(hash_value.to_be_bytes());
        }
    }
    hasher.finalize().into()
}

pub fn hex_identity(id: &FingerprintId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_hex_identity(text: &str) -> Option<FingerprintId> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let raw = text.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = (nibble(raw[index * 2])? << 4) | nibble(raw[index * 2 + 1])?;
    }
    Some(id)
}

extern "C" {
    fn sqlfw_fingerprint_scan(
        text: *const std::os::raw::c_char,
        standard_strings: bool,
        lexical_error: *mut *mut std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char;
    fn sqlfw_policy_scan(
        text: *const std::os::raw::c_char,
        standard_strings: bool,
        lexical_error: *mut *mut std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char;
}

/// Token texts of `query` with literal values kept (fingerprint_scan.c),
/// one per accepted standard_conforming_strings reading: one, or two when a
/// backslash makes the readings differ. `None` when the lexer accepts no
/// reading; callers then fall back to the raw text.
pub fn policy_readings(query: &str) -> Option<Vec<String>> {
    let text = std::ffi::CString::new(query).ok()?;
    let read = |standard: bool| -> Option<String> {
        let mut lexical_error: *mut std::os::raw::c_char = std::ptr::null_mut();
        let out = unsafe {
            pg_sys::ffi::pg_guard_ffi_boundary(|| sqlfw_policy_scan(text.as_ptr(), standard, &mut lexical_error))
        };
        if out.is_null() {
            None
        } else {
            crate::encoding::decode_palloc(out)
        }
    };
    let on = read(true);
    let off = if query.contains('\\') { read(false) } else { None };
    let readings: Vec<String> = match (on, off) {
        (Some(a), Some(b)) if a == b => vec![a],
        (Some(a), Some(b)) => vec![a, b],
        (Some(a), None) | (None, Some(a)) => vec![a],
        (None, None) => return None,
    };
    Some(readings)
}

enum Reading {
    Tokens(String),
    Rejected(String),
}

fn read_tokens(text: &std::ffi::CStr, standard_strings: bool) -> Reading {
    let mut lexical_error: *mut std::os::raw::c_char = std::ptr::null_mut();
    // The shim consumes only the lexer's own rejections. Any other error
    // crosses into Rust through the FFI guard and aborts the statement.
    let out = unsafe {
        pg_sys::ffi::pg_guard_ffi_boundary(|| {
            sqlfw_fingerprint_scan(text.as_ptr(), standard_strings, &mut lexical_error)
        })
    };
    if out.is_null() {
        let message = crate::encoding::decode_palloc(lexical_error)
            .unwrap_or_else(|| "lexical error".to_string());
        Reading::Rejected(message)
    } else {
        Reading::Tokens(crate::encoding::decode_palloc(out).unwrap_or_default())
    }
}

/// Canonical token text of one statement; see the module documentation.
pub fn canonical_form(query: &str) -> String {
    let Ok(text) = std::ffi::CString::new(query) else {
        normalization_failed("statement text contains a NUL byte");
    };
    if !query.contains('\\') {
        return match read_tokens(&text, true) {
            Reading::Tokens(tokens) => tokens,
            Reading::Rejected(message) => normalization_failed(&message),
        };
    }
    // PostgreSQL parsed this text under one of the two settings. The lexer
    // runs here with backslash_quote on, so it accepts every text either
    // setting could have accepted: the reading PostgreSQL used is always
    // among the accepted ones. One accepted reading is therefore that
    // reading, and two equal ones agree with it. Two different accepted
    // readings leave the executed structure undetermined.
    match (read_tokens(&text, true), read_tokens(&text, false)) {
        (Reading::Tokens(on), Reading::Tokens(off)) if on == off => on,
        (Reading::Tokens(_), Reading::Tokens(_)) => ambiguous_reading(),
        (Reading::Tokens(on), Reading::Rejected(_)) => on,
        (Reading::Rejected(_), Reading::Tokens(off)) => off,
        (Reading::Rejected(message), Reading::Rejected(_)) => normalization_failed(&message),
    }
}

/// Neither the session's current setting nor any other state records which
/// setting PostgreSQL parsed with (a SET earlier in the same message, or a
/// plan prepared under an earlier setting), so no reading is chosen and no
/// identity is formed.
fn ambiguous_reading() -> ! {
    crate::firewall::record_refusal(
        "sql_firewall: statement reads differently with standard_conforming_strings on and off; its fingerprint is ambiguous",
    );
    pgrx::pg_sys::panic::ErrorReport::new(
        pgrx::pg_sys::errcodes::PgSqlErrorCode::ERRCODE_FEATURE_NOT_SUPPORTED,
        "sql_firewall: statement reads differently with standard_conforming_strings on and off; its fingerprint is ambiguous",
        "fingerprints::canonical_form",
    )
    .set_detail(
        "In a plain '...' string, a backslash escapes the next character when standard_conforming_strings is off and is an \
         ordinary character when it is on. Both readings of this text are valid and differ, and fingerprinting cannot tell \
         which one PostgreSQL parsed.",
    )
    .set_hint("Write the string as E'...' or with dollar quoting, or write a quote inside a string as ''.")
    .report(pgrx::pg_sys::elog::PgLogLevel::ERROR);
    unreachable!()
}

fn normalization_failed(reason: &str) -> ! {
    let message =
        format!("sql_firewall: statement could not be tokenized for fingerprinting: {reason}");
    crate::firewall::record_refusal(&message);
    pgrx::ereport!(
        ERROR,
        pgrx::pg_sys::errcodes::PgSqlErrorCode::ERRCODE_INTERNAL_ERROR,
        &message
    );
}

const LEARNED_ACTION: &str = "LEARNED (FINGERPRINT AUTO)";
const LEARNED_REASON: &str = "Learn mode - new fingerprint observed; approval awaits threshold";
const PERMISSIVE_ACTION: &str = "ALLOWED (PERMISSIVE - FINGERPRINT)";
const PERMISSIVE_REASON: &str = "Fingerprint pending approval";

pub fn enforce(
    ctx: &ExecutionContext,
    command: &str,
    mode: FirewallMode,
    query: &str,
    bindings: &PlanBindings,
) -> Option<String> {
    if crate::activation::policy_stopped() {
        return None;
    }
    if !unsafe { pg_sys::IsTransactionState() } {
        return None;
    }
    if !guc::fingerprint_learning_enabled() {
        return None;
    }
    let role = ctx.role.as_deref()?;
    // Raises on a text the lexer cannot read; no identity is formed then.
    let summary = FingerprintSummary::with_bindings(query, bindings);
    let fingerprint_hex = summary.hex();
    let command_code = fingerprint_cache::command_code(command);

    // A learn-mode memo records only that discovery was logged. It does not
    // authorize a query or suppress further hit events.
    let scope = policy_visibility::cache_scope(PolicyTable::Fingerprints, ctx.role_oid, role);
    let cached = scope
        .as_ref()
        .and_then(|scope| fingerprint_cache::lookup(scope, summary.hash, command_code));
    if let Some(Hit::Committed(state)) = cached {
        match state {
            CacheState::Approved => {
                return None;
            }
            CacheState::Blocked => {
                return Some(format!(
                    "sql_firewall: Fingerprint '{}' is blocked for role '{}'.",
                    fingerprint_hex, role
                ));
            }
            CacheState::Pending | CacheState::Unknown => {}
        }
    }

    let generation = scope
        .as_ref()
        .map(|scope| fingerprint_cache::generation(scope.db_oid));
    let (fingerprint_exists, policy_epoch) =
        match record_fingerprint_hit(&fingerprint_hex, &summary, role, command) {
        Ok(read) => read,
        Err(()) => {
            crate::activation::degrade(mode, "sql_firewall_query_fingerprints");
            return None;
        }
    };

    let (hit_count, approved) = match fingerprint_exists {
        Some((raw_hit, is_app)) => (raw_hit.max(1), is_app),
        None => (1, false), // New fingerprint, not approved yet
    };

    // Every Learn execution below the threshold is a separate observation.
    // The worker increments the persisted count and makes the promotion in
    // one atomic upsert, so backend cache timing cannot move the boundary.
    let mut learn_hit_enqueued = false;
    if !approved && mode == FirewallMode::Learn {
        learn_hit_enqueued = crate::pending_approvals::enqueue_fingerprint(
            &fingerprint_hex,
            &summary.normalized,
            role,
            ctx.role_oid.unwrap_or(pg_sys::InvalidOid),
            command,
            &summary.sample,
            guc::fingerprint_learn_threshold() as u16,
            policy_epoch,
        );

        if !learn_hit_enqueued {
            pgrx::warning!(
                "sql_firewall: Learn mode - fingerprint was not published to the ring: fp={}, role={}",
                fingerprint_hex, role
            );
        } else {
            pgrx::debug1!(
                "sql_firewall: Learn mode - fingerprint hit queued: fp={}, role={}, command={}",
                fingerprint_hex,
                role,
                command
            );
        }

        if learn_hit_enqueued && fingerprint_exists.is_none() && cached != Some(Hit::Learned) {
            spi_checks::log_activity(ctx, command, LEARNED_ACTION, Some(LEARNED_REASON), query);
        }
    }

    let hit_count = hit_count.max(1) as u32;
    if let (Some(scope), Some(generation)) = (scope.as_ref(), generation) {
        #[cfg(feature = "policy_probe")]
        crate::policy_probe::hold_before_publish("fingerprints");
        if approved {
            fingerprint_cache::remember_committed(
                scope,
                summary.hash,
                command_code,
                CacheState::Approved,
                hit_count,
                generation,
            );
        } else if mode == FirewallMode::Learn && fingerprint_exists.is_none() && learn_hit_enqueued
        {
            // This memo suppresses duplicate discovery records only.
            fingerprint_cache::remember_learned(scope, summary.hash, command_code, hit_count);
        } else {
            fingerprint_cache::remember_committed(
                scope,
                summary.hash,
                command_code,
                CacheState::Pending,
                hit_count,
                generation,
            );
        }
    }

    if approved {
        return None;
    }

    match mode {
        FirewallMode::Learn => None,
        FirewallMode::Permissive => {
            spi_checks::log_activity(
                ctx,
                command,
                PERMISSIVE_ACTION,
                Some(PERMISSIVE_REASON),
                query,
            );
            None
        }
        FirewallMode::Enforce => {
            // Record the attempted fingerprint as pending for admin review.
            let enqueued = crate::pending_approvals::enqueue_fingerprint(
                &fingerprint_hex,
                &summary.normalized,
                role,
                ctx.role_oid.unwrap_or(pg_sys::InvalidOid),
                command,
                query,
                0, // Enforce observations never auto-approve.
                policy_epoch,
            );

            if !enqueued {
                pgrx::warning!(
                    "sql_firewall: fingerprint was not published to the ring: fp={}, role={}",
                    fingerprint_hex,
                    role
                );
            }

            Some(format!(
                "sql_firewall: Fingerprint '{}' for role '{}' is pending approval. \
                 Admin can approve via: UPDATE sql_firewall_query_fingerprints SET is_approved=true \
                 WHERE fingerprint='{}' AND role_name='{}'",
                fingerprint_hex, role, fingerprint_hex, role
            ))
        }
    }
}

/// The fingerprint row, if any, and the policy epoch of the same snapshot,
/// which a hit event published from this read carries.
fn record_fingerprint_hit(
    fingerprint_hex: &str,
    _summary: &FingerprintSummary,
    role: &str,
    command: &str,
) -> Result<(Option<(i32, bool)>, i64), ()> {
    // Read only. The worker persists fingerprints. A failed read is not a new
    // unapproved fingerprint and must not be auto-approved. The snapshot is
    // taken for this read (policy_visibility.rs).
    match policy_visibility::read_fingerprint(fingerprint_hex, role, command) {
        Ok((None, epoch)) => Ok((None, epoch)),
        Ok((Some((Some(hit), Some(approved))), epoch)) => Ok((Some((hit, approved)), epoch)),
        Ok((Some(_), _)) => Err(()),
        Err(err) => {
            pgrx::warning!("sql_firewall: fingerprint fetch failed: {err}");
            Err(())
        }
    }
}

/// Truncate to at most `max_len` BYTES without splitting a UTF-8 character.
///
/// `&s[..max_len]` panics when `max_len` lands inside a multi-byte character,
/// which turned any query longer than the limit containing non-ASCII text into
/// a backend error. Walk back to the nearest character boundary instead.
pub fn truncate_query(query: &str, max_len: usize) -> String {
    if query.len() <= max_len {
        return query.to_owned();
    }
    let mut end = max_len;
    while end > 0 && !query.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &query[..end])
}
