// Test-only hold point and cache inspection. Compiled only with
// `--features policy_probe`; the release library contains neither.
//
// The hold point sits between a policy catalog read and the publication of
// its result to a shared cache (spi_checks.rs, fingerprints.rs): the window
// in which a policy commit can race a reader. qa/probe/07 holds a reader
// there, commits a policy change, releases the reader, and then inspects the
// cache entry with the functions below.

use std::ffi::CStr;

use pgrx::pg_sys;
use pgrx::prelude::*;

use crate::policy_visibility::CacheScope;

/// Transaction-scoped advisory lock key the hold point waits on (shared).
const HOLD_KEY: i64 = 20_260_928;

/// Waits, when this session's `sql_firewall_probe.hold_publish` names
/// `cache` ("approvals" or "fingerprints"), until it can take the shared
/// advisory lock that the test holds exclusively.
pub fn hold_before_publish(cache: &str) {
    let setting = unsafe {
        let raw = pg_sys::GetConfigOption(c"sql_firewall_probe.hold_publish".as_ptr(), true, false);
        if raw.is_null() {
            return;
        }
        CStr::from_ptr(raw).to_string_lossy().into_owned()
    };
    if setting != cache {
        return;
    }
    if let Err(err) = Spi::run(&format!("SELECT pg_catalog.pg_advisory_xact_lock_shared({HOLD_KEY})")) {
        pgrx::error!("sql_firewall: policy probe hold failed: {err}");
    }
}

fn scope_for(role_name: &str) -> CacheScope {
    if !unsafe { pg_sys::superuser() } {
        pgrx::error!("sql_firewall: policy probe requires a superuser");
    }
    let Ok(role) = std::ffi::CString::new(role_name) else {
        pgrx::error!("sql_firewall: role name contains a NUL byte");
    };
    let role_oid = unsafe { pg_sys::get_role_oid(role.as_ptr(), false) };
    let extension_oid = unsafe { pg_sys::get_extension_oid(c"sql_firewall".as_ptr(), false) };
    CacheScope::new(extension_oid, role_oid, role_name)
}

/// The shared approval cache entry for `role_name` and `command` in this
/// database's current installation: `absent`, or `current` / `stale` with the
/// cached decision and both generations.
#[pg_extern]
fn sql_firewall_policy_probe_approval(role_name: &str, command: &str) -> String {
    let scope = scope_for(role_name);
    match crate::approval_cache::probe_entry(&scope, command) {
        (None, current) => format!("absent generation={current}"),
        (Some((approved, entry)), current) => format!(
            "{} approved={approved} entry_generation={entry} generation={current}",
            if entry == current { "current" } else { "stale" }
        ),
    }
}

/// The shared fingerprint cache entry for `role_name`, `fingerprint` (64 hex
/// digits), and `command`, in the same form; a learn-mode memo is `learned`.
#[pg_extern]
fn sql_firewall_policy_probe_fingerprint(role_name: &str, fingerprint: &str, command: &str) -> String {
    let scope = scope_for(role_name);
    let Some(hash) = crate::fingerprints::parse_hex_identity(fingerprint) else {
        pgrx::error!("sql_firewall: policy probe needs 64 lowercase hex digits");
    };
    let code = crate::fingerprint_cache::command_code(command);
    match crate::fingerprint_cache::probe_entry(&scope, hash, code) {
        (None, current) => format!("absent generation={current}"),
        (Some((_, true, entry)), current) => format!("learned entry_generation={entry} generation={current}"),
        (Some((state, false, entry)), current) => format!(
            "{} state={state:?} entry_generation={entry} generation={current}",
            if entry == current { "current" } else { "stale" }
        ),
    }
}
