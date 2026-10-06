// Test-only adapter. Compiled only with `--features fingerprint_probe`.
// The release library does not contain this function. It returns what the
// production path computes for a statement text: the same
// `FingerprintSummary` that `fingerprints::enforce` builds.

use pgrx::pg_sys;
use pgrx::prelude::*;

use crate::fingerprints::FingerprintSummary;

#[pg_extern]
fn sql_firewall_fingerprint_probe(
    query: &str,
) -> TableIterator<'static, (name!(fingerprint, String), name!(normalized_query, String))> {
    if !unsafe { pg_sys::superuser() } {
        pgrx::error!("sql_firewall: fingerprint probe requires a superuser");
    }
    let summary = FingerprintSummary::new(query);
    TableIterator::once((summary.hex(), summary.normalized))
}

/// Records `fingerprint` as learned for `role_name` and `command` in this
/// database's current installation, in the shared fingerprint cache, as a
/// learn-mode auto-approval would (a learn-mode memo, honored only by
/// learn-mode lookups). Tests use it to put an identity that the current
/// normalizer no longer produces (such as an old combined-reading identity)
/// into the cache, and to check with a positive control that a seeded entry
/// is honored.
#[pg_extern]
fn sql_firewall_fingerprint_probe_cache(role_name: &str, fingerprint: &str, command: &str) -> String {
    if !unsafe { pg_sys::superuser() } {
        pgrx::error!("sql_firewall: fingerprint probe requires a superuser");
    }
    let Some(hash) = crate::fingerprints::parse_hex_identity(fingerprint) else {
        pgrx::error!("sql_firewall: fingerprint probe needs 64 lowercase hex digits");
    };
    let Ok(role) = std::ffi::CString::new(role_name) else {
        pgrx::error!("sql_firewall: role name contains a NUL byte");
    };
    let role_oid = unsafe { pg_sys::get_role_oid(role.as_ptr(), false) };
    let extension_oid = unsafe { pg_sys::get_extension_oid(c"sql_firewall".as_ptr(), false) };
    let code = crate::fingerprint_cache::command_code(command);
    let scope = crate::policy_visibility::CacheScope::new(extension_oid, role_oid, role_name);
    crate::fingerprint_cache::remember_learned(&scope, hash, code, 1);
    format!("cached {fingerprint} approved for {role_name}/{command} (code {code})")
}
