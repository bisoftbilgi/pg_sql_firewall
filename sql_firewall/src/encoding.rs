//! UTF8 is the only supported database encoding.
//!
//! Installation SQL rejects other encodings before any extension object is
//! created. This module is the runtime backstop for a database that already
//! has the extension (an older build, or a restore). It runs before query
//! or context bytes are decoded, and it does not apply in a database where
//! the extension is not installed.

use std::ffi::{c_char, CStr};
use std::os::raw::c_void;

use pgrx::pg_sys::{self, errcodes::PgSqlErrorCode};

use crate::{activation, guc};

pub const UNSUPPORTED_PREFIX: &str =
    "sql_firewall: UTF8 database encoding is required; server_encoding is ";
pub const INVALID_UTF8: &str = "sql_firewall: invalid UTF8 byte sequence";

pub fn server_is_utf8() -> bool {
    unsafe { pg_sys::GetDatabaseEncoding() as u32 == pg_sys::pg_enc::PG_UTF8 }
}

/// `GetDatabaseEncodingName` returns a static C string. It is not palloc'd.
pub fn server_encoding_name() -> String {
    unsafe {
        let ptr = pg_sys::GetDatabaseEncodingName();
        if ptr.is_null() {
            return "UNKNOWN".to_string();
        }
        match CStr::from_ptr(ptr).to_str() {
            Ok(name) => name.to_owned(),
            Err(_) => "UNKNOWN".to_string(),
        }
    }
}

pub fn reject_unsupported_database() -> ! {
    let message = format!("{UNSUPPORTED_PREFIX}{}", server_encoding_name());
    pgrx::ereport!(
        ERROR,
        PgSqlErrorCode::ERRCODE_FEATURE_NOT_SUPPORTED,
        &message
    );
}

pub fn reject_invalid_utf8() -> ! {
    pgrx::ereport!(
        ERROR,
        PgSqlErrorCode::ERRCODE_CHARACTER_NOT_IN_REPERTOIRE,
        INVALID_UTF8
    );
}

/// Query text to inspect, or `None` when inspection does not apply.
///
/// Unsupported encoding and invalid UTF8 do not return: they raise.
/// A null statement pointer is an absent value, not a decoding failure.
/// Called only from the foreground hooks, after the transaction-state check.
pub fn client_query_for_inspection(sql: *const c_char) -> Option<String> {
    if !guc::firewall_enabled() {
        return None;
    }
    // The same narrow exemption as firewall::inspect_query: another
    // extension's background worker (pg_cron's job runner) is inspected.
    if crate::firewall::exempt_background_worker() {
        return None;
    }
    if unsafe { pg_sys::superuser() } && guc::allow_superuser_auth_bypass() {
        return None;
    }

    match activation::install_state(guc::mode()) {
        activation::InstallState::NotInstalled | activation::InstallState::Bootstrapping => None,
        activation::InstallState::Active | activation::InstallState::Unavailable(_) => {
            if !server_is_utf8() {
                reject_unsupported_database();
            }
            decode_borrowed(sql)
        }
    }
}

/// Borrowed PostgreSQL string. Null is absent. Invalid UTF8 raises.
/// The pointer is not freed.
pub fn decode_borrowed(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(decode_bytes(unsafe { CStr::from_ptr(ptr).to_bytes() }))
}

/// `palloc`'d C string. Null is absent. The buffer is freed on every
/// non-null path, including invalid UTF8, before the error is raised.
pub fn decode_palloc(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let copied = unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() };
    unsafe { pg_sys::pfree(ptr.cast::<c_void>()) };
    Some(decode_bytes(&copied))
}

fn decode_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => reject_invalid_utf8(),
    }
}
