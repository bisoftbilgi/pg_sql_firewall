use crate::{context::ExecutionContext, guc, sql::text_arg};
use libc::{self, c_char};
use pgrx::Spi;
use std::ffi::CString;
use std::fmt::Write as _;

fn block_payload(
    role: &str,
    database: &str,
    application: &str,
    client_ip: &str,
    command: &str,
    reason: &str,
) -> String {
    format!(
        r#"{{"event":"query_block","role":"{}","database":"{}","command":"{}","reason":"{}","application":"{}","client_ip":"{}"}}"#,
        escape_json(role),
        escape_json(database),
        escape_json(command),
        escape_json(reason),
        escape_json(application),
        escape_json(client_ip),
    )
}

/// Syslog is external to the rejecting transaction. The producer must not
/// issue NOTIFY here: PostgreSQL discards it together with the ERROR.
pub fn emit_block_alert(ctx: &ExecutionContext, command: &str, reason: &str) {
    if !guc::syslog_alerts_enabled() {
        return;
    }
    let payload = block_payload(
        ctx.role.as_deref().unwrap_or("unknown"),
        ctx.database.as_deref().unwrap_or("unknown"),
        ctx.application_name.as_deref().unwrap_or("unknown"),
        ctx.client_addr.as_deref().unwrap_or("unknown"),
        command,
        reason,
    );
    maybe_syslog(&format!("sql_firewall {payload}"));
}

/// Called by the worker in the same transaction as the blocked-query row and
/// its checkpoint. A retry rolls back both the row and its notification.
///
/// Any role connected to the database can LISTEN on any channel, so the
/// payload names only the event, the row, and the command family. The role,
/// client address, application, and reason are in the row, which only its
/// authorized readers can select (README 6.8). Syslog, a server-side
/// channel, keeps the full payload.
pub fn notify_persisted_block(channel: &str, block_id: i32, command: &str) -> Result<(), pgrx::spi::Error> {
    let payload = format!(
        r#"{{"event":"query_block","block_id":{block_id},"command":"{}"}}"#,
        escape_json(command)
    );
    Spi::run_with_args(
        "SELECT pg_catalog.pg_notify($1, $2)",
        &[text_arg(channel), text_arg(&payload)],
    )
}

const SYSLOG_IDENT: &[u8] = b"sql_firewall\0";

fn maybe_syslog(message: &str) {
    if let Ok(c_string) = CString::new(message) {
        unsafe {
            libc::openlog(SYSLOG_IDENT.as_ptr().cast::<c_char>(), libc::LOG_PID, libc::LOG_USER);
            libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), c_string.as_ptr());
            libc::closelog();
        }
    }
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{0008}' => escaped.push_str("\\b"),
            '\u{000c}' => escaped.push_str("\\f"),
            c if c <= '\u{001f}' => {
                let _ = write!(&mut escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped
}
