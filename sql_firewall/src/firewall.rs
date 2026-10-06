use std::cell::Cell;

use pgrx::pg_sys::{self, errcodes::PgSqlErrorCode};

use crate::{activation, context::ExecutionContext, guc, spi_checks, structured_log};

thread_local! {
    static INSIDE_FIREWALL: Cell<bool> = Cell::new(false);
}

struct ReentryGuard;

impl ReentryGuard {
    fn enter() -> Option<Self> {
        let mut entered = false;
        INSIDE_FIREWALL.with(|flag| {
            if flag.get() {
                entered = false;
            } else {
                flag.set(true);
                entered = true;
            }
        });
        if entered {
            Some(Self)
        } else {
            None
        }
    }
}

impl Drop for ReentryGuard {
    fn drop(&mut self) {
        INSIDE_FIREWALL.with(|flag| flag.set(false));
    }
}

/// Runs `f` as the firewall's own work outside `inspect_query` (transaction
/// callbacks): statements it executes through SPI are not inspected.
pub fn as_internal_work(f: impl FnOnce()) {
    let _guard = ReentryGuard::enter();
    f();
}

/// Inside `inspect_query` or [`as_internal_work`]: statements now running
/// are the firewall's own.
pub fn in_internal_work() -> bool {
    INSIDE_FIREWALL.with(|flag| flag.get())
}

/// The statement `inspect_query` is deciding, for refusals raised below it
/// (policy catalog, fingerprint text) that know no statement of their own.
/// Pointers into `inspect_query`'s arguments, cleared when it returns or
/// unwinds.
struct Inspection {
    ctx: *const ExecutionContext,
    command: *const str,
    query: *const str,
}

thread_local! {
    static INSPECTION: Cell<Option<Inspection>> = const { Cell::new(None) };
}

struct InspectionFrame(Option<Inspection>);

impl InspectionFrame {
    fn enter(ctx: &ExecutionContext, command: &str, query: &str) -> Self {
        Self(INSPECTION.with(|slot| {
            slot.replace(Some(Inspection {
                ctx,
                command,
                query,
            }))
        }))
    }
}

impl Drop for InspectionFrame {
    fn drop(&mut self) {
        INSPECTION.with(|slot| slot.set(self.0.take()));
    }
}

/// Records a firewall refusal of the statement being inspected as a blocked
/// query before the caller raises it. Outside an inspection nothing is
/// recorded here (see [`record_uninspectable`]).
pub fn record_refusal(reason: &str) {
    let frame = INSPECTION.with(|slot| {
        let current = slot.take();
        let copy = current.as_ref().map(|i| (i.ctx, i.command, i.query));
        slot.set(current);
        copy
    });
    if let Some((ctx, command, query)) = frame {
        // SAFETY: the frame is set only while inspect_query's arguments live.
        unsafe { spi_checks::record_block(&*ctx, &*command, reason, &*query) };
    }
}

/// Records a refusal raised before a statement could be inspected (no
/// source text, or no unambiguous statement span). Superusers under bypass
/// and databases without the extension record nothing.
pub fn record_uninspectable(command: &str, text: &str, reason: &str) {
    if !guc::firewall_enabled() || !unsafe { pg_sys::IsTransactionState() } {
        return;
    }
    if is_superuser() && guc::allow_superuser_auth_bypass() {
        return;
    }
    if crate::pending_approvals::current_extension_oid().is_none() {
        return;
    }
    let ctx = ExecutionContext::collect();
    spi_checks::record_block(&ctx, command, reason, text);
}

#[derive(Debug, Copy, Clone)]
pub enum QueryOrigin {
    Executor,
    Utility,
}

pub fn inspect_query(
    _origin: QueryOrigin,
    query: &str,
    ctx: &ExecutionContext,
    command: &str,
    bindings: &crate::fingerprints::PlanBindings,
) {
    // KILL SWITCH: Bypass all firewall processing if disabled (emergency override)
    if !guc::firewall_enabled() {
        return;
    }

    if query.trim().is_empty() {
        return;
    }

    // Exempt background workers (README 6.1c "Who is inspected"): this
    // extension's own launcher and consumers, whose SQL is its maintenance;
    // parallel workers, which run fragments of a plan their leader's
    // statement already passed; and logical replication workers, which apply
    // a publisher's changes. Any other background worker (pg_cron and other
    // extensions' job runners) runs SQL on behalf of a role and is inspected
    // like a client session.
    if exempt_background_worker() {
        return;
    }

    // Recursion protection. The firewall's own SPI (activity logging, approval
    // and fingerprint lookups) re-enters the executor hook; the guard short-
    // circuits those nested calls.
    //
    // NOTE: this replaces the former is_firewall_internal_query() text match,
    // which returned true for ANY query merely mentioning a firewall table name
    // and so let `SELECT ... -- sql_firewall_activity_log` skip every check.
    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return,
    };

    // Cleared only on a real entry. A nested SPI call returns above and must
    // not wipe a stop set by this statement's own policy lookup.
    activation::clear_policy_stop();
    let _inspection = InspectionFrame::enter(ctx, command, query);
    let mode = guc::mode();
    let superuser = is_superuser();
    match activation::install_state(mode) {
        activation::InstallState::NotInstalled | activation::InstallState::Bootstrapping => {
            return;
        }
        activation::InstallState::Unavailable(object) => {
            // Existing superuser bypass remains the repair hatch.
            if superuser && guc::allow_superuser_auth_bypass() {
                return;
            }
            activation::degrade(mode, object);
            return;
        }
        activation::InstallState::Active => {}
    }

    if superuser && guc::allow_superuser_auth_bypass() {
        return;
    }

    if let Some(reason) = session_policy_violation(ctx) {
        spi_checks::record_block(ctx, command, &reason, query);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
    }

    // CRITICAL FIX: Check quiet hours FIRST before any logging
    // If in quiet hours, throw error IMMEDIATELY without calling log_activity or other SPI checks
    if let Some(reason) = quiet_hours_violation_reason() {
        if guc::quiet_hours_logging_enabled() {
            if let Some((start, end)) = guc::quiet_hours_window() {
                structured_log::log_quiet_hours(ctx, command, &start, &end);
            }
        }
        spi_checks::record_block(ctx, command, &reason, query);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
        // ereport! aborts, so we never reach here
    }

    // Now safe to proceed with normal firewall checks that may call log_activity
    if let Some(keyword) = blocked_keyword(query) {
        structured_log::log_keyword_block(ctx, command, &keyword);
        let message = format!("sql_firewall: Blocked due to blacklisted keyword '{keyword}'.");
        spi_checks::record_block(ctx, command, &message, query);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION,
            &message
        );
    }

    if let Some(reason) = spi_checks::regex_block_reason(ctx, command, query) {
        spi_checks::record_block(ctx, command, &reason, query);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
    }
    if activation::policy_stopped() {
        return;
    }

    if let Some(reason) = spi_checks::rate_limit_violation(ctx, command, query) {
        spi_checks::record_block(ctx, command, &reason, query);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_CONFIGURATION_LIMIT_EXCEEDED,
            &reason
        );
    }

    if let Some(reason) = spi_checks::approval_requirement(ctx, command, mode, query, bindings) {
        spi_checks::record_block(ctx, command, &reason, query);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
    }
}

/// Quiet hours that are on but cannot be applied (a bound unset or empty,
/// or the policy time zone unreadable) refuse the statement instead of
/// silently applying no window (README 6.3).
fn quiet_hours_violation_reason() -> Option<String> {
    if !guc::quiet_hours_enabled() {
        return None;
    }

    let window = guc::quiet_hours_window().and_then(|(start_raw, end_raw)| {
        Some((parse_hhmm_minutes(&start_raw)?, parse_hhmm_minutes(&end_raw)?, start_raw, end_raw))
    });
    let Some((start, end, start_raw, end_raw)) = window else {
        return Some(
            "sql_firewall: Quiet hours are enabled but quiet_hours_start and quiet_hours_end are not both set; the statement is refused."
                .to_string(),
        );
    };
    let Some(now) = current_minutes_of_day() else {
        return Some("sql_firewall: The quiet-hours time zone could not be read; the statement is refused.".to_string());
    };

    let in_window = if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    };

    if in_window {
        Some(format!(
            "sql_firewall: Blocked during quiet hours ({start_raw} - {end_raw})."
        ))
    } else {
        None
    }
}

fn parse_hhmm_minutes(value: &str) -> Option<i32> {
    let mut parts = value.split(':');
    let hour = parts.next()?.trim().parse::<i32>().ok()?;
    let minute = parts.next()?.trim().parse::<i32>().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) {
        return None;
    }
    Some(hour * 60 + minute)
}

/// Minutes since midnight now, in the quiet-hours policy time zone
/// (sql_firewall.quiet_hours_timezone, else log_timezone). The session's
/// TimeZone setting has no effect.
fn current_minutes_of_day() -> Option<i32> {
    unsafe {
        let now = pg_sys::timestamptz_to_time_t(pg_sys::GetCurrentTimestamp());
        let tz = guc::quiet_hours_timezone();
        if tz.is_null() {
            return None;
        }
        let tm = pg_sys::pg_localtime(&now, tz);
        if tm.is_null() {
            return None;
        }
        Some((*tm).tm_hour * 60 + (*tm).tm_min)
    }
}

/// A blacklisted keyword among the statement's SQL tokens (sql_tokens.rs):
/// words inside literals and comments do not count. Raw text only when the
/// lexer accepts no reading of the statement.
fn blocked_keyword(query: &str) -> Option<String> {
    if !guc::keyword_scan_enabled() {
        return None;
    }

    let keywords = guc::blacklisted_keywords();
    if keywords.is_empty() {
        return None;
    }

    match crate::sql_tokens::readings(query) {
        Some(readings) => readings
            .iter()
            .find_map(|tokens| crate::sql_tokens::keyword_hit(tokens, &keywords)),
        None => raw_keyword(query, &keywords),
    }
}

fn raw_keyword(query: &str, keywords: &[String]) -> Option<String> {
    let keywords = keywords.to_vec();
    let lower_query = query.to_ascii_lowercase();
    for keyword in keywords {
        if keyword.is_empty() {
            continue;
        }
        for (idx, _) in lower_query.match_indices(&keyword) {
            if is_boundary_before(&lower_query, idx)
                && is_boundary_after(&lower_query, idx + keyword.len())
            {
                return Some(keyword);
            }
        }
    }

    None
}

fn is_boundary_before(text: &str, byte_idx: usize) -> bool {
    if byte_idx == 0 {
        return true;
    }
    text[..byte_idx]
        .chars()
        .next_back()
        .map(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(true)
}

fn is_boundary_after(text: &str, byte_idx: usize) -> bool {
    if byte_idx >= text.len() {
        return true;
    }
    text[byte_idx..]
        .chars()
        .next()
        .map(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(true)
}

fn is_superuser() -> bool {
    unsafe { pg_sys::superuser() }
}

/// PostgreSQL 17 replaced the `IsBackgroundWorker` flag with the backend type.
unsafe fn is_background_worker() -> bool {
    #[cfg(not(any(feature = "pg17", feature = "pg18")))]
    {
        pg_sys::IsBackgroundWorker
    }
    #[cfg(any(feature = "pg17", feature = "pg18"))]
    {
        pg_sys::MyBackendType == pg_sys::BackendType::B_BG_WORKER
    }
}

pub(crate) fn exempt_background_worker() -> bool {
    unsafe {
        if !is_background_worker() {
            return false;
        }
        if pg_sys::ParallelWorkerNumber >= 0 || pg_sys::IsLogicalWorker() {
            return true;
        }
        let entry = pg_sys::MyBgworkerEntry;
        if entry.is_null() {
            return false;
        }
        // Only the launcher's and the consumers' entry points: another
        // worker function, even in this library, is inspected.
        let library = std::ffi::CStr::from_ptr((*entry).bgw_library_name.as_ptr()).to_bytes();
        let function = std::ffi::CStr::from_ptr((*entry).bgw_function_name.as_ptr()).to_bytes();
        library == b"sql_firewall" && matches!(function, b"firewall_launcher_main" | b"approval_worker_main")
    }
}

#[allow(dead_code)]
fn log_quiet_hours_block(ctx: &ExecutionContext, command: &str, query: &str, reason: &str) {
    let role = ctx.role.as_deref().unwrap_or("unknown");
    let database = ctx.database.as_deref().unwrap_or("unknown");
    let snippet = crate::fingerprints::truncate_query(query, 200);

    spi_checks::log_activity(ctx, command, "BLOCKED (QUIET HOURS)", Some(reason), query);

    pgrx::warning!(
        "sql_firewall: Quiet-hours block | role={} db={} command={} reason={} sample={}",
        role,
        database,
        command,
        reason,
        snippet
    );
}

/// The client's IP address for policy, from the connection's numeric
/// address (port_shim.c). An IPv4-mapped IPv6 address is its IPv4 address.
/// A Unix-domain socket ("[local]") has none.
fn client_ip(addr: Option<&str>) -> Option<std::net::IpAddr> {
    let addr = addr?;
    // A link-local IPv6 address may carry a zone ("fe80::1%eth0").
    let bare = addr.split('%').next().unwrap_or(addr);
    normalize_ip(bare.parse().ok()?)
}

fn normalize_ip(ip: std::net::IpAddr) -> Option<std::net::IpAddr> {
    Some(match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        v4 => v4,
    })
}

/// An address listed in a setting, compared by value: `10.0.0.1`,
/// `::ffff:10.0.0.1`, and `0:0:0:0:0:ffff:a00:1` are one address. Entries
/// that are not IP addresses match nothing (the settings' check hooks refuse
/// them).
fn listed_ip(entry: &str) -> Option<std::net::IpAddr> {
    normalize_ip(entry.trim().parse().ok()?)
}

fn session_policy_violation(ctx: &ExecutionContext) -> Option<String> {
    let client_display = ctx.client_addr.as_deref();
    let ip = client_ip(client_display);
    let application = ctx.application_name.as_deref();
    let role = ctx.role.as_deref();

    if guc::ip_blocking_enabled() {
        if let Some(ip) = ip {
            let blocked = guc::blocked_ips().iter().any(|entry| listed_ip(entry) == Some(ip));
            if blocked {
                return Some(format!(
                    "sql_firewall: Connection from blocked IP address '{}' is not allowed.",
                    ip
                ));
            }
        }
    }

    if guc::application_blocking_enabled() {
        if let Some(app) = application {
            let app_lower = app.to_ascii_lowercase();
            let blocked = guc::blocked_applications()
                .iter()
                .any(|entry| entry.to_ascii_lowercase() == app_lower);
            if blocked {
                return Some(format!(
                    "sql_firewall: Connections from application '{}' are not allowed.",
                    app
                ));
            }
        }
    }

    // A bound role may connect only from its addresses. A connection without
    // an IP address (a Unix-domain socket) is not from any of them.
    if guc::role_ip_binding_enabled() {
        if let Some(role_name) = role {
            let bindings = guc::role_ip_bindings();
            let allowed: Vec<Option<std::net::IpAddr>> = bindings
                .iter()
                .filter(|(r, _)| r == role_name)
                .map(|(_, addr)| listed_ip(addr))
                .collect();
            if !allowed.is_empty() && !allowed.iter().any(|a| a.is_some() && *a == ip) {
                return Some(format!(
                    "sql_firewall: Role '{}' is not allowed to connect from IP '{}'.",
                    role_name,
                    ip.map(|ip| ip.to_string())
                        .unwrap_or_else(|| client_display.unwrap_or("[local]").to_string())
                ));
            }
        }
    }

    None
}
