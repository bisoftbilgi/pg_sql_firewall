use std::borrow::Cow;

use pgrx::pg_sys;

use crate::{
    alerts,
    context::ExecutionContext,
    fingerprints,
    guc::{self, FirewallMode},
    rate_state,
};

extern "C" {
    fn sqlfw_regex_match(
        query: *const std::os::raw::c_char,
        role: *const std::os::raw::c_char,
        timeout_ms: i32,
        catalog_snapshot: bool,
        in_subtransaction: bool,
        message: *mut *mut std::os::raw::c_char,
        no_rules: *mut bool,
    ) -> i32;
}

const REGEX_MATCH: i32 = 1;
const REGEX_DEADLINE: i32 = 2;
const REGEX_INVALID: i32 = 3;

/// Built-in injection patterns, then the active regex rules (README 6.6).
/// The rules are evaluated under `sql_firewall.regex_timeout_ms`
/// (regex_eval.c): reaching it refuses the statement, and so does a rule
/// PostgreSQL rejects as an invalid expression; neither is allowed silently.
/// The session's statement_timeout, lock_timeout, and a client cancel keep
/// their own effect.
pub fn regex_block_reason(ctx: &ExecutionContext, _command: &str, query: &str) -> Option<String> {
    if query.is_empty() || !in_transaction() {
        return None;
    }

    // Recursion is handled by the ReentryGuard in firewall::inspect_query.
    let lower = query.to_ascii_lowercase();

    // The built-in check (enable_builtin_injection_check) is independent of
    // enable_regex_scan and runs on the statement's SQL tokens
    // (sql_tokens.rs): a tautology inside a string literal or a comment is
    // not one.
    let tautology = guc::builtin_injection_check_enabled()
        && match crate::sql_tokens::readings(query) {
            Some(readings) => readings.iter().any(|tokens| crate::sql_tokens::tautology(tokens)),
            None => matches_builtin_injection(&lower),
        };
    if tautology {
        return Some("sql_firewall: Query matched default injection pattern.".to_string());
    }

    if !guc::regex_scan_enabled() {
        return None;
    }

    // With no active rule in the committed catalog (the installation
    // default is inactive), nothing to evaluate: remembered per backend
    // until a commit changes the rules (policy_visibility::regex_memo_scope).
    let memo = crate::policy_visibility::regex_memo_scope();
    if memo.is_some_and(crate::policy_visibility::no_regex_rules) {
        return None;
    }

    let role = ctx.role.as_deref().unwrap_or("unknown");
    let (Ok(query_c), Ok(role_c)) = (std::ffi::CString::new(query), std::ffi::CString::new(role)) else {
        return Some("sql_firewall: statement text contains a NUL byte; regex rules cannot be evaluated.".to_string());
    };
    let mut message: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut no_rules = false;
    let outcome = unsafe {
        pg_sys::ffi::pg_guard_ffi_boundary(|| {
            sqlfw_regex_match(
                query_c.as_ptr(),
                role_c.as_ptr(),
                guc::regex_timeout_ms(),
                crate::policy_visibility::without_first_snapshot(),
                !crate::policy_visibility::inspecting_transaction_control(),
                &mut message,
                if memo.is_some() { &mut no_rules } else { std::ptr::null_mut() },
            )
        })
    };
    if no_rules {
        if let Some(scope) = memo {
            crate::policy_visibility::remember_no_regex_rules(scope);
        }
    }
    match outcome {
        REGEX_MATCH => Some("sql_firewall: Query blocked by security regex pattern.".to_string()),
        REGEX_DEADLINE => Some(format!(
            "sql_firewall: regex rules could not be evaluated within {} ms; the statement is refused.",
            guc::regex_timeout_ms()
        )),
        REGEX_INVALID => {
            let detail = unsafe { crate::encoding::decode_palloc(message) }.unwrap_or_default();
            Some(format!("sql_firewall: a regex rule could not be evaluated ({detail}); the statement is refused."))
        }
        _ => None,
    }
}

pub fn rate_limit_violation(ctx: &ExecutionContext, command: &str, _query: &str) -> Option<String> {
    if !in_transaction() {
        return None;
    }

    let role_name = ctx.role.as_deref()?;
    let role_oid = ctx.role_oid?;
    let full = || {
        Some(format!(
            "sql_firewall: Rate-limit state is full; the statement of role '{}' was not counted and is refused.",
            role_name
        ))
    };

    if guc::rate_limit_enabled() {
        match rate_state::check_global(Some(role_oid), guc::rate_limit_count(), guc::rate_limit_seconds()) {
            rate_state::Count::Within => {}
            rate_state::Count::Exceeded => {
                return Some(format!("sql_firewall: Rate limit exceeded for role '{}'.", role_name));
            }
            rate_state::Count::Full => return full(),
        }
    }

    let command_limit = guc::command_limit(command);
    let window_secs = guc::command_limit_seconds();
    if command_limit > 0 && window_secs > 0 {
        let command_code = rate_state::command_code(command);
        match rate_state::check_command(Some(role_oid), command_code, command_limit, window_secs) {
            rate_state::Count::Within => {}
            rate_state::Count::Exceeded => {
                return Some(format!(
                    "sql_firewall: Rate limit for command '{}' exceeded for role '{}'",
                    command, role_name
                ));
            }
            rate_state::Count::Full => return full(),
        }
    }

    None
}

pub fn approval_requirement(
    ctx: &ExecutionContext,
    command: &str,
    mode: FirewallMode,
    query: &str,
    bindings: &fingerprints::PlanBindings,
) -> Option<String> {
    if !in_transaction() {
        return None;
    }

    // SECURITY: "OTHER" commands are less common utility commands
    // In enforce mode, we should still require approval for safety
    // Only bypass in learn/permissive modes
    if command == "OTHER" {
        match mode {
            FirewallMode::Learn | FirewallMode::Permissive => {
                log_activity(
                    ctx,
                    command,
                    "ALLOWED (OTHER)",
                    Some("Uncommon utility command - automatically allowed in non-enforce mode"),
                    query,
                );
                return None;
            }
            FirewallMode::Enforce => {
                // In enforce mode, treat OTHER like any other command
                // Fall through to normal approval logic
                pgrx::warning!(
                    "sql_firewall: Uncommon utility command detected for role '{}' - requires approval in enforce mode",
                    ctx.role.as_deref().unwrap_or("unknown")
                );
            }
        }
    }

    let role = match ctx.role.as_deref() {
        Some(r) => r,
        None => {
            let decision = Decision::Allow {
                action: Cow::Borrowed("ALLOWED"),
                reason: Some("Role unknown".to_string()),
                skip_fingerprint_check: true, // No role, can't check fingerprints anyway
                enqueue_approval: None,
            };
            return finalize_decision(decision, ctx, command, mode, query, bindings);
        }
    };

    // The catalog gate in inspect_query has already rejected an unusable
    // approvals relation. A cache hit is consulted only after that gate.
    // A lookup error is not "no matching rule" and must not be auto-approved.
    // Shared-cache use follows policy_visibility.rs: the generation is read
    // before the catalog read takes its snapshot, and the result is
    // published only if no policy commit advanced it in between.
    let scope = crate::policy_visibility::cache_scope(
        crate::policy_visibility::PolicyTable::Approvals,
        ctx.role_oid,
        role,
    );
    let mut lookup_failed = false;
    // The policy epoch of the catalog read, for a learn event it publishes.
    // A cached decision is a row, and a row never publishes one.
    let mut policy_epoch = None;
    let cached = scope
        .as_ref()
        .and_then(|scope| crate::approval_cache::get_approval(scope, command));
    let approval = if cached.is_some() {
        cached
    } else {
        let generation = scope
            .as_ref()
            .map(|scope| crate::approval_cache::generation(scope.db_oid));
        let db_result = match crate::policy_visibility::read_command_approval(role, command) {
            Ok((result, epoch)) => {
                policy_epoch = Some(epoch);
                result
            }
            Err(err) => {
                pgrx::warning!("sql_firewall: approval lookup failed: {err}");
                lookup_failed = true;
                None
            }
        };

        if let (Some(scope), Some(generation), Some(approved)) =
            (scope.as_ref(), generation, db_result)
        {
            #[cfg(feature = "policy_probe")]
            crate::policy_probe::hold_before_publish("approvals");
            crate::approval_cache::publish(scope, command, approved, generation);
        }

        db_result
    };
    if lookup_failed {
        crate::activation::degrade(mode, "sql_firewall_command_approvals");
        return None;
    }

    let decision = match approval {
        Some(true) => Decision::Allow {
            action: Cow::Borrowed("ALLOWED"),
            reason: Some("Approved command type".to_string()),
            skip_fingerprint_check: false,
            enqueue_approval: None,
        },
        Some(false) => match mode {
            FirewallMode::Learn => Decision::Allow {
                action: Cow::Borrowed("ALLOWED (LEARN MODE - PENDING)"),
                reason: Some("Command type approval pending but allowed in learn mode".to_string()),
                skip_fingerprint_check: false, // Still track fingerprints
                enqueue_approval: None,
            },
            FirewallMode::Permissive => Decision::Allow {
                action: Cow::Borrowed("ALLOWED (PERMISSIVE - PENDING)"),
                reason: Some("Command type approval pending".to_string()),
                skip_fingerprint_check: false, // Still check fingerprints in permissive mode
                enqueue_approval: None,
            },
            _ => Decision::Block {
                action: Cow::Borrowed("BLOCKED"),
                reason: Some("Command type approval pending".to_string()),
                error: format!(
                    "sql_firewall: BLOCKED - Approval for command '{}' is pending for role '{}'",
                    command, role
                ),
            },
        },
        None => match mode {
            FirewallMode::Learn => {
                // Enqueue and the success log happen in finalize_decision, after
                // a fingerprint lookup that can still degrade. Doing them here
                // would record a learning event for a statement whose policy
                // evaluation then stopped.
                Decision::Allow {
                    action: Cow::Borrowed("ALLOWED (LEARN MODE - AUTO)"),
                    reason: Some("Command type auto-approved in learn mode".to_string()),
                    skip_fingerprint_check: false,
                    enqueue_approval: policy_epoch.map(|epoch| (true, epoch)),
                }
            }
            FirewallMode::Permissive => Decision::Allow {
                action: Cow::Borrowed("ALLOWED (PERMISSIVE - UNAPPROVED)"),
                reason: Some("No rule for command type".to_string()),
                skip_fingerprint_check: false,
                enqueue_approval: None,
            },
            FirewallMode::Enforce => Decision::Block {
                action: Cow::Borrowed("BLOCKED"),
                reason: Some("No rule for command type".to_string()),
                error: format!(
                    "sql_firewall: No rule found for command '{}' for role '{}'",
                    command, role
                ),
            },
        },
    };

    finalize_decision(decision, ctx, command, mode, query, bindings)
}

/// Records an allowed statement's decision. The record goes to the activity
/// queue at once and the database's approval worker writes the row
/// (activity_queue.rs): nothing is written in the client's transaction, so
/// the record cannot fail, block, or change the client's statement, snapshot,
/// or commit, and it stays after the transaction rolls back.
pub fn log_activity(
    ctx: &ExecutionContext,
    command: &str,
    action: &str,
    reason: Option<&str>,
    query: &str,
) {
    if !in_transaction() {
        return;
    }
    if !guc::enable_activity_logging() {
        return;
    }
    let Some(extension_oid) = crate::pending_approvals::current_extension_oid() else {
        return;
    };
    crate::activity_queue::publish(
        &crate::activity_queue::Record {
            role: ctx.role.as_deref().unwrap_or("unknown"),
            database: ctx.database.as_deref().unwrap_or("unknown"),
            query,
            application: ctx.application_name.as_deref(),
            client: ctx.client_addr.as_deref(),
            command,
            action,
            decision: decision_for(action),
            reason,
        },
        extension_oid,
    );
}

/// The decision class of an allowed action (sql_firewall_activity_log.decision).
fn decision_for(action: &str) -> &'static str {
    if action.starts_with("ALLOWED (PERMISSIVE") {
        "would_block"
    } else if action.starts_with("ALLOWED (LEARN") || action.starts_with("LEARNED") {
        "learn"
    } else if action == "ALLOWED (OTHER)" {
        "unchecked"
    } else {
        "allowed"
    }
}

/// Records a rejection independently of the transaction that is about to abort.
pub fn record_block(ctx: &ExecutionContext, command: &str, reason: &str, query: &str) {
    let role = ctx.role.as_deref().unwrap_or("unknown");
    let database = ctx.database.as_deref().unwrap_or("unknown");
    let app_name = ctx.application_name.as_deref();
    let client_addr = ctx.client_addr.as_deref();

    let channel = guc::alert_notifications_enabled().then(guc::alert_channel);
    alerts::emit_block_alert(ctx, command, reason);
    let enqueued = crate::pending_approvals::enqueue_blocked_query(
        role,
        database,
        query,
        app_name,
        client_addr,
        command,
        Some(reason),
        channel.as_deref(),
    );

    if !enqueued {
        pgrx::warning!(
            "sql_firewall: blocked query was rejected, but the event was not published to the ring"
        );
    }
}

fn in_transaction() -> bool {
    unsafe { pg_sys::IsTransactionState() }
}

enum Decision {
    Allow {
        action: Cow<'static, str>,
        reason: Option<String>,
        skip_fingerprint_check: bool,
        /// Enqueue this command approval, with the policy epoch of the lookup
        /// that found no row, only after policy evaluation finishes.
        enqueue_approval: Option<(bool, i64)>,
    },
    Block {
        action: Cow<'static, str>,
        reason: Option<String>,
        error: String,
    },
}

fn finalize_decision(
    decision: Decision,
    ctx: &ExecutionContext,
    command: &str,
    mode: FirewallMode,
    query: &str,
    bindings: &fingerprints::PlanBindings,
) -> Option<String> {
    match decision {
        Decision::Allow {
            action,
            reason,
            skip_fingerprint_check,
            enqueue_approval,
        } => {
            // An approved command does not replace fingerprint approval when
            // fingerprint checking is enabled.
            if !skip_fingerprint_check && guc::fingerprint_learning_enabled() {
                if let Some(reason_text) =
                    fingerprints::enforce(ctx, command, mode, query, bindings)
                {
                    return Some(reason_text);
                }
                // A failed fingerprint read warns and stops. It must not fall
                // through to the success log or to a learning enqueue.
                if crate::activation::policy_stopped() {
                    return None;
                }
            }
            let role_name = ctx.role.as_deref().unwrap_or("unknown");
            if action.as_ref() == "ALLOWED (LEARN MODE - PENDING)" {
                pgrx::warning!(
                    "sql_firewall: Learn mode - allowing command with pending approval: role='{}' command='{}'",
                    role_name, command
                );
            }
            if action.as_ref() == "ALLOWED (PERMISSIVE - PENDING)" {
                pgrx::warning!(
                    "sql_firewall: role '{}' command '{}' allowed in permissive mode (pending approval)",
                    role_name, command
                );
            }
            if let Some((is_approved, policy_epoch)) = enqueue_approval {
                let db_name = ctx.database.as_deref().unwrap_or("unknown");
                let enqueued = crate::pending_approvals::enqueue_approval(
                    role_name,
                    ctx.role_oid.unwrap_or(pg_sys::InvalidOid),
                    command,
                    db_name,
                    is_approved,
                    policy_epoch,
                );
                if !enqueued {
                    pgrx::warning!(
                        "sql_firewall: approval was not published to the ring: role={}, command={}",
                        role_name,
                        command
                    );
                } else if mode == FirewallMode::Learn {
                    pgrx::debug1!(
                        "sql_firewall: Learn mode - auto-approved & queued for persistence: role={}, command={}, db={}",
                        role_name, command, db_name
                    );
                }
            }
            log_activity(ctx, command, action.as_ref(), reason.as_deref(), query);
            None
        }
        Decision::Block { error, .. } => Some(error),
    }
}

/// Raw-text fallback for text PostgreSQL's lexer rejects: OR directly
/// followed by the classic tautologies. `WHERE 1=1` and `AND 1=1` are
/// query-builder idioms and do not count (README 6.6).
fn matches_builtin_injection(lower: &str) -> bool {
    lower.contains(" or '1'='1'")
        || lower.contains(" or 1=1")
        || lower.contains(" or 1 = 1")
        || lower.contains("' or '1'='1")
        || lower.contains("\" or \"1\"=\"1\"")
}
