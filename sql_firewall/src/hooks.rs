use std::sync::atomic::{AtomicBool, Ordering};

use pgrx::pg_sys;

use crate::{context::ExecutionContext, encoding, firewall};

static INSTALLED: AtomicBool = AtomicBool::new(false);
extern "C-unwind" {
    fn sqlfw_invalidate_extension_membership();
}

static mut PREV_EXECUTOR_START: pg_sys::ExecutorStart_hook_type = None;
static mut PREV_PROCESS_UTILITY: pg_sys::ProcessUtility_hook_type = None;
static mut PREV_OBJECT_ACCESS: pg_sys::object_access_hook_type = None;

pub fn install() {
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    unsafe {
        PREV_EXECUTOR_START = pg_sys::ExecutorStart_hook;
        pg_sys::ExecutorStart_hook = Some(executor_start_hook);

        PREV_PROCESS_UTILITY = pg_sys::ProcessUtility_hook;
        pg_sys::ProcessUtility_hook = Some(process_utility_hook);

        PREV_OBJECT_ACCESS = pg_sys::object_access_hook;
        pg_sys::object_access_hook = Some(object_access_hook);
    }
}

pub fn uninstall() {
    if INSTALLED
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    unsafe {
        pg_sys::ExecutorStart_hook = PREV_EXECUTOR_START;
        pg_sys::ProcessUtility_hook = PREV_PROCESS_UTILITY;
        pg_sys::object_access_hook = PREV_OBJECT_ACCESS;

        PREV_EXECUTOR_START = None;
        PREV_PROCESS_UTILITY = None;
        PREV_OBJECT_ACCESS = None;
    }
}

/// `CREATE EXTENSION` inserts the `pg_extension` row, runs the script, then
/// fires `ddl_command_end` event triggers, and only then returns to
/// `process_utility_hook`. A trigger can call pause/resume in between. Record
/// creation here, in the subtransaction that inserted the row, so that call
/// already owns the slot when its wait begins. An event trigger's inner
/// exception block is a later subtransaction and is not the owner.
/// `ALTER EXTENSION UPDATE` does not insert a row, so it is not recorded.
#[pgrx::pg_guard]
unsafe extern "C-unwind" fn object_access_hook(
    access: pg_sys::ObjectAccessType::Type,
    class_id: pg_sys::Oid,
    object_id: pg_sys::Oid,
    sub_id: i32,
    arg: *mut std::ffi::c_void,
) {
    if let Some(prev) = PREV_OBJECT_ACCESS {
        prev(access, class_id, object_id, sub_id, arg);
    }
    if class_id == pg_sys::TriggerRelationId
        && (access == pg_sys::ObjectAccessType::OAT_POST_ALTER
            || access == pg_sys::ObjectAccessType::OAT_DROP)
        && pg_sys::IsTransactionState()
    {
        // Disabling or dropping the policy invalidation triggers hides the
        // policy writes that follow from the generations. Any trigger ALTER
        // or DROP therefore advances both generations when it commits.
        crate::policy_visibility::mark_written(crate::policy_visibility::PolicyTable::Approvals);
        crate::policy_visibility::mark_written(crate::policy_visibility::PolicyTable::Fingerprints);
        return;
    }
    if class_id == pg_sys::ExtensionRelationId
        && access == pg_sys::ObjectAccessType::OAT_POST_ALTER
        && pg_sys::IsTransactionState()
    {
        // ALTER EXTENSION ADD/DROP of any extension can change which
        // relations belong to this one (port_shim.c).
        sqlfw_invalidate_extension_membership();
        return;
    }
    if access != pg_sys::ObjectAccessType::OAT_POST_CREATE
        || class_id != pg_sys::ExtensionRelationId
        || !pg_sys::IsTransactionState()
    {
        return;
    }
    // The row was inserted in this command and is not in the catalog snapshot
    // yet. SnapshotSelf sees it. A name lookup with the catalog snapshot does not.
    if !inserted_extension_is_sql_firewall(object_id) {
        return;
    }
    // A new installation's policy is not published from the creating
    // transaction (policy_visibility.rs), also if it rolls back.
    crate::policy_visibility::mark_installation_changed();
    let Some(ring) = crate::pending_approvals::ring_view() else {
        return;
    };
    let identity = crate::consumer_control::Identity {
        db_oid: u32::from(pg_sys::MyDatabaseId),
        extension_oid: u32::from(object_id),
        ring_generation: ring.generation,
    };
    if !crate::consumer_control::note_created(identity, pg_sys::GetCurrentSubTransactionId()) {
        pgrx::ereport!(
            ERROR,
            pg_sys::errcodes::PgSqlErrorCode::ERRCODE_PROGRAM_LIMIT_EXCEEDED,
            "sql_firewall: too many nested savepoints that each create and remove this extension"
        );
    }
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn executor_start_hook(query_desc: *mut pg_sys::QueryDesc, eflags: i32) {
    if !query_desc.is_null() && unsafe { pg_sys::IsTransactionState() } {
        // Encoding and installation are decided before any query bytes are
        // decoded. A null source text is absent. Invalid UTF8 raises.
        // Non-UTF8 databases without this extension never reach the decoder.
        let src = unsafe { (*query_desc).sourceText };
        // SQL-standard function bodies can hand ExecutorStart a null or empty
        // source. Still consult activation before deciding whether their
        // otherwise invisible plan must be refused.
        let inspect_source = if src.is_null() {
            b"\0".as_ptr().cast()
        } else {
            src
        };
        if let Some(query) = encoding::client_query_for_inspection(inspect_source) {
            let planned = unsafe { (*query_desc).plannedstmt };
            if query.is_empty() {
                if !firewall::in_internal_work() {
                    let family = command_family(planned, unsafe { (*query_desc).operation });
                    firewall::record_uninspectable(family, "", UNINSPECTABLE_PLAN);
                    uninspectable_plan();
                }
            } else {
                let (location, len) = statement_span(planned);
                // Offsets belong to this QueryDesc's source, which for a prepared
                // plan is the plan's saved string, not the current EXECUTE text.
                let enclosing = if lacks_own_span(location, len) {
                    enclosing_statement(src, &query)
                } else {
                    None
                };
                let command = command_family(planned, unsafe { (*query_desc).operation });
                let (start, end) = match enclosing {
                    Some(outer) => (outer.start, outer.end),
                    None if location < 0 => missing_executor_span(src, &query, command),
                    None => statement_range(&query, location, len),
                };
                let statement = statement_text(&query, start, end);
                let ctx = ExecutionContext::collect();
                let bindings = crate::fingerprints::PlanBindings::from_planned(planned);
                firewall::inspect_query(
                    firewall::QueryOrigin::Executor,
                    &statement,
                    &ctx,
                    command,
                    &bindings,
                );
                for inner_command in modifying_cte_families(planned) {
                    firewall::inspect_query(
                        firewall::QueryOrigin::Executor,
                        &statement,
                        &ctx,
                        inner_command,
                        &bindings,
                    );
                }
            }
        }
    }

    if let Some(prev) = PREV_EXECUTOR_START {
        prev(query_desc, eflags);
    } else {
        pg_sys::standard_ExecutorStart(query_desc, eflags);
    }
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn process_utility_hook(
    pstmt: *mut pg_sys::PlannedStmt,
    query_string: *const std::os::raw::c_char,
    read_only_tree: bool,
    context: pg_sys::ProcessUtilityContext::Type,
    params: pg_sys::ParamListInfo,
    query_env: *mut pg_sys::QueryEnvironment,
    dest: *mut pg_sys::DestReceiver,
    qc: *mut pg_sys::QueryCompletion,
) {
    let mut running = None;
    let mut deferred_transaction_options = None;
    let unplanned = crate::fingerprints::PlanBindings::default();
    // Aborted transactions accept only rollback. collect() looks up the role
    // in the catalog, and that asserts IsTransactionState(); doing it here
    // aborts the backend before ROLLBACK TO SAVEPOINT can run.
    if unsafe { pg_sys::IsTransactionState() } {
        if rolls_back(pstmt) {
            // Not inspected: ROLLBACK and ROLLBACK TO SAVEPOINT can only undo
            // work that was inspected when it ran, so no policy (approval,
            // regex, rate, quiet hours) may stand between a session and its
            // recovery. PostgreSQL already skips them in a failed
            // transaction, where nothing is inspected.
        } else if let Some(query) = encoding::client_query_for_inspection(query_string) {
            let (location, len) = statement_span(pstmt);
            let enclosing = enclosing_statement(query_string, &query);
            let (start, end) = match enclosing {
                Some(outer) if lacks_own_span(location, len) => (outer.start, outer.end),
                _ => statement_range(&query, location, len),
            };
            // PostgreSQL runs the pieces of CREATE TABLE, ALTER TABLE, and
            // CREATE SCHEMA (a serial column's sequence, a foreign key, a
            // schema element) as sub-commands on the same source and span.
            // They are checked under the statement the client sent, not as
            // separate commands needing their own approval.
            let mut command = command_family(pstmt, pg_sys::CmdType::CMD_UTILITY);
            if context == pg_sys::ProcessUtilityContext::PROCESS_UTILITY_SUBCOMMAND {
                if let Some(outer) = enclosing {
                    command = outer.family;
                }
            }
            let statement = statement_text(&query, start, end);
            if transaction_options_first(pstmt) {
                // PostgreSQL must apply transaction characteristics before
                // policy SPI can take the first snapshot of this transaction.
                deferred_transaction_options = Some((statement, command));
            } else if inspect_before_first_snapshot(pstmt) {
                // Still inspected before it runs: a SET must not change the
                // settings the firewall reads before it is authorized.
                let _no_snapshot = crate::policy_visibility::BeforeFirstSnapshot::enter();
                let ctx = ExecutionContext::collect();
                firewall::inspect_query(
                    firewall::QueryOrigin::Utility,
                    &statement,
                    &ctx,
                    command,
                    &unplanned,
                );
            } else {
                let ctx = ExecutionContext::collect();
                firewall::inspect_query(
                    firewall::QueryOrigin::Utility,
                    &statement,
                    &ctx,
                    command,
                    &unplanned,
                );
            }
            running = Some((query_string, query.len(), start, end, command));
        }
    }

    let lifecycle = lifecycle_before(pstmt);

    let token = running.map(|(source, source_len, start, end, family)| {
        push_enclosing(source, source_len, start, end, family)
    });
    if let Some(prev) = PREV_PROCESS_UTILITY {
        prev(
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            qc,
        );
    } else {
        pg_sys::standard_ProcessUtility(
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            qc,
        );
    }
    if let Some((statement, family)) = deferred_transaction_options {
        let _snapshot_guard = crate::policy_visibility::TransactionControlInspection::enter();
        let ctx = ExecutionContext::collect();
        firewall::inspect_query(
            firewall::QueryOrigin::Utility,
            &statement,
            &ctx,
            family,
            &unplanned,
        );
    }
    if let Some(token) = token {
        pop_enclosing(token);
    }
    if let Some(before) = lifecycle {
        lifecycle_after(before);
    }
    if finishes_prepared_transaction(pstmt) {
        crate::policy_visibility::after_prepared_finish();
    }
}

fn transaction_stmt(pstmt: *mut pg_sys::PlannedStmt) -> Option<&'static pg_sys::TransactionStmt> {
    unsafe {
        if pstmt.is_null() {
            return None;
        }
        let node = (*pstmt).utilityStmt;
        if node.is_null() || (*node).type_ != pg_sys::NodeTag::T_TransactionStmt {
            return None;
        }
        Some(&*node.cast::<pg_sys::TransactionStmt>())
    }
}

/// ROLLBACK (also ABORT and AND CHAIN) and ROLLBACK TO SAVEPOINT of this
/// session's own transaction. ROLLBACK PREPARED, which ends another
/// transaction, is not one of them.
fn rolls_back(pstmt: *mut pg_sys::PlannedStmt) -> bool {
    transaction_stmt(pstmt).is_some_and(|stmt| {
        stmt.kind == pg_sys::TransactionStmtKind::TRANS_STMT_ROLLBACK
            || stmt.kind == pg_sys::TransactionStmtKind::TRANS_STMT_ROLLBACK_TO
    })
}

/// These commands set isolation or snapshot state in PostgreSQL's utility
/// handler. Their firewall inspection must follow the native setting change.
unsafe fn transaction_options_first(pstmt: *mut pg_sys::PlannedStmt) -> bool {
    if pstmt.is_null() {
        return false;
    }
    let node = (*pstmt).utilityStmt;
    if node.is_null() {
        return false;
    }
    if (*node).type_ == pg_sys::NodeTag::T_TransactionStmt {
        let kind = (*node.cast::<pg_sys::TransactionStmt>()).kind;
        return kind == pg_sys::TransactionStmtKind::TRANS_STMT_BEGIN
            || kind == pg_sys::TransactionStmtKind::TRANS_STMT_START;
    }
    if (*node).type_ != pg_sys::NodeTag::T_VariableSetStmt {
        return false;
    }
    let name = (*node.cast::<pg_sys::VariableSetStmt>()).name;
    if name.is_null() {
        return false;
    }
    let name = std::ffi::CStr::from_ptr(name).to_bytes();
    matches!(
        name,
        b"TRANSACTION"
            | b"TRANSACTION SNAPSHOT"
            | b"transaction_isolation"
            | b"transaction_read_only"
            | b"transaction_deferrable"
    )
}

/// A utility that PostgreSQL runs without a transaction snapshot
/// (`PlannedStmtRequiresSnapshot`: SHOW, SET and RESET, savepoint commands,
/// LOCK, SET CONSTRAINTS, and the few others it lists), in a transaction that
/// has not taken its first snapshot. Its inspection must not take that
/// snapshot either: a later SET TRANSACTION or BEGIN ISOLATION LEVEL depends
/// on it, and so does which commits a REPEATABLE READ transaction sees.
///
/// This holds whether or not the transaction is a block. Outside a block the
/// transaction can still continue past this statement: an extended-protocol
/// client can send more statements, and even BEGIN, before Sync ends it. A
/// statement cannot tell which messages follow, so the transaction's end is
/// never inferred from the statement or its message.
///
/// Commands that end the transaction are left out, and BEGIN/START and
/// transaction-characteristic SET are inspected after they run
/// (`transaction_options_first`).
unsafe fn inspect_before_first_snapshot(pstmt: *mut pg_sys::PlannedStmt) -> bool {
    if pstmt.is_null() || (*pstmt).utilityStmt.is_null() {
        return false;
    }
    if std::ptr::addr_of!(pg_sys::FirstSnapshotSet).read() {
        return false;
    }
    if pg_sys::PlannedStmtRequiresSnapshot(pstmt) {
        return false;
    }
    let node = (*pstmt).utilityStmt;
    if (*node).type_ == pg_sys::NodeTag::T_TransactionStmt {
        let kind = (*node.cast::<pg_sys::TransactionStmt>()).kind;
        return kind == pg_sys::TransactionStmtKind::TRANS_STMT_SAVEPOINT
            || kind == pg_sys::TransactionStmtKind::TRANS_STMT_RELEASE
            || kind == pg_sys::TransactionStmtKind::TRANS_STMT_ROLLBACK_TO;
    }
    true
}

/// COMMIT PREPARED and ROLLBACK PREPARED end, in this database, a transaction
/// another session prepared; its policy writes (if any) are unknown here.
unsafe fn finishes_prepared_transaction(pstmt: *mut pg_sys::PlannedStmt) -> bool {
    if pstmt.is_null() {
        return false;
    }
    let node = (*pstmt).utilityStmt;
    if node.is_null() || (*node).type_ != pg_sys::NodeTag::T_TransactionStmt {
        return false;
    }
    let kind = (*node.cast::<pg_sys::TransactionStmt>()).kind;
    kind == pg_sys::TransactionStmtKind::TRANS_STMT_COMMIT_PREPARED
        || kind == pg_sys::TransactionStmtKind::TRANS_STMT_ROLLBACK_PREPARED
}

/// A utility statement whose execution is in progress.
///
/// Only `transformTopLevelStmt` copies a statement's location and length into
/// its `Query`. The inner query of EXPLAIN, CREATE TABLE AS, SELECT INTO,
/// CREATE MATERIALIZED VIEW, and DECLARE CURSOR, and a materialized view's
/// stored query at REFRESH, are planned without offsets of their own (0 and 0,
/// or -1 once read back from the catalog), against the whole source string
/// passed to the utility. In a multi-statement message that string holds the
/// other statements too. PostgreSQL associates such a plan with the utility
/// that runs it, so the plan is inspected with that utility's span.
///
/// Entries are pushed around the call that executes the utility and popped by
/// token. An error that leaves the call early is cleaned up by the
/// transaction and subtransaction abort callbacks, so an entry is never read
/// after its utility stopped running.
#[derive(Clone, Copy)]
struct Enclosing {
    token: u64,
    subid: pg_sys::SubTransactionId,
    source: *const std::os::raw::c_char,
    source_len: usize,
    start: usize,
    end: usize,
    family: &'static str,
}

thread_local! {
    static ENCLOSING: std::cell::RefCell<Vec<Enclosing>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static NEXT_TOKEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn push_enclosing(
    source: *const std::os::raw::c_char,
    source_len: usize,
    start: usize,
    end: usize,
    family: &'static str,
) -> u64 {
    let token = NEXT_TOKEN.with(|next| {
        let token = next.get().wrapping_add(1);
        next.set(token);
        token
    });
    let subid = unsafe { pg_sys::GetCurrentSubTransactionId() };
    ENCLOSING.with(|stack| {
        stack.borrow_mut().push(Enclosing {
            token,
            subid,
            source,
            source_len,
            start,
            end,
            family,
        })
    });
    token
}

/// Removes this utility's entry. A procedure's ROLLBACK can already have
/// cleared it, which leaves nothing to remove.
fn pop_enclosing(token: u64) {
    ENCLOSING.with(|stack| {
        let mut stack = stack.borrow_mut();
        if let Some(index) = stack.iter().rposition(|entry| entry.token == token) {
            stack.truncate(index);
        }
    });
}

/// Transaction abort: no utility of this transaction is still running.
/// A procedure's COMMIT does not clear the stack; its CALL is still running.
pub fn enclosing_at_xact_abort() {
    ENCLOSING.with(|stack| {
        if let Ok(mut stack) = stack.try_borrow_mut() {
            stack.clear();
        }
    });
}

/// Subtransaction abort: utilities started inside it, or inside its
/// children, stopped running. Transaction control is refused inside a
/// subtransaction, so a live entry never predates a reuse of these ids.
pub fn enclosing_at_subxact_abort(subid: pg_sys::SubTransactionId) {
    ENCLOSING.with(|stack| {
        if let Ok(mut stack) = stack.try_borrow_mut() {
            stack.retain(|entry| entry.subid < subid);
        }
    });
}

/// The innermost running utility, if `source` is that utility's source text.
/// DECLARE CURSOR plans on a copy of the text, so equal bytes are the same
/// source. Any other source (a function body, SPI text, a prepared
/// statement's saved text) keeps its own offsets.
fn enclosing_statement(source_ptr: *const std::os::raw::c_char, source: &str) -> Option<Enclosing> {
    ENCLOSING.with(|stack| {
        let stack = stack.borrow();
        let outer = *stack.last()?;
        let same = outer.source == source_ptr
            || (outer.source_len == source.len()
                // SAFETY: the entry's utility is still running, so its
                // source string is live; stale entries are removed on abort.
                && unsafe { std::slice::from_raw_parts(outer.source.cast::<u8>(), outer.source_len) }
                    == source.as_bytes());
        same.then_some(outer)
    })
}

struct LifecycleBefore {
    extension: Option<u32>,
    dropped_database: u32,
}

/// Installation visible before this command, and the database a
/// `DROP DATABASE` names. Read before the command runs.
unsafe fn lifecycle_before(pstmt: *mut pg_sys::PlannedStmt) -> Option<LifecycleBefore> {
    if !crate::consumer_control::available() || !pg_sys::IsTransactionState() {
        return None;
    }
    Some(LifecycleBefore {
        extension: crate::pending_approvals::current_extension_oid().map(u32::from),
        dropped_database: dropdb_target(pstmt),
    })
}

unsafe fn dropdb_target(pstmt: *mut pg_sys::PlannedStmt) -> u32 {
    if pstmt.is_null() {
        return 0;
    }
    let node = (*pstmt).utilityStmt;
    if node.is_null() || (*node).type_ != pg_sys::NodeTag::T_DropdbStmt {
        return 0;
    }
    let stmt = node.cast::<pg_sys::DropdbStmt>();
    if (*stmt).dbname.is_null() {
        return 0;
    }
    u32::from(pg_sys::get_database_oid((*stmt).dbname, true))
}

/// Tag installations this command removed or created, in the subtransaction
/// that ran it. An installation visible before and absent after was removed
/// by this command or by a committed transaction; either way it is gone if
/// this transaction commits. A new installation counts as created here only
/// if its catalog row was written by this transaction. Catalog reads happen
/// here, outside the control spinlock; the transaction callbacks only apply
/// the tags.
unsafe fn lifecycle_after(before: LifecycleBefore) {
    if !pg_sys::IsTransactionState() {
        return;
    }
    if crate::pending_approvals::current_extension_oid().map(u32::from) != before.extension {
        crate::policy_visibility::mark_installation_changed();
    }
    let Some(ring) = crate::pending_approvals::ring_view() else {
        return;
    };
    let db_oid = u32::from(pg_sys::MyDatabaseId);
    let subid = pg_sys::GetCurrentSubTransactionId();
    let identity = |extension_oid| crate::consumer_control::Identity {
        db_oid,
        extension_oid,
        ring_generation: ring.generation,
    };
    let after = crate::pending_approvals::current_extension_oid().map(u32::from);
    if let Some(old) = before.extension {
        if after != Some(old) {
            crate::consumer_control::tag_removed_installation(identity(old), subid);
        }
    }
    // Idempotent with the post-create hook, which already recorded this
    // subtransaction. This still covers a creation the post-create hook did
    // not see, and it never treats an unchanged installation as new.
    if let Some(new) = after {
        if before.extension != Some(new)
            && crate::extension_created_in_this_transaction(new)
            && !crate::consumer_control::note_created(identity(new), subid)
        {
            pgrx::ereport!(
                ERROR,
                pg_sys::errcodes::PgSqlErrorCode::ERRCODE_PROGRAM_LIMIT_EXCEEDED,
                "sql_firewall: too many nested savepoints that each create and remove this extension"
            );
        }
    }
    if before.dropped_database != 0 && !skip_database_tags() {
        crate::consumer_control::tag_removed_database(before.dropped_database, subid);
    }
}

#[cfg(feature = "queue_probe")]
fn skip_database_tags() -> bool {
    crate::consumer_control::probe_skip_database_tags()
}

#[cfg(not(feature = "queue_probe"))]
fn skip_database_tags() -> bool {
    false
}

/// The extension row inserted by the current command, read with SnapshotSelf.
unsafe fn inserted_extension_is_sql_firewall(extension_oid: pg_sys::Oid) -> bool {
    let rel = pg_sys::table_open(
        pg_sys::ExtensionRelationId,
        pg_sys::AccessShareLock as pg_sys::LOCKMODE,
    );
    let mut key: pg_sys::ScanKeyData = std::mem::zeroed();
    pg_sys::ScanKeyInit(
        &mut key,
        pg_sys::Anum_pg_extension_oid as pg_sys::AttrNumber,
        pg_sys::BTEqualStrategyNumber as pg_sys::StrategyNumber,
        pg_sys::Oid::from(pg_sys::F_OIDEQ),
        pg_sys::ObjectIdGetDatum(extension_oid),
    );
    let scan = pg_sys::systable_beginscan(
        rel,
        pg_sys::Oid::from(pg_sys::ExtensionOidIndexId),
        true,
        std::ptr::addr_of_mut!(pg_sys::SnapshotSelfData),
        1,
        &mut key,
    );
    let tuple = pg_sys::systable_getnext(scan);
    let matches = if tuple.is_null() {
        false
    } else {
        let header = (*tuple).t_data;
        let form = (header as *const u8).add((*header).t_hoff as usize)
            as *const pg_sys::FormData_pg_extension;
        std::ffi::CStr::from_ptr((*form).extname.data.as_ptr()).to_bytes() == b"sql_firewall"
    };
    pg_sys::systable_endscan(scan);
    pg_sys::table_close(rel, pg_sys::AccessShareLock as pg_sys::LOCKMODE);
    matches
}

fn statement_span(planned: *mut pg_sys::PlannedStmt) -> (i32, i32) {
    if planned.is_null() {
        return (-1, 0);
    }
    unsafe { ((*planned).stmt_location, (*planned).stmt_len) }
}

/// No offsets of its own: unknown, or 0/0 ("the whole string"), which is also
/// what an inner query gets. At top level 0/0 is a real single-statement span
/// and no utility is running, so [`enclosing_statement`] finds nothing.
fn lacks_own_span(location: i32, length: i32) -> bool {
    location < 0 || (location == 0 && length == 0)
}

/// A rewrite-rule action may have no location even though its source is the
/// client's entire multi-statement message. PostgreSQL's raw parser supplies
/// exact statement spans without guessing at semicolons in SQL text. One
/// modifying statement in the message identifies the parent of a write rule
/// action. Read actions require a unique read of their own family and no
/// modifying statement, since a read action could otherwise be attributed to
/// an unrelated write in the same message. Ambiguous
/// batches are refused instead of assigning another statement's fingerprint.
fn missing_executor_span(
    source_ptr: *const std::os::raw::c_char,
    source: &str,
    action_family: &str,
) -> (usize, usize) {
    let raw =
        unsafe { pgrx::PgList::<pg_sys::RawStmt>::from_pg(pg_sys::pg_parse_query(source_ptr)) };
    if raw.len() <= 1 {
        return statement_range(source, -1, 0);
    }
    let mut writes = Vec::new();
    let mut matching = Vec::new();
    for index in 0..raw.len() {
        let Some(stmt) = raw.get_ptr(index) else {
            continue;
        };
        if stmt.is_null() {
            continue;
        }
        let span = unsafe { statement_range(source, (*stmt).stmt_location, (*stmt).stmt_len) };
        let node = unsafe { (*stmt).stmt };
        if node.is_null() {
            continue;
        }
        let tag = unsafe { pg_sys::GetCommandTagName(pg_sys::CreateCommandTag(node)) };
        if tag.is_null() {
            continue;
        }
        let family = family_from_tag(unsafe { std::ffi::CStr::from_ptr(tag).to_bytes() });
        if matches!(family, "INSERT" | "UPDATE" | "DELETE" | "MERGE") {
            writes.push(span);
        }
        if family == action_family {
            matching.push(span);
        }
    }
    let candidates = if matches!(action_family, "INSERT" | "UPDATE" | "DELETE" | "MERGE") {
        &writes
    } else if writes.is_empty() {
        &matching
    } else {
        ambiguous_source(action_family, source);
    };
    if candidates.len() != 1 {
        ambiguous_source(action_family, source);
    }
    candidates[0]
}

const AMBIGUOUS_SOURCE: &str = "sql_firewall: executable plan has no unambiguous source statement";

/// Refused, and recorded with the whole message it came from.
fn ambiguous_source(family: &str, source: &str) -> ! {
    firewall::record_uninspectable(family, source, AMBIGUOUS_SOURCE);
    pgrx::ereport!(
        ERROR,
        pg_sys::errcodes::PgSqlErrorCode::ERRCODE_FEATURE_NOT_SUPPORTED,
        AMBIGUOUS_SOURCE
    );
}

/// Command family for policy, fingerprints, and logs.
///
/// The name comes from `CreateCommandTag` on the planned statement, which is
/// PostgreSQL's own reading of the parsed node. The detailed tag is then
/// reduced to the public family. Comments, whitespace, and capitalization
/// never participate.
///
/// Aliases and special cases:
/// - `START TRANSACTION` is BEGIN. `END` is parsed as COMMIT. `ABORT` is
///   parsed as ROLLBACK. `ROLLBACK TO` stays ROLLBACK.
/// - `PREPARE TRANSACTION`, `COMMIT PREPARED`, and `ROLLBACK PREPARED` keep
///   the PREPARE, COMMIT, and ROLLBACK families. SQL `PREPARE`/`EXECUTE` stay
///   PREPARE and EXECUTE.
/// - `CREATE TABLE AS` and `SELECT INTO` are CREATE. Both are
///   `CreateTableAsStmt`; `SELECT INTO` is the `is_select_into` form.
/// - `SELECT FOR UPDATE`, `FOR SHARE`, and the other row-mark tags are SELECT.
/// - `TRUNCATE TABLE` is TRUNCATE. `REFRESH MATERIALIZED VIEW` is REFRESH.
///   `DISCARD ALL` and the other discard targets are DISCARD.
/// - `ALTER ... RENAME` is ALTER. There is no separate RENAME statement.
/// - MERGE is its own family. `CMD_MERGE` exists from PostgreSQL 15; the
///   pg13 and pg14 features have no MERGE statement.
/// - CALL, DO, DECLARE CURSOR, FETCH, MOVE, CLOSE, SECURITY LABEL, REASSIGN
///   OWNED, and IMPORT FOREIGN SCHEMA have no family of their own: OTHER.
/// - A tag whose first word is not one of the families below is OTHER.
///   OTHER is not an allow path: enforce mode still requires approval.
///
/// A sub-command that PostgreSQL runs for a utility takes that utility's family (see
/// `process_utility_hook`). An inner plan that the executor starts (EXPLAIN
/// ANALYZE, CREATE TABLE AS, COPY (query), REFRESH, a cursor) keeps its own
/// operation's family and is inspected in addition to the wrapper.
fn command_family(
    planned: *mut pg_sys::PlannedStmt,
    operation: pg_sys::CmdType::Type,
) -> &'static str {
    if !planned.is_null() {
        let matched = unsafe {
            let tag = pg_sys::CreateCommandTag(planned.cast());
            let name = pg_sys::GetCommandTagName(tag);
            if name.is_null() {
                None
            } else {
                let bytes = std::ffi::CStr::from_ptr(name).to_bytes();
                if bytes.is_empty() || bytes == b"???" {
                    None
                } else {
                    Some(family_from_tag(bytes))
                }
            }
        };
        if let Some(family) = matched {
            return family;
        }
    }
    match operation {
        value if value == pg_sys::CmdType::CMD_SELECT => "SELECT",
        value if value == pg_sys::CmdType::CMD_INSERT => "INSERT",
        value if value == pg_sys::CmdType::CMD_UPDATE => "UPDATE",
        value if value == pg_sys::CmdType::CMD_DELETE => "DELETE",
        #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17", feature = "pg18"))]
        value if value == pg_sys::CmdType::CMD_MERGE => "MERGE",
        _ => "OTHER",
    }
}

/// PostgreSQL plans a data-modifying CTE as a ModifyTable subplan. Check each
/// distinct write family against the same client statement as the outer
/// command. The planner owns this classification: text scanning cannot tell
/// a CTE body from a string, comment, or nested SELECT. If a future planner
/// shape reports a modifying CTE without a recognizable write subplan, refuse
/// it instead of letting the outer SELECT approval cover an unknown write.
fn modifying_cte_families(planned: *mut pg_sys::PlannedStmt) -> Vec<&'static str> {
    if planned.is_null() || !unsafe { (*planned).hasModifyingCTE } {
        return Vec::new();
    }
    let subplans = unsafe { pgrx::PgList::<pg_sys::Plan>::from_pg((*planned).subplans) };
    let mut families = Vec::new();
    for index in 0..subplans.len() {
        let Some(plan) = subplans.get_ptr(index) else {
            continue;
        };
        if plan.is_null() || unsafe { (*plan).type_ } != pg_sys::NodeTag::T_ModifyTable {
            continue;
        }
        let operation = unsafe { (*plan.cast::<pg_sys::ModifyTable>()).operation };
        let family = match operation {
            value if value == pg_sys::CmdType::CMD_INSERT => "INSERT",
            value if value == pg_sys::CmdType::CMD_UPDATE => "UPDATE",
            value if value == pg_sys::CmdType::CMD_DELETE => "DELETE",
            #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17", feature = "pg18"))]
            value if value == pg_sys::CmdType::CMD_MERGE => "MERGE",
            _ => uninspectable_modifying_cte(),
        };
        if !families.contains(&family) {
            families.push(family);
        }
    }
    if families.is_empty() {
        uninspectable_modifying_cte();
    }
    families
}

const UNINSPECTABLE_PLAN: &str = "sql_firewall: executable plan has no SQL source text for policy inspection";

fn uninspectable_plan() -> ! {
    pgrx::ereport!(
        ERROR,
        pg_sys::errcodes::PgSqlErrorCode::ERRCODE_FEATURE_NOT_SUPPORTED,
        UNINSPECTABLE_PLAN
    );
}

/// Raised while the outer command's inspection is still on the stack
/// (modifying_cte_families runs inside executor_start_hook's statement), so
/// it is recorded with that statement.
fn uninspectable_modifying_cte() -> ! {
    firewall::record_uninspectable("OTHER", "", "sql_firewall: could not classify a data-modifying CTE");
    pgrx::ereport!(
        ERROR,
        pg_sys::errcodes::PgSqlErrorCode::ERRCODE_FEATURE_NOT_SUPPORTED,
        "sql_firewall: could not classify a data-modifying CTE"
    );
}

fn family_from_tag(tag: &[u8]) -> &'static str {
    if tag == b"START TRANSACTION" {
        return "BEGIN";
    }
    if tag == b"SELECT INTO" {
        return "CREATE";
    }
    let word = tag.split(|byte| *byte == b' ').next().unwrap_or(b"");
    match word {
        b"SELECT" => "SELECT",
        b"INSERT" => "INSERT",
        b"UPDATE" => "UPDATE",
        b"DELETE" => "DELETE",
        b"MERGE" => "MERGE",
        b"CREATE" => "CREATE",
        b"ALTER" => "ALTER",
        b"DROP" => "DROP",
        b"TRUNCATE" => "TRUNCATE",
        b"COMMENT" => "COMMENT",
        b"GRANT" => "GRANT",
        b"REVOKE" => "REVOKE",
        b"VACUUM" => "VACUUM",
        b"ANALYZE" => "ANALYZE",
        b"REINDEX" => "REINDEX",
        b"CLUSTER" => "CLUSTER",
        b"REFRESH" => "REFRESH",
        b"COPY" => "COPY",
        b"LOCK" => "LOCK",
        b"BEGIN" => "BEGIN",
        b"COMMIT" => "COMMIT",
        b"ROLLBACK" => "ROLLBACK",
        b"SAVEPOINT" => "SAVEPOINT",
        b"RELEASE" => "RELEASE",
        b"PREPARE" => "PREPARE",
        b"EXECUTE" => "EXECUTE",
        b"DEALLOCATE" => "DEALLOCATE",
        b"SET" => "SET",
        b"SHOW" => "SHOW",
        b"RESET" => "RESET",
        b"EXPLAIN" => "EXPLAIN",
        b"LISTEN" => "LISTEN",
        b"NOTIFY" => "NOTIFY",
        b"UNLISTEN" => "UNLISTEN",
        b"CHECKPOINT" => "CHECKPOINT",
        b"DISCARD" => "DISCARD",
        b"LOAD" => "LOAD",
        _ => "OTHER",
    }
}

/// Byte range of `source` given by PostgreSQL's statement location and length.
///
/// `location < 0` means the location is unavailable; PostgreSQL then treats
/// the length as unknown too, and the whole source string attached to this
/// hook call is used. Inspection is not skipped. `length == 0` means from
/// `location` through the end of that source. Both values are byte offsets.
///
/// The source must be the one PostgreSQL stored with this plan: a prepared
/// statement's saved text for its saved offsets, never the current `EXECUTE`
/// text. COPY (query) and SQL PREPARE give their inner plan the enclosing
/// statement's offsets; other inner plans are covered by [`Enclosing`].
fn statement_range(source: &str, location: i32, length: i32) -> (usize, usize) {
    if location < 0 {
        return (0, source.len());
    }
    let start = location as usize;
    let end = match length {
        0 => Some(source.len()),
        len if len > 0 => start.checked_add(len as usize),
        _ => None,
    };
    match end {
        Some(end) if start <= end && end <= source.len() => (start, end),
        _ => invalid_span(),
    }
}

/// The statement in `source[start..end]` without PostgreSQL's lexer
/// whitespace (`scanner_isspace`) at either edge, as pg_stat_statements trims
/// it. A later statement's location is just past the previous semicolon, so
/// untrimmed it would carry separator whitespace that the same statement sent
/// on its own does not. Comments are kept. A range that splits a UTF8
/// character is an error, not a skip.
fn statement_text(source: &str, start: usize, end: usize) -> String {
    let Some(span) = source.get(start..end) else {
        invalid_span();
    };
    span.trim_matches(|ch: char| matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c'))
        .to_string()
}

fn invalid_span() -> ! {
    pgrx::ereport!(
        ERROR,
        pg_sys::errcodes::PgSqlErrorCode::ERRCODE_INTERNAL_ERROR,
        "sql_firewall: statement text span is not a valid UTF8 byte range"
    );
}
