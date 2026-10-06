//! Transaction-safe use of the shared policy caches.
//!
//! Two shared-memory caches hold policy decisions for every backend: command
//! approvals (`approval_cache`) and fingerprints (`fingerprint_cache`).
//! PostgreSQL's MVCC rules do not apply to shared memory, so this module
//! decides when a decision may be read from or published to them.
//!
//! Visibility contract:
//!
//! 1. A policy decision uses the latest committed policy at the moment the
//!    statement is inspected, plus the inspecting transaction's own
//!    uncommitted policy writes. It does not use the transaction's snapshot:
//!    an open REPEATABLE READ or SERIALIZABLE transaction sees a committed
//!    revocation at its next inspected statement, as PostgreSQL's own
//!    privilege checks do. Catalog reads normally use `GetLatestSnapshot`.
//!    BEGIN/START and transaction-characteristic SET use a fresh
//!    `GetCatalogSnapshot` instead, so their inspection does not fix the
//!    first user-data snapshot before PostgreSQL can apply the settings.
//!    So do the utilities PostgreSQL runs without a snapshot (SHOW, SET,
//!    savepoints, LOCK, ...) when a transaction block has none yet
//!    ([`BeforeFirstSnapshot`]).
//! 2. A shared-cache entry is committed policy only. It carries the
//!    installation (extension OID), database, role OID and role name, and
//!    the per-database generation of its policy table that the reader
//!    observed before it took its snapshot. It is published only if that
//!    generation is still current, and it is used only while it is.
//! 3. A committed policy write advances the generation after the commit is
//!    visible to new snapshots and before COMMIT returns to the client
//!    (`XACT_EVENT_COMMIT`). A transaction that starts after a policy commit
//!    was acknowledged therefore never uses a decision older than it.
//! 4. A transaction that wrote a policy table, or created or removed the
//!    installation, neither reads nor publishes shared entries for the rest
//!    of the transaction: it reads its own writes from the catalog, and
//!    nothing it saw can reach another transaction. A rolled-back write
//!    leaves no shared state behind, whole or savepoint rollback alike.
//!    Protection starts before the writing statement changes any row, not
//!    after: a `BEFORE` statement trigger marks the transaction, so a
//!    `RETURNING` expression, a user trigger, or any other nested evaluation
//!    within that statement already sees a writer and goes to the catalog.
//! 5. The shared caches are bypassed where this cannot be guaranteed: no
//!    invalidation triggers on the policy table (an installation created
//!    before they existed, or triggers disabled), hot standby (replayed
//!    changes fire no triggers), and parallel operations (no fresh snapshot
//!    can be taken there). A transaction that alters or drops any trigger
//!    advances both generations when it commits, so policy rows written
//!    while the invalidation triggers were disabled are not hidden by
//!    entries published before.
//!
//! Learn mode keeps a fingerprint memo after logging a new identity. The memo
//! is not policy and does not suppress later hit events;
//! permissive and enforce lookups ignore it and read the catalog.

use std::cell::Cell;
use std::ffi::CStr;
use std::os::raw::c_char;

use pgrx::datum::DatumWithOid;
use pgrx::pg_sys;
use pgrx::prelude::*;
use pgrx::Spi;

use crate::sql::{name_arg, text_arg};

const PUBLIC_NSP: &CStr = c"public";
const APPROVALS: &CStr = c"sql_firewall_command_approvals";
const FINGERPRINTS: &CStr = c"sql_firewall_query_fingerprints";
const REGEX_RULES: &CStr = c"sql_firewall_regex_rules";
const TRIGGER_FUNCTION: &[u8] = b"sql_firewall_policy_changed";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyTable {
    Approvals,
    Fingerprints,
}

thread_local! {
    static APPROVALS_WRITTEN: Cell<bool> = const { Cell::new(false) };
    static FINGERPRINTS_WRITTEN: Cell<bool> = const { Cell::new(false) };
    static INSTALLATION_CHANGED: Cell<bool> = const { Cell::new(false) };
    static TRANSACTION_CONTROL_INSPECTION: Cell<bool> = const { Cell::new(false) };
    static BEFORE_FIRST_SNAPSHOT: Cell<bool> = const { Cell::new(false) };
    /// This transaction wrote `sql_firewall_regex_rules` (marked like the
    /// policy tables; the approval generation advances when it commits).
    static REGEX_WRITTEN: Cell<bool> = const { Cell::new(false) };
    /// Per table (approvals, fingerprints, regex rules): the relation, if its
    /// invalidation triggers are in their installed form, as (catalog
    /// generation, database, extension, relation). See `triggers_in_place`.
    static TRIGGERS_CHECKED: [Cell<Option<(u64, pg_sys::Oid, pg_sys::Oid, Option<pg_sys::Oid>)>>; 3] =
        const { [Cell::new(None), Cell::new(None), Cell::new(None)] };
    /// No active BLOCK regex rule existed at (database, extension, approval
    /// generation). See `regex_memo_scope`.
    static NO_REGEX_RULES: Cell<Option<RegexMemoScope>> = const { Cell::new(None) };
}

/// Transaction characteristics must be set before PostgreSQL takes the first
/// transaction snapshot. Policy reads in this scope use a fresh catalog-style
/// snapshot, which does not set FirstSnapshotSet.
pub struct TransactionControlInspection(bool);

impl TransactionControlInspection {
    pub fn enter() -> Self {
        Self(TRANSACTION_CONTROL_INSPECTION.with(|flag| flag.replace(true)))
    }
}

impl Drop for TransactionControlInspection {
    fn drop(&mut self) {
        TRANSACTION_CONTROL_INSPECTION.with(|flag| flag.set(self.0));
    }
}

pub fn inspecting_transaction_control() -> bool {
    TRANSACTION_CONTROL_INSPECTION.with(Cell::get)
}

/// A utility that PostgreSQL runs without a transaction snapshot, inspected
/// inside a transaction block that has not taken its first snapshot. Policy
/// reads use the same fresh catalog-style snapshot as transaction control.
/// Activity records take no snapshot: they go to the activity queue.
pub struct BeforeFirstSnapshot(bool);

impl BeforeFirstSnapshot {
    pub fn enter() -> Self {
        Self(BEFORE_FIRST_SNAPSHOT.with(|flag| flag.replace(true)))
    }
}

impl Drop for BeforeFirstSnapshot {
    fn drop(&mut self) {
        BEFORE_FIRST_SNAPSHOT.with(|flag| flag.set(self.0));
    }
}

pub fn inspecting_before_first_snapshot() -> bool {
    BEFORE_FIRST_SNAPSHOT.with(Cell::get)
}

/// Either inspection above: no foreground read or write may take the
/// transaction's first snapshot.
pub fn without_first_snapshot() -> bool {
    inspecting_transaction_control() || inspecting_before_first_snapshot()
}

fn written(table: PolicyTable) -> bool {
    match table {
        PolicyTable::Approvals => APPROVALS_WRITTEN.with(Cell::get),
        PolicyTable::Fingerprints => FINGERPRINTS_WRITTEN.with(Cell::get),
    }
}

/// This transaction wrote `table`. Kept until the top-level transaction ends,
/// also when the writing subtransaction rolls back: the effect is only that
/// this transaction bypasses the shared caches and bumps at commit.
pub fn mark_written(table: PolicyTable) {
    match table {
        PolicyTable::Approvals => APPROVALS_WRITTEN.with(|flag| flag.set(true)),
        PolicyTable::Fingerprints => FINGERPRINTS_WRITTEN.with(|flag| flag.set(true)),
    }
}

/// This transaction created or removed this database's installation.
pub fn mark_installation_changed() {
    INSTALLATION_CHANGED.with(|flag| flag.set(true));
}

fn reset() {
    REGEX_WRITTEN.with(|flag| flag.set(false));
    APPROVALS_WRITTEN.with(|flag| flag.set(false));
    FINGERPRINTS_WRITTEN.with(|flag| flag.set(false));
    INSTALLATION_CHANGED.with(|flag| flag.set(false));
}

/// `XACT_EVENT_COMMIT`: the writes are visible to new snapshots
/// (`ProcArrayEndTransaction` ran before the callbacks) and the client has
/// not been told yet. Advancing the generation now makes every earlier entry
/// for this database unusable.
pub fn at_commit() {
    let db = unsafe { pg_sys::MyDatabaseId };
    let installation = INSTALLATION_CHANGED.with(Cell::get);
    // The approval generation also versions the regex-rule memo.
    if installation || written(PolicyTable::Approvals) || REGEX_WRITTEN.with(Cell::get) {
        crate::approval_cache::bump_generation(db);
    }
    if installation || written(PolicyTable::Fingerprints) {
        crate::fingerprint_cache::bump_generation(db);
    }
    reset();
}

/// Abort and PREPARE. Nothing from a transaction that wrote policy was
/// published, so there is nothing to withdraw. A prepared transaction's
/// writes become visible at COMMIT PREPARED; see [`after_prepared_finish`].
pub fn at_abort() {
    reset();
}

/// After COMMIT PREPARED or ROLLBACK PREPARED in this database. The
/// preparing backend's marks are gone, so both generations advance.
pub fn after_prepared_finish() {
    let db = unsafe { pg_sys::MyDatabaseId };
    crate::approval_cache::bump_generation(db);
    crate::fingerprint_cache::bump_generation(db);
}

/// Marks this transaction as a policy writer, for the table named by the
/// trigger's argument. Fires from management functions, direct DML by a
/// superuser, and the approval worker alike. Created `ENABLE ALWAYS`, so it
/// also fires with `session_replication_role = replica` and in logical
/// replication apply.
///
/// The marking must happen before anything in the writing statement can
/// observe that statement's own uncommitted policy rows. A `RETURNING`
/// expression, and any user AFTER-row trigger that sorts before ours, run
/// after the row is inserted but before our AFTER-row trigger; a policy
/// lookup nested in one of those would have found the transaction unmarked,
/// read its own uncommitted row with a fresh snapshot, and published it to
/// the shared cache, where another session could use it and a rollback could
/// not withdraw it. The statement-level trigger below is `BEFORE`, so it
/// runs before the statement touches a single row, which is before any such
/// nested evaluation exists.
///
/// Decision order. A write that is not the approval worker applying a queued
/// event is an administrator write. It advances `sql_firewall_policy_epoch`
/// once per transaction (again after a rolled-back savepoint that made the
/// advance), from the `BEFORE` statement trigger, so before the statement
/// locks any policy row, and holds that row lock until the transaction
/// ends. The worker takes the same row `FOR SHARE` before it touches policy
/// rows, so the two never interleave, and epochs follow commit order. The
/// row trigger advances it too if the statement trigger did not run (logical
/// replication apply). Each row change is recorded in
/// `sql_firewall_policy_history` with that epoch; `TRUNCATE`, which has no
/// row trigger, is recorded by the statement trigger. The worker records
/// only the changes that alter a decision. Both writes are internal
/// bookkeeping made as the policy table's owner, so they do not depend on
/// the writer's privileges; the history names the writer's session and
/// effective roles.
#[pg_trigger]
fn sql_firewall_policy_changed<'a>(
    trigger: &'a pgrx::PgTrigger<'a>,
) -> Result<Option<PgHeapTuple<'a, AllocatedByRust>>, pgrx::PgTriggerError> {
    let args = trigger.extra_args()?;
    let table = match args.first().map(String::as_str) {
        Some("approvals") => PolicyTable::Approvals,
        Some("fingerprints") => PolicyTable::Fingerprints,
        Some("regex_rules") => {
            // Regex rules have no epoch or history; the mark only versions
            // the "no active rule" memo (regex_memo_scope).
            REGEX_WRITTEN.with(|flag| flag.set(true));
            let row = matches!(trigger.level(), pgrx::PgTriggerLevel::Row);
            let before = matches!(trigger.when()?, pgrx::PgTriggerWhen::Before);
            if row && before {
                return Ok(trigger.new().or_else(|| trigger.old()).map(PgHeapTuple::into_owned));
            }
            return Ok(None);
        }
        _ => {
            mark_written(PolicyTable::Approvals);
            mark_written(PolicyTable::Fingerprints);
            REGEX_WRITTEN.with(|flag| flag.set(true));
            pgrx::error!("sql_firewall: invalid policy trigger argument");
        }
    };
    mark_written(table);
    let row = matches!(trigger.level(), pgrx::PgTriggerLevel::Row);
    let before = matches!(trigger.when()?, pgrx::PgTriggerWhen::Before);
    let op = trigger.op()?;
    let data = trigger.trigger_data();
    let owner = unsafe { (*(*data.tg_relation).rd_rel).relowner };
    let learn = crate::approval_worker::applying_policy_event();
    if !row && before {
        if learn.is_none() {
            let epoch = administrator_epoch(table, owner);
            if matches!(op, pgrx::PgTriggerOperation::Truncate) {
                record_history(table, "TRUNCATE", None, epoch, None, None, owner);
            }
        }
    } else if row && !before {
        let (operation, old, new) = unsafe {
            let desc = (*data.tg_relation).rd_att;
            match op {
                pgrx::PgTriggerOperation::Insert => ("INSERT", None, Some(RowImage::read(table, data.tg_trigtuple, desc))),
                pgrx::PgTriggerOperation::Update => (
                    "UPDATE",
                    Some(RowImage::read(table, data.tg_trigtuple, desc)),
                    Some(RowImage::read(table, data.tg_newtuple, desc)),
                ),
                pgrx::PgTriggerOperation::Delete => ("DELETE", Some(RowImage::read(table, data.tg_trigtuple, desc)), None),
                pgrx::PgTriggerOperation::Truncate => ("TRUNCATE", None, None),
            }
        };
        match learn {
            None => {
                let epoch = administrator_epoch(table, owner);
                record_history(table, operation, None, epoch, old.as_ref(), new.as_ref(), owner);
            }
            Some(epoch) if decision_changed(old.as_ref(), new.as_ref()) => {
                record_history(table, operation, Some(()), epoch, old.as_ref(), new.as_ref(), owner);
            }
            Some(_) => {}
        }
    }
    // Only a BEFORE ... FOR EACH ROW trigger uses this value, and there NULL
    // means "skip this row change". The installed triggers are BEFORE ... FOR
    // EACH STATEMENT and AFTER ... FOR EACH ROW, both of which discard it, but
    // returning the row unchanged keeps the function from silently dropping
    // policy writes if it is ever attached FOR EACH ROW BEFORE.
    if row && before {
        // INSERT and UPDATE supply the new row; DELETE supplies only the old.
        return Ok(trigger
            .new()
            .or_else(|| trigger.old())
            .map(PgHeapTuple::into_owned));
    }
    Ok(None)
}

/// Every table of this extension is written only by a superuser session or
/// by the firewall's own processes (whose session is the bootstrap
/// superuser). Policy administration is superuser-only (the management
/// functions check `session_user`), so a table privilege granted to another
/// role, membership in `pg_write_all_data`, or `BYPASSRLS` must not let that
/// role change approvals, rules, decision history, audit records, or the
/// consumers' runtime state. Installed as the first `BEFORE` statement
/// trigger of every table, and as a `BEFORE` row trigger of the policy
/// tables, which logical replication apply fires (it fires no statement
/// triggers); `ENABLE ALWAYS`.
#[pg_trigger]
fn sql_firewall_guard<'a>(
    trigger: &'a pgrx::PgTrigger<'a>,
) -> Result<Option<PgHeapTuple<'a, AllocatedByRust>>, pgrx::PgTriggerError> {
    if !unsafe { pg_sys::superuser_arg(pg_sys::GetSessionUserId()) } {
        let table = trigger.table_name()?;
        let message = format!(
            "sql_firewall: only a superuser session can change {table}; table privileges granted to other roles do not delegate firewall administration"
        );
        pgrx::ereport!(
            ERROR,
            pgrx::PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &message
        );
    }
    if matches!(trigger.level(), pgrx::PgTriggerLevel::Row) {
        // BEFORE ROW: NULL would skip the row change.
        return Ok(trigger.new().or_else(|| trigger.old()).map(PgHeapTuple::into_owned));
    }
    Ok(None)
}

/// Only an administrator's explicit UPDATE of is_approved is a manual
/// fingerprint decision. Worker upserts name the same column while recording
/// hits, so comparing old/new row values (or the hit count) cannot reliably
/// distinguish a false-to-false denial from a Learn observation.
#[pg_trigger]
fn sql_firewall_fingerprint_decision<'a>(
    trigger: &'a pgrx::PgTrigger<'a>,
) -> Result<Option<PgHeapTuple<'a, AllocatedByRust>>, pgrx::PgTriggerError> {
    let old = trigger.old().expect("fingerprint decision requires an UPDATE row");
    let mut new = trigger.new().expect("fingerprint decision requires an UPDATE row").into_owned();
    if crate::approval_worker::applying_policy_event().is_none() {
        let old_disabled = old.get_by_name::<bool>("auto_approval_disabled")
            .expect("fingerprint denial flag exists");
        let new_disabled = new.get_by_name::<bool>("auto_approval_disabled")
            .expect("fingerprint denial flag exists");
        if old_disabled == new_disabled {
            let approved = new.get_by_name::<bool>("is_approved")
                .expect("fingerprint approval flag exists")
                .expect("fingerprint approval flag is not null");
            new.set_by_name("auto_approval_disabled", !approved)
                .expect("fingerprint denial flag is writable");
        }
    }
    Ok(Some(new))
}

thread_local! {
    /// Per policy table: the (sub)transaction that advanced the epoch in
    /// this backend, and the value it wrote.
    static ADMIN_EPOCH: [Cell<(pg_sys::TransactionId, i64)>; 2] =
        const { [Cell::new((pg_sys::TransactionId::INVALID, 0)), Cell::new((pg_sys::TransactionId::INVALID, 0))] };
}

fn epoch_kind(table: PolicyTable) -> &'static str {
    match table {
        PolicyTable::Approvals => "approvals",
        PolicyTable::Fingerprints => "fingerprints",
    }
}

/// This transaction's administrator epoch for `table`, advancing it on first
/// use. A value written by a subtransaction that later rolled back is gone,
/// and so is its row lock: that subtransaction's xid is no longer current,
/// so the next write advances again.
fn administrator_epoch(table: PolicyTable, owner: pg_sys::Oid) -> i64 {
    let index = table as usize;
    let (xid, epoch) = ADMIN_EPOCH.with(|slots| slots[index].get());
    if xid != pg_sys::TransactionId::INVALID && unsafe { pg_sys::TransactionIdIsCurrentTransactionId(xid) } {
        return epoch;
    }
    let kind = epoch_kind(table);
    let advanced = as_owner(owner, || {
        Spi::get_one_with_args::<i64>(
            "UPDATE public.sql_firewall_policy_epoch SET epoch = epoch OPERATOR(pg_catalog.+) 1 \
             WHERE kind OPERATOR(pg_catalog.=) $1 RETURNING epoch",
            &[text_arg(kind)],
        )
    });
    let epoch = match advanced {
        Ok(Some(value)) => value,
        Ok(None) => pgrx::error!("sql_firewall: policy epoch row for {kind} is missing"),
        Err(err) => pgrx::error!("sql_firewall: policy epoch update for {kind} failed: {err}"),
    };
    let xid = unsafe { pg_sys::GetCurrentTransactionId() };
    ADMIN_EPOCH.with(|slots| slots[index].set((xid, epoch)));
    epoch
}

/// A Learn observation records the epoch it saw. Any administrator write
/// after that observation in this transaction needs a newer epoch, even if an
/// earlier statement in the same transaction already advanced the table.
/// The row update and history remain transactional; an aborted subtransaction
/// cannot leave a published epoch behind.
pub(crate) fn note_learn_observation(table: PolicyTable) {
    ADMIN_EPOCH.with(|slots| slots[table as usize].set((pg_sys::TransactionId::INVALID, 0)));
}

/// Runs `f` as `owner` and as the firewall's own work (its statements are
/// not inspected). PostgreSQL restores the user on error at (sub)transaction
/// abort; the guard restores it on every other exit.
fn as_owner<T>(owner: pg_sys::Oid, f: impl FnOnce() -> T) -> T {
    struct Restore(pg_sys::Oid, i32);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { pg_sys::SetUserIdAndSecContext(self.0, self.1) };
        }
    }
    let mut user = pg_sys::InvalidOid;
    let mut context = 0i32;
    unsafe {
        pg_sys::GetUserIdAndSecContext(&mut user, &mut context);
        pg_sys::SetUserIdAndSecContext(owner, context | pg_sys::SECURITY_LOCAL_USERID_CHANGE as i32);
    }
    let _restore = Restore(user, context);
    let mut out = None;
    crate::firewall::as_internal_work(|| out = Some(f()));
    out.expect("as_internal_work runs its closure")
}

/// A policy row's key and decision, as raw datums of the row being changed.
struct RowImage {
    role_name: Option<pg_sys::Datum>,
    command_type: Option<pg_sys::Datum>,
    fingerprint: Option<pg_sys::Datum>,
    is_approved: Option<bool>,
    auto_approval_disabled: Option<bool>,
}

impl RowImage {
    unsafe fn read(table: PolicyTable, tuple: pg_sys::HeapTuple, desc: pg_sys::TupleDesc) -> Self {
        let datum = |name: &CStr| -> Option<pg_sys::Datum> {
            let attnum = pg_sys::SPI_fnumber(desc, name.as_ptr());
            if attnum <= 0 {
                return None;
            }
            let mut isnull = false;
            let value = pg_sys::heap_getattr(tuple, attnum, desc, &mut isnull);
            (!isnull).then_some(value)
        };
        let flag = |name: &CStr| datum(name).map(|value| value.value() != 0);
        Self {
            role_name: datum(c"role_name"),
            command_type: datum(c"command_type"),
            fingerprint: match table {
                PolicyTable::Approvals => None,
                PolicyTable::Fingerprints => datum(c"fingerprint"),
            },
            is_approved: flag(c"is_approved"),
            auto_approval_disabled: match table {
                PolicyTable::Approvals => None,
                PolicyTable::Fingerprints => flag(c"auto_approval_disabled"),
            },
        }
    }

    fn args(image: Option<&Self>) -> [DatumWithOid<'static>; 5] {
        let with = |value: Option<pg_sys::Datum>, oid| match value {
            Some(datum) => unsafe { DatumWithOid::new(datum, oid) },
            None => DatumWithOid::null_oid(oid),
        };
        let flag = |value: Option<bool>| match value {
            Some(v) => crate::sql::bool_arg(v),
            None => DatumWithOid::null_oid(pg_sys::BOOLOID),
        };
        [
            with(image.and_then(|i| i.role_name), pg_sys::NAMEOID),
            with(image.and_then(|i| i.command_type), pg_sys::TEXTOID),
            with(image.and_then(|i| i.fingerprint), pg_sys::TEXTOID),
            flag(image.and_then(|i| i.is_approved)),
            flag(image.and_then(|i| i.auto_approval_disabled)),
        ]
    }
}

/// A worker change worth a history row: a row that starts approved, or a
/// change of `is_approved` or `auto_approval_disabled`. A discovered pending
/// fingerprint and hit counting are observations, not decisions.
fn decision_changed(old: Option<&RowImage>, new: Option<&RowImage>) -> bool {
    match (old, new) {
        (None, Some(new)) => new.is_approved == Some(true),
        (Some(old), Some(new)) => {
            old.is_approved != new.is_approved || old.auto_approval_disabled != new.auto_approval_disabled
        }
        _ => true,
    }
}

fn user_name(oid: pg_sys::Oid) -> String {
    unsafe { crate::encoding::decode_palloc(pg_sys::GetUserNameFromId(oid, true)) }.unwrap_or_default()
}

/// `learn` is `Some` for the approval worker's own change.
fn record_history(
    table: PolicyTable,
    operation: &str,
    learn: Option<()>,
    epoch: i64,
    old: Option<&RowImage>,
    new: Option<&RowImage>,
    owner: pg_sys::Oid,
) {
    let Some(extension_oid) = crate::pending_approvals::current_extension_oid() else {
        pgrx::error!("sql_firewall: policy history needs an installed extension");
    };
    // Captured before switching to the owner.
    let session_role = user_name(unsafe { pg_sys::GetSessionUserId() });
    let effective_role = user_name(unsafe { pg_sys::GetUserId() });
    let system_identifier = unsafe { pg_sys::GetSystemIdentifier() }.to_string();
    let policy_table = match table {
        PolicyTable::Approvals => "command_approvals",
        PolicyTable::Fingerprints => "query_fingerprints",
    };
    let source = if learn.is_some() { "learn" } else { "administrator" };
    let mut args = vec![
        text_arg(&system_identifier),
        crate::sql::oid_carrier_arg(u32::from(unsafe { pg_sys::MyDatabaseId })),
        crate::sql::oid_carrier_arg(u32::from(extension_oid)),
        unsafe { DatumWithOid::new(epoch, pg_sys::INT8OID) },
        text_arg(policy_table),
        text_arg(operation),
        text_arg(source),
        name_arg(&session_role),
        name_arg(&effective_role),
    ];
    args.extend(RowImage::args(old));
    args.extend(RowImage::args(new));
    let inserted = as_owner(owner, || {
        Spi::run_with_args(
            "INSERT INTO public.sql_firewall_policy_history (system_identifier, database_oid, extension_oid, \
               policy_epoch, policy_table, operation, source, session_role, effective_role, \
               old_role_name, old_command_type, old_fingerprint, old_is_approved, old_auto_approval_disabled, \
               new_role_name, new_command_type, new_fingerprint, new_is_approved, new_auto_approval_disabled) \
             VALUES ($1::pg_catalog.numeric, $2::pg_catalog.oid, $3::pg_catalog.oid, $4, $5, $6, $7, $8, $9, \
               $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
            &args,
        )
    });
    if let Err(err) = inserted {
        pgrx::error!("sql_firewall: policy history record failed: {err}");
    }
}

pgrx::extension_sql!(
    r#"
-- Cache invalidation (policy_visibility.rs). ENABLE ALWAYS: these fire even
-- with session_replication_role = replica.
--
-- The BEFORE statement trigger is the writer protection: it runs before the
-- statement changes any row, so a RETURNING expression or an earlier user
-- trigger cannot read and publish this transaction's uncommitted policy. It
-- also covers TRUNCATE, which has no row trigger.
--
-- The AFTER row trigger covers logical replication apply, which fires row
-- triggers but no statement triggers. Both must be present and ENABLE ALWAYS
-- for the shared caches to be used at all (invalidation_triggers_enabled).
CREATE TRIGGER sql_firewall_policy_changing
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.sql_firewall_command_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION sql_firewall_policy_changed('approvals');
CREATE TRIGGER sql_firewall_policy_changed
    AFTER INSERT OR UPDATE OR DELETE ON public.sql_firewall_command_approvals
    FOR EACH ROW EXECUTE FUNCTION sql_firewall_policy_changed('approvals');
ALTER TABLE public.sql_firewall_command_approvals ENABLE ALWAYS TRIGGER sql_firewall_policy_changing;
ALTER TABLE public.sql_firewall_command_approvals ENABLE ALWAYS TRIGGER sql_firewall_policy_changed;
CREATE TRIGGER sql_firewall_policy_changing
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.sql_firewall_query_fingerprints
    FOR EACH STATEMENT EXECUTE FUNCTION sql_firewall_policy_changed('fingerprints');
CREATE TRIGGER sql_firewall_policy_changed
    AFTER INSERT OR UPDATE OR DELETE ON public.sql_firewall_query_fingerprints
    FOR EACH ROW EXECUTE FUNCTION sql_firewall_policy_changed('fingerprints');
ALTER TABLE public.sql_firewall_query_fingerprints ENABLE ALWAYS TRIGGER sql_firewall_policy_changing;
ALTER TABLE public.sql_firewall_query_fingerprints ENABLE ALWAYS TRIGGER sql_firewall_policy_changed;
-- The column-specific trigger sees direct false-to-false denials. Its Rust
-- context distinguishes those from the consumer's own pending-hit updates.
CREATE TRIGGER sql_firewall_fingerprint_decision
    BEFORE UPDATE OF is_approved ON public.sql_firewall_query_fingerprints
    FOR EACH ROW EXECUTE FUNCTION sql_firewall_fingerprint_decision();
ALTER TABLE public.sql_firewall_query_fingerprints ENABLE ALWAYS TRIGGER sql_firewall_fingerprint_decision;
-- Regex rules: the same pair versions the "no active rule" memo
-- (regex_memo_scope); there is no epoch or history for rules.
CREATE TRIGGER sql_firewall_policy_changing
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.sql_firewall_regex_rules
    FOR EACH STATEMENT EXECUTE FUNCTION sql_firewall_policy_changed('regex_rules');
CREATE TRIGGER sql_firewall_policy_changed
    AFTER INSERT OR UPDATE OR DELETE ON public.sql_firewall_regex_rules
    FOR EACH ROW EXECUTE FUNCTION sql_firewall_policy_changed('regex_rules');
ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_policy_changing;
ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_policy_changed;
-- A trigger function cannot be called directly; firing does not check EXECUTE.
REVOKE ALL ON FUNCTION sql_firewall_policy_changed() FROM PUBLIC;
REVOKE ALL ON FUNCTION sql_firewall_fingerprint_decision() FROM PUBLIC;

-- Superuser-only writes (sql_firewall_guard). The name sorts before the
-- other triggers, so it fires first among the BEFORE triggers of a table.
DO $guard$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'sql_firewall_activity_log', 'sql_firewall_blocked_queries',
        'sql_firewall_command_approvals', 'sql_firewall_query_fingerprints',
        'sql_firewall_regex_rules', 'sql_firewall_regex_default_removals',
        'sql_firewall_policy_epoch', 'sql_firewall_policy_history',
        'sql_firewall_fingerprint_hits', 'sql_firewall_consumer_checkpoint',
        'sql_firewall_activity_checkpoint', 'sql_firewall_retention_status']
    LOOP
        EXECUTE pg_catalog.format(
            'CREATE TRIGGER sql_firewall_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION sql_firewall_guard()', t);
        EXECUTE pg_catalog.format('ALTER TABLE public.%I ENABLE ALWAYS TRIGGER sql_firewall_guard', t);
    END LOOP;
    -- Policy tables: also per row, for logical replication apply. The audit
    -- log's own writes are batches; it keeps the statement trigger only.
    FOREACH t IN ARRAY ARRAY[
        'sql_firewall_command_approvals', 'sql_firewall_query_fingerprints',
        'sql_firewall_regex_rules', 'sql_firewall_regex_default_removals',
        'sql_firewall_policy_epoch', 'sql_firewall_policy_history']
    LOOP
        EXECUTE pg_catalog.format(
            'CREATE TRIGGER sql_firewall_guard_row BEFORE INSERT OR UPDATE OR DELETE ON public.%I '
            'FOR EACH ROW EXECUTE FUNCTION sql_firewall_guard()', t);
        EXECUTE pg_catalog.format('ALTER TABLE public.%I ENABLE ALWAYS TRIGGER sql_firewall_guard_row', t);
    END LOOP;
END
$guard$;
REVOKE ALL ON FUNCTION sql_firewall_guard() FROM PUBLIC;
"#,
    name = "policy_invalidation_triggers",
    requires = ["firewall_schema", sql_firewall_policy_changed, sql_firewall_fingerprint_decision, sql_firewall_guard],
);

/// Who a shared-cache entry belongs to.
#[derive(Copy, Clone)]
pub struct CacheScope {
    pub db_oid: pg_sys::Oid,
    pub extension_oid: pg_sys::Oid,
    pub role_oid: pg_sys::Oid,
    pub role_name_hash: u64,
}

impl CacheScope {
    pub fn new(extension_oid: pg_sys::Oid, role_oid: pg_sys::Oid, role_name: &str) -> Self {
        Self {
            db_oid: unsafe { pg_sys::MyDatabaseId },
            extension_oid,
            role_oid,
            role_name_hash: name_hash(role_name),
        }
    }
}

fn name_hash(name: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// The scope in which this statement may read and publish `table` entries,
/// or `None` when it must do neither (see the module contract).
pub fn cache_scope(table: PolicyTable, role_oid: Option<pg_sys::Oid>, role_name: &str) -> Option<CacheScope> {
    let role_oid = role_oid.filter(|oid| *oid != pg_sys::InvalidOid)?;
    if written(table) || INSTALLATION_CHANGED.with(Cell::get) {
        return None;
    }
    let ext = shared_state_installation()?;
    let (index, relname, argument) = match table {
        PolicyTable::Approvals => (0, APPROVALS, b"approvals".as_slice()),
        PolicyTable::Fingerprints => (1, FINGERPRINTS, b"fingerprints".as_slice()),
    };
    triggers_in_place(index, ext, relname, argument)?;
    Some(CacheScope::new(ext, role_oid, role_name))
}

/// The installation whose committed policy may be versioned by the shared
/// generations, or `None` where that cannot be guaranteed (module contract,
/// point 5): hot standby, parallel operation, no installation, or one this
/// transaction created.
fn shared_state_installation() -> Option<pg_sys::Oid> {
    unsafe {
        if pg_sys::RecoveryInProgress() || pg_sys::IsInParallelMode() {
            return None;
        }
    }
    let ext = crate::activation::installed_extension_oid()?;
    if crate::extension_created_in_this_transaction(u32::from(ext)) {
        return None;
    }
    Some(ext)
}

/// The policy table's relation when its invalidation triggers are in their
/// installed form (`invalidation_triggers_enabled`), kept per backend while
/// no catalog invalidation was processed (activation::catalog_generation):
/// trigger changes, a renamed or dropped table or function, and a changed
/// schema all send one.
fn triggers_in_place(index: usize, ext: pg_sys::Oid, relname: &CStr, argument: &[u8]) -> Option<pg_sys::Oid> {
    let db = unsafe { pg_sys::MyDatabaseId };
    let generation = crate::activation::catalog_generation();
    if crate::preloaded() {
        if let Some((stored, stored_db, stored_ext, relid)) = TRIGGERS_CHECKED.with(|slots| slots[index].get()) {
            if stored == generation && stored_db == db && stored_ext == ext {
                return relid;
            }
        }
    }
    let relid = unsafe {
        let nsp = pg_sys::get_namespace_oid(PUBLIC_NSP.as_ptr(), true);
        if nsp == pg_sys::InvalidOid {
            None
        } else {
            let relid = pg_sys::get_relname_relid(relname.as_ptr(), nsp);
            (relid != pg_sys::InvalidOid && invalidation_triggers_enabled(relid, argument)).then_some(relid)
        }
    };
    if crate::preloaded() {
        TRIGGERS_CHECKED.with(|slots| slots[index].set(Some((generation, db, ext, relid))));
    }
    relid
}

/// Where "this database has no active BLOCK regex rule" may be remembered
/// and used: the database, the installation, and the approval generation
/// read now, before the rules are read with a fresh snapshot. A commit that
/// writes `sql_firewall_regex_rules` (its two invalidation triggers, as for
/// the policy tables), creates or drops the installation, or changes a
/// trigger advances that generation before COMMIT returns, so a statement
/// inspected after it never uses an older memo. `None` (read the rules) in
/// a transaction that wrote rules, and wherever the shared caches are
/// bypassed (`shared_state_installation`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RegexMemoScope {
    db_oid: pg_sys::Oid,
    extension_oid: pg_sys::Oid,
    relation: pg_sys::Oid,
    generation: u64,
}

pub fn regex_memo_scope() -> Option<RegexMemoScope> {
    if REGEX_WRITTEN.with(Cell::get) || INSTALLATION_CHANGED.with(Cell::get) {
        return None;
    }
    let ext = shared_state_installation()?;
    let relation = triggers_in_place(2, ext, REGEX_RULES, b"regex_rules")?;
    let db = unsafe { pg_sys::MyDatabaseId };
    Some(RegexMemoScope {
        db_oid: db,
        extension_oid: ext,
        relation,
        generation: crate::approval_cache::generation(db),
    })
}

/// The memo says there is no active rule for exactly this scope, and the
/// rules table can be read now: the read lock a rule evaluation would take is
/// taken without waiting (and kept to the end of the transaction, as that
/// read would keep it). While another transaction holds a lock that blocks
/// reading the rules (DDL, `LOCK TABLE`, `VACUUM FULL`) this is false, and
/// the evaluation waits and is refused at the deadline as before (README 6.6).
pub fn no_regex_rules(scope: RegexMemoScope) -> bool {
    NO_REGEX_RULES.with(Cell::get) == Some(scope)
        && unsafe { pg_sys::ConditionalLockRelationOid(scope.relation, pg_sys::AccessShareLock as pg_sys::LOCKMODE) }
}

/// Remember an empty read made after `scope` was taken, unless a commit
/// advanced the generation meanwhile.
pub fn remember_no_regex_rules(scope: RegexMemoScope) {
    if crate::approval_cache::generation(scope.db_oid) == scope.generation {
        NO_REGEX_RULES.with(|memo| memo.set(Some(scope)));
    }
}

/// The installed invalidation triggers are both present and `ENABLE ALWAYS`,
/// with no WHEN condition or column list, and name this table:
///
///  - a `BEFORE` statement trigger for INSERT, UPDATE, DELETE and TRUNCATE.
///    Being `BEFORE`, it marks this transaction as a writer before the
///    statement changes any row, so nothing nested in that statement can read
///    and publish the transaction's own uncommitted policy.
///  - an `AFTER` row trigger for INSERT, UPDATE and DELETE, which covers
///    logical replication apply: it fires row triggers but no statement
///    triggers.
///
/// Anything else is not the configuration this module reasons about, so the
/// shared caches are bypassed. Read from the relcache entry; the lock is the
/// one the policy read takes anyway.
unsafe fn invalidation_triggers_enabled(relid: pg_sys::Oid, argument: &[u8]) -> bool {
    let rel = pg_sys::try_relation_open(relid, pg_sys::AccessShareLock as pg_sys::LOCKMODE);
    if rel.is_null() {
        return false;
    }
    let desc = (*rel).trigdesc;
    let mut before_statement = false;
    let mut after_row = false;
    if !desc.is_null() {
        let dml = pg_sys::TRIGGER_TYPE_INSERT | pg_sys::TRIGGER_TYPE_UPDATE | pg_sys::TRIGGER_TYPE_DELETE;
        for i in 0..(*desc).numtriggers.max(0) as usize {
            let trigger = &*(*desc).triggers.add(i);
            if trigger.tgenabled as u8 != pg_sys::TRIGGER_FIRES_ALWAYS
                || !trigger.tgqual.is_null()
                || trigger.tgnattr != 0
                || trigger.tgnargs != 1
                || CStr::from_ptr(*trigger.tgargs).to_bytes() != argument
            {
                continue;
            }
            let name = pg_sys::get_func_name(trigger.tgfoid);
            if name.is_null() {
                continue;
            }
            let ours = CStr::from_ptr(name).to_bytes() == TRIGGER_FUNCTION;
            pg_sys::pfree(name.cast());
            let tgtype = trigger.tgtype as u32;
            if !ours || tgtype & pg_sys::TRIGGER_TYPE_INSTEAD != 0 {
                continue;
            }
            let row = tgtype & pg_sys::TRIGGER_TYPE_ROW != 0;
            let before = tgtype & pg_sys::TRIGGER_TYPE_BEFORE != 0;
            if !row && before && tgtype & (dml | pg_sys::TRIGGER_TYPE_TRUNCATE) == dml | pg_sys::TRIGGER_TYPE_TRUNCATE {
                before_statement = true;
            }
            if row && !before && tgtype & dml == dml {
                after_row = true;
            }
        }
    }
    pg_sys::relation_close(rel, pg_sys::NoLock as pg_sys::LOCKMODE);
    before_statement && after_row
}

/// `approved` from the command approvals catalog, read with a snapshot taken
/// now, and `sql_firewall_policy_epoch` for approvals in the same snapshot.
/// `None` is no row. The caller reads the cache generation first. An event
/// published from this lookup carries this epoch (see the trigger above).
pub fn read_command_approval(role: &str, command: &str) -> Result<(Option<bool>, i64), String> {
    fresh_query(
        c"SELECT e.epoch, (SELECT a.is_approved FROM public.sql_firewall_command_approvals a \
            WHERE a.role_name OPERATOR(pg_catalog.=) $1 \
              AND a.command_type OPERATOR(pg_catalog.=) $2) \
          FROM public.sql_firewall_policy_epoch e \
          WHERE e.kind OPERATOR(pg_catalog.=) 'approvals'::pg_catalog.text",
        &[name_arg(role), text_arg(command)],
        |tuple, desc| unsafe { (column_int8(tuple, desc, 1), column_bool(tuple, desc, 2)) },
    )?
    .and_then(|(epoch, approved)| epoch.map(|epoch| (approved, epoch)))
    .ok_or_else(|| "sql_firewall: the approvals policy epoch is missing".to_string())
}

/// `(hit_count, is_approved)` from the fingerprint catalog, read with a
/// snapshot taken now, and the fingerprint policy epoch in the same snapshot
/// (as for [`read_command_approval`]). A NULL column is `None` inside the row.
pub fn read_fingerprint(
    fingerprint: &str,
    role: &str,
    command: &str,
) -> Result<(Option<(Option<i32>, Option<bool>)>, i64), String> {
    fresh_query(
        c"SELECT e.epoch, f.fingerprint IS NOT NULL, f.hit_count, f.is_approved \
          FROM public.sql_firewall_policy_epoch e \
          LEFT JOIN public.sql_firewall_query_fingerprints f \
            ON f.fingerprint OPERATOR(pg_catalog.=) $1 \
           AND f.role_name OPERATOR(pg_catalog.=) $2 \
           AND f.command_type OPERATOR(pg_catalog.=) $3 \
          WHERE e.kind OPERATOR(pg_catalog.=) 'fingerprints'::pg_catalog.text",
        &[text_arg(fingerprint), name_arg(role), text_arg(command)],
        |tuple, desc| unsafe {
            let row = (column_bool(tuple, desc, 2) == Some(true))
                .then(|| (column_int4(tuple, desc, 3), column_bool(tuple, desc, 4)));
            (column_int8(tuple, desc, 1), row)
        },
    )?
    .and_then(|(epoch, row)| epoch.map(|epoch| (row, epoch)))
    .ok_or_else(|| "sql_firewall: the fingerprint policy epoch is missing".to_string())
}

/// The committed policy epoch for `table`, read with a snapshot taken now.
#[cfg_attr(not(feature = "queue_probe"), allow(dead_code))]
pub fn read_policy_epoch(table: PolicyTable) -> Result<i64, String> {
    let kind = epoch_kind(table);
    fresh_query(
        c"SELECT epoch FROM public.sql_firewall_policy_epoch WHERE kind OPERATOR(pg_catalog.=) $1",
        &[text_arg(kind)],
        |tuple, desc| unsafe { column_int8(tuple, desc, 1) },
    )?
    .flatten()
    .ok_or_else(|| format!("sql_firewall: missing policy epoch for {kind}"))
}

unsafe fn column_bool(tuple: pg_sys::HeapTuple, desc: pg_sys::TupleDesc, column: i32) -> Option<bool> {
    let mut isnull = false;
    let datum = pg_sys::SPI_getbinval(tuple, desc, column, &mut isnull);
    (!isnull).then(|| datum.value() != 0)
}

unsafe fn column_int4(tuple: pg_sys::HeapTuple, desc: pg_sys::TupleDesc, column: i32) -> Option<i32> {
    let mut isnull = false;
    let datum = pg_sys::SPI_getbinval(tuple, desc, column, &mut isnull);
    (!isnull).then(|| datum.value() as i32)
}

unsafe fn column_int8(tuple: pg_sys::HeapTuple, desc: pg_sys::TupleDesc, column: i32) -> Option<i64> {
    let mut isnull = false;
    let datum = pg_sys::SPI_getbinval(tuple, desc, column, &mut isnull);
    (!isnull).then(|| datum.value() as i64)
}

/// First row of `query`, read with a snapshot taken for this lookup rather
/// than the transaction's older data snapshot. While [`without_first_snapshot`]
/// holds, a fresh catalog snapshot is used to leave the first data snapshot unset.
/// During a parallel operation no new snapshot can be taken; the active one
/// is used, and `cache_scope` has already refused shared-cache use.
fn fresh_query<T>(
    query: &CStr,
    args: &[DatumWithOid<'_>],
    read: impl FnOnce(pg_sys::HeapTuple, pg_sys::TupleDesc) -> T,
) -> Result<Option<T>, String> {
    Spi::connect(|_client| unsafe {
        let mut types: Vec<pg_sys::Oid> = args.iter().map(DatumWithOid::oid).collect();
        let mut values: Vec<pg_sys::Datum> = args
            .iter()
            .map(|arg| arg.datum().map(|d| d.sans_lifetime()).unwrap_or(pg_sys::Datum::from(0usize)))
            .collect();
        let nulls: Vec<c_char> = args
            .iter()
            .map(|arg| if arg.datum().is_some() { b' ' } else { b'n' } as c_char)
            .collect();
        let plan = pg_sys::SPI_prepare(query.as_ptr(), types.len() as i32, types.as_mut_ptr());
        if plan.is_null() {
            return Err(format!("SPI_prepare failed ({})", std::ptr::addr_of!(pg_sys::SPI_result).read()));
        }
        let snapshot = if without_first_snapshot() {
            // This is a fresh MVCC snapshot, but unlike GetLatestSnapshot it
            // does not fix the transaction's first user-data snapshot.  This
            // relation has no syscache, so PostgreSQL invalidates the catalog
            // snapshot before each read.  InvalidOid is likewise uncached.
            pg_sys::GetCatalogSnapshot(pg_sys::InvalidOid)
        } else if pg_sys::IsInParallelMode() {
            pg_sys::GetActiveSnapshot()
        } else {
            pg_sys::GetLatestSnapshot()
        };
        let rc = pg_sys::SPI_execute_snapshot(
            plan,
            values.as_mut_ptr(),
            nulls.as_ptr(),
            snapshot,
            std::ptr::null_mut(),
            true,
            false,
            1,
        );
        let table = std::ptr::addr_of!(pg_sys::SPI_tuptable).read();
        let processed = std::ptr::addr_of!(pg_sys::SPI_processed).read();
        let result = if rc != pg_sys::SPI_OK_SELECT as i32 {
            Err(format!("SPI_execute_snapshot returned {rc}"))
        } else if processed == 0 || table.is_null() {
            Ok(None)
        } else {
            Ok(Some(read(*(*table).vals, (*table).tupdesc)))
        };
        pg_sys::SPI_freeplan(plan);
        result
    })
}
