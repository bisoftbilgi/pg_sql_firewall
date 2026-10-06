use pgrx::bgworkers::BackgroundWorkerBuilder;
use pgrx::pg_sys::{self, errcodes::PgSqlErrorCode};
use pgrx::prelude::*;

mod activation;
mod activity_queue;
mod audit_retention;
mod consumer_control;
mod alerts;
mod encoding;
mod approval_cache;
mod approval_worker;
mod consumer_checkpoint;
mod worker_persist;
mod context;
mod fingerprint_cache;
mod fingerprints;
mod firewall;
mod guc;
mod hooks;
mod launcher;
mod pending_approvals;
mod policy_visibility;
#[cfg(feature = "queue_probe")]
mod queue_probe;
#[cfg(feature = "fingerprint_probe")]
mod fingerprint_probe;
#[cfg(feature = "policy_probe")]
mod policy_probe;
#[cfg(feature = "session_probe")]
mod session_probe;
mod port;
mod rate_state;
mod spi_checks;
mod seqlock;
mod sql_tokens;
mod sql;
mod structured_log;

pub use approval_worker::approval_worker_main;
pub use launcher::firewall_launcher_main;

pgrx::pg_module_magic!();
// bootstrap places this DO block before every other generated statement.
pgrx::extension_sql_file!(
    "../sql/utf8_required.sql",
    name = "utf8_required",
    bootstrap,
);
// Before any object of the installation: a library that was not loaded at
// server start cannot inspect anything (README 4), so the installation is
// refused rather than left looking protected.
pgrx::extension_sql!(
    "SELECT public.sql_firewall_require_preload();",
    name = "preload_required",
    requires = [sql_firewall_require_preload],
);
pgrx::extension_sql_file!(
    "../sql/firewall_schema.sql",
    name = "firewall_schema",
    requires = ["preload_required"],
);
pgrx::extension_sql_file!(
    "../sql/admin_revoke.sql",
    name = "admin_revoke",
    finalize
);

/// Set by `_PG_init` when the library is loaded from shared_preload_libraries.
/// Backends inherit it from the postmaster. Loaded any other way (CREATE
/// EXTENSION, a function call, LOAD), the library installs no hooks.
static PRELOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn preloaded() -> bool {
    PRELOADED.load(std::sync::atomic::Ordering::Relaxed)
}

static mut PREV_SHMEM_REQUEST_HOOK: Option<unsafe extern "C-unwind" fn()> = None;
static mut PREV_SHMEM_STARTUP_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

#[pgrx::pg_guard]
pub extern "C-unwind" fn _PG_init() {
    unsafe {
        if !pg_sys::process_shared_preload_libraries_in_progress {
            // Not silent: nothing is inspected in this server (README 3).
            if pg_sys::IsUnderPostmaster {
                pgrx::warning!(
                    "sql_firewall: the library is not loaded through shared_preload_libraries; statements are not inspected and no firewall policy applies"
                );
            }
            return;
        }
        // pg_upgrade starts both servers in binary-upgrade mode and drops and
        // recreates databases there; a launcher connected to one makes the
        // upgrade fail. Nothing is inspected in that mode either: only
        // pg_upgrade can connect (README 6.9b).
        if pg_sys::IsBinaryUpgrade {
            pgrx::log!("sql_firewall: binary upgrade mode; hooks and background workers are not started");
            return;
        }
    }
    PRELOADED.store(true, std::sync::atomic::Ordering::Relaxed);

    unsafe {
        PREV_SHMEM_REQUEST_HOOK = pg_sys::shmem_request_hook;
        pg_sys::shmem_request_hook = Some(shmem_request_hook);

        PREV_SHMEM_STARTUP_HOOK = pg_sys::shmem_startup_hook;
        pg_sys::shmem_startup_hook = Some(shmem_startup_hook);
    }

    guc::register();
    activation::register_catalog_callbacks();
    unsafe {
        pg_sys::RegisterXactCallback(Some(control_xact_callback), std::ptr::null_mut());
        pg_sys::RegisterSubXactCallback(Some(control_subxact_callback), std::ptr::null_mut());
    }
    
    hooks::install();
    
    // The launcher. Restarted 5 s after it fails or the server reinitializes
    // after a crash; a launcher that exits normally (shutdown) is not.
    BackgroundWorkerBuilder::new("sql_firewall_launcher")
        .set_function("firewall_launcher_main")
        .set_library("sql_firewall")
        .enable_spi_access()
        .set_start_time(pgrx::bgworkers::BgWorkerStartTime::RecoveryFinished)
        .set_restart_time(Some(std::time::Duration::from_secs(5)))
        .load();
    
}

#[pgrx::pg_guard]
pub extern "C-unwind" fn _PG_fini() {
    hooks::uninstall();
    unsafe {
        pg_sys::shmem_request_hook = PREV_SHMEM_REQUEST_HOOK;
        pg_sys::shmem_startup_hook = PREV_SHMEM_STARTUP_HOOK;
        PREV_SHMEM_REQUEST_HOOK = None;
        PREV_SHMEM_STARTUP_HOOK = None;
    }
    pgrx::log!("sql_firewall: extension unloaded");
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn shmem_request_hook() {
    if let Some(prev) = PREV_SHMEM_REQUEST_HOOK {
        prev();
    }
    pg_sys::RequestAddinShmemSpace(approval_cache::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(fingerprint_cache::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(rate_state::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(pending_approvals::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(activity_queue::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(consumer_control::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(std::mem::size_of::<LibraryStamp>());
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn shmem_startup_hook() {
    if let Some(prev) = PREV_SHMEM_STARTUP_HOOK {
        prev();
    }
    approval_cache::initialize();
    fingerprint_cache::init();
    rate_state::init();
    pending_approvals::init();
    activity_queue::init();
    consumer_control::init();
    stamp_library_version();
}

/// The version of the library the postmaster loaded at server start, in a
/// small shared-memory block whose name and layout every release keeps, so
/// that any build can read it (`sql_firewall_library_version`, the update
/// tool, update scripts). Rewritten at each shared-memory initialization.
#[repr(C)]
struct LibraryStamp {
    magic: u64,
    version: [u8; 56],
}

const LIBRARY_STAMP_MAGIC: u64 = 0x5351_4c46_5753_5401; // "SQLFWST" v1

unsafe fn stamp_library_version() {
    let mut found = false;
    let stamp = pg_sys::ShmemInitStruct(
        c"sql_firewall_library".as_ptr(),
        std::mem::size_of::<LibraryStamp>(),
        &mut found,
    ) as *mut LibraryStamp;
    if stamp.is_null() {
        return;
    }
    let mut version = [0u8; 56];
    let bytes = env!("CARGO_PKG_VERSION").as_bytes();
    version[..bytes.len().min(55)].copy_from_slice(&bytes[..bytes.len().min(55)]);
    std::ptr::write(stamp, LibraryStamp { magic: LIBRARY_STAMP_MAGIC, version });
}

fn running_library_version() -> Option<String> {
    if !preloaded() {
        return None;
    }
    unsafe {
        let mut found = false;
        let stamp = pg_sys::ShmemInitStruct(
            c"sql_firewall_library".as_ptr(),
            std::mem::size_of::<LibraryStamp>(),
            &mut found,
        ) as *const LibraryStamp;
        if stamp.is_null() || !found || (*stamp).magic != LIBRARY_STAMP_MAGIC {
            return None;
        }
        let version = &(*stamp).version;
        let end = version.iter().position(|byte| *byte == 0).unwrap_or(version.len());
        String::from_utf8(version[..end].to_vec()).ok()
    }
}

/// `library_version`: the code executing this call. `running_version`: the
/// library the server loaded at start (NULL without preload). They differ
/// after a new package was installed and before the restart that loads it;
/// update scripts and `sql_firewall_upgrade` require `running_version` to
/// be the release being installed.
#[pg_extern]
fn sql_firewall_library_version() -> TableIterator<
    'static,
    (name!(library_version, String), name!(running_version, Option<String>)),
> {
    TableIterator::once((env!("CARGO_PKG_VERSION").to_string(), running_library_version()))
}

/// Refuses unless this server loaded the library from
/// shared_preload_libraries when it started. A name in the setting is not
/// enough: the setting applies only at the next start. Called first by the
/// installation script and by update scripts; its ERROR rolls back the
/// whole CREATE or ALTER EXTENSION.
#[pg_extern]
fn sql_firewall_require_preload() {
    if preloaded() {
        return;
    }
    let active = unsafe {
        let raw = pg_sys::GetConfigOption(c"shared_preload_libraries".as_ptr(), true, false);
        encoding::decode_borrowed(raw).unwrap_or_default()
    };
    // The setting takes effect only at start; the value written for the next
    // start is the last entry in the configuration files (superuser-readable,
    // and only a superuser runs this script). Until the restart PostgreSQL
    // marks that entry "could not be applied" and sets pending_restart, so
    // the error column is no filter here (filtering on it read an older,
    // superseded entry, or none when only ALTER SYSTEM had written it).
    let next_start = match Spi::get_two::<bool, String>(
        "SELECT s.pending_restart, f.setting FROM pg_catalog.pg_settings AS s \
         LEFT JOIN LATERAL ( \
           SELECT setting FROM pg_catalog.pg_file_settings \
           WHERE name OPERATOR(pg_catalog.=) 'shared_preload_libraries' \
           ORDER BY seqno DESC LIMIT 1 \
         ) AS f ON true \
         WHERE s.name OPERATOR(pg_catalog.=) 'shared_preload_libraries'",
    ) {
        Ok((Some(true), Some(value))) => Some(value),
        _ => None,
    };
    let names_library = |value: &str| {
        value
            .split(',')
            .any(|entry| entry.trim().trim_matches('"') == "sql_firewall")
    };
    let detail = match next_start {
        Some(value) if names_library(&value) && !names_library(&active) => format!(
            "shared_preload_libraries is '{active}' in this server; the configuration sets '{value}', which takes effect only after a restart"
        ),
        _ => format!("shared_preload_libraries is '{active}'"),
    };
    pgrx::ereport!(
        ERROR,
        PgSqlErrorCode::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE,
        "sql_firewall: the library is not loaded through shared_preload_libraries; add sql_firewall to shared_preload_libraries, restart PostgreSQL, and run the command again",
        detail
    );
}

/// Whether this server inspects statements, and in which mode.
#[pg_extern]
fn sql_firewall_status() -> String {
    if !preloaded() {
        return "sql_firewall NOT ACTIVE: not loaded through shared_preload_libraries; statements are not inspected".to_string();
    }
    if !guc::firewall_enabled() {
        return "sql_firewall disabled (sql_firewall.enabled = off); statements are not inspected".to_string();
    }
    let status = format!("sql_firewall running in {:?} mode", guc::mode());
    if unsafe { pg_sys::RecoveryInProgress() } {
        // README 6.10: no consumer runs during recovery.
        return format!(
            "{status} on a hot standby: decisions use the replicated policy; blocked, activity, and learn events stay in this server's memory queues and are written only after promotion"
        );
    }
    status
}

/// Pause the consumer for this database and this extension installation.
///
/// Returns `approval worker paused` only after that consumer has acknowledged
/// the request outside a persistence transaction. `pause pending` means the
/// request was issued but not acknowledged before the wait ended, including
/// when no consumer is attached or one is still inside SQL. `pause superseded`
/// means a later resume or pause replaced this request. Cancelling this call
/// or rolling it back does not undo a request already stored for a committed
/// installation. If this transaction created the installation, the record is
/// released when that creation rolls back, including by a savepoint.
/// Shared memory restart clears the request and the next generation starts running.
#[pg_extern]
fn sql_firewall_pause_approval_worker() -> String {
    require_session_superuser();
    match control_command(true) {
        consumer_control::CommandResult::Paused { epoch, incarnation } => {
            format!("approval worker paused epoch={epoch} incarnation={incarnation}")
        }
        consumer_control::CommandResult::Pending { epoch } => {
            format!("pause pending epoch={epoch}")
        }
        consumer_control::CommandResult::Superseded => "pause superseded".to_string(),
        consumer_control::CommandResult::Full => "control registry is full".to_string(),
        consumer_control::CommandResult::NoExtension => {
            "sql_firewall is not installed in this database".to_string()
        }
        consumer_control::CommandResult::NoRing => "consumer control registry is unavailable".to_string(),
        consumer_control::CommandResult::Running { .. }
        | consumer_control::CommandResult::Acknowledged { .. } => "pause superseded".to_string(),
    }
}

/// Clear the pause for this database and this extension installation.
/// `approval worker running` means the consumer is processing. `resume
/// acknowledged` means it accepted the request but is still stalled on
/// checkpoint metadata or a retry. This does not repair or skip that metadata.
#[pg_extern]
fn sql_firewall_resume_approval_worker() -> String {
    require_session_superuser();
    match control_command(false) {
        consumer_control::CommandResult::Running { epoch, incarnation } => {
            format!("approval worker running epoch={epoch} incarnation={incarnation}")
        }
        consumer_control::CommandResult::Acknowledged { epoch, incarnation } => {
            format!("resume acknowledged epoch={epoch} incarnation={incarnation}")
        }
        consumer_control::CommandResult::Pending { epoch } => {
            format!("resume pending epoch={epoch}")
        }
        consumer_control::CommandResult::Superseded => "resume superseded".to_string(),
        consumer_control::CommandResult::Full => "control registry is full".to_string(),
        consumer_control::CommandResult::NoExtension => {
            "sql_firewall is not installed in this database".to_string()
        }
        consumer_control::CommandResult::NoRing => "consumer control registry is unavailable".to_string(),
        consumer_control::CommandResult::Paused { .. } => "resume superseded".to_string(),
    }
}

/// Shared observed state for this database and installation.
/// A row in pg_stat_activity is not itself a running or paused acknowledgement.
///
/// `paused`, `running`, `starting`, `stopping`, and `retrying` include the
/// acknowledged epoch and incarnation. `pause pending` and `resume pending`
/// have not been acknowledged by a live consumer. `stopped` means no live
/// consumer and no pending pause.
#[pg_extern]
fn sql_firewall_approval_worker_status() -> String {
    require_session_superuser();
    match current_control_identity() {
        Some(identity) => consumer_control::status_text(identity),
        None => "stopped".to_string(),
    }
}

/// Cluster-wide event ring counters since the ring was created (postmaster
/// start). `approval_events` and `fingerprint_events` count publications,
/// not rows: a learn observation is published when its transaction commits.
/// `learn_observations_dropped` counts observations a transaction could not
/// hold (README 6.1b). The `activity_*` columns describe the activity queue
/// (activity_queue.rs, README 6.7). Superuser only.
#[pg_extern]
fn sql_firewall_queue_statistics() -> TableIterator<
    'static,
    (
        name!(write_position, i64),
        name!(slot_overwrites, i64),
        name!(capacity, i64),
        name!(approval_events, i64),
        name!(blocked_query_events, i64),
        name!(fingerprint_events, i64),
        name!(learn_observations_dropped, i64),
        name!(activity_write_position, i64),
        name!(activity_capacity, i64),
        name!(activity_slot_overwrites, i64),
        name!(activity_publish_failed, i64),
        name!(activity_positions_skipped, i64),
        name!(activity_records_rejected, i64),
        name!(activity_generation, String),
    ),
> {
    require_session_superuser();
    let activity = activity_queue::statistics();
    let rows = pending_approvals::queue_statistics().map(|stats| {
        let n = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        let a = |f: fn(&activity_queue::Statistics) -> u64| activity.as_ref().map(|s| n(f(s))).unwrap_or(0);
        (
            n(stats.write_position),
            n(stats.slot_overwrites),
            n(stats.capacity),
            n(stats.published[0]),
            n(stats.published[1]),
            n(stats.published[2]),
            n(stats.learn_dropped),
            a(|s| s.write_position),
            a(|s| s.capacity),
            a(|s| s.overwrites),
            a(|s| s.publish_failed),
            a(|s| s.consumer_skipped),
            a(|s| s.consumer_rejected),
            activity.as_ref().map(|s| s.generation.to_string()).unwrap_or_default(),
        )
    });
    TableIterator::new(rows)
}

/// Clear the shared-memory approval cache for this postmaster.
/// Durable approval rows, checkpoints, and pause requests are unchanged.
/// The cache is cluster-wide process memory, not a per-session map.
#[pg_extern]
fn sql_firewall_clear_approval_cache() -> &'static str {
    require_session_superuser();
    approval_cache::invalidate_all();
    "approval cache cleared"
}

/// Resolves this backend's lifecycle tags. Only shared memory is touched.
/// A prepared transaction's outcome is decided by another session, which
/// cannot resolve these tags, so PREPARE is refused while any are held.
#[pgrx::pg_guard]
unsafe extern "C-unwind" fn control_xact_callback(
    event: pg_sys::XactEvent::Type,
    _arg: *mut std::ffi::c_void,
) {
    match event {
        pg_sys::XactEvent::XACT_EVENT_PRE_PREPARE => {
            if consumer_control::owns_lifecycle_tags() {
                pgrx::ereport!(
                    ERROR,
                    PgSqlErrorCode::ERRCODE_FEATURE_NOT_SUPPORTED,
                    "sql_firewall: cannot PREPARE a transaction that created or removed an installation with a pause/resume record"
                );
            }
        }
        pg_sys::XactEvent::XACT_EVENT_COMMIT | pg_sys::XactEvent::XACT_EVENT_PARALLEL_COMMIT => {
            // After ProcArrayEndTransaction, before the client hears COMMIT.
            policy_visibility::at_commit();
            // Only a committed transaction's learn observations count.
            pending_approvals::learn_at_commit();
            consumer_control::at_xact_end(true);
        }
        pg_sys::XactEvent::XACT_EVENT_ABORT
        | pg_sys::XactEvent::XACT_EVENT_PARALLEL_ABORT
        | pg_sys::XactEvent::XACT_EVENT_PREPARE => {
            hooks::enclosing_at_xact_abort();
            policy_visibility::at_abort();
            pending_approvals::learn_at_abort();
            consumer_control::at_xact_end(false);
        }
        _ => {}
    }
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn control_subxact_callback(
    event: pg_sys::SubXactEvent::Type,
    my_subid: pg_sys::SubTransactionId,
    parent_subid: pg_sys::SubTransactionId,
    _arg: *mut std::ffi::c_void,
) {
    match event {
        pg_sys::SubXactEvent::SUBXACT_EVENT_COMMIT_SUB => {
            pending_approvals::learn_at_subxact_end(true, my_subid, parent_subid);
            consumer_control::at_subxact_end(true, my_subid, parent_subid);
        }
        pg_sys::SubXactEvent::SUBXACT_EVENT_ABORT_SUB => {
            hooks::enclosing_at_subxact_abort(my_subid);
            pending_approvals::learn_at_subxact_end(false, my_subid, parent_subid);
            consumer_control::at_subxact_end(false, my_subid, parent_subid);
        }
        _ => {}
    }
}

fn require_session_superuser() {
    let allowed = unsafe { pg_sys::superuser_arg(pg_sys::GetSessionUserId()) };
    if !allowed {
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            "sql_firewall: only a superuser session can perform this operation"
        );
    }
}

fn control_command(pause: bool) -> consumer_control::CommandResult {
    if pending_approvals::ring_view().is_none() {
        return consumer_control::CommandResult::NoRing;
    }
    let Some(identity) = locked_control_identity() else {
        return consumer_control::CommandResult::NoExtension;
    };
    let created = consumer_control::created_subid(identity);
    if pause {
        consumer_control::request_pause(identity, created)
    } else {
        consumer_control::request_resume(identity, created)
    }
}

/// True when the visible `pg_extension` row was written by this transaction.
/// That includes `ALTER EXTENSION UPDATE`, so creation is decided only by the
/// utility hook, which also requires the installation to be new.
pub(crate) fn extension_created_in_this_transaction(extension_oid: u32) -> bool {
    unsafe {
        // PostgreSQL 17 names this syscache ZEXTENSIONOID (a back-branch ABI
        // arrangement); 16 and 18 call it EXTENSIONOID.
        #[cfg(not(feature = "pg17"))]
        let cache = pg_sys::SysCacheIdentifier::EXTENSIONOID;
        #[cfg(feature = "pg17")]
        let cache = pg_sys::SysCacheIdentifier::ZEXTENSIONOID;
        let tuple = pg_sys::SearchSysCache1(
            cache as i32,
            pg_sys::ObjectIdGetDatum(pg_sys::Oid::from(extension_oid)),
        );
        if tuple.is_null() {
            return false;
        }
        // The raw xmin: a frozen tuple's inserting transaction has ended, so
        // it is never the current one. Read from the header because
        // PostgreSQL 18 made the accessor macros static inline functions.
        let xmin = (*(*tuple).t_data).t_choice.t_heap.t_xmin;
        let created_here = pg_sys::TransactionIdIsCurrentTransactionId(xmin);
        pg_sys::ReleaseSysCache(tuple);
        created_here
    }
}

fn current_control_identity() -> Option<consumer_control::Identity> {
    let ring = pending_approvals::ring_view()?;
    let extension_oid = u32::from(pending_approvals::current_extension_oid()?);
    Some(consumer_control::Identity {
        db_oid: unsafe { u32::from(pg_sys::MyDatabaseId) },
        extension_oid,
        ring_generation: ring.generation,
    })
}

/// Lock the installation, then recheck that it is still the visible one.
/// A concurrent `DROP EXTENSION` holds a conflicting lock until it ends, so
/// no request can be stored for an installation after its removal has been
/// tagged. The lock is held to the end of this transaction.
fn locked_control_identity() -> Option<consumer_control::Identity> {
    let mut identity = current_control_identity()?;
    for _ in 0..4 {
        unsafe {
            pg_sys::LockDatabaseObject(
                pg_sys::ExtensionRelationId,
                pg_sys::Oid::from(identity.extension_oid),
                0,
                pg_sys::AccessShareLock as pg_sys::LOCKMODE,
            );
        }
        let now = current_control_identity()?;
        if now.extension_oid == identity.extension_oid {
            return Some(now);
        }
        identity = now;
    }
    None
}


#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn status_reports_mode() {
        let status = crate::sql_firewall_status();
        assert!(
            status.contains("sql_firewall running"),
            "unexpected status text: {status}"
        );
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
