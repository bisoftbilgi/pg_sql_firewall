//! Test-only (feature `session_probe`): runs one statement in a dynamic
//! background worker of this library as a given role, the way pg_cron and
//! similar job runners do. Only the launcher's and the consumers' entry
//! points are exempt from inspection (firewall.rs), so this worker's
//! statement is inspected like a client's. The outcome is written to the
//! server log with the marker `sql_firewall session probe:`.

use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
#[allow(unused_imports)]
use pgrx::pg_sys;
use pgrx::prelude::*;

fn require_superuser() {
    if !unsafe { pg_sys::superuser() } {
        pgrx::error!("sql_firewall: session probe functions require a superuser");
    }
}

/// Starts the worker for `sql` as `role` in this database and waits for it
/// to exit. Returns the worker's pid; the outcome is in the server log.
#[pg_extern]
fn sql_firewall_session_probe_worker(role: &str, sql: &str) -> i32 {
    require_superuser();
    let extra = format!("{} {} {}", u32::from(unsafe { pg_sys::MyDatabaseId }), role, sql);
    if extra.len() >= 128 || role.contains(' ') {
        pgrx::error!("sql_firewall: session probe statement too long or role name has a space");
    }
    unsafe {
        let mut worker: pg_sys::BackgroundWorker = std::mem::zeroed();
        copy(&mut worker.bgw_name, "sql_firewall session probe");
        copy(&mut worker.bgw_type, "sql_firewall session probe");
        worker.bgw_flags = (pg_sys::BGWORKER_SHMEM_ACCESS | pg_sys::BGWORKER_BACKEND_DATABASE_CONNECTION) as i32;
        worker.bgw_start_time = pg_sys::BgWorkerStartTime::BgWorkerStart_RecoveryFinished;
        worker.bgw_restart_time = pg_sys::BGW_NEVER_RESTART;
        copy(&mut worker.bgw_library_name, "sql_firewall");
        copy(&mut worker.bgw_function_name, "session_probe_worker_main");
        copy(&mut worker.bgw_extra, &extra);
        worker.bgw_notify_pid = pg_sys::MyProcPid;
        let mut handle: *mut pg_sys::BackgroundWorkerHandle = std::ptr::null_mut();
        if !pg_sys::RegisterDynamicBackgroundWorker(&mut worker, &mut handle) {
            pgrx::error!("sql_firewall: could not register the session probe worker");
        }
        let mut pid: pg_sys::pid_t = 0;
        if pg_sys::WaitForBackgroundWorkerStartup(handle, &mut pid) != pg_sys::BgwHandleStatus::BGWH_STARTED {
            pgrx::error!("sql_firewall: session probe worker did not start");
        }
        pg_sys::WaitForBackgroundWorkerShutdown(handle);
        pid
    }
}

unsafe fn copy(dest: &mut [std::os::raw::c_char], text: &str) {
    let bytes = text.as_bytes();
    let n = bytes.len().min(dest.len() - 1);
    for (i, b) in bytes[..n].iter().enumerate() {
        dest[i] = *b as std::os::raw::c_char;
    }
    dest[n] = 0;
}

#[pg_guard]
#[no_mangle]
pub unsafe extern "C-unwind" fn session_probe_worker_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGTERM);
    let extra = std::ffi::CStr::from_ptr((*pg_sys::MyBgworkerEntry).bgw_extra.as_ptr())
        .to_string_lossy()
        .into_owned();
    let mut parts = extra.splitn(3, ' ');
    let db: u32 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let role = parts.next().unwrap_or("").to_string();
    let sql = parts.next().unwrap_or("").to_string();
    let role_c = std::ffi::CString::new(role.clone()).unwrap_or_default();
    pg_sys::BackgroundWorkerInitializeConnectionByOid(pg_sys::Oid::from(db), pg_sys::InvalidOid, 0);
    // Run as the role, in a transaction that aborts on error (worker_persist).
    let attempt = crate::worker_persist::persist_event_transaction(|| {
        let oid = pg_sys::get_role_oid(role_c.as_ptr(), true);
        if oid == pg_sys::InvalidOid {
            return Err(pgrx::spi::Error::InvalidPosition);
        }
        pg_sys::SetSessionAuthorization(oid, false);
        Spi::run(&sql)
    });
    let outcome = match attempt {
        crate::worker_persist::PersistAttempt::Committed => "OK".to_string(),
        crate::worker_persist::PersistAttempt::Retry { sqlstate } => format!("ERROR {sqlstate}"),
    };
    pgrx::log!("sql_firewall session probe: role={role} statement={sql:?} outcome={outcome}");
}
