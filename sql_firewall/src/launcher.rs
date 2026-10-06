use pgrx::bgworkers::*;
use pgrx::pg_sys;
use pgrx::prelude::*;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::sql::{int4_arg, oid_carrier_arg};

/// One launcher scan registers at most this many consumers, then waits for
/// the next interval. A database whose worker exits is only one slot in a
/// later rotation, not the only database considered.
const SPAWN_BATCH: usize = 4;
/// Catalog rows examined per scan, including databases that already have a
/// consumer. Bounds the work of one pass.
const EXAMINE_LIMIT: i32 = 32;
const SCAN_INTERVAL_SECS: u64 = 5;
/// A database whose consumer ended without a control record (no committed
/// installation of this extension there) gets its next consumer only after
/// this wait, doubled on each such exit up to IDLE_MAX_SECS. An installation
/// committed in it (consumer_control announcements) ends the wait at the next
/// scan, so CREATE EXTENSION is served within one scan interval.
const IDLE_FIRST_SECS: u64 = 30;
const IDLE_MAX_SECS: u64 = 600;
/// Waiting databases kept; beyond it, entries whose wait has ended are dropped.
const IDLE_KEEP: usize = 4096;

struct TrackedWorker {
    handle: *mut pg_sys::BackgroundWorkerHandle,
}

struct Idle {
    retry_at: Instant,
    wait_secs: u64,
}

/// Firewall launcher. One process, connected to `sql_firewall.launcher_database`
/// (default `postgres`), registers a consumer per eligible database. Scheduling identity is the database OID. Extension
/// installation is checked by that consumer after it connects, because
/// `pg_extension` in this session does not describe other databases.
#[pg_guard]
#[no_mangle]
pub extern "C-unwind" fn firewall_launcher_main(_arg: pg_sys::Datum) {
    unsafe {
        BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
        let database = crate::guc::launcher_database();
        BackgroundWorker::connect_worker_to_spi(Some(&database), None);
        pgrx::log!("sql_firewall: launcher started in database {database}");

        let mut tracked: HashMap<u32, TrackedWorker> = HashMap::new();
        let mut idle: HashMap<u32, Idle> = HashMap::new();
        // Announced while an earlier consumer (which may have found no
        // installation yet) was still running: not put in a wait when it ends.
        let mut installed_since_spawn: HashSet<u32> = HashSet::new();
        let mut announce_seen = crate::consumer_control::announcement_count();
        // Cursor 0 is before every real database OID. Identity is the unsigned
        // OID, never a signed int4.
        let mut cursor: u32 = 0;
        let mut last_scan = Instant::now() - std::time::Duration::from_secs(SCAN_INTERVAL_SECS + 1);

        loop {
            let rc = pg_sys::WaitLatch(
                pg_sys::MyLatch,
                (pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_POSTMASTER_DEATH) as i32,
                1000,
                pg_sys::PG_WAIT_EXTENSION,
            );
            pg_sys::ResetLatch(pg_sys::MyLatch);
            pg_sys::check_for_interrupts!();

            if BackgroundWorker::sigterm_received() {
                pgrx::log!("sql_firewall: launcher received SIGTERM, shutting down");
                break;
            }
            if (rc & pg_sys::WL_POSTMASTER_DEATH as i32) != 0 {
                pgrx::log!("sql_firewall: postmaster died, launcher exiting");
                break;
            }
            if BackgroundWorker::sighup_received() {
                pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP);
            }
            if last_scan.elapsed().as_secs() < SCAN_INTERVAL_SECS {
                continue;
            }
            last_scan = Instant::now();

            reap_finished(&mut tracked, &mut idle, &mut installed_since_spawn);
            reconcile_removed_databases();
            let mut announced = Vec::new();
            match crate::consumer_control::announcements_since(&mut announce_seen) {
                crate::consumer_control::Announcements::Databases(oids) => announced = oids,
                crate::consumer_control::Announcements::Overflow => idle.clear(),
            }
            for oid in &announced {
                idle.remove(oid);
                if tracked.contains_key(oid) {
                    installed_since_spawn.insert(*oid);
                }
            }
            let candidates = match list_candidates(cursor) {
                Ok(rows) => rows,
                Err(err) => {
                    pgrx::warning!("sql_firewall: launcher scan failed: {err:?}");
                    continue;
                }
            };
            if BackgroundWorker::sigterm_received() {
                break;
            }

            let mut spawned = 0usize;
            // A newly installed database first, wherever the cursor is. The
            // consumer itself checks the database's encoding and installation.
            for &oid in &announced {
                if spawned >= SPAWN_BATCH || tracked.contains_key(&oid) {
                    continue;
                }
                if let Some(handle) = register_consumer(oid) {
                    tracked.insert(oid, TrackedWorker { handle });
                    spawned += 1;
                    pgrx::log!("sql_firewall: registered consumer for newly installed database oid {oid}");
                }
            }
            let mut next_cursor = cursor;
            let now = Instant::now();
            for oid in candidates {
                if tracked.contains_key(&oid) || idle.get(&oid).is_some_and(|wait| now < wait.retry_at) {
                    next_cursor = oid;
                    continue;
                }
                if spawned >= SPAWN_BATCH {
                    break;
                }
                match register_consumer(oid) {
                    Some(handle) => {
                        tracked.insert(oid, TrackedWorker { handle });
                        spawned += 1;
                        next_cursor = oid;
                        pgrx::debug1!("sql_firewall: registered consumer for database oid {oid}");
                    }
                    None => {
                        // One attempt per scan, then move on. The same OID is
                        // retried when the cursor wraps, so a failed
                        // registration does not occupy every later scan.
                        next_cursor = oid;
                        // RegisterDynamicBackgroundWorker fails when every
                        // background worker slot is taken (README 3).
                        pgrx::warning!(
                            "sql_firewall: consumer registration failed for database oid {oid}: no free background worker slot (max_worker_processes = {})",
                            pg_sys::max_worker_processes
                        );
                        break;
                    }
                }
            }
            cursor = next_cursor;
            if idle.len() > IDLE_KEEP {
                idle.retain(|_, wait| now < wait.retry_at);
            }
            pgrx::debug1!(
                "sql_firewall: launcher scan cursor={cursor} spawned={spawned} tracked={} waiting={}",
                tracked.len(),
                idle.len()
            );
        }

        pgrx::log!("sql_firewall: launcher stopped");
    }
}

/// Forgets stopped consumers. One that ended while its database has no
/// control record found no installation there (or failed before attaching):
/// that database waits before its next consumer (see IDLE_FIRST_SECS).
fn reap_finished(
    tracked: &mut HashMap<u32, TrackedWorker>,
    idle: &mut HashMap<u32, Idle>,
    installed_since_spawn: &mut HashSet<u32>,
) {
    let mut finished = Vec::new();
    for (oid, slot) in tracked.iter() {
        let mut pid: pg_sys::pid_t = 0;
        let status = unsafe { pg_sys::GetBackgroundWorkerPid(slot.handle, &mut pid) };
        if status == pg_sys::BgwHandleStatus::BGWH_STOPPED
            || status == pg_sys::BgwHandleStatus::BGWH_POSTMASTER_DIED
        {
            finished.push(*oid);
        }
    }
    for oid in finished {
        // RegisterDynamicBackgroundWorker palloc's the handle in this
        // process. GetBackgroundWorkerPid has already reported that this
        // generation stopped, so the handle is no longer used. Freeing it
        // does not release or reuse the postmaster's worker slot.
        if let Some(slot) = tracked.remove(&oid) {
            unsafe { pg_sys::pfree(slot.handle.cast()) };
        }
        let announced = installed_since_spawn.remove(&oid);
        if announced || crate::consumer_control::database_has_record(oid) {
            idle.remove(&oid);
            pgrx::log!("sql_firewall: consumer for database oid {oid} has exited");
        } else {
            let wait_secs = idle
                .get(&oid)
                .map_or(IDLE_FIRST_SECS, |wait| (wait.wait_secs * 2).min(IDLE_MAX_SECS));
            idle.insert(
                oid,
                Idle {
                    retry_at: Instant::now() + std::time::Duration::from_secs(wait_secs),
                    wait_secs,
                },
            );
            pgrx::debug1!(
                "sql_firewall: database oid {oid} has no installation; next consumer in {wait_secs} s unless one is installed"
            );
        }
    }
}

/// Release control records whose database `pg_database` no longer lists.
/// `pg_database` is cluster-wide, so this never uses one database's
/// `pg_extension` to judge another. Claims are copied before the transaction
/// starts, so its snapshot is newer than every claim; a record exists only
/// after a session connected to its database, so an absent database was
/// dropped and committed. Records still tagged by the dropping transaction
/// are left for it, and a record reallocated since the copy is left alone.
fn reconcile_removed_databases() {
    let claims = crate::consumer_control::claims();
    if claims.is_empty() {
        return;
    }
    let present = BackgroundWorker::transaction(|| {
        Spi::run("SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false)")?;
        Spi::connect(|client| {
            let table = client.select(
                "SELECT d.oid::pg_catalog.int8 FROM pg_catalog.pg_database AS d",
                None,
                &[],
            )?;
            let mut oids = Vec::new();
            for row in table {
                if let Some(oid) = row.get::<i64>(1)? {
                    oids.extend(u32::try_from(oid).ok());
                }
            }
            Ok::<Vec<u32>, pgrx::spi::Error>(oids)
        })
    });
    let present = match present {
        Ok(oids) => oids,
        Err(err) => {
            pgrx::warning!("sql_firewall: launcher could not read pg_database: {err:?}");
            return;
        }
    };
    for claim in claims.iter().filter(|claim| !present.contains(&claim.db_oid)) {
        if crate::consumer_control::reclaim_absent(
            claim.db_oid,
            claim.ring_generation,
            claim.extension_oid,
            claim.version,
        ) {
            pgrx::log!(
                "sql_firewall: released control record for removed database oid {}",
                claim.db_oid
            );
        }
    }
}

/// Eligible OIDs after `cursor`, wrapping once. Templates, databases that
/// disallow connections, and non-UTF8 encodings are not returned. The
/// encoding test uses `pg_database.encoding` in this database; it does not
/// read another database's `pg_extension`.
fn list_candidates(cursor: u32) -> Result<Vec<u32>, pgrx::spi::Error> {
    // $2 is int8 only so OID 0 stays non-NULL and values above 2147483647
    // survive. The comparison casts it to oid and uses oid's unsigned order.
    const LOOKUP: &str = "SELECT d.oid \
         FROM pg_catalog.pg_database AS d \
         WHERE d.datallowconn OPERATOR(pg_catalog.=) true \
           AND d.datistemplate OPERATOR(pg_catalog.=) false \
           AND d.encoding OPERATOR(pg_catalog.=) $1::pg_catalog.int4 \
           AND d.oid OPERATOR(pg_catalog.>) ($2::pg_catalog.int8)::pg_catalog.oid \
         ORDER BY d.oid \
         LIMIT 1";
    let utf8 = pg_sys::pg_enc::PG_UTF8 as i32;
    BackgroundWorker::transaction(|| {
        Spi::run("SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false)")?;
        let mut found = Vec::new();
        let mut scan_at = cursor;
        for _ in 0..EXAMINE_LIMIT {
            match next_oid(LOOKUP, utf8, scan_at)? {
                Some(oid) => {
                    found.push(oid);
                    scan_at = oid;
                }
                None => break,
            }
        }
        if found.len() < EXAMINE_LIMIT as usize {
            let mut wrap_at = 0u32;
            let remain = EXAMINE_LIMIT as usize - found.len();
            for _ in 0..remain {
                match next_oid(LOOKUP, utf8, wrap_at)? {
                    Some(oid) if oid <= cursor && !found.contains(&oid) => {
                        found.push(oid);
                        wrap_at = oid;
                    }
                    _ => break,
                }
            }
        }
        Ok(found)
    })
}

/// An empty catalog lookup is `InvalidPosition` from `Spi::get_one_with_args`,
/// not a failed scan.
fn next_oid(query: &str, utf8: i32, after: u32) -> Result<Option<u32>, pgrx::spi::Error> {
    match Spi::get_one_with_args::<pg_sys::Oid>(
        query,
        &[int4_arg(utf8), oid_carrier_arg(after)],
    ) {
        Ok(Some(oid)) => Ok(Some(u32::from(oid))),
        Ok(None) => Ok(None),
        Err(pgrx::spi::Error::InvalidPosition) => Ok(None),
        Err(err) => Err(err),
    }
}

fn register_consumer(oid: u32) -> Option<*mut pg_sys::BackgroundWorkerHandle> {
    let worker_name = format!("sql_firewall_worker_{oid}");
    let worker_name_cstr = std::ffi::CString::new(worker_name.as_str()).ok()?;
    const WORKER_LIBRARY: &str = "sql_firewall";
    let library_cstr = std::ffi::CString::new(WORKER_LIBRARY).ok()?;
    let function_cstr = std::ffi::CString::new("approval_worker_main").ok()?;
    let oid_cstr = std::ffi::CString::new(oid.to_string()).ok()?;

    unsafe {
        let mut worker: pg_sys::BackgroundWorker = std::mem::zeroed();
        copy_c_string(&mut worker.bgw_name, worker_name_cstr.as_ptr());
        // backend_type must stay sql_firewall_worker_% so existing liveness
        // checks can see the consumer. The suffix is the OID, not the name.
        copy_c_string(&mut worker.bgw_type, worker_name_cstr.as_ptr());
        worker.bgw_flags = pg_sys::BGWORKER_SHMEM_ACCESS as i32
            | pg_sys::BGWORKER_BACKEND_DATABASE_CONNECTION as i32;
        worker.bgw_start_time = pg_sys::BgWorkerStartTime::BgWorkerStart_RecoveryFinished;
        worker.bgw_restart_time = pg_sys::BGW_NEVER_RESTART;
        copy_c_string(&mut worker.bgw_library_name, library_cstr.as_ptr());
        copy_c_string(&mut worker.bgw_function_name, function_cstr.as_ptr());
        copy_c_string(&mut worker.bgw_extra, oid_cstr.as_ptr());
        worker.bgw_main_arg = pg_sys::Datum::from(0_usize);
        worker.bgw_notify_pid = 0;

        let mut handle: *mut pg_sys::BackgroundWorkerHandle = std::ptr::null_mut();
        let ok = pg_sys::RegisterDynamicBackgroundWorker(&mut worker, &mut handle);
        if ok && !handle.is_null() {
            Some(handle)
        } else {
            None
        }
    }
}

unsafe fn copy_c_string(dest: &mut [std::ffi::c_char], src: *const std::ffi::c_char) {
    let bytes = std::ffi::CStr::from_ptr(src).to_bytes();
    let n = bytes.len().min(dest.len().saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dest.as_mut_ptr() as *mut u8, n);
    dest[n] = 0;
}
