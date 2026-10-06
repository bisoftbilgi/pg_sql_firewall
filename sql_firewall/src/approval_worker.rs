// ============================================================================
// Background Worker - Process Pending Approvals
// ============================================================================
// Runs independently from main transactions, reads from shared memory queue
// and writes to database. Survives transaction rollbacks.
//
// ARCHITECTURE: The launcher registers one consumer per database. This
// process stays connected to the database OID in bgw_extra. Every event is
// routed by FirewallEvent.db_oid. database_name in a payload is descriptive
// and is not an authority for routing.

use crate::audit_retention;
use crate::consumer_checkpoint;
use crate::consumer_control::{self, Identity};
use crate::pending_approvals;
use crate::sql::{bool_arg, int4_arg, name_arg, oid_carrier_arg, text_arg};
use std::cell::Cell;
use crate::worker_persist::{self, PersistAttempt};
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::pg_sys;
use pgrx::prelude::*;

thread_local! {
    /// Set while this process applies one queued event: the policy epoch it
    /// locked, or -1 before the lock. Only the approval worker sets it.
    static APPLYING_POLICY_EVENT: Cell<Option<i64>> = const { Cell::new(None) };
}

/// Marks the policy writes of one event application as the worker's own
/// (policy_visibility.rs): they do not advance the administrator epoch, and
/// only decision changes are recorded in the history.
struct ApplyingPolicyEvent;

impl ApplyingPolicyEvent {
    fn enter() -> Self {
        APPLYING_POLICY_EVENT.with(|flag| flag.set(Some(-1)));
        Self
    }
}

impl Drop for ApplyingPolicyEvent {
    fn drop(&mut self) {
        APPLYING_POLICY_EVENT.with(|flag| flag.set(None));
    }
}

/// `Some(epoch)` while this process applies a queued event.
pub(crate) fn applying_policy_event() -> Option<i64> {
    APPLYING_POLICY_EVENT.with(Cell::get)
}

#[derive(Clone, Copy)]
struct Binding {
    identity: Identity,
    incarnation: u64,
}

enum PauseAction {
    Continue,
    Exit { release: bool },
    Rebound(Binding),
}

/// Entry point. `#[pg_guard]` turns an ERROR or a Rust panic that reaches
/// here into PostgreSQL's background-worker error exit (exit code 1, the
/// launcher registers a replacement). Without it the unwind would leave
/// through PostgreSQL's C frames and abort the process, which the postmaster
/// treats as a crash of the whole server.
#[pg_guard]
#[no_mangle]
pub unsafe extern "C-unwind" fn approval_worker_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);

    // The database OID comes from bgw_extra, set by the launcher.
    let target_oid = unsafe {
        let bgw = pg_sys::MyBgworkerEntry;
        if bgw.is_null() {
            pgrx::error!("sql_firewall: worker MyBgworkerEntry is null!");
        }
        
        let extra_ptr = (*bgw).bgw_extra.as_ptr();
        let extra_cstr = std::ffi::CStr::from_ptr(extra_ptr);
        let extra_str = match extra_cstr.to_str() {
            Ok(text) => text,
            Err(_) => {
                pgrx::error!("sql_firewall: worker bgw_extra is not the database OID");
            }
        };

        // bgw_extra is the unsigned decimal OID. A signed rendering such as
        // "-1294967296" does not parse as u32 and must not select a database.
        match extra_str.parse::<u32>() {
            Ok(oid_u32) => {
                let oid = pg_sys::Oid::from(oid_u32);

                // Connect to the target database first.
                // NOTE: get_database_name() / any syscache call MUST NOT be used
                // before BackgroundWorkerInitializeConnectionByOid – syscache is
                // not yet initialised and will assert-fail (SIGABRT / crash
                // recovery) if called here.
                pg_sys::BackgroundWorkerInitializeConnectionByOid(oid, pg_sys::InvalidOid, 0);
                let connected = u32::from(pg_sys::MyDatabaseId);
                if connected != oid_u32 {
                    pgrx::error!(
                        "sql_firewall: worker connected to database oid {}, bgw_extra requested {}",
                        connected,
                        oid_u32
                    );
                }
                oid_u32
            }
            Err(e) => {
                pgrx::error!("sql_firewall: worker failed to parse OID from bgw_extra '{}': {}", extra_str, e);
            }
        }
    };

    // Event application relies on READ COMMITTED: after waiting for an
    // administrator's policy epoch lock, the next statement must see that
    // administrator's committed history (persist_approval). A cluster-wide
    // default_transaction_isolation must not change that.
    unsafe {
        pg_sys::SetConfigOption(
            c"default_transaction_isolation".as_ptr(),
            c"read committed".as_ptr(),
            pg_sys::GucContext::PGC_SUSET,
            pg_sys::GucSource::PGC_S_OVERRIDE,
        );
    }

    if !crate::encoding::server_is_utf8() {
        pgrx::log!(
            "{}{}. Worker exiting without processing.",
            crate::encoding::UNSUPPORTED_PREFIX,
            crate::encoding::server_encoding_name()
        );
        return;
    }

    // Keep pgrx-managed signal handlers; overriding SIGTERM to default handler can
    // make postmaster treat worker termination as abnormal during shutdown/reload.
    // Note: attach_signal_handlers already called BackgroundWorkerUnblockSignals().

    pgrx::debug1!("sql_firewall: approval worker started for database oid {}", target_oid);

    // Extension installation is local to this connection's database.
    let is_extension_active: Result<bool, spi::Error> = BackgroundWorker::transaction(|| {
        let exists = Spi::get_one::<i64>(
            "SELECT count(*)::pg_catalog.int8 FROM pg_catalog.pg_extension \
             WHERE extname OPERATOR(pg_catalog.=) 'sql_firewall'::pg_catalog.name",
        );
        Ok(exists.unwrap_or(Some(0)).unwrap_or(0) > 0)
    });
    
    if !is_extension_active.unwrap_or(false) {
        pgrx::log!("sql_firewall: Extension NOT installed in DB OID {}. Worker exiting gracefully.", target_oid);
        return;
    }
    
    pgrx::log!("sql_firewall: consumer started for database oid {}", target_oid);

    let mut binding = match bind_control(target_oid) {
        Some(binding) => binding,
        None => return,
    };
    let mut release_on_exit = false;

    // Cursor comes from the committed checkpoint, not the ring write head.
    // A copied retry is still lost if this process exits; a replacement
    // recovers the slot only while that ring generation still retains it.
    let mut my_cursor = 0u64;
    // Positions this worker skipped because they were no longer retained.
    // Unit: shared-stream positions. Reset when this worker process exits.
    // Not a count of events that belonged to this database.
    let mut skipped_positions: u64 = 0;
    let mut last_gap_warn_us: i64 = 0;
    let mut last_retry_warn_us: i64 = 0;
    let mut last_checkpoint_warn_us: i64 = 0;
    let mut last_prune_us: i64 = 0;
    let mut last_prune_warn_us: i64 = 0;
    // Copied event whose database effects have not committed. Not reread from
    // the ring. If this process exits, a replacement can recover the slot only
    // while this ring generation still retains it.
    let mut retrying: Option<RetryingEvent> = None;
    let mut progress: Option<consumer_checkpoint::Progress> = None;
    // Activity records (activity_queue.rs) are written between events.
    let mut activity = crate::activity_queue::Consumer::new();
    let mut activity_pending = false;
    pgrx::debug1!("sql_firewall: approval worker waiting for consumer checkpoint");

    loop {
        reload_if_requested();
        if BackgroundWorker::sigterm_received() {
            if let Some(pending) = &retrying {
                pgrx::log!(
                    "sql_firewall: worker exiting with uncommitted event at position {}; process-local retry state is not replayed",
                    pending.position
                );
            }
            pgrx::log!("sql_firewall: approval worker shutting down");
            break;
        }
        match service_pause(&binding, target_oid, &mut progress) {
            PauseAction::Continue => {}
            PauseAction::Exit { release } => {
                release_on_exit = release;
                break;
            }
            PauseAction::Rebound(next) => {
                binding = next;
                progress = None;
                retrying = None;
                continue;
            }
        }
        if wait_if_probe_held() {
            continue;
        }

        if progress.is_none() {
            let Some(ring) = pending_approvals::ring_view() else {
                worker_wait(500);
                continue;
            };
            match consumer_checkpoint::sync_startup(&ring) {
                consumer_checkpoint::Startup::Resume {
                    progress: loaded,
                    gap,
                } => {
                    if let Some((from, to)) = gap {
                        note_gap(
                            target_oid,
                            from,
                            to,
                            &mut skipped_positions,
                            &mut last_gap_warn_us,
                        );
                    }
                    pgrx::log!(
                        "sql_firewall: consumer checkpoint generation {} extension {} next_position {}",
                        loaded.generation,
                        u32::from(loaded.extension_oid),
                        loaded.next_position
                    );
                    my_cursor = loaded.next_position;
                    progress = Some(loaded);
                    consumer_control::observe(
                        binding.identity,
                        binding.incarnation,
                        consumer_control::OBS_RUNNING,
                    );
                }
                consumer_checkpoint::Startup::Ahead {
                    next_position,
                    write_pos,
                } => {
                    mark_retrying(&binding);
                    pgrx::warning!(
                        "sql_firewall: consumer checkpoint next_position {next_position} is ahead of ring head {write_pos}; not resetting"
                    );
                    worker_wait(RETRY_CAP_MS);
                    continue;
                }
                consumer_checkpoint::Startup::Unavailable => {
                    mark_retrying(&binding);
                    warn_limited(
                        &mut last_checkpoint_warn_us,
                        "consumer checkpoint is missing or is not a member of this extension; not resetting progress",
                    );
                    worker_wait(RETRY_CAP_MS);
                    continue;
                }
                consumer_checkpoint::Startup::Invalid => {
                    mark_retrying(&binding);
                    warn_limited(
                        &mut last_checkpoint_warn_us,
                        "consumer checkpoint metadata is invalid; not resetting progress",
                    );
                    worker_wait(RETRY_CAP_MS);
                    continue;
                }
                consumer_checkpoint::Startup::ExtensionGone => {
                    pgrx::log!(
                        "sql_firewall: extension dropped in database oid {}; consumer exiting",
                        target_oid
                    );
                    release_on_exit = true;
                    break;
                }
            }
        }
        let Some(progress_now) = progress else {
            continue;
        };

        let mut maintenance_pending = false;
        if retrying.is_none() {
            activity_pending = crate::activity_queue::drain(&mut activity, progress_now.extension_oid);
            maintenance_pending = audit_retention::maybe_prune(
                &mut last_prune_us, &mut last_prune_warn_us, &activity,
            );
        }

        if let Some(pending) = retrying.take() {
            match watch_installation(&progress_now) {
                InstallWatch::Gone => {
                    pgrx::log!(
                        "sql_firewall: extension dropped in database oid {}; consumer exiting",
                        target_oid
                    );
                    release_on_exit = true;
                    break;
                }
                InstallWatch::Replaced => {
                    if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                    progress = None;
                    continue;
                }
                InstallWatch::Current => {}
            }
            match persist_copied_event(&progress_now, pending.position, &pending.event) {
                PersistOutcome::Committed { next } => {
                    consumer_control::observe(
                        binding.identity,
                        binding.incarnation,
                        consumer_control::OBS_RUNNING,
                    );
                    exit_if_probe_requested();
                    my_cursor = next;
                    if let Some(slot) = progress.as_mut() {
                        slot.next_position = my_cursor;
                    }
                }
                PersistOutcome::Malformed => {
                    log_malformed(target_oid, pending.position, pending.event.event_type);
                    my_cursor = pending.position + 1;
                    if let Some(slot) = progress.as_mut() {
                        slot.next_position = my_cursor;
                    }
                }
                PersistOutcome::ExtensionGone => {
                    pgrx::log!(
                        "sql_firewall: extension dropped in database oid {}; consumer exiting",
                        target_oid
                    );
                    release_on_exit = true;
                    break;
                }
                PersistOutcome::StaleInstallation => {
                    pgrx::log!(
                        "sql_firewall: discarding copied event at position {} for a previous extension installation",
                        pending.position
                    );
                    progress = None;
                    continue;
                }
                PersistOutcome::CheckpointAhead {
                    next_position,
                    write_pos,
                } => {
                    warn_limited(
                        &mut last_checkpoint_warn_us,
                        &format!(
                            "consumer checkpoint next_position {next_position} is ahead of ring head {write_pos}; not acknowledging"
                        ),
                    );
                    retrying = Some(RetryingEvent {
                        backoff_ms: RETRY_CAP_MS,
                        ..pending
                    });
                    mark_retrying(&binding);
                    worker_wait(RETRY_CAP_MS);
                }
                PersistOutcome::CheckpointInvalid => {
                    warn_limited(
                        &mut last_checkpoint_warn_us,
                        "consumer checkpoint metadata is invalid; not resetting progress",
                    );
                    retrying = Some(RetryingEvent {
                        backoff_ms: RETRY_CAP_MS,
                        ..pending
                    });
                    mark_retrying(&binding);
                    worker_wait(RETRY_CAP_MS);
                }
                PersistOutcome::Retry { sqlstate } => {
                    log_retry(
                        target_oid,
                        pending.position,
                        pending.event.event_type,
                        pending.attempt,
                        &sqlstate,
                        &mut last_retry_warn_us,
                    );
                    let wait_ms = pending.backoff_ms;
                    retrying = Some(RetryingEvent {
                        attempt: pending.attempt.saturating_add(1),
                        backoff_ms: next_backoff(pending.backoff_ms),
                        ..pending
                    });
                    mark_retrying(&binding);
                    worker_wait(wait_ms);
                }
            }
            continue;
        }

        let event = match pending_approvals::read_at(my_cursor) {
            pending_approvals::ReadOutcome::Unavailable
            | pending_approvals::ReadOutcome::NotYetPublished => {
                match watch_installation(&progress_now) {
                    InstallWatch::Gone => {
                        pgrx::log!(
                            "sql_firewall: extension dropped in database oid {}; consumer exiting",
                            target_oid
                        );
                        release_on_exit = true;
                        break;
                    }
                    InstallWatch::Replaced => {
                        if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                        progress = None;
                        retrying = None;
                        continue;
                    }
                    InstallWatch::Current => {
                        match flush_skips(
                            &progress_now,
                            my_cursor,
                            progress.as_mut(),
                            &mut last_checkpoint_warn_us,
                        ) {
                            SkipAction::Exit => {
                                release_on_exit = true;
                                break;
                            },
                            SkipAction::Resync => {
                                if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                                progress = None;
                                retrying = None;
                            }
                            SkipAction::Continue => {}
                        }
                        if !activity_pending && !maintenance_pending {
                            worker_wait(activity.idle_wait_ms());
                        }
                        continue;
                    }
                }
            }
            pending_approvals::ReadOutcome::Overwritten { retained_from } => {
                match watch_installation(&progress_now) {
                    InstallWatch::Gone => {
                        pgrx::log!(
                            "sql_firewall: extension dropped in database oid {}; consumer exiting",
                            target_oid
                        );
                        release_on_exit = true;
                        break;
                    }
                    InstallWatch::Replaced => {
                        if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                        progress = None;
                        retrying = None;
                        continue;
                    }
                    InstallWatch::Current => {}
                }
                if retained_from > my_cursor {
                    note_gap(
                        target_oid,
                        my_cursor,
                        retained_from,
                        &mut skipped_positions,
                        &mut last_gap_warn_us,
                    );
                    my_cursor = retained_from;
                    match flush_skips(
                        &progress_now,
                        my_cursor,
                        progress.as_mut(),
                        &mut last_checkpoint_warn_us,
                    ) {
                        SkipAction::Exit => {
                                release_on_exit = true;
                                break;
                            },
                        SkipAction::Resync => {
                            if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                            progress = None;
                            retrying = None;
                        }
                        SkipAction::Continue => {}
                    }
                }
                continue;
            }
            pending_approvals::ReadOutcome::Ready(event) => event,
        };

        // Every event type carries the originating database OID on the
        // published event. Payload database_name is not an authority for routing.
        if u32::from(event.db_oid) != target_oid || event.extension_oid != progress_now.extension_oid
        {
            match watch_installation(&progress_now) {
                InstallWatch::Gone => {
                    pgrx::log!(
                        "sql_firewall: extension dropped in database oid {}; consumer exiting",
                        target_oid
                    );
                    release_on_exit = true;
                    break;
                }
                InstallWatch::Replaced => {
                    if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                    progress = None;
                    retrying = None;
                    continue;
                }
                InstallWatch::Current => {
                    my_cursor += 1;
                    if my_cursor.saturating_sub(progress_now.next_position) >= 32 {
                        match flush_skips(
                            &progress_now,
                            my_cursor,
                            progress.as_mut(),
                            &mut last_checkpoint_warn_us,
                        ) {
                            SkipAction::Exit => {
                                release_on_exit = true;
                                break;
                            },
                            SkipAction::Resync => {
                                if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                                progress = None;
                                retrying = None;
                            }
                            SkipAction::Continue => {}
                        }
                    }
                    continue;
                }
            }
        }

        let position = my_cursor;
        match persist_copied_event(&progress_now, position, &event) {
            PersistOutcome::Committed { next } => {
                consumer_control::observe(
                    binding.identity,
                    binding.incarnation,
                    consumer_control::OBS_RUNNING,
                );
                exit_if_probe_requested();
                my_cursor = next;
                if let Some(slot) = progress.as_mut() {
                    slot.next_position = my_cursor;
                }
            }
            PersistOutcome::Malformed => {
                log_malformed(target_oid, position, event.event_type);
                my_cursor = position + 1;
                match flush_skips(
                    &progress_now,
                    my_cursor,
                    progress.as_mut(),
                    &mut last_checkpoint_warn_us,
                ) {
                    SkipAction::Exit => {
                                release_on_exit = true;
                                break;
                            },
                    SkipAction::Resync => {
                        if !adopt_replacement(&mut binding, target_oid) {
                        release_on_exit = true;
                        break;
                    }
                        progress = None;
                        retrying = None;
                    }
                    SkipAction::Continue => {}
                }
            }
            PersistOutcome::ExtensionGone => {
                pgrx::log!(
                    "sql_firewall: extension dropped in database oid {}; consumer exiting",
                    target_oid
                );
                release_on_exit = true;
                break;
            }
            PersistOutcome::StaleInstallation => {
                pgrx::log!(
                    "sql_firewall: discarding copied event at position {position} for a previous extension installation"
                );
                progress = None;
                retrying = None;
            }
            PersistOutcome::CheckpointAhead {
                next_position,
                write_pos,
            } => {
                warn_limited(
                    &mut last_checkpoint_warn_us,
                    &format!(
                        "consumer checkpoint next_position {next_position} is ahead of ring head {write_pos}; not acknowledging"
                    ),
                );
                retrying = Some(RetryingEvent {
                    position,
                    event,
                    attempt: 1,
                    backoff_ms: RETRY_CAP_MS,
                });
                mark_retrying(&binding);
                worker_wait(RETRY_CAP_MS);
            }
            PersistOutcome::CheckpointInvalid => {
                warn_limited(
                    &mut last_checkpoint_warn_us,
                    "consumer checkpoint metadata is invalid; not resetting progress",
                );
                retrying = Some(RetryingEvent {
                    position,
                    event,
                    attempt: 1,
                    backoff_ms: RETRY_CAP_MS,
                });
                mark_retrying(&binding);
                worker_wait(RETRY_CAP_MS);
            }
            PersistOutcome::Retry { sqlstate } => {
                log_retry(
                    target_oid,
                    position,
                    event.event_type,
                    1,
                    &sqlstate,
                    &mut last_retry_warn_us,
                );
                let wait_ms = RETRY_INITIAL_MS;
                retrying = Some(RetryingEvent {
                    position,
                    event,
                    attempt: 2,
                    backoff_ms: next_backoff(RETRY_INITIAL_MS),
                });
                mark_retrying(&binding);
                worker_wait(wait_ms);
            }
        }
    }

    consumer_control::observe(
        binding.identity,
        binding.incarnation,
        consumer_control::OBS_STOPPING,
    );
    if release_on_exit {
        consumer_control::release(binding.identity, binding.incarnation);
    } else {
        consumer_control::detach_keep_request(binding.identity, binding.incarnation);
    }
    pgrx::log!("sql_firewall: approval worker stopped");
}

/// First retry waits this long. Later waits double until the cap, then reset
/// after a commit. The wait is a latch timeout outside any transaction.
const RETRY_INITIAL_MS: i64 = 200;
const RETRY_CAP_MS: i64 = 5_000;

struct RetryingEvent {
    position: u64,
    event: pending_approvals::PublishedEvent,
    attempt: u32,
    backoff_ms: i64,
}

enum PersistOutcome {
    Committed { next: u64 },
    Retry { sqlstate: String },
    Malformed,
    ExtensionGone,
    StaleInstallation,
    CheckpointAhead { next_position: u64, write_pos: u64 },
    CheckpointInvalid,
}

enum InstallWatch {
    Current,
    Gone,
    Replaced,
}

#[derive(PartialEq, Eq)]
enum SkipAction {
    Continue,
    Resync,
    Exit,
}

fn bind_control(db_oid: u32) -> Option<Binding> {
    let mut extension_oid = None;
    let ready = worker_persist::persist_event_transaction(|| {
        extension_oid = pending_approvals::current_extension_oid();
        Ok(())
    });
    if !matches!(ready, PersistAttempt::Committed) {
        return None;
    }
    let extension_oid = extension_oid?;
    let ring = pending_approvals::ring_view()?;
    let identity = Identity {
        db_oid,
        extension_oid: u32::from(extension_oid),
        ring_generation: ring.generation,
    };
    match consumer_control::attach(identity) {
        Ok(incarnation) => {
            let binding = Binding {
                identity,
                incarnation,
            };
            arm_exit_cleanup(binding);
            Some(binding)
        }
        Err(_) => {
            pgrx::warning!(
                "sql_firewall: control registry is full; consumer for database oid {db_oid} is exiting"
            );
            None
        }
    }
}

fn service_pause(
    binding: &Binding,
    target_oid: u32,
    progress: &mut Option<consumer_checkpoint::Progress>,
) -> PauseAction {
    let snap = consumer_control::snapshot(binding.identity);
    if snap.present && snap.incarnation != 0 && snap.incarnation != binding.incarnation {
        return PauseAction::Exit { release: false };
    }
    if !snap.desired_paused {
        // A checkpoint stall publishes retrying. Do not hide it by reporting
        // running merely because pause is not requested. Acknowledge the
        // desired mode without changing that observed state.
        if snap.observed == consumer_control::OBS_RETRYING {
            consumer_control::acknowledge_mode(binding.identity, binding.incarnation);
        } else {
            consumer_control::observe(
                binding.identity,
                binding.incarnation,
                consumer_control::OBS_RUNNING,
            );
        }
        return PauseAction::Continue;
    }
    let mut checks = 0u32;
    loop {
        consumer_control::observe(
            binding.identity,
            binding.incarnation,
            consumer_control::OBS_PAUSED,
        );
        reload_if_requested();
        if BackgroundWorker::sigterm_received() {
            return PauseAction::Exit { release: false };
        }
        checks = checks.wrapping_add(1);
        if checks % 5 == 0 {
            match installation_now(binding) {
                InstallWatch::Gone => return PauseAction::Exit { release: true },
                InstallWatch::Replaced => {
                    let mut next = *binding;
                    if adopt_replacement(&mut next, target_oid) {
                        *progress = None;
                        return PauseAction::Rebound(next);
                    }
                    return PauseAction::Exit { release: true };
                }
                InstallWatch::Current => {}
            }
        }
        let snap = consumer_control::snapshot(binding.identity);
        if snap.present && !snap.desired_paused {
            consumer_control::acknowledge_mode(binding.identity, binding.incarnation);
            return PauseAction::Continue;
        }
        worker_wait(200);
    }
}

fn installation_now(binding: &Binding) -> InstallWatch {
    let mut outcome = InstallWatch::Current;
    let attempt = worker_persist::persist_event_transaction(|| {
        outcome = match pending_approvals::current_extension_oid() {
            None => InstallWatch::Gone,
            Some(ext) if u32::from(ext) == binding.identity.extension_oid => InstallWatch::Current,
            Some(_) => InstallWatch::Replaced,
        };
        Ok(())
    });
    if matches!(attempt, PersistAttempt::Committed) {
        outcome
    } else {
        InstallWatch::Current
    }
}

fn watch_installation(progress: &consumer_checkpoint::Progress) -> InstallWatch {
    // get_extension_oid reads the catalog cache and must run in a transaction.
    let mut outcome = InstallWatch::Current;
    let attempt = worker_persist::persist_event_transaction(|| {
        outcome = match pending_approvals::current_extension_oid() {
            None => InstallWatch::Gone,
            Some(ext) if ext == progress.extension_oid => InstallWatch::Current,
            Some(_) => InstallWatch::Replaced,
        };
        Ok(())
    });
    match attempt {
        worker_persist::PersistAttempt::Committed => outcome,
        worker_persist::PersistAttempt::Retry { .. } => InstallWatch::Current,
    }
}

fn log_replaced(target_oid: u32) {
    pgrx::log!(
        "sql_firewall: extension installation replaced in database oid {}; discarding local consumer progress",
        target_oid
    );
}

fn adopt_replacement(binding: &mut Binding, target_oid: u32) -> bool {
    log_replaced(target_oid);
    consumer_control::release(binding.identity, binding.incarnation);
    match bind_control(target_oid) {
        Some(next) => {
            *binding = next;
            arm_exit_cleanup(*binding);
            true
        }
        None => false,
    }
}

fn warn_limited(last_warn_us: &mut i64, message: &str) {
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    if now.saturating_sub(*last_warn_us) < 5 * 1_000_000 {
        return;
    }
    *last_warn_us = now;
    pgrx::warning!("sql_firewall: {message}");
}

fn next_backoff(current_ms: i64) -> i64 {
    (current_ms.saturating_mul(2)).min(RETRY_CAP_MS)
}

fn event_type_name(event_type: pending_approvals::EventType) -> &'static str {
    match event_type {
        pending_approvals::EventType::Approval => "approval",
        pending_approvals::EventType::BlockedQuery => "blocked_query",
        pending_approvals::EventType::FingerprintHit => "fingerprint_hit",
    }
}

fn log_malformed(db_oid: u32, position: u64, event_type: pending_approvals::EventType) {
    pgrx::warning!(
        "sql_firewall: skip malformed database oid {} position {} type {}",
        db_oid,
        position,
        event_type_name(event_type)
    );
}

fn log_retry(
    db_oid: u32,
    position: u64,
    event_type: pending_approvals::EventType,
    attempt: u32,
    sqlstate: &str,
    last_warn_us: &mut i64,
) {
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    let due = attempt <= 4 || now.saturating_sub(*last_warn_us) >= 60 * 1_000_000;
    if !due {
        return;
    }
    *last_warn_us = now;
    pgrx::warning!(
        "sql_firewall: retry database oid {} position {} type {} attempt {} SQLSTATE {}",
        db_oid,
        position,
        event_type_name(event_type),
        attempt,
        sqlstate
    );
}

fn note_gap(db_oid: u32, from: u64, to: u64, skipped: &mut u64, last_warn_us: &mut i64) {
    if to <= from {
        return;
    }
    *skipped = skipped.saturating_add(to - from);
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    if now.saturating_sub(*last_warn_us) < 60 * 1_000_000 && *skipped != to - from {
        return;
    }
    *last_warn_us = now;
    pgrx::warning!(
        "sql_firewall: database oid {} skipped shared-stream positions [{}, {}): {} positions were no longer retained. This is not a count of events for this database. worker_skipped_positions={}",
        db_oid,
        from,
        to,
        to - from,
        *skipped
    );
}

fn flush_skips(
    progress: &consumer_checkpoint::Progress,
    cursor: u64,
    slot: Option<&mut consumer_checkpoint::Progress>,
    last_warn_us: &mut i64,
) -> SkipAction {
    if cursor <= progress.next_position {
        return SkipAction::Continue;
    }
    match consumer_checkpoint::advance_skips(progress, cursor) {
        consumer_checkpoint::SkipResult::Committed => {
            if let Some(slot) = slot {
                slot.next_position = cursor;
            }
            SkipAction::Continue
        }
        consumer_checkpoint::SkipResult::ExtensionGone => {
            pgrx::log!("sql_firewall: extension dropped while checkpointing skips; consumer exiting");
            SkipAction::Exit
        }
        consumer_checkpoint::SkipResult::Replaced => SkipAction::Resync,
        consumer_checkpoint::SkipResult::Invalid => {
            warn_limited(
                last_warn_us,
                "consumer checkpoint metadata is invalid; not resetting progress",
            );
            SkipAction::Continue
        }
        consumer_checkpoint::SkipResult::Ahead {
            next_position,
            write_pos,
        } => {
            warn_limited(
                last_warn_us,
                &format!(
                    "consumer checkpoint next_position {next_position} is ahead of ring head {write_pos}; not acknowledging"
                ),
            );
            SkipAction::Continue
        }
        consumer_checkpoint::SkipResult::Retry { sqlstate } => {
            warn_limited(
                last_warn_us,
                &format!(
                    "skip checkpoint failed SQLSTATE {sqlstate}; progress was not reset"
                ),
            );
            SkipAction::Continue
        }
    }
}

fn exit_if_probe_requested() {
    #[cfg(feature = "queue_probe")]
    if pending_approvals::probe_exit_after_commit() {
        unsafe { pg_sys::proc_exit(0) };
    }
}

fn persist_copied_event(
    progress: &consumer_checkpoint::Progress,
    position: u64,
    event: &pending_approvals::PublishedEvent,
) -> PersistOutcome {
    if !event_is_well_formed(event) {
        return PersistOutcome::Malformed;
    }
    if event.extension_oid != progress.extension_oid {
        return PersistOutcome::StaleInstallation;
    }
    let Some(ring) = pending_approvals::ring_view() else {
        return PersistOutcome::Retry {
            sqlstate: "08000".to_string(),
        };
    };
    let mut kind = 0u8;
    let mut resume_at = position + 1;
    let mut ahead_write = 0u64;
    let kind_ptr: *mut u8 = &mut kind;
    let resume_ptr: *mut u64 = &mut resume_at;
    let ahead_write_ptr: *mut u64 = &mut ahead_write;
    let attempt = worker_persist::persist_event_transaction(|| {
        let claim = consumer_checkpoint::claim(&ring, event.extension_oid, position)?;
        match claim {
            consumer_checkpoint::Claim::Apply => {
                unsafe { *kind_ptr = 1 };
                let _applying = ApplyingPolicyEvent::enter();
                apply_event_sql(event)?;
                #[cfg(feature = "queue_probe")]
                if pending_approvals::probe_fail_before_checkpoint() {
                    // A real SQL error after the event statement and before the
                    // checkpoint update. pgrx::error! here aborts the worker
                    // instead of returning through the transaction catch.
                    let _: Option<i32> = Spi::get_one("SELECT 1/0")?;
                }
                consumer_checkpoint::advance(progress, position + 1)?;
            }
            consumer_checkpoint::Claim::AlreadyDone { resume } => unsafe {
                *kind_ptr = 2;
                *resume_ptr = resume;
            },
            consumer_checkpoint::Claim::ExtensionGone => unsafe { *kind_ptr = 3 },
            consumer_checkpoint::Claim::StaleInstallation { .. } => unsafe { *kind_ptr = 4 },
            consumer_checkpoint::Claim::Unavailable => unsafe { *kind_ptr = 5 },
            consumer_checkpoint::Claim::Ahead {
                next_position,
                write_pos,
            } => unsafe {
                *kind_ptr = 6;
                *resume_ptr = next_position;
                *ahead_write_ptr = write_pos;
            },
            consumer_checkpoint::Claim::Invalid => unsafe { *kind_ptr = 7 },
        }
        Ok(())
    });
    match attempt {
        PersistAttempt::Retry { sqlstate } => PersistOutcome::Retry { sqlstate },
        PersistAttempt::Committed => match kind {
            1 | 2 => PersistOutcome::Committed { next: resume_at },
            3 => PersistOutcome::ExtensionGone,
            4 => PersistOutcome::StaleInstallation,
            6 => PersistOutcome::CheckpointAhead {
                next_position: resume_at,
                write_pos: ahead_write,
            },
            7 => PersistOutcome::CheckpointInvalid,
            _ => PersistOutcome::Retry {
                sqlstate: "55000".to_string(),
            },
        },
    }
}

fn event_is_well_formed(event: &pending_approvals::PublishedEvent) -> bool {
    match event.event_type {
        pending_approvals::EventType::Approval => {
            let approval = unsafe { &event.data.approval };
            required_text(pending_approvals::decode_field(&approval.role_name)).is_some()
                && required_text(pending_approvals::decode_field(&approval.command_type)).is_some()
        }
        pending_approvals::EventType::BlockedQuery => {
            let blocked = unsafe { &event.data.blocked_query };
            required_text(pending_approvals::decode_field(&blocked.role_name)).is_some()
                && required_text(pending_approvals::decode_field(&blocked.database_name)).is_some()
                && required_text(pending_approvals::decode_field(&blocked.query)).is_some()
                && required_text(pending_approvals::decode_field(&blocked.command_type)).is_some()
        }
        pending_approvals::EventType::FingerprintHit => {
            let fp = unsafe { &event.data.fingerprint_hit };
            required_text(pending_approvals::decode_field(&fp.fingerprint_hex)).is_some()
                && required_text(pending_approvals::decode_field(&fp.role_name)).is_some()
                && required_text(pending_approvals::decode_field(&fp.command_type)).is_some()
        }
    }
}

fn apply_event_sql(event: &pending_approvals::PublishedEvent) -> Result<(), pgrx::spi::Error> {
    match event.event_type {
        pending_approvals::EventType::Approval => persist_approval(event),
        pending_approvals::EventType::BlockedQuery => persist_blocked(event),
        pending_approvals::EventType::FingerprintHit => persist_fingerprint(event),
    }
}

fn persist_approval(
    event: &pending_approvals::PublishedEvent,
) -> Result<(), pgrx::spi::Error> {
    let approval = unsafe { &event.data.approval };
    let role = required_text(pending_approvals::decode_field(&approval.role_name)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let command = required_text(pending_approvals::decode_field(&approval.command_type)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let key = PolicyKey {
        table: crate::policy_visibility::PolicyTable::Approvals,
        role: &role,
        command: &command,
        fingerprint: None,
    };
    if !event_still_applies(&key, event.extension_oid, approval.role_oid, approval.policy_epoch)? {
        return Ok(());
    }
    // A learn observation only creates a decision where there is none. An
    // existing row (approved, pending, or an administrator's denial) is left
    // as it is.
    Spi::run_with_args(
        "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) \
         VALUES ($1, $2, $3) ON CONFLICT (role_name, command_type) DO NOTHING",
        &[name_arg(&role), text_arg(&command), bool_arg(approval.is_approved)],
    )?;
    Ok(())
}

struct PolicyKey<'a> {
    table: crate::policy_visibility::PolicyTable,
    role: &'a str,
    command: &'a str,
    fingerprint: Option<&'a str>,
}

/// Decides whether a learn event may still change policy. Takes the policy
/// epoch row FOR SHARE first, as every administrator policy write takes it
/// FOR UPDATE before touching a policy row: an administrator transaction in
/// progress is waited for, and the history read below (a new READ COMMITTED
/// snapshot) includes it. Discarded, and logged, when
///  - the role name no longer belongs to the role the event observed
///    (renamed, or dropped and recreated with the same name), or
///  - an administrator changed this key, or truncated the table, after the
///    snapshot the event's decision was made in.
/// Changes to other keys do not discard it.
fn event_still_applies(
    key: &PolicyKey<'_>,
    extension_oid: pg_sys::Oid,
    role_oid: u32,
    event_epoch: i64,
) -> Result<bool, pgrx::spi::Error> {
    let (kind, policy_table) = match key.table {
        crate::policy_visibility::PolicyTable::Approvals => ("approvals", "command_approvals"),
        crate::policy_visibility::PolicyTable::Fingerprints => ("fingerprints", "query_fingerprints"),
    };
    let current = Spi::get_one_with_args::<i64>(
        "SELECT epoch FROM public.sql_firewall_policy_epoch WHERE kind = $1 FOR SHARE",
        &[text_arg(kind)],
    )?
    .ok_or(pgrx::spi::Error::InvalidPosition)?;
    APPLYING_POLICY_EVENT.with(|flag| flag.set(Some(current)));

    let named = std::ffi::CString::new(key.role)
        .map(|name| u32::from(unsafe { pg_sys::get_role_oid(name.as_ptr(), true) }))
        .unwrap_or(0);
    if role_oid == 0 || named != role_oid {
        pgrx::log!(
            "sql_firewall: discarded learn event for role \"{}\" command {}: the name now belongs to role oid {} (observed oid {})",
            key.role,
            key.command,
            named,
            role_oid
        );
        return Ok(false);
    }
    if event_epoch >= current {
        return Ok(true);
    }
    let system_identifier = unsafe { pg_sys::GetSystemIdentifier() }.to_string();
    let changed = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS (SELECT 1 FROM public.sql_firewall_policy_history h \
           WHERE h.extension_oid = $1::oid AND h.database_oid = $2::oid \
             AND h.policy_table = $3 AND h.source = 'administrator' AND h.policy_epoch > $4 \
             AND h.system_identifier = $5::numeric \
             AND (h.operation = 'TRUNCATE' \
                  OR (h.old_role_name = $6 AND h.old_command_type = $7 AND h.old_fingerprint IS NOT DISTINCT FROM $8) \
                  OR (h.new_role_name = $6 AND h.new_command_type = $7 AND h.new_fingerprint IS NOT DISTINCT FROM $8)))",
        &[
            oid_carrier_arg(u32::from(extension_oid)),
            oid_carrier_arg(u32::from(unsafe { pg_sys::MyDatabaseId })),
            text_arg(policy_table),
            unsafe { pgrx::datum::DatumWithOid::new(event_epoch, pg_sys::INT8OID) },
            text_arg(&system_identifier),
            name_arg(key.role),
            text_arg(key.command),
            match key.fingerprint {
                Some(fingerprint) => text_arg(fingerprint),
                None => pgrx::datum::DatumWithOid::null_oid(pg_sys::TEXTOID),
            },
        ],
    )?
    .unwrap_or(true);
    if changed {
        pgrx::log!(
            "sql_firewall: discarded learn event for role \"{}\" command {}{}: an administrator changed this decision after the observation (event epoch {}, current {})",
            key.role,
            key.command,
            key.fingerprint.map(|fp| format!(" fingerprint {fp}")).unwrap_or_default(),
            event_epoch,
            current
        );
    }
    Ok(!changed)
}

fn persist_blocked(
    event: &pending_approvals::PublishedEvent,
) -> Result<(), pgrx::spi::Error> {
    let blocked = unsafe { &event.data.blocked_query };
    let role = required_text(pending_approvals::decode_field(&blocked.role_name)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let database = required_text(pending_approvals::decode_field(&blocked.database_name)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let query = required_text(pending_approvals::decode_field(&blocked.query)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let command = required_text(pending_approvals::decode_field(&blocked.command_type)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let app_name = optional_text(pending_approvals::decode_field(&blocked.application_name));
    let client_addr = optional_text(pending_approvals::decode_field(&blocked.client_addr));
    let reason = optional_text(pending_approvals::decode_field(&blocked.reason));
    let channel = optional_text(pending_approvals::decode_field(&blocked.notify_channel));
    let truncated = blocked.query_truncated;
    // blocked_at is when the statement was rejected; recorded_at (default)
    // is this transaction's time. Waiting, retries, and pauses change only
    // the latter.
    let block_id = Spi::get_one_with_args::<i32>(
            "INSERT INTO public.sql_firewall_blocked_queries \
             (role_name, database_name, query_text, query_truncated, application_name, client_addr, command_type, reason, blocked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING block_id",
            &[
                name_arg(&role),
                name_arg(&database),
                text_arg(&query),
                bool_arg(truncated),
                text_arg(&app_name),
                text_arg(&client_addr),
                text_arg(&command),
                text_arg(&reason),
                unsafe { pgrx::datum::DatumWithOid::new(pg_sys::Datum::from(blocked.timestamp), pg_sys::TIMESTAMPTZOID) },
            ],
    )?
    .ok_or(pgrx::spi::Error::InvalidPosition)?;
    if !channel.is_empty() {
        crate::alerts::notify_persisted_block(&channel, block_id, &command)?;
    }
    Ok(())
}

fn persist_fingerprint(
    event: &pending_approvals::PublishedEvent,
) -> Result<(), pgrx::spi::Error> {
    let fp = unsafe { &event.data.fingerprint_hit };
    let fingerprint = required_text(pending_approvals::decode_field(&fp.fingerprint_hex)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let role = required_text(pending_approvals::decode_field(&fp.role_name)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let command = required_text(pending_approvals::decode_field(&fp.command_type)).ok_or(pgrx::spi::Error::InvalidPosition)?;
    let normalized = optional_text(pending_approvals::decode_field(&fp.normalized_query));
    let sample = optional_text(pending_approvals::decode_field(&fp.sample_query));
    let threshold = i32::from(fp.learn_threshold);
    let hits = i32::try_from(fp.hits.max(1)).unwrap_or(i32::MAX);
    let key = PolicyKey {
        table: crate::policy_visibility::PolicyTable::Fingerprints,
        role: &role,
        command: &command,
        fingerprint: Some(&fingerprint),
    };
    if !event_still_applies(&key, event.extension_oid, fp.role_oid, fp.policy_epoch)? {
        return Ok(());
    }
    Spi::run_with_args(
            "INSERT INTO public.sql_firewall_query_fingerprints \
             (fingerprint, normalized_query, role_name, command_type, sample_query, first_seen_at, last_seen_at, hit_count, is_approved) \
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $7, ($6 > 0 AND $7 >= $6)) \
             ON CONFLICT (fingerprint, role_name, command_type) \
             DO UPDATE SET \
               last_seen_at = CURRENT_TIMESTAMP, \
               hit_count = LEAST(sql_firewall_query_fingerprints.hit_count::bigint + $7, 2147483647)::integer, \
               is_approved = sql_firewall_query_fingerprints.is_approved \
                 OR ($6 > 0 AND NOT sql_firewall_query_fingerprints.auto_approval_disabled \
                   AND sql_firewall_query_fingerprints.hit_count::bigint + $7 >= $6)",
            &[
                text_arg(&fingerprint),
                text_arg(&normalized),
                name_arg(&role),
                text_arg(&command),
                text_arg(&sample),
                int4_arg(threshold),
                int4_arg(hits),
            ],
    )?;
    Ok(())
}

fn required_text(field: pending_approvals::DecodedField) -> Option<String> {
    match field {
        pending_approvals::DecodedField::Text(text) => Some(text),
        pending_approvals::DecodedField::Empty | pending_approvals::DecodedField::Invalid => None,
    }
}

fn optional_text(field: pending_approvals::DecodedField) -> String {
    match field {
        pending_approvals::DecodedField::Text(text) => text,
        pending_approvals::DecodedField::Empty | pending_approvals::DecodedField::Invalid => String::new(),
    }
}

#[cfg(feature = "queue_probe")]
fn wait_if_probe_held() -> bool {
    if pending_approvals::probe_consumers_held() {
        // This branch does not read the ring. The acknowledgement is written
        // only after the hold flag is visible, and only for the armed pid.
        pending_approvals::acknowledge_probe_hold();
        worker_wait(200);
        true
    } else {
        false
    }
}

#[cfg(not(feature = "queue_probe"))]
fn wait_if_probe_held() -> bool {
    false
}

/// A configuration reload (`pg_reload_conf()`, SIGHUP) takes effect before
/// the next unit of work, as it does between a backend's statements. The
/// consumer reads retention and alert settings on every use.
fn reload_if_requested() {
    if BackgroundWorker::sighup_received() {
        unsafe { pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP) };
    }
}

/// Exits the process if the postmaster has died (`WL_EXIT_ON_PM_DEATH`):
/// an orphaned consumer would keep the shared memory attached and prevent
/// the server from starting again.
fn worker_wait(timeout_ms: i64) {
    unsafe {
        pg_sys::WaitLatch(
            pg_sys::MyLatch,
            (pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_EXIT_ON_PM_DEATH) as i32,
            timeout_ms,
            pg_sys::PG_WAIT_EXTENSION,
        );
        pg_sys::ResetLatch(pg_sys::MyLatch);
        pg_sys::check_for_interrupts!();
    }
}

fn mark_retrying(binding: &Binding) {
    consumer_control::observe(
        binding.identity,
        binding.incarnation,
        consumer_control::OBS_RETRYING,
    );
}

struct ExitCleanup {
    armed: bool,
    registered: bool,
    identity: Identity,
    incarnation: u64,
}

static mut EXIT_CLEANUP: ExitCleanup = ExitCleanup {
    armed: false,
    registered: false,
    identity: Identity {
        db_oid: 0,
        extension_oid: 0,
        ring_generation: 0,
    },
    incarnation: 0,
};

fn arm_exit_cleanup(binding: Binding) {
    unsafe {
        EXIT_CLEANUP.identity = binding.identity;
        EXIT_CLEANUP.incarnation = binding.incarnation;
        EXIT_CLEANUP.armed = true;
        if !EXIT_CLEANUP.registered {
            pg_sys::before_shmem_exit(Some(control_before_shmem_exit), pg_sys::Datum::from(0));
            EXIT_CLEANUP.registered = true;
        }
    }
}

/// Runs on FATAL and on normal process exit, including `proc_exit`, before
/// shared memory is detached. It only clears this process's incarnation.
unsafe extern "C-unwind" fn control_before_shmem_exit(_code: i32, _arg: pg_sys::Datum) {
    if !EXIT_CLEANUP.armed {
        return;
    }
    let identity = EXIT_CLEANUP.identity;
    let incarnation = EXIT_CLEANUP.incarnation;
    EXIT_CLEANUP.armed = false;
    consumer_control::detach_keep_request(identity, incarnation);
}
