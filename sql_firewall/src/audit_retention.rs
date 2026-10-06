//! Small, independent maintenance transactions in each database's consumer.
//! These never run in a client statement or while an event is awaiting retry.

use crate::guc;
use crate::sql::int4_arg;

fn int8_arg(value: i64) -> pgrx::datum::DatumWithOid<'static> {
    unsafe { pgrx::datum::DatumWithOid::new(value, pgrx::pg_sys::INT8OID) }
}
use crate::worker_persist::{self, PersistAttempt};
use pgrx::{pg_sys, Spi};

const BATCH: i64 = 1_000;
const MICROS_PER_SECOND: i64 = 1_000_000;
// One batch per consumer pass: the next pass drains activity and handles
// event-ring work before another cleanup transaction. There is no fixed
// rows/second throttle that would fall behind a sustained supported load.
/// The row limit's cutoff (log_time as text, log_id) while a run continues
/// across passes of the consumer's loop; read again for every new run.
type Cutoff = Option<(Option<String>, Option<i64>)>;

thread_local! {
    static CONTINUED: std::cell::RefCell<(Cutoff, i64)> = const { std::cell::RefCell::new((None, 0)) };
}

/// Returns whether cleanup remains due, so the worker need not sleep between
/// catch-up batches. Recheck live queue pressure after each committed drain.
pub fn maybe_prune(
    last_attempt_us: &mut i64,
    last_warning_us: &mut i64,
    activity: &crate::activity_queue::Consumer,
) -> bool {
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    let interval_us = i64::from(guc::activity_log_prune_interval_seconds().max(5))
        .saturating_mul(MICROS_PER_SECOND);
    if *last_attempt_us == 0 {
        // Give newly installed databases time to finish setup and initial QA.
        *last_attempt_us = now;
        return false;
    }
    if now.saturating_sub(*last_attempt_us) < interval_us {
        return false;
    }
    if !activity.maintenance_can_run() {
        return false;
    }
    let (mut cutoff, previous_max) = CONTINUED.with(|c| c.borrow().clone());
    *last_attempt_us = now;
    let keep = |cutoff: Cutoff, max: i64| CONTINUED.with(|c| *c.borrow_mut() = (cutoff, max));

    let activity_days = guc::activity_log_retention_days();
    let blocked_days = guc::retention_days();
    let activity_max = guc::activity_log_max_rows();
    // The row limit's cutoff, read once per run: the first row past the
    // newest activity_max rows. Rows added later are newer, so every row up
    // to it stays beyond the limit while the run deletes them.
    if previous_max != activity_max {
        cutoff = None;
    }
    {
        let mut full_batch = false;
        let mut deleted_activity = 0i64;
        let mut deleted_blocked = 0i64;
        let cutoff_ref = &mut cutoff;
        let result = worker_persist::persist_event_transaction(|| {
            // Maintenance must not sit behind a user-held table lock while
            // incoming events fill the ring. This local setting rolls back
            // with the cleanup transaction and affects no application session.
            Spi::run("SET LOCAL lock_timeout = '10ms'")?;
            if activity_days > 0 {
                let deleted = Spi::get_one_with_args::<i64>(
                    "WITH doomed AS ( \
                       SELECT ctid FROM public.sql_firewall_activity_log \
                       WHERE log_time OPERATOR(pg_catalog.<) \
                         (pg_catalog.now() OPERATOR(pg_catalog.-) pg_catalog.make_interval(days => $1::pg_catalog.int4)) \
                       ORDER BY log_time, log_id LIMIT 1000 FOR UPDATE SKIP LOCKED \
                     ), deleted AS ( \
                       DELETE FROM public.sql_firewall_activity_log AS log \
                       USING doomed WHERE log.ctid OPERATOR(pg_catalog.=) doomed.ctid \
                       RETURNING 1 \
                     ) SELECT pg_catalog.count(*)::pg_catalog.int8 FROM deleted",
                    &[int4_arg(activity_days)],
                )?.unwrap_or(0);
                full_batch |= deleted >= BATCH;
                deleted_activity += deleted;
            }
            if blocked_days > 0 {
                let deleted = Spi::get_one_with_args::<i64>(
                    "WITH doomed AS ( \
                       SELECT ctid FROM public.sql_firewall_blocked_queries \
                       WHERE blocked_at OPERATOR(pg_catalog.<) \
                         (pg_catalog.now() OPERATOR(pg_catalog.-) pg_catalog.make_interval(days => $1::pg_catalog.int4)) \
                       ORDER BY blocked_at, block_id LIMIT 1000 FOR UPDATE SKIP LOCKED \
                     ), deleted AS ( \
                       DELETE FROM public.sql_firewall_blocked_queries AS log \
                       USING doomed WHERE log.ctid OPERATOR(pg_catalog.=) doomed.ctid \
                       RETURNING 1 \
                     ) SELECT pg_catalog.count(*)::pg_catalog.int8 FROM deleted",
                    &[int4_arg(blocked_days)],
                )?.unwrap_or(0);
                full_batch |= deleted >= BATCH;
                deleted_blocked += deleted;
            }
            if activity_max > 0 {
                // A backward scan of the (log_time, log_id) index: the work
                // is bounded by the limit, not by the table's size.
                if cutoff_ref.is_none() {
                    *cutoff_ref = Some(Spi::get_two_with_args::<String, i64>(
                        "SELECT c.log_time::pg_catalog.text, c.log_id FROM (SELECT 1) AS one \
                         LEFT JOIN LATERAL ( \
                           SELECT log_time, log_id FROM public.sql_firewall_activity_log \
                           ORDER BY log_time DESC, log_id DESC OFFSET $1 LIMIT 1 \
                         ) AS c ON true",
                        &[int8_arg(activity_max)],
                    )?);
                }
                if let Some((Some(time), Some(id))) = cutoff_ref.as_ref() {
                    // Everything up to the cutoff goes, oldest first, one
                    // batch per transaction.
                    let deleted = Spi::get_one_with_args::<i64>(
                        "WITH doomed AS ( \
                           SELECT ctid FROM public.sql_firewall_activity_log \
                           WHERE (log_time, log_id) OPERATOR(pg_catalog.<=) ($1::pg_catalog.timestamptz, $2::pg_catalog.int8) \
                           ORDER BY log_time, log_id LIMIT 1000 FOR UPDATE SKIP LOCKED \
                         ), deleted AS ( \
                           DELETE FROM public.sql_firewall_activity_log AS log \
                           USING doomed WHERE log.ctid OPERATOR(pg_catalog.=) doomed.ctid \
                           RETURNING 1 \
                         ) SELECT pg_catalog.count(*)::pg_catalog.int8 FROM deleted",
                        &[crate::sql::text_arg(time), int8_arg(*id)],
                    )?.unwrap_or(0);
                    full_batch |= deleted > 0;
                    deleted_activity += deleted;
                }
            }
            Spi::run_with_args(
                "UPDATE public.sql_firewall_retention_status SET \
                   runs = runs OPERATOR(pg_catalog.+) 1, last_run_at = pg_catalog.now(), last_success_at = pg_catalog.now(), \
                   last_activity_deleted = $1, last_blocked_deleted = $2, \
                   total_activity_deleted = total_activity_deleted OPERATOR(pg_catalog.+) $1, \
                   total_blocked_deleted = total_blocked_deleted OPERATOR(pg_catalog.+) $2 \
                 WHERE singleton OPERATOR(pg_catalog.=) 1",
                &[int8_arg(deleted_activity), int8_arg(deleted_blocked)],
            )?;
            Ok(())
        });

        if !matches!(result, PersistAttempt::Committed) {
            keep(None, 0);
            finish(result, now, last_warning_us);
            return false;
        }
        if full_batch {
            // Once the fixed cutoff is exhausted, refresh it on the next
            // pass to account for records inserted during this catch-up run.
            let exhausted = cutoff
                .as_ref()
                .is_some_and(|(t, i)| t.is_some() && i.is_some())
                && deleted_activity < BATCH;
            keep(if exhausted { None } else { cutoff }, activity_max);
            *last_attempt_us = now.saturating_sub(interval_us);
            return true;
        }
        keep(None, 0);
        false
    }
}

fn finish(result: PersistAttempt, now: i64, last_warning_us: &mut i64) {
    match result {
        PersistAttempt::Committed => {}
        PersistAttempt::Retry { sqlstate } => {
            let recorded = worker_persist::persist_event_transaction(|| {
                Spi::run_with_args(
                    "UPDATE public.sql_firewall_retention_status SET \
                       runs = runs OPERATOR(pg_catalog.+) 1, failures = failures OPERATOR(pg_catalog.+) 1, \
                       last_run_at = pg_catalog.now(), last_error_sqlstate = $1, last_error_at = pg_catalog.now() \
                     WHERE singleton OPERATOR(pg_catalog.=) 1",
                    &[crate::sql::text_arg(&sqlstate)],
                )
            });
            let _ = recorded;
            if now.saturating_sub(*last_warning_us) >= 60 * MICROS_PER_SECOND {
                pgrx::warning!(
                    "sql_firewall: audit retention failed in database oid {} (SQLSTATE {}); will retry",
                    u32::from(unsafe { pg_sys::MyDatabaseId }),
                    sqlstate
                );
                *last_warning_us = now;
            }
        }
    }
}
