// Test-only adapter. Compiled only with `--features queue_probe`.
// The release library does not contain these functions. They call the same
// publish and read path as production and do not hold the ring spinlock
// across SPI, logging, or sleeps.

use pgrx::pg_sys;
use pgrx::prelude::*;

use crate::pending_approvals::{self, EventType, ReadOutcome};

fn require_superuser() {
    if !unsafe { pg_sys::superuser() } {
        pgrx::error!("sql_firewall: queue probe requires a superuser");
    }
}

#[pg_extern]
fn sql_firewall_queue_probe_hold(hold: bool) -> String {
    require_superuser();
    pending_approvals::set_probe_hold(hold);
    if hold {
        "held".to_string()
    } else {
        "released".to_string()
    }
}

/// Arm a hold for one consumer. The returned epoch is not quiescence.
/// `sql_firewall_queue_probe_status` reports when that consumer has reached
/// the hold branch and has not yet read the ring.
#[pg_extern]
fn sql_firewall_queue_probe_arm(pid: i32) -> String {
    require_superuser();
    if pid <= 0 {
        pgrx::error!("sql_firewall: queue probe target pid must be positive");
    }
    let db = u32::from(unsafe { pg_sys::MyDatabaseId });
    let epoch = pending_approvals::arm_probe_hold(pid, db);
    if epoch == 0 {
        pgrx::error!("sql_firewall: queue probe ring is not attached");
    }
    format!("armed pid={pid} db={db} epoch={epoch}")
}

#[pg_extern]
fn sql_firewall_queue_probe_status() -> String {
    require_superuser();
    let Some(view) = pending_approvals::probe_hold_view() else {
        return "unavailable".to_string();
    };
    if !view.held || view.epoch == 0 || view.target_pid <= 0 {
        return "not_held".to_string();
    }
    let alive = target_worker_alive(view.target_pid, view.target_db);
    if !alive {
        return format!(
            "exited pid={} db={} epoch={}",
            view.target_pid, view.target_db, view.epoch
        );
    }
    if view.ack_epoch == view.epoch
        && view.ack_pid == view.target_pid
        && view.ack_db == view.target_db
    {
        format!(
            "quiescent pid={} db={} epoch={}",
            view.target_pid, view.target_db, view.epoch
        )
    } else {
        format!(
            "waiting pid={} db={} epoch={}",
            view.target_pid, view.target_db, view.epoch
        )
    }
}

fn target_worker_alive(pid: i32, db: u32) -> bool {
    let sql = "SELECT a.backend_type FROM pg_catalog.pg_stat_activity a \
               WHERE a.pid OPERATOR(pg_catalog.=) $1::pg_catalog.int4 \
                 AND a.datid OPERATOR(pg_catalog.=) ($2::pg_catalog.int8)::pg_catalog.oid";
    let kind = Spi::connect(|client| {
        let table = client.select(
            sql,
            Some(1),
            &[
                crate::sql::int4_arg(pid),
                crate::sql::oid_carrier_arg(db),
            ],
        )?;
        if table.is_empty() {
            return Ok::<Option<String>, pgrx::spi::Error>(None);
        }
        table.first().get_one::<String>()
    });
    match kind {
        Ok(Some(backend_type)) => backend_type.starts_with("sql_firewall_worker_"),
        Ok(None) => false,
        Err(pgrx::spi::Error::InvalidPosition) => false,
        Err(err) => {
            pgrx::warning!("sql_firewall: queue probe could not read pg_stat_activity: {err:?}");
            false
        }
    }
}

#[pg_extern]
fn sql_firewall_queue_probe_stats() -> String {
    require_superuser();
    let (publications, slot_overwrites, capacity) = pending_approvals::probe_stats();
    format!("publications={publications} slot_overwrites={slot_overwrites} capacity={capacity}")
}

#[pg_extern]
fn sql_firewall_queue_probe_read(pos: i64) -> String {
    require_superuser();
    if pos < 0 {
        return "unavailable".to_string();
    }
    match pending_approvals::read_at(pos as u64) {
        ReadOutcome::Unavailable => "unavailable".to_string(),
        ReadOutcome::NotYetPublished => "not_yet".to_string(),
        ReadOutcome::Overwritten { retained_from } => format!("overwritten {retained_from}"),
        ReadOutcome::Ready(event) => {
            let kind = match event.event_type {
                EventType::Approval => "approval",
                EventType::BlockedQuery => "blocked",
                EventType::FingerprintHit => "fingerprint",
            };
            let detail = unsafe {
                match event.event_type {
                    EventType::BlockedQuery => match pending_approvals::decode_field(
                        &event.data.blocked_query.query,
                    ) {
                        pending_approvals::DecodedField::Text(text) => text,
                        pending_approvals::DecodedField::Empty => String::new(),
                        pending_approvals::DecodedField::Invalid => "invalid".to_string(),
                    },
                    EventType::FingerprintHit => match pending_approvals::decode_field(
                        &event.data.fingerprint_hit.fingerprint_hex,
                    ) {
                        pending_approvals::DecodedField::Text(text) => text,
                        pending_approvals::DecodedField::Empty => String::new(),
                        pending_approvals::DecodedField::Invalid => "invalid".to_string(),
                    },
                    EventType::Approval => match pending_approvals::decode_field(
                        &event.data.approval.command_type,
                    ) {
                        pending_approvals::DecodedField::Text(text) => text,
                        pending_approvals::DecodedField::Empty => String::new(),
                        pending_approvals::DecodedField::Invalid => "invalid".to_string(),
                    },
                }
            };
            format!(
                "ready {kind} {} {detail}",
                u32::from(event.db_oid)
            )
        }
    }
}

#[pg_extern]
fn sql_firewall_queue_probe_exit_after_commit(enabled: bool) -> String {
    require_superuser();
    pending_approvals::set_probe_exit_after_commit(enabled);
    if enabled {
        "armed".to_string()
    } else {
        "cleared".to_string()
    }
}

#[pg_extern]
fn sql_firewall_queue_probe_fail_before_checkpoint(enabled: bool) -> String {
    require_superuser();
    pending_approvals::set_probe_fail_before_checkpoint(enabled);
    if enabled {
        "armed".to_string()
    } else {
        "cleared".to_string()
    }
}

#[pg_extern]
fn sql_firewall_queue_probe_apply_blocked(marker: &str, position: i64) -> String {
    require_superuser();
    if position < 0 {
        pgrx::error!("sql_firewall: queue probe position must be non-negative");
    }
    crate::consumer_checkpoint::apply_blocked_marker(marker, position as u64)
}

/// Ask the production detach path to drop `incarnation` if it is still current.
/// A newer incarnation is left in place. Returns the status after the attempt.
#[pg_extern]
fn sql_firewall_queue_probe_stale_detach(incarnation: i64) -> String {
    require_superuser();
    let Some(extension_oid) = pending_approvals::current_extension_oid() else {
        return "no extension".to_string();
    };
    let Some(ring) = pending_approvals::ring_view() else {
        return "no ring".to_string();
    };
    if incarnation < 0 {
        pgrx::error!("sql_firewall: queue probe incarnation must be non-negative");
    }
    let identity = crate::consumer_control::Identity {
        db_oid: u32::from(unsafe { pg_sys::MyDatabaseId }),
        extension_oid: u32::from(extension_oid),
        ring_generation: ring.generation,
    };
    crate::consumer_control::detach_keep_request(identity, incarnation as u64);
    crate::consumer_control::status_text(identity)
}

/// Occupied control records for `db_oid`, in any installation or generation.
#[pg_extern]
fn sql_firewall_queue_probe_control_slots(db_oid: i64) -> i32 {
    require_superuser();
    let Ok(db_oid) = u32::try_from(db_oid) else {
        pgrx::error!("sql_firewall: queue probe database oid is out of range");
    };
    crate::consumer_control::slots_for_database(db_oid)
}

/// In this session only, stop `DROP DATABASE` from tagging that database's
/// control records, so the launcher's `pg_database` reconciliation is the only
/// path that can release them.
#[pg_extern]
fn sql_firewall_queue_probe_skip_database_tags(enabled: bool) -> String {
    require_superuser();
    crate::consumer_control::set_probe_skip_database_tags(enabled);
    if enabled {
        "skipping".to_string()
    } else {
        "tagging".to_string()
    }
}

#[pg_extern]
fn sql_firewall_queue_probe_one_approval(role_name: &str) -> bool {
    require_superuser();
    let (role_oid, epoch) = probe_identity(role_name, crate::policy_visibility::PolicyTable::Approvals);
    pending_approvals::enqueue_approval(role_name, role_oid, "SELECT", "qa_probe", true, epoch)
}

/// The role's current OID (InvalidOid when it does not exist; the worker then
/// discards the event) and the current policy epoch, as a real observation
/// would carry them.
fn probe_identity(role_name: &str, table: crate::policy_visibility::PolicyTable) -> (pg_sys::Oid, i64) {
    let role_oid = std::ffi::CString::new(role_name)
        .map(|name| unsafe { pg_sys::get_role_oid(name.as_ptr(), true) })
        .unwrap_or(pg_sys::InvalidOid);
    let epoch = crate::policy_visibility::read_policy_epoch(table)
        .unwrap_or_else(|err| pgrx::error!("{err}"));
    (role_oid, epoch)
}

#[pg_extern]
fn sql_firewall_queue_probe_one_fingerprint(role_name: &str, fingerprint_hex: &str, sample: &str) -> bool {
    require_superuser();
    let (role_oid, epoch) = probe_identity(role_name, crate::policy_visibility::PolicyTable::Fingerprints);
    pending_approvals::enqueue_fingerprint(
        fingerprint_hex,
        "select $1",
        role_name,
        role_oid,
        "SELECT",
        sample,
        0,
        epoch,
    )
}

#[pg_extern]
fn sql_firewall_queue_probe_bad_approval() -> bool {
    require_superuser();
    pending_approvals::publish_invalid_approval()
}

#[pg_extern]
fn sql_firewall_queue_probe_fill(count: i32, marker: &str) -> i32 {
    require_superuser();
    let mut published = 0i32;
    for i in 0..count.max(0) {
        let query = format!("{marker}-{i}");
        if pending_approvals::enqueue_blocked_query(
            "qa_probe",
            "qa_probe_db",
            &query,
            None,
            None,
            "SELECT",
            Some("probe"),
            None,
        ) {
            published += 1;
        }
    }
    published
}
