// Per-database consumer progress. The row advances in the same transaction
// as a local event's effects. It is not an event journal.
//
// Non-local slots (another database, another extension installation, a
// diagnosed malformed event, or a position already outside the retained
// window) do not apply effects. Their progress is checkpointed in batches
// before the worker waits, and also covered when the next local event
// commits at a higher position. A crash in the middle of a batch rescans
// those slots and skips them again. A local event is never left behind the
// committed cursor without its effects, because both change in one commit.

use std::ffi::CStr;

use crate::pending_approvals::{self, RingView};
use crate::sql::text_arg;
use crate::worker_persist::{self, PersistAttempt};
use pgrx::pg_sys;
use pgrx::prelude::*;

const CHECKPOINT_NAME: &CStr = c"sql_firewall_consumer_checkpoint";
const PUBLIC_NSP: &CStr = c"public";

#[derive(Clone, Copy)]
pub struct Progress {
    pub generation: u64,
    pub extension_oid: pg_sys::Oid,
    pub next_position: u64,
}

pub enum Startup {
    Resume {
        progress: Progress,
        /// Shared-stream positions `[from, to)` that were already gone.
        gap: Option<(u64, u64)>,
    },
    /// Same generation, but the checkpoint is past the ring head.
    Ahead { next_position: u64, write_pos: u64 },
    /// Missing, or not an extension member. Do not invent a cursor.
    Unavailable,
    /// Present but not a valid initialized or uninitialized row. Leave it unchanged.
    Invalid,
    ExtensionGone,
}

#[allow(dead_code)]
pub enum Claim {
    /// This position is still the next uncommitted local effect.
    Apply,
    /// A committed checkpoint already passed this position.
    AlreadyDone { resume: u64 },
    ExtensionGone,
    /// The copied event belongs to a previous CREATE EXTENSION.
    StaleInstallation { current: pg_sys::Oid },
    Unavailable,
    /// The stored row is not usable metadata. Do not acknowledge or rewrite it.
    Invalid,
    Ahead { next_position: u64, write_pos: u64 },
}

pub enum SkipResult {
    Committed,
    ExtensionGone,
    /// The connected installation is not the one in local progress.
    Replaced,
    /// The row or relation cannot be used. Do not write and do not move local progress.
    Invalid,
    Ahead { next_position: u64, write_pos: u64 },
    Retry { sqlstate: String },
}

pub fn sync_startup(ring: &RingView) -> Startup {
    let mut outcome = Startup::Unavailable;
    let attempt = worker_persist::persist_event_transaction(|| {
        outcome = sync_startup_in_transaction(ring)?;
        Ok(())
    });
    match attempt {
        PersistAttempt::Committed => outcome,
        PersistAttempt::Retry { sqlstate } => {
            pgrx::warning!(
                "sql_firewall: consumer checkpoint sync failed SQLSTATE {sqlstate}; not resetting progress"
            );
            Startup::Unavailable
        }
    }
}

fn sync_startup_in_transaction(ring: &RingView) -> Result<Startup, pgrx::spi::Error> {
    let Some(ext) = pending_approvals::current_extension_oid() else {
        return Ok(Startup::ExtensionGone);
    };
    lock_extension(ext);
    if !checkpoint_relation_is_member(ext) {
        return Ok(Startup::Unavailable);
    }
    let row = match read_for_update()? {
        Loaded::Missing => return Ok(Startup::Unavailable),
        Loaded::Invalid => return Ok(Startup::Invalid),
        Loaded::Uninitialized => {
            let progress = Progress {
                generation: ring.generation,
                extension_oid: ext,
                next_position: ring.oldest,
            };
            write_progress(&progress)?;
            return Ok(Startup::Resume {
                progress,
                gap: None,
            });
        }
        Loaded::Ready(row) => row,
    };
    if row.generation != ring.generation || row.extension_oid != ext {
        let progress = Progress {
            generation: ring.generation,
            extension_oid: ext,
            next_position: ring.oldest,
        };
        write_progress(&progress)?;
        pgrx::log!(
            "sql_firewall: consumer checkpoint generation {} extension {} replaced by generation {} extension {}; resume at {}",
            row.generation,
            u32::from(row.extension_oid),
            ring.generation,
            u32::from(ext),
            ring.oldest
        );
        return Ok(Startup::Resume {
            progress,
            gap: None,
        });
    }
    if row.next_position > ring.write_pos {
        return Ok(Startup::Ahead {
            next_position: row.next_position,
            write_pos: ring.write_pos,
        });
    }
    if row.next_position < ring.oldest {
        let progress = Progress {
            generation: ring.generation,
            extension_oid: ext,
            next_position: ring.oldest,
        };
        write_progress(&progress)?;
        return Ok(Startup::Resume {
            progress,
            gap: Some((row.next_position, ring.oldest)),
        });
    }
    Ok(Startup::Resume {
        progress: Progress {
            generation: row.generation,
            extension_oid: ext,
            next_position: row.next_position,
        },
        gap: None,
    })
}

/// Lock the singleton and decide whether `position` still needs effects.
/// Call this inside the event transaction, before the event SQL.
///
/// The ring head is read after the row lock. A checkpoint another backend
/// committed while this transaction waited is judged against that later head,
/// not against the caller's pre-lock snapshot.
pub fn claim(ring: &RingView, event_extension: pg_sys::Oid, position: u64) -> Result<Claim, pgrx::spi::Error> {
    let _prelock_generation = ring.generation;
    let Some(ext) = pending_approvals::current_extension_oid() else {
        return Ok(Claim::ExtensionGone);
    };
    lock_extension(ext);
    if ext != event_extension {
        return Ok(Claim::StaleInstallation { current: ext });
    }
    if !checkpoint_relation_is_member(ext) {
        return Ok(Claim::Unavailable);
    }
    let row = match read_for_update()? {
        Loaded::Ready(row) => row,
        Loaded::Invalid => return Ok(Claim::Invalid),
        Loaded::Missing | Loaded::Uninitialized => return Ok(Claim::Unavailable),
    };
    let Some(fresh) = pending_approvals::ring_view() else {
        return Ok(Claim::Unavailable);
    };
    if row.extension_oid != ext || row.generation != fresh.generation {
        return Ok(Claim::Unavailable);
    }
    if row.next_position > fresh.write_pos {
        return Ok(Claim::Ahead {
            next_position: row.next_position,
            write_pos: fresh.write_pos,
        });
    }
    if row.next_position > position {
        return Ok(Claim::AlreadyDone {
            resume: row.next_position,
        });
    }
    Ok(Claim::Apply)
}

/// Probe race entry. The caller is already inside a statement transaction, so
/// this must not call `StartTransactionCommand`. It uses the same claim, event
/// insert, and checkpoint update as the worker; the statement commit is the
/// commit of that work. Two callers serialize on the singleton row.
pub fn apply_blocked_marker(marker: &str, position: u64) -> String {
    let Some(ring) = pending_approvals::ring_view() else {
        return "unavailable".to_string();
    };
    let Some(ext) = pending_approvals::current_extension_oid() else {
        return "extension_gone".to_string();
    };
    match apply_blocked_marker_in_transaction(&ring, ext, marker, position) {
        Ok(label) => label,
        Err(err) => format!("retry {err}"),
    }
}

fn apply_blocked_marker_in_transaction(
    ring: &pending_approvals::RingView,
    ext: pg_sys::Oid,
    marker: &str,
    position: u64,
) -> Result<String, pgrx::spi::Error> {
    match claim(ring, ext, position)? {
        Claim::Apply => {
            Spi::run_with_args(
                "INSERT INTO public.sql_firewall_blocked_queries \
                 (role_name, database_name, query_text, query_truncated, application_name, client_addr, command_type, reason) \
                 VALUES ('qa_probe', 'qa_probe', $1, false, '', '', 'SELECT', 'probe')",
                &[text_arg(marker)],
            )?;
            advance(
                &Progress {
                    generation: ring.generation,
                    extension_oid: ext,
                    next_position: position,
                },
                position + 1,
            )?;
            Ok(format!("applied {position}"))
        }
        Claim::AlreadyDone { resume } => Ok(format!("already {resume}")),
        Claim::ExtensionGone => Ok("extension_gone".to_string()),
        Claim::Ahead { .. } => Ok("ahead".to_string()),
        Claim::Invalid => Ok("invalid".to_string()),
        _ => Ok("other".to_string()),
    }
}

pub fn advance(progress: &Progress, next_position: u64) -> Result<(), pgrx::spi::Error> {
    write_progress(&Progress {
        generation: progress.generation,
        extension_oid: progress.extension_oid,
        next_position,
    })
}

/// Commit progress over slots that had no local effect. Monotonic within the
/// current generation: a stored cursor ahead of `next_position` is left alone.
/// A stale local installation, an invalid row, or a cursor past the ring head
/// is not written.
pub fn advance_skips(progress: &Progress, next_position: u64) -> SkipResult {
    if next_position <= progress.next_position {
        return SkipResult::Committed;
    }
    let mut outcome = SkipResult::Retry {
        sqlstate: "55000".to_string(),
    };
    let attempt = worker_persist::persist_event_transaction(|| {
        outcome = advance_skips_in_transaction(progress, next_position)?;
        Ok(())
    });
    match attempt {
        PersistAttempt::Committed => outcome,
        PersistAttempt::Retry { sqlstate } => SkipResult::Retry { sqlstate },
    }
}

fn advance_skips_in_transaction(
    progress: &Progress,
    next_position: u64,
) -> Result<SkipResult, pgrx::spi::Error> {
    let Some(ext) = pending_approvals::current_extension_oid() else {
        return Ok(SkipResult::ExtensionGone);
    };
    lock_extension(ext);
    if ext != progress.extension_oid {
        return Ok(SkipResult::Replaced);
    }
    if !checkpoint_relation_is_member(ext) {
        return Ok(SkipResult::Invalid);
    }
    let row = match read_for_update()? {
        Loaded::Ready(row) => row,
        Loaded::Missing | Loaded::Uninitialized | Loaded::Invalid => {
            return Ok(SkipResult::Invalid);
        }
    };
    if row.extension_oid != ext {
        return Ok(SkipResult::Replaced);
    }
    if row.generation != progress.generation {
        return Ok(SkipResult::Invalid);
    }
    let Some(fresh) = pending_approvals::ring_view() else {
        return Ok(SkipResult::Retry {
            sqlstate: "08000".to_string(),
        });
    };
    if row.generation != fresh.generation || row.next_position > fresh.write_pos {
        if row.next_position > fresh.write_pos && row.generation == fresh.generation {
            return Ok(SkipResult::Ahead {
                next_position: row.next_position,
                write_pos: fresh.write_pos,
            });
        }
        return Ok(SkipResult::Invalid);
    }
    if row.next_position >= next_position {
        return Ok(SkipResult::Committed);
    }
    write_progress(&Progress {
        generation: progress.generation,
        extension_oid: ext,
        next_position,
    })?;
    Ok(SkipResult::Committed)
}

struct Row {
    generation: u64,
    extension_oid: pg_sys::Oid,
    next_position: u64,
}

fn lock_extension(ext: pg_sys::Oid) {
    unsafe {
        pg_sys::LockDatabaseObject(
            pg_sys::ExtensionRelationId,
            ext,
            0,
            pg_sys::AccessShareLock as pg_sys::LOCKMODE,
        );
    }
}

fn checkpoint_relation_is_member(ext: pg_sys::Oid) -> bool {
    unsafe {
        let nsp = pg_sys::get_namespace_oid(PUBLIC_NSP.as_ptr(), true);
        if nsp == pg_sys::InvalidOid {
            return false;
        }
        let rel = pg_sys::get_relname_relid(CHECKPOINT_NAME.as_ptr(), nsp);
        if rel == pg_sys::InvalidOid {
            return false;
        }
        if pg_sys::get_rel_relkind(rel) as u8 != pg_sys::RELKIND_RELATION {
            return false;
        }
        if pg_sys::getExtensionOfObject(pg_sys::RelationRelationId, rel) != ext {
            return false;
        }
        pg_sys::LockRelationOid(rel, pg_sys::AccessShareLock as pg_sys::LOCKMODE);
        pg_sys::getExtensionOfObject(pg_sys::RelationRelationId, rel) == ext
    }
}

enum Loaded {
    Missing,
    Uninitialized,
    Ready(Row),
    Invalid,
}

fn read_for_update() -> Result<Loaded, pgrx::spi::Error> {
    let packed: Option<String> = Spi::get_one(
        "SELECT initialized::pg_catalog.text \
                OPERATOR(pg_catalog.||) '|' \
                OPERATOR(pg_catalog.||) coalesce(ring_generation::pg_catalog.text, '') \
                OPERATOR(pg_catalog.||) '|' \
                OPERATOR(pg_catalog.||) coalesce(extension_oid::pg_catalog.text, '') \
                OPERATOR(pg_catalog.||) '|' \
                OPERATOR(pg_catalog.||) coalesce(next_position::pg_catalog.text, '') \
         FROM public.sql_firewall_consumer_checkpoint \
         WHERE singleton OPERATOR(pg_catalog.=) 1 \
         FOR UPDATE",
    )?;
    Ok(match packed {
        None => Loaded::Missing,
        Some(text) => parse_row(&text),
    })
}

fn parse_u64(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

fn parse_oid(text: &str) -> Option<pg_sys::Oid> {
    let value = parse_u64(text)?;
    let oid = u32::try_from(value).ok()?;
    if oid == 0 {
        return None;
    }
    Some(pg_sys::Oid::from(oid))
}

/// `false` with all metadata null is the explicit uninitialized row.
/// Any other missing, negative, or out-of-range value is invalid and must
/// not be rewritten into a fresh cursor. Generation zero remains valid.
fn parse_row(packed: &str) -> Loaded {
    let mut parts = packed.split('|');
    let Some(flag) = parts.next() else {
        return Loaded::Invalid;
    };
    let Some(generation) = parts.next() else {
        return Loaded::Invalid;
    };
    let Some(extension) = parts.next() else {
        return Loaded::Invalid;
    };
    let Some(next) = parts.next() else {
        return Loaded::Invalid;
    };
    if parts.next().is_some() {
        return Loaded::Invalid;
    }
    match flag {
        "false" => {
            if generation.is_empty() && extension.is_empty() && next.is_empty() {
                Loaded::Uninitialized
            } else {
                Loaded::Invalid
            }
        }
        "true" => {
            let Some(generation) = parse_u64(generation) else {
                return Loaded::Invalid;
            };
            let Some(extension_oid) = parse_oid(extension) else {
                return Loaded::Invalid;
            };
            let Some(next_position) = parse_u64(next) else {
                return Loaded::Invalid;
            };
            Loaded::Ready(Row {
                generation,
                extension_oid,
                next_position,
            })
        }
        _ => Loaded::Invalid,
    }
}

fn write_progress(progress: &Progress) -> Result<(), pgrx::spi::Error> {
    Spi::run_with_args(
        "UPDATE public.sql_firewall_consumer_checkpoint \
         SET initialized = true, \
             ring_generation = $1::pg_catalog.numeric, \
             extension_oid = $2::pg_catalog.oid, \
             next_position = $3::pg_catalog.numeric \
         WHERE singleton OPERATOR(pg_catalog.=) 1",
        &[
            text_arg(&progress.generation.to_string()),
            text_arg(&u32::from(progress.extension_oid).to_string()),
            text_arg(&progress.next_position.to_string()),
        ],
    )?;
    Ok(())
}
