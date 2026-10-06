//! Shared rate-limit counters (README 6.4).
//!
//! Scope: one counter per database, role OID, and command family (the global
//! limit uses family 0), so a role's traffic in one database never consumes
//! its allowance in another, and a dropped and recreated role (new OID)
//! starts fresh.
//!
//! Window: fixed. It starts at the first counted attempt after the previous
//! window ended and lasts the window length configured when the attempt is
//! checked, so a reload applies at once. Time is CLOCK_MONOTONIC, so wall
//! clock changes neither lengthen nor end a window. An attempt is counted
//! when it reaches the check, whether the statement is then allowed or
//! rejected; an attempt rejected by the global limit is not counted against
//! its command limit. Counts saturate at u32::MAX.
//!
//! Capacity: an open-addressing table of [`ENTRIES`] counters. A counter
//! whose window has ended can be reused; an active one is never evicted. If
//! no counter can be found or placed within [`MAX_PROBE`] slots the attempt
//! is refused (fail closed): evicting an active counter would reset it and
//! let a role exceed its limit.

use pgrx::pg_sys;
use std::ptr;

#[cfg(not(feature = "session_probe"))]
const ENTRIES: usize = 8192;
#[cfg(not(feature = "session_probe"))]
const MAX_PROBE: usize = 256;
// Test builds only: a table small enough to fill (qa/probe/08).
#[cfg(feature = "session_probe")]
const ENTRIES: usize = 16;
#[cfg(feature = "session_probe")]
const MAX_PROBE: usize = 16;
const NANOS_PER_SEC: i64 = 1_000_000_000;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Entry {
    used: bool,
    command: u8,
    db_oid: u32,
    role_oid: u32,
    window_start_ns: i64,
    window_ns: i64,
    count: u32,
}

#[repr(C)]
struct RateState {
    lock: pg_sys::slock_t,
    entries: [Entry; ENTRIES],
}

static mut RATE_STATE_PTR: *mut RateState = ptr::null_mut();
const RATE_SEGMENT: &std::ffi::CStr = c"sql_firewall_rate_state_v3";

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<RateState>()
}

pub unsafe fn init() {
    // Runs in every shared-memory initialization, including the postmaster's
    // reinitialization after a crash: the segment is new, so the pointer is
    // always taken from ShmemInitStruct and never kept from before.
    let mut found = false;
    let ptr = pg_sys::ShmemInitStruct(
        RATE_SEGMENT.as_ptr(),
        shared_memory_bytes(),
        &mut found as *mut bool,
    ) as *mut RateState;
    if ptr.is_null() {
        pgrx::error!("sql_firewall: failed to allocate rate-limit state");
    }
    if !found {
        ptr::write_bytes(ptr.cast::<u8>(), 0, shared_memory_bytes());
        pg_sys::SpinLockInit(&mut (*ptr).lock);
    }
    RATE_STATE_PTR = ptr;
}

/// The outcome of counting one attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Count {
    Within,
    Exceeded,
    /// No counter could be kept: refuse the attempt.
    Full,
}

fn monotonic_ns() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as i64).saturating_mul(NANOS_PER_SEC).saturating_add(ts.tv_nsec as i64)
}

fn slot_of(db: u32, role: u32, command: u8) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in db.to_le_bytes().into_iter().chain(role.to_le_bytes()).chain([command]) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize) % ENTRIES
}

/// Counts one attempt for `role_oid` in this database against `limit` per
/// `window_secs`. `command` 0 is the global counter.
fn count(role_oid: pg_sys::Oid, command: u8, limit: i32, window_secs: i32) -> Count {
    let db = u32::from(unsafe { pg_sys::MyDatabaseId });
    let role = u32::from(role_oid);
    let window_ns = i64::from(window_secs).saturating_mul(NANOS_PER_SEC);
    let now = monotonic_ns();
    unsafe {
        let state = RATE_STATE_PTR;
        if state.is_null() {
            return Count::Within;
        }
        let _guard = SpinLockGuard::new(&mut (*state).lock);
        let entries = &mut (*state).entries;
        let start = slot_of(db, role, command);
        let mut reusable = None;
        let mut target = None;
        for step in 0..MAX_PROBE {
            let index = (start + step) % ENTRIES;
            let entry = &entries[index];
            if !entry.used {
                target = Some(reusable.unwrap_or(index));
                break;
            }
            if entry.db_oid == db && entry.role_oid == role && entry.command == command {
                target = Some(index);
                break;
            }
            // A different role's shorter configured window must not evict this
            // entry while its own window is still active.
            if reusable.is_none() && now.saturating_sub(entry.window_start_ns) >= entry.window_ns {
                reusable = Some(index);
            }
        }
        let Some(index) = target.or(reusable) else {
            return Count::Full;
        };
        let entry = &mut entries[index];
        let same = entry.used && entry.db_oid == db && entry.role_oid == role && entry.command == command;
        if !same || now.saturating_sub(entry.window_start_ns) >= window_ns {
            *entry = Entry {
                used: true,
                command,
                db_oid: db,
                role_oid: role,
                window_start_ns: now,
                window_ns,
                count: 0,
            };
        } else {
            // A changed setting takes effect on the next attempt by this
            // same role, as documented for reloads.
            entry.window_ns = window_ns;
        }
        entry.count = entry.count.saturating_add(1);
        if entry.count > limit as u32 {
            Count::Exceeded
        } else {
            Count::Within
        }
    }
}

pub fn check_global(role_oid: Option<pg_sys::Oid>, limit: i32, window_secs: i32) -> Count {
    match role_oid {
        Some(role) if limit > 0 && window_secs > 0 => count(role, 0, limit, window_secs),
        _ => Count::Within,
    }
}

pub fn check_command(role_oid: Option<pg_sys::Oid>, command_code: u8, limit: i32, window_secs: i32) -> Count {
    match role_oid {
        Some(role) if limit > 0 && window_secs > 0 && command_code != 0 => {
            count(role, command_code, limit, window_secs)
        }
        _ => Count::Within,
    }
}

pub fn command_code(command: &str) -> u8 {
    match command {
        "SELECT" => 1,
        "INSERT" => 2,
        "UPDATE" => 3,
        "DELETE" => 4,
        _ => 0,
    }
}

struct SpinLockGuard<'a> {
    lock: &'a mut pg_sys::slock_t,
}

impl<'a> SpinLockGuard<'a> {
    unsafe fn new(lock: &'a mut pg_sys::slock_t) -> Self {
        pg_sys::SpinLockAcquire(lock);
        Self { lock }
    }
}

impl Drop for SpinLockGuard<'_> {
    fn drop(&mut self) {
        unsafe { pg_sys::SpinLockRelease(self.lock) };
    }
}
