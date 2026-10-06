use pgrx::pg_sys;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::policy_visibility::CacheScope;
use crate::fingerprints::FingerprintId;
use crate::seqlock::{self, Sequence};

// Shared fingerprint decisions. Every inspected statement with fingerprint
// checking reads it, so it is set-associative: an entry lives in one of
// SETS sets chosen by a hash of its key, each set has WAYS entries, and a
// lookup reads only that set, without a lock: its entries are atomic words
// read under the set's sequence counter (seqlock.rs). Writers hold the set's
// spinlock. Generations are atomics read without a lock (see
// approval_cache.rs for why a publish that races a bump is harmless). A full
// set evicts its least recently stored entry.
const CACHE_ENTRIES: usize = 4096;
const WAYS: usize = 8;
const SETS: usize = CACHE_ENTRIES / WAYS;
/// Per-database generations; see approval_cache.rs.
const GENERATION_SLOTS: usize = 256;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CacheState {
    Unknown = 0,
    Approved = 1,
    Pending = 2,
    Blocked = 3,
}

/// What a lookup found for this scope.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Hit {
    /// Committed catalog state, still current.
    Committed(CacheState),
    /// Learn mode already logged the discovery of this fingerprint. Not policy.
    Learned,
}

#[derive(Copy, Clone)]
struct CacheEntry {
    fingerprint: FingerprintId,
    role_name_hash: u64,
    generation: u64,
    last_seen: pg_sys::TimestampTz,
    role_oid: pg_sys::Oid,
    // SECURITY: same reason as approval_cache - fingerprint approvals are
    // per-database rows, this cache is cluster-wide shared memory.
    db_oid: pg_sys::Oid,
    extension_oid: pg_sys::Oid,
    hit_count: u32,
    command_code: u8,
    state: u8,
    learned: bool,
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self {
            fingerprint: [0; 32],
            role_name_hash: 0,
            generation: 0,
            last_seen: 0,
            role_oid: pg_sys::InvalidOid,
            db_oid: pg_sys::InvalidOid,
            extension_oid: pg_sys::InvalidOid,
            hit_count: 0,
            command_code: 0,
            state: CacheState::Unknown as u8,
            learned: false,
        }
    }
}

/// Words of one stored entry (see `CacheEntry::encode`).
const ENTRY_WORDS: usize = 10;
const SET_WORDS: usize = WAYS * ENTRY_WORDS;

impl CacheEntry {
    /// Field layout: fingerprint (4 words); role name hash; generation;
    /// last seen; role and database OIDs; extension OID and hit count;
    /// command code, state, learned flag.
    fn encode(&self) -> [u64; ENTRY_WORDS] {
        let fingerprint: [u64; 4] = seqlock::bytes_to_words(&self.fingerprint);
        [
            fingerprint[0],
            fingerprint[1],
            fingerprint[2],
            fingerprint[3],
            self.role_name_hash,
            self.generation,
            self.last_seen as u64,
            seqlock::pack_u32s(u32::from(self.role_oid), u32::from(self.db_oid)),
            seqlock::pack_u32s(u32::from(self.extension_oid), self.hit_count),
            u64::from(self.command_code) | (u64::from(self.state) << 8) | (u64::from(self.learned) << 16),
        ]
    }

    fn decode(words: &[u64]) -> Self {
        let (role_oid, db_oid) = seqlock::unpack_u32s(words[7]);
        let (extension_oid, hit_count) = seqlock::unpack_u32s(words[8]);
        Self {
            fingerprint: seqlock::words_to_bytes(&words[0..4]),
            role_name_hash: words[4],
            generation: words[5],
            last_seen: words[6] as i64,
            role_oid: pg_sys::Oid::from(role_oid),
            db_oid: pg_sys::Oid::from(db_oid),
            extension_oid: pg_sys::Oid::from(extension_oid),
            hit_count,
            command_code: words[9] as u8,
            state: (words[9] >> 8) as u8,
            learned: (words[9] >> 16) & 1 == 1,
        }
    }
}

fn decode_set(words: &[u64; SET_WORDS]) -> [CacheEntry; WAYS] {
    std::array::from_fn(|way| CacheEntry::decode(&words[way * ENTRY_WORDS..(way + 1) * ENTRY_WORDS]))
}

#[repr(C, align(64))]
struct CacheSet {
    lock: pg_sys::slock_t,
    sequence: Sequence,
    words: [AtomicU64; SET_WORDS],
}

#[repr(C)]
struct FingerprintCache {
    generations: [AtomicU64; GENERATION_SLOTS],
    sets: [CacheSet; SETS],
}

static mut CACHE: *mut FingerprintCache = ptr::null_mut();

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<FingerprintCache>()
}

pub unsafe fn init() {
    // Runs in every shared-memory initialization, including the postmaster's
    // reinitialization after a crash: the segment is new, so the pointer is
    // always taken from ShmemInitStruct and never kept from before.
    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        b"sql_firewall_fingerprint_cache\0".as_ptr() as *const std::ffi::c_char,
        shared_memory_bytes(),
        &mut found as *mut bool,
    ) as *mut FingerprintCache;

    if cache_ptr.is_null() {
        pgrx::error!("sql_firewall: failed to initialize fingerprint cache");
    }

    if !found {
        for generation in (*cache_ptr).generations.iter_mut() {
            ptr::write(generation, AtomicU64::new(1));
        }
        for set in (*cache_ptr).sets.iter_mut() {
            pg_sys::SpinLockInit(&mut set.lock);
            ptr::write(&mut set.sequence, Sequence::new());
            // All-zero words decode to the default (empty) entry.
            seqlock::zero(set.words.as_mut_ptr(), SET_WORDS);
        }
        pgrx::log!(
            "sql_firewall: fingerprint cache allocated ({} bytes)",
            shared_memory_bytes()
        );
    } else {
        pgrx::log!("sql_firewall: fingerprint cache attached to existing segment");
    }

    CACHE = cache_ptr;
}

/// Holds a set's spinlock; released on every exit path, unwinding included.
struct SetGuard(*mut CacheSet);

impl SetGuard {
    unsafe fn lock(cache: *mut FingerprintCache, set: usize) -> Self {
        let set = ptr::addr_of_mut!((*cache).sets[set]);
        pg_sys::SpinLockAcquire(ptr::addr_of_mut!((*set).lock));
        Self(set)
    }

    /// The set's entries, read while the lock is held.
    fn entries(&mut self) -> [CacheEntry; WAYS] {
        unsafe { decode_set(&Sequence::read_locked(&(*self.0).words)) }
    }

    /// Store one way; lock-free readers see either all of it or retry.
    fn write(&mut self, way: usize, entry: CacheEntry) {
        unsafe {
            (*self.0).sequence.write_locked(&(*self.0).words, way * ENTRY_WORDS, &entry.encode());
        }
    }
}

/// A consistent copy of a set's entries without taking its lock. After a
/// few attempts overlapping a writer, it takes the lock.
unsafe fn read_set(cache: *mut FingerprintCache, set: usize) -> [CacheEntry; WAYS] {
    let target = ptr::addr_of!((*cache).sets[set]);
    for _ in 0..16 {
        if let Some(copy) = (*target).sequence.try_read(&(*target).words) {
            return decode_set(&copy);
        }
        std::hint::spin_loop();
    }
    SetGuard::lock(cache, set).entries()
}

impl Drop for SetGuard {
    fn drop(&mut self) {
        unsafe { pg_sys::SpinLockRelease(ptr::addr_of_mut!((*self.0).lock)) };
    }
}

fn generation_slot(db_oid: pg_sys::Oid) -> usize {
    (u32::from(db_oid) as usize) % GENERATION_SLOTS
}

unsafe fn current_generation(cache: *mut FingerprintCache, db_oid: pg_sys::Oid) -> u64 {
    (*cache).generations[generation_slot(db_oid)].load(Ordering::SeqCst)
}

/// The set of a key. The identity is a SHA-256 digest, so its leading bytes
/// are already uniformly distributed; role, database and command are mixed
/// in so one statement shape of many roles spreads over sets.
fn set_index(scope: &CacheScope, fingerprint: &FingerprintId, command_code: u8) -> usize {
    let mut leading = [0u8; 8];
    leading.copy_from_slice(&fingerprint[..8]);
    let mixed = u64::from_le_bytes(leading)
        ^ u64::from(u32::from(scope.role_oid)).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ u64::from(u32::from(scope.db_oid)).wrapping_mul(0xc2b2_ae3d_27d4_eb4f)
        ^ u64::from(command_code).wrapping_mul(0x1656_67b1_9e37_79f9);
    (mixed % SETS as u64) as usize
}

fn matches(entry: &CacheEntry, scope: &CacheScope, fingerprint: FingerprintId, command_code: u8) -> bool {
    entry.fingerprint == fingerprint
        && entry.command_code == command_code
        && entry.role_oid == scope.role_oid
        && entry.db_oid == scope.db_oid
        && entry.extension_oid == scope.extension_oid
        && entry.role_name_hash == scope.role_name_hash
}

fn state_of(raw: u8) -> CacheState {
    match raw {
        1 => CacheState::Approved,
        2 => CacheState::Pending,
        3 => CacheState::Blocked,
        _ => CacheState::Unknown,
    }
}

/// A current committed entry, or a learn-mode memo, for this scope.
pub fn lookup(scope: &CacheScope, fingerprint: FingerprintId, command_code: u8) -> Option<Hit> {
    unsafe {
        if CACHE.is_null() {
            return None;
        }
        let entries = read_set(CACHE, set_index(scope, &fingerprint, command_code));
        let entry = *entries
            .iter()
            .find(|entry| entry.role_oid != pg_sys::InvalidOid && matches(entry, scope, fingerprint, command_code))?;
        if entry.learned {
            Some(Hit::Learned)
        } else if entry.generation == current_generation(CACHE, scope.db_oid) {
            Some(Hit::Committed(state_of(entry.state)))
        } else {
            None
        }
    }
}

/// Test-only (policy_probe): the entry for this scope whether or not it is
/// current, as (state, learned, entry generation), and this database's
/// generation.
#[cfg(feature = "policy_probe")]
pub fn probe_entry(scope: &CacheScope, fingerprint: FingerprintId, command_code: u8) -> (Option<(CacheState, bool, u64)>, u64) {
    unsafe {
        if CACHE.is_null() {
            return (None, 0);
        }
        let found = read_set(CACHE, set_index(scope, &fingerprint, command_code))
            .iter()
            .find(|entry| entry.role_oid != pg_sys::InvalidOid && matches(entry, scope, fingerprint, command_code))
            .map(|entry| (state_of(entry.state), entry.learned, entry.generation));
        (found, current_generation(CACHE, scope.db_oid))
    }
}

/// This database's generation; read it before the snapshot of the catalog
/// read whose result is published with it.
pub fn generation(db_oid: pg_sys::Oid) -> u64 {
    unsafe {
        if CACHE.is_null() {
            return 0;
        }
        current_generation(CACHE, db_oid)
    }
}

/// Committed catalog state read after `generation`; dropped if a policy
/// commit in this database advanced the generation since.
pub fn remember_committed(
    scope: &CacheScope,
    fingerprint: FingerprintId,
    command_code: u8,
    state: CacheState,
    hit_count: u32,
    generation: u64,
) {
    store(scope, fingerprint, command_code, state, hit_count, Some(generation));
}

/// Remember that a newly observed fingerprint was logged; this is not approval.
pub fn remember_learned(scope: &CacheScope, fingerprint: FingerprintId, command_code: u8, hit_count: u32) {
    store(scope, fingerprint, command_code, CacheState::Pending, hit_count, None);
}

fn store(
    scope: &CacheScope,
    fingerprint: FingerprintId,
    command_code: u8,
    state: CacheState,
    hit_count: u32,
    generation: Option<u64>,
) {
    unsafe {
        if CACHE.is_null() {
            return;
        }
        let now = pg_sys::GetCurrentTimestamp();
        let mut set = SetGuard::lock(CACHE, set_index(scope, &fingerprint, command_code));
        if generation.is_some_and(|observed| observed != current_generation(CACHE, scope.db_oid)) {
            return;
        }
        let value = CacheEntry {
            fingerprint,
            role_name_hash: scope.role_name_hash,
            generation: generation.unwrap_or(0),
            last_seen: now,
            role_oid: scope.role_oid,
            db_oid: scope.db_oid,
            extension_oid: scope.extension_oid,
            hit_count,
            command_code,
            state: state as u8,
            learned: generation.is_none(),
        };
        let entries = set.entries();
        let index = entries
            .iter()
            .position(|entry| entry.role_oid != pg_sys::InvalidOid && matches(entry, scope, fingerprint, command_code))
            .or_else(|| entries.iter().position(|entry| entry.role_oid == pg_sys::InvalidOid))
            .or_else(|| {
                entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.last_seen)
                    .map(|(index, _)| index)
            });
        if let Some(index) = index {
            set.write(index, value);
        }
    }
}

/// A policy commit in `db_oid` is visible: committed entries published
/// before it are no longer current. Learn-mode memos are not affected.
pub fn bump_generation(db_oid: pg_sys::Oid) {
    unsafe {
        if CACHE.is_null() {
            return;
        }
        (*CACHE).generations[generation_slot(db_oid)].fetch_add(1, Ordering::SeqCst);
    }
}

pub fn command_code(command: &str) -> u8 {
    match command {
        "SELECT" => 1,
        "INSERT" => 2,
        "UPDATE" => 3,
        "DELETE" => 4,
        // A wrapper and its inner plan share statement text (EXPLAIN ANALYZE
        // MERGE, COPY (MERGE ...)). Utility families are all 0, so MERGE needs
        // its own code or both checks would share one cache entry.
        "MERGE" => 5,
        _ => 0,
    }
}
