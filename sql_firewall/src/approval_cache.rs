use pgrx::pg_sys;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::policy_visibility::CacheScope;
use crate::seqlock::{self, Sequence};

// Shared cache for command approvals (role + command -> approved boolean).
// Saves an SPI lookup per statement. Entries are committed policy only; see
// policy_visibility.rs for when they may be read and published.
//
// Every inspected statement reads this cache, and the busiest key (one
// application role, one command) is read by every backend at once, so reads
// take no lock: the per-database generations are atomics, and an entry is
// stored as atomic words and read under its partition's sequence counter
// (seqlock.rs). Writers, which are rare (a miss, a TTL expiry), hold one of
// LOCK_PARTITIONS spinlocks, each on its own cache line, and make the
// counter odd while they write. A publish compares the generation under its
// partition lock; a bump that lands after that comparison leaves the entry
// stamped with the older generation, which no reader will use.

const APPROVAL_CACHE_SIZE: usize = 1024; // 1K entries should cover most active roles
/// Generations are kept per database slot. Databases that share a slot
/// invalidate each other's entries, which costs lookups, never correctness.
const GENERATION_SLOTS: usize = 256;
/// Command families are short upper-case words; longer text is not cached.
const COMMAND_BYTES: usize = 16;
const LOCK_PARTITIONS: usize = 64;

#[derive(Copy, Clone)]
struct ApprovalEntry {
    generation: u64,
    role_name_hash: u64,
    timestamp: i64, // Defense in depth only; correctness uses the generation.
    role_oid: pg_sys::Oid,
    // SECURITY: approvals live in per-database catalog tables, but this cache is
    // cluster-wide shared memory. Without the database in the key, an approval
    // granted in database A silently authorised the same role in database B.
    db_oid: pg_sys::Oid,
    // A new installation (DROP/CREATE EXTENSION) is a new policy identity.
    extension_oid: pg_sys::Oid,
    command: [u8; COMMAND_BYTES],
    command_len: u8,
    is_approved: bool,
    in_use: bool,
}

impl Default for ApprovalEntry {
    fn default() -> Self {
        Self {
            generation: 0,
            role_name_hash: 0,
            timestamp: 0,
            role_oid: pg_sys::InvalidOid,
            db_oid: pg_sys::InvalidOid,
            extension_oid: pg_sys::InvalidOid,
            command: [0; COMMAND_BYTES],
            command_len: 0,
            is_approved: false,
            in_use: false,
        }
    }
}

/// Words of one stored entry (see `ApprovalEntry::encode`).
const ENTRY_WORDS: usize = 7;

impl ApprovalEntry {
    /// Field layout: generation; role name hash; timestamp; role and
    /// database OIDs; extension OID, command length, flags; command bytes.
    fn encode(&self) -> [u64; ENTRY_WORDS] {
        let command: [u64; 2] = seqlock::bytes_to_words(&self.command);
        [
            self.generation,
            self.role_name_hash,
            self.timestamp as u64,
            seqlock::pack_u32s(u32::from(self.role_oid), u32::from(self.db_oid)),
            u64::from(u32::from(self.extension_oid))
                | (u64::from(self.command_len) << 32)
                | (u64::from(self.is_approved) << 40)
                | (u64::from(self.in_use) << 41),
            command[0],
            command[1],
        ]
    }

    fn decode(words: &[u64; ENTRY_WORDS]) -> Self {
        let (role_oid, db_oid) = seqlock::unpack_u32s(words[3]);
        Self {
            generation: words[0],
            role_name_hash: words[1],
            timestamp: words[2] as i64,
            role_oid: pg_sys::Oid::from(role_oid),
            db_oid: pg_sys::Oid::from(db_oid),
            extension_oid: pg_sys::Oid::from(words[4] as u32),
            command: seqlock::words_to_bytes(&words[5..7]),
            command_len: (words[4] >> 32) as u8,
            is_approved: (words[4] >> 40) & 1 == 1,
            in_use: (words[4] >> 41) & 1 == 1,
        }
    }
}

/// A spinlock and its write sequence, alone on their cache line.
#[repr(C, align(64))]
struct PartitionLock {
    lock: pg_sys::slock_t,
    sequence: Sequence,
}

#[repr(C)]
struct ApprovalCache {
    generations: [AtomicU64; GENERATION_SLOTS],
    locks: [PartitionLock; LOCK_PARTITIONS],
    entries: [[AtomicU64; ENTRY_WORDS]; APPROVAL_CACHE_SIZE],
}

/// Holds an entry's partition lock; released on every exit path.
struct EntryLock(*mut PartitionLock);

impl EntryLock {
    unsafe fn acquire(cache: *mut ApprovalCache, index: usize) -> Self {
        let partition = ptr::addr_of_mut!((*cache).locks[index % LOCK_PARTITIONS]);
        pg_sys::SpinLockAcquire(ptr::addr_of_mut!((*partition).lock));
        Self(partition)
    }

    /// Store `entry` at `index`, which is in this lock's partition.
    unsafe fn write(&self, cache: *mut ApprovalCache, index: usize, entry: ApprovalEntry) {
        (*self.0).sequence.write_locked(&(*cache).entries[index], 0, &entry.encode());
    }
}

impl Drop for EntryLock {
    fn drop(&mut self) {
        unsafe { pg_sys::SpinLockRelease(ptr::addr_of_mut!((*self.0).lock)) };
    }
}

/// A consistent copy of the entry at `index` without taking its lock. After
/// a few attempts overlapping a writer, it takes the lock.
unsafe fn read_entry(cache: *mut ApprovalCache, index: usize) -> ApprovalEntry {
    let partition = ptr::addr_of!((*cache).locks[index % LOCK_PARTITIONS]);
    let words = &(*cache).entries[index];
    for _ in 0..16 {
        if let Some(copy) = (*partition).sequence.try_read(words) {
            return ApprovalEntry::decode(&copy);
        }
        std::hint::spin_loop();
    }
    let _lock = EntryLock::acquire(cache, index);
    ApprovalEntry::decode(&Sequence::read_locked(words))
}

unsafe fn current_generation(cache: *mut ApprovalCache, db_oid: pg_sys::Oid) -> u64 {
    (*cache).generations[generation_slot(db_oid)].load(Ordering::SeqCst)
}

static mut CACHE: *mut ApprovalCache = ptr::null_mut();

const CACHE_TTL_SECONDS: i64 = 60;

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<ApprovalCache>()
}

pub fn initialize() {
    unsafe {
        // Runs in every shared-memory initialization, including the postmaster's
        // reinitialization after a crash: the segment is new, so the pointer is
        // always taken from ShmemInitStruct and never kept from before.
        let size = std::mem::size_of::<ApprovalCache>();
        let mut found = false;
        let cache_ptr = pg_sys::ShmemInitStruct(
            c"sql_firewall_approval_cache".as_ptr(),
            size,
            &mut found,
        ) as *mut ApprovalCache;

        if cache_ptr.is_null() {
            pgrx::error!("sql_firewall: failed to initialize approval cache");
        }

        if !found {
            for generation in (*cache_ptr).generations.iter_mut() {
                ptr::write(generation, AtomicU64::new(1));
            }
            for partition in (*cache_ptr).locks.iter_mut() {
                pg_sys::SpinLockInit(&mut partition.lock);
                ptr::write(&mut partition.sequence, Sequence::new());
            }
            // All-zero words decode to the default (unused) entry.
            seqlock::zero(
                ptr::addr_of_mut!((*cache_ptr).entries).cast::<AtomicU64>(),
                APPROVAL_CACHE_SIZE * ENTRY_WORDS,
            );
            pgrx::log!(
                "sql_firewall: approval cache allocated ({} bytes, {} entries)",
                size,
                APPROVAL_CACHE_SIZE
            );
        } else {
            pgrx::log!("sql_firewall: approval cache attached");
        }

        CACHE = cache_ptr;
    }
}

fn hash_command(command: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for byte in command {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u32);
    }
    hash
}

fn get_current_timestamp() -> i64 {
    unsafe { pg_sys::GetCurrentTimestamp() }
}

fn generation_slot(db_oid: pg_sys::Oid) -> usize {
    (u32::from(db_oid) as usize) % GENERATION_SLOTS
}

/// Slot index mixes role and database so distinct principals do not evict each
/// other on every lookup (the old index used the command hash alone).
fn slot_index(role_oid: pg_sys::Oid, db_oid: pg_sys::Oid, command_hash: u32) -> usize {
    let mixed = command_hash
        .wrapping_mul(31)
        .wrapping_add(u32::from(role_oid).wrapping_mul(2654435761))
        .wrapping_add(u32::from(db_oid).wrapping_mul(40503));
    (mixed as usize) % APPROVAL_CACHE_SIZE
}

fn command_key(command: &str) -> Option<([u8; COMMAND_BYTES], u8)> {
    let bytes = command.as_bytes();
    if bytes.is_empty() || bytes.len() > COMMAND_BYTES {
        return None;
    }
    let mut key = [0u8; COMMAND_BYTES];
    key[..bytes.len()].copy_from_slice(bytes);
    Some((key, bytes.len() as u8))
}

fn matches(entry: &ApprovalEntry, scope: &CacheScope, key: &[u8; COMMAND_BYTES], len: u8) -> bool {
    entry.in_use
        && entry.role_oid == scope.role_oid
        && entry.db_oid == scope.db_oid
        && entry.extension_oid == scope.extension_oid
        && entry.role_name_hash == scope.role_name_hash
        && entry.command_len == len
        && entry.command == *key
}

/// A committed decision for (installation, role, command) that is still
/// current: its generation is this database's generation now.
pub fn get_approval(scope: &CacheScope, command: &str) -> Option<bool> {
    let (key, len) = command_key(command)?;
    let now = get_current_timestamp();
    let ttl_micros = CACHE_TTL_SECONDS * 1_000_000;

    unsafe {
        if CACHE.is_null() {
            return None;
        }
        let index = slot_index(scope.role_oid, scope.db_oid, hash_command(&key[..len as usize]));
        let entry = read_entry(CACHE, index);
        let current = current_generation(CACHE, scope.db_oid);
        if matches(&entry, scope, &key, len) && entry.generation == current && now - entry.timestamp < ttl_micros {
            Some(entry.is_approved)
        } else {
            None
        }
    }
}

/// This database's generation. Read before taking the snapshot for the
/// catalog read whose result will be published with it.
pub fn generation(db_oid: pg_sys::Oid) -> u64 {
    unsafe {
        if CACHE.is_null() {
            return 0;
        }
        current_generation(CACHE, db_oid)
    }
}

/// Publish a committed decision read with a snapshot taken after
/// `generation` was read. Dropped if a policy commit in this database
/// advanced the generation since: that commit may not be in the snapshot.
pub fn publish(scope: &CacheScope, command: &str, is_approved: bool, generation: u64) {
    let Some((key, len)) = command_key(command) else {
        return;
    };
    let now = get_current_timestamp();

    unsafe {
        if CACHE.is_null() {
            return;
        }
        let index = slot_index(scope.role_oid, scope.db_oid, hash_command(&key[..len as usize]));
        let lock = EntryLock::acquire(CACHE, index);
        if current_generation(CACHE, scope.db_oid) == generation {
            lock.write(CACHE, index, ApprovalEntry {
                generation,
                role_name_hash: scope.role_name_hash,
                timestamp: now,
                role_oid: scope.role_oid,
                db_oid: scope.db_oid,
                extension_oid: scope.extension_oid,
                command: key,
                command_len: len,
                is_approved,
                in_use: true,
            });
        }
    }
}

/// A policy commit in `db_oid` is visible: every entry published before it
/// is no longer current.
pub fn bump_generation(db_oid: pg_sys::Oid) {
    unsafe {
        if CACHE.is_null() {
            return;
        }
        (*CACHE).generations[generation_slot(db_oid)].fetch_add(1, Ordering::SeqCst);
    }
}

/// Test-only (policy_probe): the entry for (scope, command) whether or not it
/// is current, as (approved, entry generation), and this database's generation.
#[cfg(feature = "policy_probe")]
pub fn probe_entry(scope: &CacheScope, command: &str) -> (Option<(bool, u64)>, u64) {
    let Some((key, len)) = command_key(command) else {
        return (None, generation(scope.db_oid));
    };
    unsafe {
        if CACHE.is_null() {
            return (None, 0);
        }
        let index = slot_index(scope.role_oid, scope.db_oid, hash_command(&key[..len as usize]));
        let entry = read_entry(CACHE, index);
        let found = matches(&entry, scope, &key, len).then_some((entry.is_approved, entry.generation));
        (found, current_generation(CACHE, scope.db_oid))
    }
}

/// Invalidate all cache entries (manual reset; not needed for correctness)
pub fn invalidate_all() {
    unsafe {
        if CACHE.is_null() {
            return;
        }

        for index in 0..APPROVAL_CACHE_SIZE {
            let lock = EntryLock::acquire(CACHE, index);
            lock.write(CACHE, index, ApprovalEntry::default());
        }
        pgrx::log!("sql_firewall: approval cache invalidated");
    }
}
