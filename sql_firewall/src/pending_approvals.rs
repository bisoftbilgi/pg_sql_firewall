// ============================================================================
// Firewall event ring
// ============================================================================
// One shared-memory ring for approvals, blocked queries, and fingerprint hits.
// Producers publish under a PostgreSQL spinlock. A position becomes visible
// only after its payload bytes are stored. Consumers copy a slot out under
// the same lock, so a later overwrite cannot change the returned snapshot.
//
// The ring overwrites the oldest slot once it is full. That is a reused slot,
// not a count of events lost for any one database. Layout changes require a
// postmaster restart; the extension version is unchanged.
//
// Learn observations (command approvals, and fingerprint hits with a learn
// threshold) are not published when the statement is inspected. They are
// held in backend memory with the subtransaction that made them and published
// only when the top-level transaction commits: a failed statement, a
// cancelled one, ROLLBACK, ROLLBACK TO SAVEPOINT, an exception block, and
// PREPARE TRANSACTION discard them. Records of rejected statements (blocked
// queries, enforce-mode pending fingerprints) are published at once, because
// their transaction is about to abort.

use pgrx::pg_sys;
use std::ptr;
#[cfg(feature = "queue_probe")]
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};

const ROLE_NAME_BYTES: usize = 64;
const COMMAND_TYPE_BYTES: usize = 32;
const DATABASE_NAME_BYTES: usize = 64;
const QUERY_BYTES: usize = 2048;
const APPLICATION_NAME_BYTES: usize = 256;
const CLIENT_ADDR_BYTES: usize = 64;
const REASON_BYTES: usize = 512;
const FINGERPRINT_HEX_BYTES: usize = 65;
const NORMALIZED_QUERY_BYTES: usize = 1024;
const SAMPLE_QUERY_BYTES: usize = 512;

/// Fixed ring length. Not a GUC. Changing it changes shared-memory size.
const RING_CAPACITY: usize = 1024;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    Approval = 1,
    BlockedQuery = 2,
    FingerprintHit = 3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ApprovalEvent {
    pub role_name: [u8; ROLE_NAME_BYTES],
    pub command_type: [u8; COMMAND_TYPE_BYTES],
    pub database_name: [u8; DATABASE_NAME_BYTES],
    pub is_approved: bool,
    /// The role the observation was made for. The worker discards the event
    /// if `role_name` no longer names this role (rename, drop and recreate).
    pub role_oid: u32,
    /// `sql_firewall_policy_epoch` in the snapshot of the policy lookup that
    /// produced this event (policy_visibility.rs).
    pub policy_epoch: i64,
    pub timestamp: pg_sys::TimestampTz,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BlockedQueryEvent {
    pub role_name: [u8; ROLE_NAME_BYTES],
    pub database_name: [u8; DATABASE_NAME_BYTES],
    pub query: [u8; QUERY_BYTES],
    pub query_truncated: bool,
    pub application_name: [u8; APPLICATION_NAME_BYTES],
    pub client_addr: [u8; CLIENT_ADDR_BYTES],
    pub command_type: [u8; COMMAND_TYPE_BYTES],
    pub reason: [u8; REASON_BYTES],
    pub notify_channel: [u8; 64],
    pub timestamp: pg_sys::TimestampTz,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FingerprintHitEvent {
    pub fingerprint_hex: [u8; FINGERPRINT_HEX_BYTES],
    pub normalized_query: [u8; NORMALIZED_QUERY_BYTES],
    pub role_name: [u8; ROLE_NAME_BYTES],
    pub command_type: [u8; COMMAND_TYPE_BYTES],
    pub sample_query: [u8; SAMPLE_QUERY_BYTES],
    /// Zero records a pending hit; positive values promote in Learn mode at
    /// this persisted hit count. Carried with the event so worker GUCs cannot
    /// change the producer's policy decision.
    pub learn_threshold: u16,
    /// Observations of this identity that one committed transaction made in
    /// the same policy epoch (at least 1). The worker adds this many hits.
    pub hits: u32,
    /// As in [`ApprovalEvent`].
    pub role_oid: u32,
    /// As in [`ApprovalEvent`].
    pub policy_epoch: i64,
    pub timestamp: pg_sys::TimestampTz,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union FirewallEventData {
    pub approval: ApprovalEvent,
    pub blocked_query: BlockedQueryEvent,
    pub fingerprint_hit: FingerprintHitEvent,
}

/// Owned copy of one published event. It does not alias shared memory.
#[derive(Copy, Clone)]
pub struct PublishedEvent {
    pub event_type: EventType,
    pub db_oid: pg_sys::Oid,
    /// `pg_extension.oid` of the installation that published the event.
    pub extension_oid: pg_sys::Oid,
    pub data: FirewallEventData,
}

pub enum ReadOutcome {
    /// `pos` is published and this value is a private copy of that publication.
    Ready(PublishedEvent),
    /// `pos` is at or beyond the published counter. Nothing has been stored there.
    NotYetPublished,
    /// `pos` is older than the retained window. Resume at `retained_from`.
    Overwritten { retained_from: u64 },
    /// Shared memory is not attached, or the ring was not initialized.
    Unavailable,
}

/// Text taken from a fixed field. Empty is a real value, not a failed decode.
pub enum DecodedField {
    Empty,
    Text(String),
    Invalid,
}

#[repr(C)]
struct FirewallEventRing {
    lock: pg_sys::slock_t,
    _pad: [u8; 7],
    /// Publications since this postmaster attached the ring. One unit is one
    /// published event. It is not reset when a worker exits.
    write_pos: u64,
    /// Publications that replaced a slot which already held an event. One unit
    /// is one reused slot. A reuse does not mean a worker had not yet read it,
    /// and it is not a per-database loss count.
    slot_overwrites: u64,
    capacity: u32,
    _pad2: u32,
    /// Identifies this shared-memory ring. Stable until the segment is
    /// recreated. Not a PID and not the write counter.
    generation: u64,
    /// Publications per event type (approval, blocked query, fingerprint hit)
    /// since the ring was created, cluster-wide. Updated under `lock`.
    published: [u64; 3],
    /// Learn observations a backend dropped because its transaction already
    /// held [`MAX_DEFERRED_LEARN`] distinct ones. Updated under `lock`.
    learn_dropped: u64,
    /// Test builds only. Workers observe these fields outside the queue lock.
    /// `probe_epoch` identifies one hold request. An acknowledgement matches
    /// only that epoch, target pid, and target database.
    #[cfg(feature = "queue_probe")]
    probe_hold: AtomicU8,
    #[cfg(feature = "queue_probe")]
    _probe_pad: [u8; 7],
    #[cfg(feature = "queue_probe")]
    probe_epoch: AtomicU64,
    #[cfg(feature = "queue_probe")]
    probe_target_pid: AtomicI32,
    #[cfg(feature = "queue_probe")]
    probe_target_db: AtomicU32,
    #[cfg(feature = "queue_probe")]
    probe_ack_epoch: AtomicU64,
    #[cfg(feature = "queue_probe")]
    probe_ack_pid: AtomicI32,
    #[cfg(feature = "queue_probe")]
    probe_ack_db: AtomicU32,
    #[cfg(feature = "queue_probe")]
    probe_exit_after_commit: AtomicU8,
    #[cfg(feature = "queue_probe")]
    probe_fail_before_checkpoint: AtomicU8,
}

/// Plain slot. `sequence` is `position + 1`, so zeroed memory is not an event.
#[repr(C)]
struct StoredSlot {
    sequence: u64,
    event_type: u8,
    _pad: [u8; 3],
    db_oid: pg_sys::Oid,
    extension_oid: pg_sys::Oid,
    data: FirewallEventData,
}

struct EncodedApproval {
    role_name: [u8; ROLE_NAME_BYTES],
    command_type: [u8; COMMAND_TYPE_BYTES],
    database_name: [u8; DATABASE_NAME_BYTES],
    is_approved: bool,
    role_oid: u32,
    policy_epoch: i64,
    timestamp: pg_sys::TimestampTz,
}

struct EncodedBlocked {
    role_name: [u8; ROLE_NAME_BYTES],
    database_name: [u8; DATABASE_NAME_BYTES],
    query: [u8; QUERY_BYTES],
    query_truncated: bool,
    application_name: [u8; APPLICATION_NAME_BYTES],
    client_addr: [u8; CLIENT_ADDR_BYTES],
    command_type: [u8; COMMAND_TYPE_BYTES],
    reason: [u8; REASON_BYTES],
    notify_channel: [u8; 64],
    timestamp: pg_sys::TimestampTz,
}

struct EncodedFingerprint {
    fingerprint_hex: [u8; FINGERPRINT_HEX_BYTES],
    normalized_query: [u8; NORMALIZED_QUERY_BYTES],
    role_name: [u8; ROLE_NAME_BYTES],
    command_type: [u8; COMMAND_TYPE_BYTES],
    sample_query: [u8; SAMPLE_QUERY_BYTES],
    learn_threshold: u16,
    hits: u32,
    role_oid: u32,
    policy_epoch: i64,
    timestamp: pg_sys::TimestampTz,
}

struct PreparedEvent {
    db_oid: pg_sys::Oid,
    extension_oid: pg_sys::Oid,
    body: EncodedEvent,
}

enum EncodedEvent {
    Approval(EncodedApproval),
    Blocked(EncodedBlocked),
    Fingerprint(EncodedFingerprint),
}

pub(crate) fn current_extension_oid() -> Option<pg_sys::Oid> {
    crate::activation::installed_extension_oid()
}

/// Random bytes from PostgreSQL. Called while initializing shared memory,
/// before the ring spinlock exists.
fn new_ring_generation() -> u64 {
    let mut bytes = [0u8; 8];
    let ok = unsafe { pg_sys::pg_strong_random(bytes.as_mut_ptr().cast(), bytes.len()) };
    if !ok {
        pgrx::error!("sql_firewall: could not initialize the ring generation");
    }
    u64::from_ne_bytes(bytes)
}

#[cfg(feature = "queue_probe")]
unsafe fn reset_probe_hold() {
    let ring = &mut *EVENT_RING;
    ring.probe_hold = AtomicU8::new(0);
    ring.probe_epoch = AtomicU64::new(0);
    ring.probe_target_pid = AtomicI32::new(0);
    ring.probe_target_db = AtomicU32::new(0);
    ring.probe_ack_epoch = AtomicU64::new(0);
    ring.probe_ack_pid = AtomicI32::new(0);
    ring.probe_ack_db = AtomicU32::new(0);
    ring.probe_exit_after_commit = AtomicU8::new(0);
    ring.probe_fail_before_checkpoint = AtomicU8::new(0);
}

#[cfg(not(feature = "queue_probe"))]
fn reset_probe_hold() {}

static mut EVENT_RING: *mut FirewallEventRing = ptr::null_mut();
static mut EVENT_SLOTS: *mut StoredSlot = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<FirewallEventRing>() + RING_CAPACITY * std::mem::size_of::<StoredSlot>()
}

pub(crate) unsafe fn init() {
    // Runs in every shared-memory initialization, including the postmaster's
    // reinitialization after a crash: the segment is new, so the pointer is
    // always taken from ShmemInitStruct and never kept from before.
    let size = shared_memory_bytes();
    let mut found = false;
    let ring_ptr = pg_sys::ShmemInitStruct(
        c"sql_firewall_event_ring".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut u8;

    if ring_ptr.is_null() {
        pgrx::error!("sql_firewall: failed to initialize firewall event ring");
    }

    EVENT_RING = ring_ptr as *mut FirewallEventRing;
    EVENT_SLOTS = ring_ptr.add(std::mem::size_of::<FirewallEventRing>()) as *mut StoredSlot;

    if found {
        pgrx::log!(
            "sql_firewall: event ring attached (capacity={})",
            (*EVENT_RING).capacity
        );
        return;
    }

    ptr::write_bytes(ring_ptr, 0, size);
    pg_sys::SpinLockInit(&mut (*EVENT_RING).lock);
    (*EVENT_RING).write_pos = 0;
    (*EVENT_RING).slot_overwrites = 0;
    (*EVENT_RING).published = [0; 3];
    (*EVENT_RING).learn_dropped = 0;
    (*EVENT_RING).capacity = RING_CAPACITY as u32;
    (*EVENT_RING).generation = new_ring_generation();
    reset_probe_hold();

    pgrx::log!(
        "sql_firewall: event ring allocated ({} bytes, capacity={})",
        size,
        RING_CAPACITY
    );
}

/// Required identity. The whole value must fit, including the trailing NUL.
/// A PostgreSQL name is at most 63 bytes, which fits these fields.
fn write_identity(value: &str, buffer: &mut [u8]) -> bool {
    let max = buffer.len().saturating_sub(1);
    if value.is_empty() || value.len() > max {
        return false;
    }
    buffer[..value.len()].copy_from_slice(value.as_bytes());
    buffer[value.len()..].fill(0);
    true
}

/// Descriptive text. Truncates only on a UTF-8 boundary and keeps the rest zero.
/// Returns whether the stored bytes are a shorter prefix of `value`.
fn write_text(value: &str, buffer: &mut [u8]) -> bool {
    let max = buffer.len().saturating_sub(1);
    let mut end = value.len().min(max);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    buffer[..end].copy_from_slice(&value.as_bytes()[..end]);
    buffer[end..].fill(0);
    end < value.len()
}

pub(crate) fn decode_field(bytes: &[u8]) -> DecodedField {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return DecodedField::Empty;
    }
    match std::str::from_utf8(&bytes[..end]) {
        Ok(text) => DecodedField::Text(text.to_string()),
        Err(_) => DecodedField::Invalid,
    }
}

/// Copy `slot` into an owned event. The caller must already hold the ring lock.
unsafe fn snapshot(slot: &StoredSlot) -> Option<PublishedEvent> {
    let event_type = match slot.event_type {
        1 => EventType::Approval,
        2 => EventType::BlockedQuery,
        3 => EventType::FingerprintHit,
        _ => return None,
    };
    let mut owned = PublishedEvent {
        event_type,
        db_oid: slot.db_oid,
        extension_oid: slot.extension_oid,
        data: std::mem::zeroed(),
    };
    // Bitwise copy of the stored payload. `owned` does not alias the slot.
    ptr::copy_nonoverlapping(&slot.data, &mut owned.data, 1);
    Some(owned)
}

unsafe fn publish(event: PreparedEvent) -> bool {
    if EVENT_RING.is_null() || EVENT_SLOTS.is_null() {
        pgrx::warning!("sql_firewall: event was not published; the ring is not attached");
        return false;
    }

    let ring = &mut *EVENT_RING;
    pg_sys::SpinLockAcquire(&mut ring.lock);
    let capacity = ring.capacity as u64;
    if capacity == 0 || ring.write_pos == u64::MAX {
        pg_sys::SpinLockRelease(&mut ring.lock);
        pgrx::warning!("sql_firewall: event was not published; the ring cannot accept it");
        return false;
    }

    let pos = ring.write_pos;
    let type_index = match &event.body {
        EncodedEvent::Approval(_) => 0,
        EncodedEvent::Blocked(_) => 1,
        EncodedEvent::Fingerprint(_) => 2,
    };
    ring.published[type_index] = ring.published[type_index].wrapping_add(1);
    let index = (pos as usize) % (capacity as usize);
    let slot = &mut *EVENT_SLOTS.add(index);
    if slot.sequence != 0 {
        ring.slot_overwrites = ring.slot_overwrites.wrapping_add(1);
    }

    let mut stored: StoredSlot = std::mem::zeroed();
    stored.sequence = pos + 1;
    stored.db_oid = event.db_oid;
    stored.extension_oid = event.extension_oid;
    match event.body {
        EncodedEvent::Approval(encoded) => {
            stored.event_type = EventType::Approval as u8;
            stored.data.approval = ApprovalEvent {
                role_name: encoded.role_name,
                command_type: encoded.command_type,
                database_name: encoded.database_name,
                is_approved: encoded.is_approved,
                role_oid: encoded.role_oid,
                policy_epoch: encoded.policy_epoch,
                timestamp: encoded.timestamp,
            };
        }
        EncodedEvent::Blocked(encoded) => {
            stored.event_type = EventType::BlockedQuery as u8;
            stored.data.blocked_query = BlockedQueryEvent {
                role_name: encoded.role_name,
                database_name: encoded.database_name,
                query: encoded.query,
                query_truncated: encoded.query_truncated,
                application_name: encoded.application_name,
                client_addr: encoded.client_addr,
                command_type: encoded.command_type,
                reason: encoded.reason,
                notify_channel: encoded.notify_channel,
                timestamp: encoded.timestamp,
            };
        }
        EncodedEvent::Fingerprint(encoded) => {
            stored.event_type = EventType::FingerprintHit as u8;
            stored.data.fingerprint_hit = FingerprintHitEvent {
                fingerprint_hex: encoded.fingerprint_hex,
                normalized_query: encoded.normalized_query,
                role_name: encoded.role_name,
                command_type: encoded.command_type,
                sample_query: encoded.sample_query,
                learn_threshold: encoded.learn_threshold,
                hits: encoded.hits,
                role_oid: encoded.role_oid,
                policy_epoch: encoded.policy_epoch,
                timestamp: encoded.timestamp,
            };
        }
    }
    ptr::write(slot, stored);
    ring.write_pos = pos + 1;
    pg_sys::SpinLockRelease(&mut ring.lock);
    true
}

/// `policy_epoch` must come from the same snapshot as the policy lookup that
/// decided to publish this approval; see policy_visibility.rs.
pub(crate) fn enqueue_approval(
    role_name: &str,
    role_oid: pg_sys::Oid,
    command_type: &str,
    database_name: &str,
    is_approved: bool,
    policy_epoch: i64,
) -> bool {
    let mut encoded = EncodedApproval {
        role_name: [0; ROLE_NAME_BYTES],
        command_type: [0; COMMAND_TYPE_BYTES],
        database_name: [0; DATABASE_NAME_BYTES],
        is_approved,
        role_oid: u32::from(role_oid),
        policy_epoch,
        timestamp: unsafe { pg_sys::GetCurrentTimestamp() },
    };
    if !write_identity(role_name, &mut encoded.role_name)
        || !write_identity(command_type, &mut encoded.command_type)
    {
        pgrx::warning!(
            "sql_firewall: approval was not published; role or command does not fit the fixed field"
        );
        return false;
    }
    if !write_identity(database_name, &mut encoded.database_name) {
        // Descriptive only. An empty or oversized name must not change the role
        // or command that identify the approval.
        encoded.database_name = [0; DATABASE_NAME_BYTES];
        if !database_name.is_empty() {
            pgrx::warning!(
                "sql_firewall: approval database name omitted; it does not fit the fixed field"
            );
        }
    }
    unsafe {
        let Some(extension_oid) = current_extension_oid() else {
            pgrx::warning!("sql_firewall: approval was not published; sql_firewall is not installed");
            return false;
        };
        let deferred = defer_learn(PreparedEvent {
            db_oid: pg_sys::MyDatabaseId,
            extension_oid,
            body: EncodedEvent::Approval(encoded),
        });
        if deferred {
            crate::policy_visibility::note_learn_observation(crate::policy_visibility::PolicyTable::Approvals);
        }
        deferred
    }
}

pub(crate) fn enqueue_blocked_query(
    role_name: &str,
    database_name: &str,
    query: &str,
    application_name: Option<&str>,
    client_addr: Option<&str>,
    command_type: &str,
    reason: Option<&str>,
    notify_channel: Option<&str>,
) -> bool {
    let mut encoded = EncodedBlocked {
        role_name: [0; ROLE_NAME_BYTES],
        database_name: [0; DATABASE_NAME_BYTES],
        query: [0; QUERY_BYTES],
        query_truncated: false,
        application_name: [0; APPLICATION_NAME_BYTES],
        client_addr: [0; CLIENT_ADDR_BYTES],
        command_type: [0; COMMAND_TYPE_BYTES],
        reason: [0; REASON_BYTES],
        notify_channel: [0; 64],
        timestamp: unsafe { pg_sys::GetCurrentTimestamp() },
    };
    if !write_identity(role_name, &mut encoded.role_name)
        || !write_identity(database_name, &mut encoded.database_name)
        || !write_identity(command_type, &mut encoded.command_type)
    {
        pgrx::warning!(
            "sql_firewall: blocked query was not published; role, database, or command does not fit the fixed field"
        );
        return false;
    }
    encoded.query_truncated = write_text(query, &mut encoded.query);
    if let Some(app) = application_name {
        write_text(app, &mut encoded.application_name);
    }
    if let Some(addr) = client_addr {
        write_text(addr, &mut encoded.client_addr);
    }
    if let Some(reason) = reason {
        write_text(reason, &mut encoded.reason);
    }
    if let Some(channel) = notify_channel {
        if !write_identity(channel, &mut encoded.notify_channel) {
            pgrx::warning!("sql_firewall: alert channel is invalid or exceeds 63 bytes; block event will be persisted without NOTIFY");
        }
    }
    unsafe {
        let Some(extension_oid) = current_extension_oid() else {
            pgrx::warning!(
                "sql_firewall: blocked query was not published; sql_firewall is not installed"
            );
            return false;
        };
        publish(PreparedEvent {
            db_oid: pg_sys::MyDatabaseId,
            extension_oid,
            body: EncodedEvent::Blocked(encoded),
        })
    }
}

/// `policy_epoch` as in [`enqueue_approval`].
pub(crate) fn enqueue_fingerprint(
    fingerprint_hex: &str,
    normalized_query: &str,
    role_name: &str,
    role_oid: pg_sys::Oid,
    command_type: &str,
    sample_query: &str,
    learn_threshold: u16,
    policy_epoch: i64,
) -> bool {
    let mut encoded = EncodedFingerprint {
        fingerprint_hex: [0; FINGERPRINT_HEX_BYTES],
        normalized_query: [0; NORMALIZED_QUERY_BYTES],
        role_name: [0; ROLE_NAME_BYTES],
        command_type: [0; COMMAND_TYPE_BYTES],
        sample_query: [0; SAMPLE_QUERY_BYTES],
        learn_threshold,
        hits: 1,
        role_oid: u32::from(role_oid),
        policy_epoch,
        timestamp: unsafe { pg_sys::GetCurrentTimestamp() },
    };
    if !write_identity(fingerprint_hex, &mut encoded.fingerprint_hex)
        || !write_identity(role_name, &mut encoded.role_name)
        || !write_identity(command_type, &mut encoded.command_type)
    {
        pgrx::warning!(
            "sql_firewall: fingerprint was not published; fingerprint, role, or command does not fit the fixed field"
        );
        return false;
    }
    write_text(normalized_query, &mut encoded.normalized_query);
    write_text(sample_query, &mut encoded.sample_query);
    unsafe {
        let Some(extension_oid) = current_extension_oid() else {
            pgrx::warning!(
                "sql_firewall: fingerprint was not published; sql_firewall is not installed"
            );
            return false;
        };
        let event = PreparedEvent {
            db_oid: pg_sys::MyDatabaseId,
            extension_oid,
            body: EncodedEvent::Fingerprint(encoded),
        };
        let published = if learn_threshold > 0 {
            defer_learn(event)
        } else {
            publish(event)
        };
        if published {
            crate::policy_visibility::note_learn_observation(crate::policy_visibility::PolicyTable::Fingerprints);
        }
        published
    }
}

/// Distinct learn observations one transaction may hold. The ring holds as
/// many events; publishing more at one commit would overwrite this
/// transaction's own events before a worker could read them.
const MAX_DEFERRED_LEARN: usize = RING_CAPACITY;

struct DeferredLearn {
    subid: pg_sys::SubTransactionId,
    event: PreparedEvent,
}

thread_local! {
    static DEFERRED_LEARN: std::cell::RefCell<Vec<DeferredLearn>> = const { std::cell::RefCell::new(Vec::new()) };
    static LEARN_FULL_WARNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Merges `event` into `held` when both are the same observation: the same
/// command approval (keeping the later epoch, whose lookup saw more
/// administrator decisions), or the same fingerprint hit in the same epoch
/// (adding the hits). Returns the event back when they differ.
fn merge_observation(held: &mut PreparedEvent, event: PreparedEvent) -> Option<PreparedEvent> {
    if held.db_oid != event.db_oid || held.extension_oid != event.extension_oid {
        return Some(event);
    }
    match (&mut held.body, &event.body) {
        (EncodedEvent::Approval(a), EncodedEvent::Approval(b))
            if a.role_oid == b.role_oid
                && a.role_name == b.role_name
                && a.command_type == b.command_type
                && a.is_approved == b.is_approved =>
        {
            a.policy_epoch = a.policy_epoch.max(b.policy_epoch);
            None
        }
        (EncodedEvent::Fingerprint(a), EncodedEvent::Fingerprint(b))
            if a.fingerprint_hex == b.fingerprint_hex
                && a.role_oid == b.role_oid
                && a.role_name == b.role_name
                && a.command_type == b.command_type
                && a.learn_threshold == b.learn_threshold
                && a.policy_epoch == b.policy_epoch =>
        {
            a.hits = a.hits.saturating_add(b.hits);
            None
        }
        _ => Some(event),
    }
}

/// Holds a learn observation until the top-level transaction commits. `false`
/// when it cannot be held (this transaction already holds the maximum).
fn defer_learn(event: PreparedEvent) -> bool {
    let subid = unsafe { pg_sys::GetCurrentSubTransactionId() };
    DEFERRED_LEARN.with(|cell| {
        let mut held = cell.borrow_mut();
        let mut event = event;
        for entry in held.iter_mut().filter(|entry| entry.subid == subid) {
            match merge_observation(&mut entry.event, event) {
                None => return true,
                Some(back) => event = back,
            }
        }
        if held.len() >= MAX_DEFERRED_LEARN {
            unsafe {
                if !EVENT_RING.is_null() {
                    let ring = &mut *EVENT_RING;
                    pg_sys::SpinLockAcquire(&mut ring.lock);
                    ring.learn_dropped = ring.learn_dropped.wrapping_add(1);
                    pg_sys::SpinLockRelease(&mut ring.lock);
                }
            }
            if !LEARN_FULL_WARNED.with(|warned| warned.replace(true)) {
                pgrx::warning!(
                    "sql_firewall: this transaction already holds {MAX_DEFERRED_LEARN} distinct learn observations; further ones are not recorded"
                );
            }
            return false;
        }
        held.push(DeferredLearn { subid, event });
        true
    })
}

/// Subtransaction end: a commit hands its observations to the parent, an
/// abort discards them.
pub(crate) fn learn_at_subxact_end(
    commit: bool,
    subid: pg_sys::SubTransactionId,
    parent: pg_sys::SubTransactionId,
) {
    DEFERRED_LEARN.with(|cell| {
        let Ok(mut held) = cell.try_borrow_mut() else {
            return;
        };
        if !held.iter().any(|entry| entry.subid == subid) {
            return;
        }
        let (mine, mut rest): (Vec<_>, Vec<_>) = held.drain(..).partition(|entry| entry.subid == subid);
        if commit {
            'next: for entry in mine {
                let mut event = entry.event;
                for kept in rest.iter_mut().filter(|kept| kept.subid == parent) {
                    match merge_observation(&mut kept.event, event) {
                        None => continue 'next,
                        Some(back) => event = back,
                    }
                }
                rest.push(DeferredLearn { subid: parent, event });
            }
        }
        *held = rest;
    });
}

/// `XACT_EVENT_COMMIT`: the transaction is durable. Publishes its learn
/// observations in the order they were first made.
pub(crate) fn learn_at_commit() {
    let held = DEFERRED_LEARN.with(|cell| cell.try_borrow_mut().map(|mut held| std::mem::take(&mut *held)));
    LEARN_FULL_WARNED.with(|warned| warned.set(false));
    let Ok(held) = held else {
        return;
    };
    for entry in held {
        unsafe {
            publish(entry.event);
        }
    }
}

/// Abort and PREPARE: nothing is published. A prepared transaction's outcome
/// is decided later, possibly by another session, so its observations are
/// not counted.
pub(crate) fn learn_at_abort() {
    DEFERRED_LEARN.with(|cell| {
        if let Ok(mut held) = cell.try_borrow_mut() {
            held.clear();
        }
    });
    LEARN_FULL_WARNED.with(|warned| warned.set(false));
}

/// Cluster-wide ring counters since the ring was created.
pub(crate) struct QueueStatistics {
    pub write_position: u64,
    pub slot_overwrites: u64,
    pub capacity: u64,
    pub published: [u64; 3],
    pub learn_dropped: u64,
}

pub(crate) fn queue_statistics() -> Option<QueueStatistics> {
    unsafe {
        if EVENT_RING.is_null() {
            return None;
        }
        let ring = &mut *EVENT_RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let stats = QueueStatistics {
            write_position: ring.write_pos,
            slot_overwrites: ring.slot_overwrites,
            capacity: ring.capacity as u64,
            published: ring.published,
            learn_dropped: ring.learn_dropped,
        };
        pg_sys::SpinLockRelease(&mut ring.lock);
        Some(stats)
    }
}

pub(crate) struct RingView {
    pub generation: u64,
    pub write_pos: u64,
    pub oldest: u64,
}

pub(crate) fn ring_view() -> Option<RingView> {
    unsafe {
        if EVENT_RING.is_null() {
            return None;
        }
        let ring = &mut *EVENT_RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let write_pos = ring.write_pos;
        let capacity = ring.capacity as u64;
        let generation = ring.generation;
        pg_sys::SpinLockRelease(&mut ring.lock);
        if capacity == 0 {
            return None;
        }
        let oldest = if write_pos > capacity {
            write_pos - capacity
        } else {
            0
        };
        Some(RingView {
            generation,
            write_pos,
            oldest,
        })
    }
}

#[allow(dead_code)]
pub(crate) fn get_write_pos() -> u64 {
    unsafe {
        if EVENT_RING.is_null() {
            return 0;
        }
        let ring = &mut *EVENT_RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let pos = ring.write_pos;
        pg_sys::SpinLockRelease(&mut ring.lock);
        pos
    }
}

/// Read `pos`. In-progress publications are invisible: `write_pos` moves only
/// after the slot is stored, and both happen under the ring lock.
pub(crate) fn read_at(pos: u64) -> ReadOutcome {
    unsafe {
        if EVENT_RING.is_null() || EVENT_SLOTS.is_null() {
            return ReadOutcome::Unavailable;
        }
        let ring = &mut *EVENT_RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let capacity = ring.capacity as u64;
        if capacity == 0 {
            pg_sys::SpinLockRelease(&mut ring.lock);
            return ReadOutcome::Unavailable;
        }
        let write_pos = ring.write_pos;
        if pos >= write_pos {
            pg_sys::SpinLockRelease(&mut ring.lock);
            return ReadOutcome::NotYetPublished;
        }
        let oldest = if write_pos > capacity {
            write_pos - capacity
        } else {
            0
        };
        if pos < oldest {
            pg_sys::SpinLockRelease(&mut ring.lock);
            return ReadOutcome::Overwritten {
                retained_from: oldest,
            };
        }
        let slot = ptr::read(EVENT_SLOTS.add((pos as usize) % (capacity as usize)));
        pg_sys::SpinLockRelease(&mut ring.lock);

        if slot.sequence != pos + 1 {
            return ReadOutcome::Overwritten {
                retained_from: oldest,
            };
        }
        match snapshot(&slot) {
            Some(event) => ReadOutcome::Ready(event),
            None => ReadOutcome::Overwritten {
                retained_from: oldest,
            },
        }
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) struct ProbeHoldView {
    pub held: bool,
    pub epoch: u64,
    pub target_pid: i32,
    pub target_db: u32,
    pub ack_epoch: u64,
    pub ack_pid: i32,
    pub ack_db: u32,
}

#[cfg(feature = "queue_probe")]
pub(crate) fn publish_invalid_approval() -> bool {
    let mut role_name = [0u8; ROLE_NAME_BYTES];
    role_name[0] = 0xFF;
    let mut command_type = [0u8; COMMAND_TYPE_BYTES];
    command_type[..6].copy_from_slice(b"SELECT");
    let mut database_name = [0u8; DATABASE_NAME_BYTES];
    database_name[..1].copy_from_slice(b"x");
    unsafe {
        let Some(extension_oid) = current_extension_oid() else {
            return false;
        };
        publish(PreparedEvent {
            db_oid: pg_sys::MyDatabaseId,
            extension_oid,
            body: EncodedEvent::Approval(EncodedApproval {
                role_name,
                command_type,
                database_name,
                is_approved: true,
                role_oid: 0,
                policy_epoch: 0,
                timestamp: pg_sys::GetCurrentTimestamp(),
            }),
        })
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn set_probe_hold(hold: bool) {
    unsafe {
        if EVENT_RING.is_null() {
            return;
        }
        (*EVENT_RING)
            .probe_hold
            .store(u8::from(hold), Ordering::Release);
    }
}

/// Start a new hold request for one worker. The epoch is stored before the
/// hold flag, so a worker that observes the flag also observes this request.
/// Returns 0 when the ring is not attached.
#[cfg(feature = "queue_probe")]
pub(crate) fn arm_probe_hold(pid: i32, db: u32) -> u64 {
    unsafe {
        if EVENT_RING.is_null() || pid <= 0 {
            return 0;
        }
        let ring = &*EVENT_RING;
        let epoch = ring.probe_epoch.fetch_add(1, Ordering::Release) + 1;
        ring.probe_target_pid.store(pid, Ordering::Release);
        ring.probe_target_db.store(db, Ordering::Release);
        ring.probe_hold.store(1, Ordering::Release);
        epoch
    }
}

/// Called only from the consumer's hold branch, before it waits and before
/// `read_at`. Another worker, or an acknowledgement of an older epoch, does
/// not update the matching epoch.
#[cfg(feature = "queue_probe")]
pub(crate) fn acknowledge_probe_hold() {
    unsafe {
        if EVENT_RING.is_null() {
            return;
        }
        let ring = &*EVENT_RING;
        if ring.probe_hold.load(Ordering::Acquire) == 0 {
            return;
        }
        let epoch = ring.probe_epoch.load(Ordering::Acquire);
        let target_pid = ring.probe_target_pid.load(Ordering::Acquire);
        let target_db = ring.probe_target_db.load(Ordering::Acquire);
        let pid = pg_sys::MyProcPid;
        let db = u32::from(pg_sys::MyDatabaseId);
        if epoch == 0 || pid != target_pid || db != target_db {
            return;
        }
        ring.probe_ack_pid.store(pid, Ordering::Release);
        ring.probe_ack_db.store(db, Ordering::Release);
        ring.probe_ack_epoch.store(epoch, Ordering::Release);
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn probe_hold_view() -> Option<ProbeHoldView> {
    unsafe {
        if EVENT_RING.is_null() {
            return None;
        }
        let ring = &*EVENT_RING;
        let ack_epoch = ring.probe_ack_epoch.load(Ordering::Acquire);
        Some(ProbeHoldView {
            held: ring.probe_hold.load(Ordering::Acquire) != 0,
            epoch: ring.probe_epoch.load(Ordering::Acquire),
            target_pid: ring.probe_target_pid.load(Ordering::Acquire),
            target_db: ring.probe_target_db.load(Ordering::Acquire),
            ack_epoch,
            ack_pid: ring.probe_ack_pid.load(Ordering::Acquire),
            ack_db: ring.probe_ack_db.load(Ordering::Acquire),
        })
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn set_probe_exit_after_commit(enabled: bool) {
    unsafe {
        if !EVENT_RING.is_null() {
            (*EVENT_RING)
                .probe_exit_after_commit
                .store(u8::from(enabled), Ordering::Release);
        }
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn probe_exit_after_commit() -> bool {
    unsafe {
        if EVENT_RING.is_null() {
            return false;
        }
        (*EVENT_RING)
            .probe_exit_after_commit
            .swap(0, Ordering::AcqRel)
            != 0
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn set_probe_fail_before_checkpoint(enabled: bool) {
    unsafe {
        if !EVENT_RING.is_null() {
            (*EVENT_RING)
                .probe_fail_before_checkpoint
                .store(u8::from(enabled), Ordering::Release);
        }
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn probe_fail_before_checkpoint() -> bool {
    unsafe {
        !EVENT_RING.is_null()
            && (*EVENT_RING)
                .probe_fail_before_checkpoint
                .load(Ordering::Acquire)
                != 0
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn probe_consumers_held() -> bool {
    unsafe {
        if EVENT_RING.is_null() {
            return false;
        }
        (*EVENT_RING).probe_hold.load(Ordering::Acquire) != 0
    }
}

#[cfg(feature = "queue_probe")]
pub(crate) fn probe_stats() -> (u64, u64, u64) {
    unsafe {
        if EVENT_RING.is_null() {
            return (0, 0, 0);
        }
        let ring = &mut *EVENT_RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let stats = (ring.write_pos, ring.slot_overwrites, ring.capacity as u64);
        pg_sys::SpinLockRelease(&mut ring.lock);
        stats
    }
}
