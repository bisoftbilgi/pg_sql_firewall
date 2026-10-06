// ============================================================================
// Activity queue
// ============================================================================
// Activity records (allowed statements, learn and permissive decisions) are
// published here when the firewall decides, and written to
// sql_firewall_activity_log by the database's approval worker. Nothing is
// written in the client's transaction, so a failing, full, or read-only
// audit write never changes the client's statement or commit, and a record
// stays after its transaction rolls back (README 6.7: a decision log).
//
// This ring is separate from the event ring (pending_approvals.rs): a burst of
// activity cannot overwrite a blocked-query record or a learn observation.
// Its capacity is sql_firewall.activity_queue_size (postmaster). The oldest
// slot is reused when the ring is full. Losses are counted, never silent:
//  - overwritten: a slot reused before every consumer had read it is not
//    known here; `consumer_skipped` counts the positions a consumer found no
//    longer retained (cluster-wide positions, not records of one database);
//  - rejected: records a consumer could not insert, after retries;
//  - publish_failed: records a backend could not publish (ring missing).
//
// Each database's consumer keeps its position in
// sql_firewall_activity_checkpoint, updated in the same transaction as the
// rows it inserts, so a restart neither repeats nor skips retained records.

use pgrx::pg_sys;
use pgrx::prelude::*;
use std::ptr;

use crate::sql::{bool_arg, name_arg, oid_carrier_arg, text_arg};
use crate::worker_persist::{self, PersistAttempt};

const ROLE_BYTES: usize = 64;
const DATABASE_BYTES: usize = 64;
const APPLICATION_BYTES: usize = 256;
const CLIENT_BYTES: usize = 64;
const COMMAND_BYTES: usize = 32;
const ACTION_BYTES: usize = 64;
const DECISION_BYTES: usize = 16;
const REASON_BYTES: usize = 512;
pub const QUERY_BYTES: usize = 2048;

/// Records one consumer transaction inserts.
const BATCH: u64 = 256;
/// Single-record attempts before a record that fails alone is skipped.
const POISON_ATTEMPTS: u32 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
struct Slot {
    /// position + 1; zero is an empty slot.
    sequence: u64,
    db_oid: u32,
    extension_oid: u32,
    timestamp: pg_sys::TimestampTz,
    query_truncated: bool,
    role: [u8; ROLE_BYTES],
    database: [u8; DATABASE_BYTES],
    application: [u8; APPLICATION_BYTES],
    client: [u8; CLIENT_BYTES],
    command: [u8; COMMAND_BYTES],
    action: [u8; ACTION_BYTES],
    decision: [u8; DECISION_BYTES],
    reason: [u8; REASON_BYTES],
    query: [u8; QUERY_BYTES],
}

#[repr(C)]
struct Ring {
    lock: pg_sys::slock_t,
    _pad: [u8; 7],
    write_pos: u64,
    overwrites: u64,
    generation: u64,
    capacity: u64,
    publish_failed: u64,
    consumer_skipped: u64,
    consumer_rejected: u64,
}

static mut RING: *mut Ring = ptr::null_mut();
static mut SLOTS: *mut Slot = ptr::null_mut();

fn configured_capacity() -> usize {
    crate::guc::activity_queue_size().max(64) as usize
}

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<Ring>() + configured_capacity() * std::mem::size_of::<Slot>()
}

pub(crate) unsafe fn init() {
    // Runs in every shared-memory initialization, including the postmaster's
    // reinitialization after a crash: the segment is new, so the pointer is
    // always taken from ShmemInitStruct and never kept from before.
    let capacity = configured_capacity();
    let size = std::mem::size_of::<Ring>() + capacity * std::mem::size_of::<Slot>();
    let mut found = false;
    let base = pg_sys::ShmemInitStruct(c"sql_firewall_activity_ring".as_ptr(), size, &mut found) as *mut u8;
    if base.is_null() {
        pgrx::error!("sql_firewall: failed to initialize the activity ring");
    }
    RING = base as *mut Ring;
    SLOTS = base.add(std::mem::size_of::<Ring>()) as *mut Slot;
    if found {
        return;
    }
    ptr::write_bytes(base, 0, size);
    pg_sys::SpinLockInit(&mut (*RING).lock);
    (*RING).capacity = capacity as u64;
    let mut bytes = [0u8; 8];
    if !pg_sys::pg_strong_random(bytes.as_mut_ptr().cast(), bytes.len()) {
        pgrx::error!("sql_firewall: could not initialize the activity ring generation");
    }
    (*RING).generation = u64::from_ne_bytes(bytes);
}

/// Descriptive text, cut on a UTF-8 boundary. Returns whether it was cut.
fn put(value: &str, buffer: &mut [u8]) -> bool {
    let max = buffer.len().saturating_sub(1);
    let mut end = value.len().min(max);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    buffer[..end].copy_from_slice(&value.as_bytes()[..end]);
    buffer[end..].fill(0);
    end < value.len()
}

fn get(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_string)
}

/// One decision, as the backend saw it when it decided.
pub struct Record<'a> {
    pub role: &'a str,
    pub database: &'a str,
    pub query: &'a str,
    pub application: Option<&'a str>,
    pub client: Option<&'a str>,
    pub command: &'a str,
    pub action: &'a str,
    pub decision: &'a str,
    pub reason: Option<&'a str>,
}

/// Publishes a record. Never raises: a record that cannot be published is
/// counted (or, without a ring, logged).
pub fn publish(record: &Record<'_>, extension_oid: pg_sys::Oid) {
    unsafe {
        if RING.is_null() || SLOTS.is_null() {
            pgrx::warning!("sql_firewall: activity record was not published; the activity ring is not attached");
            return;
        }
        let mut slot: Slot = std::mem::zeroed();
        slot.db_oid = u32::from(pg_sys::MyDatabaseId);
        slot.extension_oid = u32::from(extension_oid);
        slot.timestamp = pg_sys::GetCurrentTimestamp();
        put(record.role, &mut slot.role);
        put(record.database, &mut slot.database);
        put(record.application.unwrap_or(""), &mut slot.application);
        put(record.client.unwrap_or(""), &mut slot.client);
        put(record.command, &mut slot.command);
        put(record.action, &mut slot.action);
        put(record.decision, &mut slot.decision);
        put(record.reason.unwrap_or(""), &mut slot.reason);
        slot.query_truncated = put(record.query, &mut slot.query);

        let ring = &mut *RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        if ring.capacity == 0 || ring.write_pos == u64::MAX {
            ring.publish_failed = ring.publish_failed.wrapping_add(1);
            pg_sys::SpinLockRelease(&mut ring.lock);
            return;
        }
        let pos = ring.write_pos;
        let target = &mut *SLOTS.add((pos % ring.capacity) as usize);
        if target.sequence != 0 {
            ring.overwrites = ring.overwrites.wrapping_add(1);
        }
        slot.sequence = pos + 1;
        ptr::write(target, slot);
        ring.write_pos = pos + 1;
        pg_sys::SpinLockRelease(&mut ring.lock);
    }
}

pub(crate) struct Statistics {
    pub generation: u64,
    pub write_position: u64,
    pub overwrites: u64,
    pub capacity: u64,
    pub publish_failed: u64,
    pub consumer_skipped: u64,
    pub consumer_rejected: u64,
}

pub(crate) fn statistics() -> Option<Statistics> {
    unsafe {
        if RING.is_null() {
            return None;
        }
        let ring = &mut *RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let stats = Statistics {
            generation: ring.generation,
            write_position: ring.write_pos,
            overwrites: ring.overwrites,
            capacity: ring.capacity,
            publish_failed: ring.publish_failed,
            consumer_skipped: ring.consumer_skipped,
            consumer_rejected: ring.consumer_rejected,
        };
        pg_sys::SpinLockRelease(&mut ring.lock);
        Some(stats)
    }
}

fn add_counter(field: impl FnOnce(&mut Ring) -> &mut u64, by: u64) {
    unsafe {
        if RING.is_null() {
            return;
        }
        let ring = &mut *RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let counter = field(ring);
        *counter = counter.wrapping_add(by);
        pg_sys::SpinLockRelease(&mut ring.lock);
    }
}

enum Read {
    Ready(Box<Slot>),
    NotYet,
    Gone { oldest: u64 },
}

/// A slot copied out under the lock. The copy is made on the stack; nothing
/// is allocated while the spinlock is held.
fn copy_slot(slot: &Slot) -> Slot {
    *slot
}

fn head() -> Option<(u64, u64, u64)> {
    unsafe {
        if RING.is_null() {
            return None;
        }
        let ring = &mut *RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let out = (ring.generation, ring.write_pos, ring.capacity);
        pg_sys::SpinLockRelease(&mut ring.lock);
        Some(out)
    }
}

fn read_at(pos: u64) -> Read {
    unsafe {
        let ring = &mut *RING;
        pg_sys::SpinLockAcquire(&mut ring.lock);
        let write_pos = ring.write_pos;
        let capacity = ring.capacity;
        if pos >= write_pos {
            pg_sys::SpinLockRelease(&mut ring.lock);
            return Read::NotYet;
        }
        let oldest = write_pos.saturating_sub(capacity);
        if pos < oldest {
            pg_sys::SpinLockRelease(&mut ring.lock);
            return Read::Gone { oldest };
        }
        let copy = copy_slot(&*SLOTS.add((pos % capacity) as usize));
        pg_sys::SpinLockRelease(&mut ring.lock);
        if copy.sequence != pos + 1 {
            return Read::Gone { oldest: pos + 1 };
        }
        Read::Ready(Box::new(copy))
    }
}

/// A consumer's per-process state between drains.
pub struct Consumer {
    /// After a batch failed: records still to be written one per
    /// transaction, which isolates a record that fails on its own.
    single_remaining: u64,
    /// Failed attempts of the next single record.
    failures: u32,
    /// Rate limits for the three warnings, so one kind never hides another.
    last_warning_us: [i64; 3],
    /// When this consumer last wrote a record.
    last_write_us: i64,
    /// Last committed cursor; used only to schedule maintenance. The database
    /// checkpoint remains the authority for persistence and restart recovery.
    position: Option<(u64, u64)>,
}

impl Consumer {
    pub fn new() -> Self {
        Self {
            single_remaining: 0,
            failures: 0,
            last_warning_us: [0; 3],
            last_write_us: 0,
            position: None,
        }
    }

    /// Read current shared-stream pressure, without SPI or a held transaction.
    /// Reserve at least three quarters of the ring for arriving records while
    /// one maintenance batch runs. Unknown progress defers maintenance too.
    pub fn maintenance_can_run(&self) -> bool {
        match (self.position, head()) {
            (Some((generation, position)), Some((current, published, capacity)))
                if generation == current => published.saturating_sub(position) < capacity / 4,
            _ => false,
        }
    }

    /// The consumer's idle wait. Publishers do not wake it, so while records
    /// are arriving it looks again after 10 ms. After a quiet second it waits
    /// 200 ms: a burst that starts then can fill the default 4096-record
    /// queue only above about 20 000 records/s before the consumer looks.
    pub fn idle_wait_ms(&self) -> i64 {
        let now = unsafe { pg_sys::GetCurrentTimestamp() };
        if now.saturating_sub(self.last_write_us) < 1_000_000 {
            10
        } else {
            200
        }
    }
}

const WARN_MISSING: usize = 0;
const WARN_SKIPPED: usize = 1;
const WARN_REJECTED: usize = 2;

fn warn_limited(consumer: &mut Consumer, kind: usize, message: &str) {
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    if now.saturating_sub(consumer.last_warning_us[kind]) < 60 * 1_000_000 {
        return;
    }
    consumer.last_warning_us[kind] = now;
    pgrx::warning!("sql_firewall: {message}");
}

/// Inserts this database's records from the committed position onward, at
/// most one batch, in one transaction with the new position. Returns whether
/// more records are waiting. `extension_oid` is the consumer's installation:
/// records of an earlier installation of this database are passed over.
pub fn drain(consumer: &mut Consumer, extension_oid: pg_sys::Oid) -> bool {
    let Some((generation, write_pos, _)) = head() else {
        return false;
    };
    let single = consumer.single_remaining > 0;
    let mut outcome = DrainOutcome::default();
    let outcome_ptr: *mut DrainOutcome = &mut outcome;
    let attempt = worker_persist::persist_event_transaction(|| {
        let out = unsafe { &mut *outcome_ptr };
        let row = Spi::get_one::<String>(
            "SELECT coalesce(ring_generation::text, '') || ' ' || coalesce(extension_oid::text, '') || ' ' || \
               coalesce(next_position::text, '') \
             FROM public.sql_firewall_activity_checkpoint WHERE singleton = 1 FOR UPDATE",
        )?;
        let Some(row) = row else {
            out.missing = true;
            return Ok(());
        };
        let mut fields = row.split(' ');
        let stored_generation = fields.next().and_then(|v| v.parse::<u64>().ok());
        let stored_extension = fields.next().and_then(|v| v.parse::<u32>().ok());
        let stored_position = fields.next().and_then(|v| v.parse::<u64>().ok());
        let mut pos = match (stored_generation, stored_extension, stored_position) {
            (Some(g), Some(e), Some(p)) if g == generation && e == u32::from(extension_oid) && p <= write_pos => p,
            // A new ring (server restart), a new installation, or no position
            // yet: start at the oldest record the ring still holds. Records of
            // another installation are passed over below.
            _ => 0,
        };
        let limit = if single { 1 } else { BATCH };
        let mut taken = 0u64;
        // A batch is written by one statement; a single record (isolating a
        // failure) by its own.
        let mut batch = Batch::default();
        while taken < limit {
            match read_at(pos) {
                Read::NotYet => break,
                Read::Gone { oldest } => {
                    if stored_generation == Some(generation) && stored_extension == Some(u32::from(extension_oid)) {
                        out.skipped += oldest - pos;
                    }
                    pos = oldest;
                }
                Read::Ready(slot) => {
                    if slot.db_oid == u32::from(unsafe { pg_sys::MyDatabaseId })
                        && slot.extension_oid == u32::from(extension_oid)
                    {
                        if single {
                            insert(&slot)?;
                        } else {
                            batch.push(&slot);
                        }
                        taken += 1;
                    }
                    pos += 1;
                }
            }
        }
        if !batch.is_empty() {
            insert_batch(batch)?;
        }
        Spi::run_with_args(
            "UPDATE public.sql_firewall_activity_checkpoint \
             SET ring_generation = $1::numeric, extension_oid = $2::oid, next_position = $3::numeric \
             WHERE singleton = 1",
            &[
                text_arg(&generation.to_string()),
                oid_carrier_arg(u32::from(extension_oid)),
                text_arg(&pos.to_string()),
            ],
        )?;
        out.position = pos;
        out.taken = taken;
        Ok(())
    });
    match attempt {
        PersistAttempt::Committed => {
            if outcome.taken > 0 {
                consumer.last_write_us = unsafe { pg_sys::GetCurrentTimestamp() };
            }
            if outcome.missing {
                warn_limited(consumer, WARN_MISSING, "activity checkpoint row is missing; activity records are not written");
                return false;
            }
            consumer.position = Some((generation, outcome.position));
            if outcome.skipped > 0 {
                add_counter(|ring| &mut ring.consumer_skipped, outcome.skipped);
                warn_limited(
                    consumer,
                    WARN_SKIPPED,
                    &format!(
                        "activity consumer of database oid {} skipped {} positions that were no longer retained (sql_firewall.activity_queue_size)",
                        u32::from(unsafe { pg_sys::MyDatabaseId }),
                        outcome.skipped
                    ),
                );
            }
            if single {
                consumer.single_remaining -= 1;
                consumer.failures = 0;
            }
            // Publications during the transaction also need another drain.
            head().is_some_and(|(g, p, _)| g == generation && outcome.position < p)
        }
        PersistAttempt::Retry { sqlstate } => {
            // `false`: the worker waits its idle interval before retrying.
            if !single {
                // Write the next batch one record per transaction.
                consumer.single_remaining = BATCH;
                consumer.failures = 0;
                return false;
            }
            consumer.failures += 1;
            if consumer.failures < POISON_ATTEMPTS {
                return false;
            }
            // The next record failed alone POISON_ATTEMPTS times: skip it.
            consumer.failures = 0;
            consumer.single_remaining -= 1;
            if skip_one(generation, extension_oid) {
                add_counter(|ring| &mut ring.consumer_rejected, 1);
                warn_limited(
                    consumer,
                    WARN_REJECTED,
                    &format!("an activity record could not be written (SQLSTATE {sqlstate}) and was skipped; see sql_firewall_queue_statistics()"),
                );
            }
            false
        }
    }
}

#[derive(Default)]
struct DrainOutcome {
    missing: bool,
    skipped: u64,
    position: u64,
    taken: u64,
}

/// Moves the committed position past the next record of this database.
fn skip_one(generation: u64, extension_oid: pg_sys::Oid) -> bool {
    let attempt = worker_persist::persist_event_transaction(|| {
        let mut pos = Spi::get_one_with_args::<String>(
            "SELECT next_position::text FROM public.sql_firewall_activity_checkpoint \
             WHERE singleton = 1 AND ring_generation = $1::numeric AND extension_oid = $2::oid FOR UPDATE",
            &[text_arg(&generation.to_string()), oid_carrier_arg(u32::from(extension_oid))],
        )?
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
        loop {
            match read_at(pos) {
                Read::NotYet => break,
                Read::Gone { oldest } => pos = oldest,
                Read::Ready(slot) => {
                    pos += 1;
                    if slot.db_oid == u32::from(unsafe { pg_sys::MyDatabaseId })
                        && slot.extension_oid == u32::from(extension_oid)
                    {
                        break;
                    }
                }
            }
        }
        Spi::run_with_args(
            "UPDATE public.sql_firewall_activity_checkpoint \
             SET ring_generation = $1::numeric, extension_oid = $2::oid, next_position = $3::numeric \
             WHERE singleton = 1",
            &[
                text_arg(&generation.to_string()),
                oid_carrier_arg(u32::from(extension_oid)),
                text_arg(&pos.to_string()),
            ],
        )?;
        Ok(())
    });
    matches!(attempt, PersistAttempt::Committed)
}

/// Many records as one statement: an executor run per batch instead of per
/// record. `ROWS FROM` zips the arrays in order, so `log_id` follows the
/// queue order as with single inserts. (The bare multi-argument `unnest(...)`
/// form is parser syntax that a schema-qualified call does not get.) The
/// text-to-name cast truncates on a character boundary.
const INSERT_BATCH_SQL: &str = "INSERT INTO public.sql_firewall_activity_log \
       (log_time, role_name, database_name, query_text, query_truncated, application_name, client_ip, \
        command_type, action, decision, reason) \
     SELECT a.t, a.r::pg_catalog.name, a.d::pg_catalog.name, a.q, a.qt, a.ap, a.c, a.cm, a.ac, a.de, a.re \
     FROM ROWS FROM (pg_catalog.unnest($1::pg_catalog.timestamptz[]), pg_catalog.unnest($2::pg_catalog.text[]), \
          pg_catalog.unnest($3::pg_catalog.text[]), pg_catalog.unnest($4::pg_catalog.text[]), \
          pg_catalog.unnest($5::pg_catalog.bool[]), pg_catalog.unnest($6::pg_catalog.text[]), \
          pg_catalog.unnest($7::pg_catalog.text[]), pg_catalog.unnest($8::pg_catalog.text[]), \
          pg_catalog.unnest($9::pg_catalog.text[]), pg_catalog.unnest($10::pg_catalog.text[]), \
          pg_catalog.unnest($11::pg_catalog.text[])) \
          AS a(t, r, d, q, qt, ap, c, cm, ac, de, re)";

#[derive(Default)]
struct Batch {
    log_time: Vec<pgrx::datum::TimestampWithTimeZone>,
    role: Vec<String>,
    database: Vec<String>,
    query: Vec<Option<String>>,
    truncated: Vec<bool>,
    application: Vec<Option<String>>,
    client: Vec<Option<String>>,
    command: Vec<Option<String>>,
    action: Vec<Option<String>>,
    decision: Vec<Option<String>>,
    reason: Vec<Option<String>>,
}

impl Batch {
    fn push(&mut self, slot: &Slot) {
        // A queued timestamp came from GetCurrentTimestamp and is in range;
        // the epoch keeps a record that is not, rather than losing it.
        self.log_time.push(
            pgrx::datum::TimestampWithTimeZone::try_from(slot.timestamp)
                .unwrap_or_else(|_| pgrx::datum::TimestampWithTimeZone::try_from(0).expect("the epoch is in range")),
        );
        self.role.push(get(&slot.role).unwrap_or_else(|| "unknown".to_string()));
        self.database.push(get(&slot.database).unwrap_or_else(|| "unknown".to_string()));
        self.query.push(get(&slot.query));
        self.truncated.push(slot.query_truncated);
        self.application.push(get(&slot.application));
        self.client.push(get(&slot.client));
        self.command.push(get(&slot.command));
        self.action.push(get(&slot.action));
        self.decision.push(get(&slot.decision));
        self.reason.push(get(&slot.reason));
    }

    fn is_empty(&self) -> bool {
        self.log_time.is_empty()
    }
}

thread_local! {
    /// This consumer's kept plan of INSERT_BATCH_SQL (see INSERT_PLAN).
    static INSERT_BATCH_PLAN: std::cell::Cell<Option<&'static pgrx::spi::OwnedPreparedStatement>> =
        const { std::cell::Cell::new(None) };
}

fn insert_batch(batch: Batch) -> Result<(), pgrx::spi::Error> {
    let args: [pgrx::datum::DatumWithOid<'static>; 11] = [
        batch.log_time.into(),
        batch.role.into(),
        batch.database.into(),
        batch.query.into(),
        batch.truncated.into(),
        batch.application.into(),
        batch.client.into(),
        batch.command.into(),
        batch.action.into(),
        batch.decision.into(),
        batch.reason.into(),
    ];
    Spi::connect_mut(|client| {
        let plan = match INSERT_BATCH_PLAN.with(std::cell::Cell::get) {
            Some(plan) => plan,
            None => {
                let types: Vec<pgrx::PgOid> = args.iter().map(|arg| pgrx::PgOid::from(arg.oid())).collect();
                let plan: &'static pgrx::spi::OwnedPreparedStatement =
                    Box::leak(Box::new(client.prepare_mut(INSERT_BATCH_SQL, &types)?.keep()));
                INSERT_BATCH_PLAN.with(|cell| cell.set(Some(plan)));
                plan
            }
        };
        client.update(plan, None, &args)?;
        Ok(())
    })
}

const INSERT_SQL: &str = "INSERT INTO public.sql_firewall_activity_log \
       (log_time, role_name, database_name, query_text, query_truncated, application_name, client_ip, \
        command_type, action, decision, reason) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

thread_local! {
    /// This consumer's kept plan of INSERT_SQL, prepared at its first record.
    /// One activity row per allowed statement makes parsing and planning the
    /// INSERT each time the consumer's main cost. PostgreSQL's plan cache
    /// replans a kept plan after the table changes (DROP/CREATE EXTENSION
    /// included: the name is schema-qualified). Never freed: it lives as
    /// long as the process.
    static INSERT_PLAN: std::cell::Cell<Option<&'static pgrx::spi::OwnedPreparedStatement>> =
        const { std::cell::Cell::new(None) };
}

fn insert(slot: &Slot) -> Result<(), pgrx::spi::Error> {
    let optional = |bytes: &[u8]| match get(bytes) {
        Some(text) => text_arg_owned(text),
        None => pgrx::datum::DatumWithOid::null_oid(pg_sys::TEXTOID),
    };
    let role = get(&slot.role).unwrap_or_else(|| "unknown".to_string());
    let database = get(&slot.database).unwrap_or_else(|| "unknown".to_string());
    let args = [
        unsafe { pgrx::datum::DatumWithOid::new(pg_sys::Datum::from(slot.timestamp), pg_sys::TIMESTAMPTZOID) },
        name_arg(&role),
        name_arg(&database),
        optional(&slot.query),
        bool_arg(slot.query_truncated),
        optional(&slot.application),
        optional(&slot.client),
        optional(&slot.command),
        optional(&slot.action),
        optional(&slot.decision),
        optional(&slot.reason),
    ];
    Spi::connect_mut(|client| {
        let plan = match INSERT_PLAN.with(std::cell::Cell::get) {
            Some(plan) => plan,
            None => {
                let types: Vec<pgrx::PgOid> = args.iter().map(|arg| pgrx::PgOid::from(arg.oid())).collect();
                let plan: &'static pgrx::spi::OwnedPreparedStatement =
                    Box::leak(Box::new(client.prepare_mut(INSERT_SQL, &types)?.keep()));
                INSERT_PLAN.with(|cell| cell.set(Some(plan)));
                plan
            }
        };
        client.update(plan, None, &args)?;
        Ok(())
    })
}

/// A text argument that owns its string for the duration of the SPI call.
fn text_arg_owned(text: String) -> pgrx::datum::DatumWithOid<'static> {
    unsafe { pgrx::datum::DatumWithOid::new(text, pg_sys::TEXTOID) }
}
