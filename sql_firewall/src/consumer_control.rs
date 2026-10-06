// Per-database pause/resume for the existing consumers.
//
// This registry is operational shared memory. It is not the event ring and it
// is not the transactional checkpoint. A postmaster restart clears it; the
// next generation starts running.
//
// Each occupied slot is owned by one (ring generation, database OID,
// extension installation) triple. A consumer incarnation is a monotonic
// counter, not a PID. An acknowledgement counts only when that incarnation
// echoes the current request epoch. Replacing the process, or DROP/CREATE
// EXTENSION, gets a new incarnation or a new slot.
//
// Empty slots and stopped slots whose desired state is running can be reused.
// A paused or pending slot is never reused while that installation still owns
// it. If every slot is live or holding a pause, the control call reports that
// the registry is full.
//
// A slot is freed for a removed installation by the transaction that removed
// it (lifecycle tags below), or by the launcher when `pg_database` no longer
// lists the slot's database. Age, a missing pid, and registry pressure never
// free a slot.
//
// Nothing inside the spinlock allocates, logs, raises, waits, or reads the
// catalog.

use pgrx::pg_sys;
use std::ptr;

const SLOTS: usize = 128;
const DESIRED_RUNNING: u8 = 0;
const DESIRED_PAUSED: u8 = 1;

pub const OBS_NONE: u8 = 0;
pub const OBS_STARTING: u8 = 1;
pub const OBS_RUNNING: u8 = 2;
pub const OBS_PAUSED: u8 = 3;
pub const OBS_STOPPING: u8 = 4;
pub const OBS_STOPPED: u8 = 5;
pub const OBS_RETRYING: u8 = 6;

#[repr(C)]
#[derive(Copy, Clone)]
struct Slot {
    occupied: u8,
    desired: u8,
    observed: u8,
    _pad: u8,
    db_oid: u32,
    extension_oid: u32,
    pid: i32,
    ring_generation: u64,
    request_epoch: u64,
    incarnation: u64,
    ack_epoch: u64,
    ack_incarnation: u64,
    /// Registry-wide counter value taken when the slot is allocated or a
    /// consumer attaches. Cleanup applies only if this value is unchanged.
    version: u64,
    /// Backend and per-backend transaction holding lifecycle tags, or 0.
    owner_pid: i32,
    /// Subtransaction that created this installation, or 0.
    create_subid: u32,
    /// Subtransaction that removed this installation or its database, or 0.
    drop_subid: u32,
    owner_xact: u64,
}

impl Slot {
    fn empty() -> Self {
        Self {
            occupied: 0,
            desired: DESIRED_RUNNING,
            observed: OBS_NONE,
            _pad: 0,
            db_oid: 0,
            extension_oid: 0,
            pid: 0,
            ring_generation: 0,
            request_epoch: 0,
            incarnation: 0,
            ack_epoch: 0,
            ack_incarnation: 0,
            version: 0,
            owner_pid: 0,
            create_subid: 0,
            drop_subid: 0,
            owner_xact: 0,
        }
    }

    fn matches(&self, identity: Identity) -> bool {
        self.occupied != 0
            && self.db_oid == identity.db_oid
            && self.extension_oid == identity.extension_oid
            && self.ring_generation == identity.ring_generation
    }

    fn reclaimable(&self) -> bool {
        self.occupied != 0
            && self.desired == DESIRED_RUNNING
            && self.observed == OBS_STOPPED
            && self.pid == 0
            && self.incarnation == 0
            && self.owner_pid == 0
    }
}

#[repr(C)]
struct Registry {
    lock: pg_sys::slock_t,
    next_incarnation: u64,
    next_version: u64,
    slots: [Slot; SLOTS],
    /// Committed installations, for the launcher (launcher.rs): the count of
    /// announcements so far, and the database OIDs of the last ANNOUNCED.
    announce_count: u64,
    announced: [u32; ANNOUNCED],
}

const ANNOUNCED: usize = 16;

/// Installations committed since the launcher last looked.
pub enum Announcements {
    Databases(Vec<u32>),
    /// More than the registry keeps: every waiting database may be affected.
    Overflow,
}

fn next_version(registry: &mut Registry) -> u64 {
    let version = registry.next_version;
    registry.next_version = registry.next_version.wrapping_add(1).max(1);
    version
}

static mut REGISTRY: *mut Registry = ptr::null_mut();

#[derive(Clone, Copy)]
pub struct Identity {
    pub db_oid: u32,
    pub extension_oid: u32,
    pub ring_generation: u64,
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub desired_paused: bool,
    pub request_epoch: u64,
    pub incarnation: u64,
    pub observed: u8,
    pub ack_epoch: u64,
    pub ack_incarnation: u64,
    pub pid: i32,
    pub present: bool,
}

pub enum ControlError {
    Full,
    Unavailable,
}

pub enum CommandResult {
    Paused { epoch: u64, incarnation: u64 },
    Running { epoch: u64, incarnation: u64 },
    /// The consumer accepted the resume epoch but is not processing events.
    Acknowledged { epoch: u64, incarnation: u64 },
    Pending { epoch: u64 },
    Superseded,
    Full,
    NoExtension,
    NoRing,
}

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<Registry>()
}

/// Runs in every shared-memory initialization, including the postmaster's
/// reinitialization after a crash, which creates the registry anew.
pub unsafe fn init() {
    let mut found = false;
    let ptr = pg_sys::ShmemInitStruct(
        c"sql_firewall_consumer_control".as_ptr(),
        shared_memory_bytes(),
        &mut found,
    ) as *mut Registry;
    if ptr.is_null() {
        pgrx::error!("sql_firewall: failed to allocate consumer control registry");
    }
    if !found {
        pg_sys::SpinLockInit(&mut (*ptr).lock);
        (*ptr).next_incarnation = 1;
        (*ptr).next_version = 1;
        for slot in (*ptr).slots.iter_mut() {
            *slot = Slot::empty();
        }
        (*ptr).announce_count = 0;
        (*ptr).announced = [0; ANNOUNCED];
    }
    REGISTRY = ptr;
}

fn with_registry<T>(body: impl FnOnce(&mut Registry) -> T) -> Result<T, ControlError> {
    unsafe {
        if REGISTRY.is_null() {
            return Err(ControlError::Unavailable);
        }
        let registry = &mut *REGISTRY;
        pg_sys::SpinLockAcquire(&mut registry.lock);
        let value = body(registry);
        pg_sys::SpinLockRelease(&mut registry.lock);
        Ok(value)
    }
}

pub fn attach(identity: Identity) -> Result<u64, ControlError> {
    let assigned = with_registry(|registry| {
        let index = match find_or_allocate(registry, identity) {
            Some(index) => index,
            None => return None,
        };
        let incarnation = registry.next_incarnation;
        registry.next_incarnation = registry.next_incarnation.wrapping_add(1).max(1);
        let version = next_version(registry);
        let slot = &mut registry.slots[index];
        slot.occupied = 1;
        slot.db_oid = identity.db_oid;
        slot.extension_oid = identity.extension_oid;
        slot.ring_generation = identity.ring_generation;
        slot.incarnation = incarnation;
        slot.pid = unsafe { pg_sys::MyProcPid };
        slot.observed = OBS_STARTING;
        slot.ack_epoch = 0;
        slot.ack_incarnation = 0;
        slot.version = version;
        Some(incarnation)
    })?;
    assigned.ok_or(ControlError::Full)
}

pub fn release(identity: Identity, incarnation: u64) {
    let _ = with_registry(|registry| {
        if let Some(slot) = find_mut(registry, identity) {
            if slot.incarnation == incarnation {
                *slot = Slot::empty();
            }
        }
    });
}

/// The process is gone. Keep a pending pause for the same installation.
/// Clear the acknowledgement so a dead incarnation cannot satisfy a request.
pub fn detach_keep_request(identity: Identity, incarnation: u64) {
    let _ = with_registry(|registry| {
        if let Some(slot) = find_mut(registry, identity) {
            if slot.incarnation == incarnation {
                slot.observed = OBS_STOPPED;
                slot.pid = 0;
                slot.incarnation = 0;
                slot.ack_epoch = 0;
                slot.ack_incarnation = 0;
            }
        }
    });
}

/// Record that this incarnation has seen the current request epoch without
/// changing its processing state.
pub fn acknowledge_mode(identity: Identity, incarnation: u64) {
    let _ = with_registry(|registry| {
        if let Some(slot) = find_mut(registry, identity) {
            if slot.incarnation == incarnation {
                slot.ack_epoch = slot.request_epoch;
                slot.ack_incarnation = incarnation;
                slot.pid = unsafe { pg_sys::MyProcPid };
            }
        }
    });
}

pub fn observe(identity: Identity, incarnation: u64, observed: u8) {
    let _ = with_registry(|registry| {
        if let Some(slot) = find_mut(registry, identity) {
            if slot.incarnation == incarnation {
                slot.observed = observed;
                slot.ack_epoch = slot.request_epoch;
                slot.ack_incarnation = incarnation;
                slot.pid = unsafe { pg_sys::MyProcPid };
            }
        }
    });
}

pub fn snapshot(identity: Identity) -> Snapshot {
    with_registry(|registry| match find(registry, identity) {
        Some(slot) => Snapshot {
            desired_paused: slot.desired == DESIRED_PAUSED,
            request_epoch: slot.request_epoch,
            incarnation: slot.incarnation,
            observed: slot.observed,
            ack_epoch: slot.ack_epoch,
            ack_incarnation: slot.ack_incarnation,
            pid: slot.pid,
            present: true,
        },
        None => Snapshot {
            desired_paused: false,
            request_epoch: 0,
            incarnation: 0,
            observed: OBS_NONE,
            ack_epoch: 0,
            ack_incarnation: 0,
            pid: 0,
            present: false,
        },
    })
    .unwrap_or(Snapshot {
        desired_paused: false,
        request_epoch: 0,
        incarnation: 0,
        observed: OBS_NONE,
        ack_epoch: 0,
        ack_incarnation: 0,
        pid: 0,
        present: false,
    })
}

/// `created` is the subtransaction that created this installation when the
/// running transaction created it. The creation tag is set in the same
/// spinlock hold that stores the request, before the interruptible wait, so a
/// cancelled wait still leaves the slot owned by this transaction.
pub fn request_pause(identity: Identity, created: Option<u32>) -> CommandResult {
    request(identity, true, created)
}

pub fn request_resume(identity: Identity, created: Option<u32>) -> CommandResult {
    request(identity, false, created)
}

pub fn status_text(identity: Identity) -> String {
    let snap = snapshot(identity);
    if !snap.present {
        return "stopped".to_string();
    }
    let live = snap.incarnation != 0 && snap.pid != 0 && snap.observed != OBS_STOPPED;
    let acked = live && snap.ack_incarnation == snap.incarnation && snap.ack_epoch == snap.request_epoch;
    if snap.desired_paused {
        if acked && snap.observed == OBS_PAUSED {
            return format!(
                "paused epoch={} incarnation={}",
                snap.request_epoch, snap.incarnation
            );
        }
        return format!("pause pending epoch={}", snap.request_epoch);
    }
    if !live {
        return "stopped".to_string();
    }
    if !acked {
        return format!("resume pending epoch={}", snap.request_epoch);
    }
    let label = match snap.observed {
        OBS_STARTING => "starting",
        OBS_RETRYING => "retrying",
        OBS_STOPPING => "stopping",
        OBS_PAUSED => "paused",
        _ => "running",
    };
    format!(
        "{label} epoch={} incarnation={}",
        snap.request_epoch, snap.incarnation
    )
}

fn request(identity: Identity, pause: bool, created: Option<u32>) -> CommandResult {
    let owner = current_owner();
    if created.is_some() {
        local().tagged = true;
    }
    let issued = match with_registry(|registry| {
        let index = match find_or_allocate(registry, identity) {
            Some(index) => index,
            None => return None,
        };
        let slot = &mut registry.slots[index];
        if let Some(subid) = created {
            if slot.claim_tags(owner) && slot.create_subid == 0 {
                slot.create_subid = subid;
            }
        }
        let want = if pause { DESIRED_PAUSED } else { DESIRED_RUNNING };
        if slot.desired != want {
            slot.desired = want;
            slot.request_epoch = slot.request_epoch.wrapping_add(1).max(1);
        } else if slot.request_epoch == 0 {
            slot.request_epoch = 1;
        }
        Some(slot.request_epoch)
    }) {
        Ok(Some(epoch)) => epoch,
        Ok(None) => return CommandResult::Full,
        Err(_) => return CommandResult::NoRing,
    };
    wait_for(identity, issued, pause)
}

fn wait_for(identity: Identity, epoch: u64, pause: bool) -> CommandResult {
    let deadline = unsafe { pg_sys::GetCurrentTimestamp() } + 5 * 1_000_000;
    loop {
        unsafe {
            pg_sys::check_for_interrupts!();
        }
        let snap = snapshot(identity);
        if !snap.present || snap.request_epoch != epoch {
            return if pause {
                CommandResult::Superseded
            } else {
                CommandResult::Superseded
            };
        }
        let live = snap.incarnation != 0 && snap.pid != 0 && snap.observed != OBS_STOPPED;
        let acked = live && snap.ack_incarnation == snap.incarnation && snap.ack_epoch == epoch;
        if pause && acked && snap.observed == OBS_PAUSED {
            return CommandResult::Paused {
                epoch,
                incarnation: snap.incarnation,
            };
        }
        if !pause && acked && snap.observed == OBS_RUNNING {
            return CommandResult::Running {
                epoch,
                incarnation: snap.incarnation,
            };
        }
        if !pause && acked && (snap.observed == OBS_RETRYING || snap.observed == OBS_STARTING) {
            return CommandResult::Acknowledged {
                epoch,
                incarnation: snap.incarnation,
            };
        }
        if unsafe { pg_sys::GetCurrentTimestamp() } >= deadline {
            return CommandResult::Pending { epoch };
        }
        unsafe {
            pg_sys::WaitLatch(
                pg_sys::MyLatch,
                (pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_EXIT_ON_PM_DEATH) as i32,
                50,
                pg_sys::PG_WAIT_EXTENSION,
            );
            pg_sys::ResetLatch(pg_sys::MyLatch);
        }
    }
}

fn find(registry: &Registry, identity: Identity) -> Option<&Slot> {
    registry.slots.iter().find(|slot| slot.matches(identity))
}

fn find_mut(registry: &mut Registry, identity: Identity) -> Option<&mut Slot> {
    registry.slots.iter_mut().find(|slot| slot.matches(identity))
}

fn find_or_allocate(registry: &mut Registry, identity: Identity) -> Option<usize> {
    if let Some(index) = registry
        .slots
        .iter()
        .position(|slot| slot.matches(identity))
    {
        return Some(index);
    }
    let index = registry
        .slots
        .iter()
        .position(|slot| slot.occupied == 0)
        .or_else(|| registry.slots.iter().position(|slot| slot.reclaimable()))?;
    let version = next_version(registry);
    let slot = &mut registry.slots[index];
    *slot = Slot::empty();
    slot.occupied = 1;
    slot.db_oid = identity.db_oid;
    slot.extension_oid = identity.extension_oid;
    slot.ring_generation = identity.ring_generation;
    slot.version = version;
    Some(index)
}

#[derive(Clone, Copy)]
pub struct SlotClaim {
    pub db_oid: u32,
    pub extension_oid: u32,
    pub ring_generation: u64,
    pub version: u64,
}

impl SlotClaim {
    const EMPTY: Self = Self {
        db_oid: 0,
        extension_oid: 0,
        ring_generation: 0,
        version: 0,
    };
}

/// Copy of occupied slot identities. Filled under the spinlock without
/// allocating; callers process it after the lock is released.
pub struct Claims {
    len: usize,
    items: [SlotClaim; SLOTS],
}

impl Claims {
    pub fn iter(&self) -> impl Iterator<Item = &SlotClaim> {
        self.items[..self.len].iter()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub fn claims() -> Claims {
    let mut out = Claims {
        len: 0,
        items: [SlotClaim::EMPTY; SLOTS],
    };
    let _ = with_registry(|registry| {
        for (item, slot) in out
            .items
            .iter_mut()
            .zip(registry.slots.iter().filter(|slot| slot.occupied != 0))
        {
            *item = SlotClaim {
                db_oid: slot.db_oid,
                extension_oid: slot.extension_oid,
                ring_generation: slot.ring_generation,
                version: slot.version,
            };
            out.len += 1;
        }
    });
    out
}

// Installation lifecycle ownership.
//
// A transaction that creates or removes an installation tags that
// installation's slot with its backend, a per-backend transaction counter,
// and the subtransaction that made the change. Only that backend changes
// the tags, from its own subtransaction and transaction callbacks:
//
// - subtransaction commit moves both tags to the parent subtransaction;
// - subtransaction abort discards a removal tag, and reclaims the slot if
//   the installation was created in that subtransaction;
// - top-level commit reclaims removed installations and clears creation tags;
// - top-level abort reclaims created installations and clears removal tags.
//
// Tags live in the fixed registry, so obligations are bounded by SLOTS and
// none is dropped. Callbacks touch only this backend's tags, never the
// catalog. Slot reuse and the launcher's reconciliation skip tagged slots.

/// Created installations this transaction may still expose. A record with no
/// removal is the visible installation; at most one exists. A record whose
/// removal is in a deeper subtransaction is kept, because aborting that
/// subtransaction makes the installation visible again. The rest are pruned.
const CREATED_MAX: usize = 32;

#[derive(Clone, Copy)]
struct Created {
    db_oid: u32,
    extension_oid: u32,
    create_subid: u32,
    drop_subid: u32,
}

impl Created {
    const EMPTY: Self = Self {
        db_oid: 0,
        extension_oid: 0,
        create_subid: 0,
        drop_subid: 0,
    };

    fn is(&self, identity: Identity) -> bool {
        self.create_subid != 0
            && self.db_oid == identity.db_oid
            && self.extension_oid == identity.extension_oid
    }

    fn dead(&self) -> bool {
        self.create_subid == 0 || self.drop_subid == self.create_subid
    }
}

#[derive(Clone, Copy)]
struct Local {
    xact: u64,
    tagged: bool,
    created: [Created; CREATED_MAX],
}

static mut LOCAL: Local = Local {
    xact: 1,
    tagged: false,
    created: [Created::EMPTY; CREATED_MAX],
};

fn local() -> &'static mut Local {
    unsafe { &mut *ptr::addr_of_mut!(LOCAL) }
}

#[derive(Clone, Copy)]
struct Owner {
    pid: i32,
    xact: u64,
}

fn current_owner() -> Owner {
    Owner {
        pid: unsafe { pg_sys::MyProcPid },
        xact: local().xact,
    }
}

impl Slot {
    fn owned_by(&self, owner: Owner) -> bool {
        self.occupied != 0 && self.owner_pid == owner.pid && self.owner_xact == owner.xact
    }

    fn clear_tags(&mut self) {
        self.owner_pid = 0;
        self.owner_xact = 0;
        self.create_subid = 0;
        self.drop_subid = 0;
    }

    /// A slot tagged by another live transaction is left alone.
    fn claim_tags(&mut self, owner: Owner) -> bool {
        if self.owner_pid == owner.pid && self.owner_xact != owner.xact {
            self.clear_tags();
        }
        if self.owner_pid != 0 && !self.owned_by(owner) {
            return false;
        }
        self.owner_pid = owner.pid;
        self.owner_xact = owner.xact;
        true
    }
}

pub fn available() -> bool {
    unsafe { !REGISTRY.is_null() }
}

/// Record that `identity` was created by the command that just ran in `subid`.
/// Returns false if the record cannot be kept; the caller must fail that
/// command so the creation is rolled back.
pub fn note_created(identity: Identity, subid: u32) -> bool {
    let state = local();
    if state.created.iter().any(|entry| entry.is(identity)) {
        return true;
    }
    for entry in state.created.iter_mut() {
        if entry.dead() {
            *entry = Created {
                db_oid: identity.db_oid,
                extension_oid: identity.extension_oid,
                create_subid: subid,
                drop_subid: 0,
            };
            return true;
        }
    }
    false
}

/// Subtransaction that created the visible installation `identity`, if this
/// transaction created it.
pub fn created_subid(identity: Identity) -> Option<u32> {
    local()
        .created
        .iter()
        .find(|entry| entry.is(identity) && entry.drop_subid == 0)
        .map(|entry| entry.create_subid)
}

/// `identity` was visible before the command that just ran in `subid` and is
/// not visible after it.
pub fn tag_removed_installation(identity: Identity, subid: u32) {
    let owner = current_owner();
    let state = local();
    for entry in state.created.iter_mut() {
        if entry.is(identity) && entry.drop_subid == 0 {
            entry.drop_subid = subid;
            if entry.dead() {
                *entry = Created::EMPTY;
            }
        }
    }
    state.tagged = true;
    let _ = with_registry(|registry| {
        if let Some(slot) = find_mut(registry, identity) {
            if slot.claim_tags(owner) && slot.drop_subid == 0 {
                slot.drop_subid = subid;
            }
        }
    });
}

/// Every slot of `db_oid` belongs to a database this transaction is dropping.
pub fn tag_removed_database(db_oid: u32, subid: u32) {
    let owner = current_owner();
    local().tagged = true;
    let _ = with_registry(|registry| {
        for slot in registry
            .slots
            .iter_mut()
            .filter(|slot| slot.occupied != 0 && slot.db_oid == db_oid)
        {
            if slot.claim_tags(owner) && slot.drop_subid == 0 {
                slot.drop_subid = subid;
            }
        }
    });
}

pub fn owns_lifecycle_tags() -> bool {
    let owner = current_owner();
    if !local().tagged {
        return false;
    }
    with_registry(|registry| registry.slots.iter().any(|slot| slot.owned_by(owner)))
        .unwrap_or(false)
}

pub fn at_subxact_end(committed: bool, my_subid: u32, parent_subid: u32) {
    let owner = current_owner();
    let state = local();
    for entry in state.created.iter_mut() {
        if entry.create_subid == 0 {
            continue;
        }
        if committed {
            if entry.create_subid >= my_subid {
                entry.create_subid = parent_subid;
            }
            if entry.drop_subid >= my_subid {
                entry.drop_subid = parent_subid;
            }
        } else if entry.create_subid >= my_subid {
            *entry = Created::EMPTY;
            continue;
        } else if entry.drop_subid >= my_subid {
            entry.drop_subid = 0;
        }
        if entry.dead() {
            *entry = Created::EMPTY;
        }
    }
    if !state.tagged {
        return;
    }
    let _ = with_registry(|registry| {
        for slot in registry.slots.iter_mut().filter(|slot| slot.owned_by(owner)) {
            if committed {
                if slot.create_subid >= my_subid {
                    slot.create_subid = parent_subid;
                }
                if slot.drop_subid >= my_subid {
                    slot.drop_subid = parent_subid;
                }
            } else if slot.create_subid >= my_subid {
                // The installation existed only inside the aborted subtransaction.
                *slot = Slot::empty();
            } else {
                if slot.drop_subid >= my_subid {
                    slot.drop_subid = 0;
                }
                if slot.create_subid == 0 && slot.drop_subid == 0 {
                    slot.clear_tags();
                }
            }
        }
    });
}

pub fn at_xact_end(committed: bool) {
    let owner = current_owner();
    let state = local();
    let tagged = state.tagged;
    // Installations this transaction created and kept, announced below.
    let mut installed = [0u32; CREATED_MAX];
    let mut announce = 0;
    if committed {
        for entry in state.created.iter().filter(|entry| entry.create_subid != 0 && entry.drop_subid == 0) {
            installed[announce] = entry.db_oid;
            announce += 1;
        }
    }
    state.tagged = false;
    state.created = [Created::EMPTY; CREATED_MAX];
    state.xact = state.xact.wrapping_add(1).max(1);
    if announce > 0 {
        let _ = with_registry(|registry| {
            for &db_oid in &installed[..announce] {
                registry.announced[(registry.announce_count % ANNOUNCED as u64) as usize] = db_oid;
                registry.announce_count = registry.announce_count.wrapping_add(1);
            }
        });
    }
    if !tagged {
        return;
    }
    let _ = with_registry(|registry| {
        for slot in registry.slots.iter_mut().filter(|slot| slot.owned_by(owner)) {
            let reclaim = if committed {
                slot.drop_subid != 0
            } else {
                slot.create_subid != 0
            };
            if reclaim {
                *slot = Slot::empty();
            } else {
                slot.clear_tags();
            }
        }
    });
}

/// The announcement count now; the launcher starts from it.
pub fn announcement_count() -> u64 {
    with_registry(|registry| registry.announce_count).unwrap_or(0)
}

/// Databases whose installation committed after `*seen`, which is advanced.
pub fn announcements_since(seen: &mut u64) -> Announcements {
    let mut copy = [0u32; ANNOUNCED];
    let count = with_registry(|registry| {
        copy = registry.announced;
        registry.announce_count
    })
    .unwrap_or(*seen);
    let new = count.wrapping_sub(*seen);
    let from = *seen;
    *seen = count;
    if new > ANNOUNCED as u64 {
        return Announcements::Overflow;
    }
    Announcements::Databases(
        (0..new)
            .map(|i| copy[(from.wrapping_add(i) % ANNOUNCED as u64) as usize])
            .collect(),
    )
}

/// Whether any control record belongs to this database: its installation's
/// consumer attached since the postmaster started, or a pause was requested.
pub fn database_has_record(db_oid: u32) -> bool {
    with_registry(|registry| {
        registry
            .slots
            .iter()
            .any(|slot| slot.occupied != 0 && slot.db_oid == db_oid)
    })
    .unwrap_or(false)
}

#[cfg(feature = "queue_probe")]
pub fn slots_for_database(db_oid: u32) -> i32 {
    with_registry(|registry| {
        registry
            .slots
            .iter()
            .filter(|slot| slot.occupied != 0 && slot.db_oid == db_oid)
            .count() as i32
    })
    .unwrap_or(-1)
}

#[cfg(feature = "queue_probe")]
static PROBE_SKIP_DATABASE_TAGS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "queue_probe")]
pub fn set_probe_skip_database_tags(enabled: bool) {
    PROBE_SKIP_DATABASE_TAGS.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(feature = "queue_probe")]
pub fn probe_skip_database_tags() -> bool {
    PROBE_SKIP_DATABASE_TAGS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Drop a slot only if it still belongs to the installation observed earlier.
/// A concurrent reallocation changes `version` and is left alone.
pub fn reclaim_absent(db_oid: u32, ring_generation: u64, extension_oid: u32, version: u64) -> bool {
    with_registry(|registry| {
        let Some(index) = registry.slots.iter().position(|slot| {
            slot.occupied != 0
                && slot.db_oid == db_oid
                && slot.ring_generation == ring_generation
                && slot.extension_oid == extension_oid
                && slot.version == version
                && slot.owner_pid == 0
        }) else {
            return false;
        };
        registry.slots[index] = Slot::empty();
        true
    })
    .unwrap_or(false)
}
