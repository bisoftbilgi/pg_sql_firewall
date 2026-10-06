//! Per-database activation.
//!
//! `shared_preload_libraries` installs the hooks in every database. Policy
//! runs only where this extension is installed. Installation is the current
//! database's `pg_extension` row for `sql_firewall`. A missing required
//! policy relation is a different state: the extension row is still there,
//! but the object is missing, not a member of this extension, not a table,
//! missing a column the check reads, or not selectable by the current user.
//!
//! The extension OID and the verdict of these checks are kept per backend
//! only while no relevant catalog invalidation has been processed since
//! they were computed (`catalog_generation`, port_shim.c): pg_extension,
//! pg_namespace, pg_class, pg_attribute, pg_proc, pg_authid, pg_auth_members,
//! and any relcache invalidation. That is the protocol PostgreSQL's own
//! syscache follows, so `CREATE EXTENSION`, `DROP EXTENSION`, a revoked
//! privilege, a renamed or retyped column, and their rollbacks are seen by
//! the next statement after this backend processes the invalidation, as the
//! uncached lookups would. The verdict is also keyed by database, current
//! user (privilege checks), and the settings that select the relations.
//! Without preload the callbacks are not registered and nothing is kept.
//! A change of extension membership alone (`ALTER EXTENSION ... ADD/DROP`)
//! changes only pg_depend, which sends no catalog invalidation; the object
//! access hook registers one for pg_extension in that transaction
//! (hooks.rs), so every backend re-checks after it commits, and the altering
//! backend also after it rolls back.
//!
//! While PostgreSQL is executing this extension's own script
//! (`creating_extension` and `CurrentExtensionObject` name `sql_firewall`),
//! policy is skipped. Other extensions' scripts are not skipped, and the
//! query text is not consulted.

use std::cell::Cell;
use std::ffi::CStr;

use pgrx::pg_sys::{self, errcodes::PgSqlErrorCode};

use crate::guc::{self, FirewallMode};

const EXT_NAME: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"sql_firewall\0") };
const PUBLIC_NSP: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"public\0") };

const APPROVALS: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"sql_firewall_command_approvals\0") };
const REGEX_RULES: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"sql_firewall_regex_rules\0") };
const FINGERPRINTS: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"sql_firewall_query_fingerprints\0") };
const POLICY_EPOCH: &CStr = c"sql_firewall_policy_epoch";

pub const DIAGNOSTIC_PREFIX: &str = "sql_firewall: required policy catalog is unavailable: ";

thread_local! {
    static POLICY_STOPPED: Cell<bool> = Cell::new(false);
    /// (catalog generation, database, extension OID or InvalidOid).
    static EXTENSION: Cell<Option<(u64, pg_sys::Oid, pg_sys::Oid)>> = const { Cell::new(None) };
    static VERDICT: Cell<Option<Verdict>> = const { Cell::new(None) };
}

extern "C-unwind" {
    fn sqlfw_register_catalog_callbacks();
    fn sqlfw_catalog_change_count() -> u64;
    fn sqlfw_accept_invalidation_messages();
}

/// Called once from `_PG_init` in the postmaster (preload only).
pub fn register_catalog_callbacks() {
    unsafe { sqlfw_register_catalog_callbacks() };
}

/// Advances whenever this process handles an invalidation of a catalog the
/// activation and cache-scope checks read. Read it before a lookup: a change
/// processed during the lookup then makes the stored result stale at once.
pub fn catalog_generation() -> u64 {
    unsafe { sqlfw_catalog_change_count() }
}

#[derive(Clone, Copy)]
struct Verdict {
    generation: u64,
    db: pg_sys::Oid,
    user: pg_sys::Oid,
    regex: bool,
    fingerprints: bool,
    extension: pg_sys::Oid,
    unavailable: Option<&'static str>,
}

/// This database's `sql_firewall` extension OID. Must run in a transaction.
pub fn installed_extension_oid() -> Option<pg_sys::Oid> {
    let db = unsafe { pg_sys::MyDatabaseId };
    if !crate::preloaded() {
        return extension_oid();
    }
    let generation = catalog_generation();
    if let Some((stored, stored_db, oid)) = EXTENSION.with(Cell::get) {
        if stored == generation && stored_db == db {
            return (oid != pg_sys::InvalidOid).then_some(oid);
        }
    }
    let oid = extension_oid();
    EXTENSION.with(|cell| cell.set(Some((generation, db, oid.unwrap_or(pg_sys::InvalidOid)))));
    oid
}

pub enum InstallState {
    NotInstalled,
    Bootstrapping,
    Active,
    /// The extension row exists, but this policy relation cannot be used.
    Unavailable(&'static str),
}

pub fn clear_policy_stop() {
    POLICY_STOPPED.with(|flag| flag.set(false));
}

pub fn policy_stopped() -> bool {
    POLICY_STOPPED.with(|flag| flag.get())
}

pub fn install_state(_mode: FirewallMode) -> InstallState {
    if unsafe { !pg_sys::IsTransactionState() } {
        return InstallState::NotInstalled;
    }

    // Each statement handles invalidations other sessions committed (a
    // revoked privilege, a renamed table) before the cached verdict is
    // trusted. The uncached lookups did this as a side effect of locking
    // pg_extension and pg_depend again for every statement; with nothing
    // pending it is a single unlocked check.
    if crate::preloaded() {
        // A relcache rebuild while handling the messages can raise an ERROR,
        // which must reach PostgreSQL as one.
        unsafe { pg_sys::ffi::pg_guard_ffi_boundary(|| sqlfw_accept_invalidation_messages()) };
    }
    let generation = catalog_generation();
    let ext = installed_extension_oid();
    if in_own_extension_script(ext) {
        return InstallState::Bootstrapping;
    }
    let Some(ext) = ext else {
        return InstallState::NotInstalled;
    };

    let key = Verdict {
        generation,
        db: unsafe { pg_sys::MyDatabaseId },
        user: unsafe { pg_sys::GetUserId() },
        regex: guc::regex_scan_enabled(),
        fingerprints: guc::fingerprint_learning_enabled(),
        extension: ext,
        unavailable: None,
    };
    if crate::preloaded() {
        if let Some(cached) = VERDICT.with(Cell::get) {
            if cached.generation == key.generation
                && cached.db == key.db
                && cached.user == key.user
                && cached.regex == key.regex
                && cached.fingerprints == key.fingerprints
                && cached.extension == key.extension
            {
                return match cached.unavailable {
                    Some(name) => InstallState::Unavailable(name),
                    None => InstallState::Active,
                };
            }
        }
    }
    let unavailable = unavailable_policy_relation(ext, key.regex, key.fingerprints);
    if crate::preloaded() {
        VERDICT.with(|cell| cell.set(Some(Verdict { unavailable, ..key })));
    }
    match unavailable {
        Some(name) => InstallState::Unavailable(name),
        None => InstallState::Active,
    }
}

fn unavailable_policy_relation(ext: pg_sys::Oid, regex: bool, fingerprints: bool) -> Option<&'static str> {
    if let Some(name) = unavailable_relation(ext, APPROVALS, APPROVAL_COLUMNS) {
        return Some(name);
    }
    // Read in the same snapshot as every approval and fingerprint lookup.
    if let Some(name) = unavailable_relation(ext, POLICY_EPOCH, EPOCH_COLUMNS) {
        return Some(name);
    }
    if regex {
        if let Some(name) = unavailable_relation(ext, REGEX_RULES, REGEX_COLUMNS) {
            return Some(name);
        }
    }
    // Fingerprint learning makes this catalog a prerequisite in every mode.
    // Enforce must not skip it merely because an approved command currently
    // bypasses fingerprint enforcement; that bypass is a separate defect.
    if fingerprints {
        if let Some(name) = unavailable_relation(ext, FINGERPRINTS, FINGERPRINT_COLUMNS) {
            return Some(name);
        }
    }
    None
}

/// Enforce rejects. Learn and permissive report the same sentence as a
/// WARNING and do not treat the statement as validated.
pub fn degrade(mode: FirewallMode, object: &'static str) {
    let message = format!("{DIAGNOSTIC_PREFIX}{object}");
    if mode == FirewallMode::Enforce {
        crate::firewall::record_refusal(&message);
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE,
            &message
        );
    } else {
        POLICY_STOPPED.with(|flag| flag.set(true));
        pgrx::warning!("{message}");
    }
}

struct Column {
    name: &'static CStr,
    type_oid: pg_sys::Oid,
}

const APPROVAL_COLUMNS: &[Column] = &[
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"role_name\0") },
        type_oid: pg_sys::NAMEOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"command_type\0") },
        type_oid: pg_sys::TEXTOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"is_approved\0") },
        type_oid: pg_sys::BOOLOID,
    },
];

const EPOCH_COLUMNS: &[Column] = &[
    Column {
        name: c"kind",
        type_oid: pg_sys::TEXTOID,
    },
    Column {
        name: c"epoch",
        type_oid: pg_sys::INT8OID,
    },
];

const REGEX_COLUMNS: &[Column] = &[
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"pattern\0") },
        type_oid: pg_sys::TEXTOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"action\0") },
        type_oid: pg_sys::TEXTOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"is_active\0") },
        type_oid: pg_sys::BOOLOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"allowed_roles\0") },
        type_oid: pg_sys::TEXTARRAYOID,
    },
];

const FINGERPRINT_COLUMNS: &[Column] = &[
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"fingerprint\0") },
        type_oid: pg_sys::TEXTOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"role_name\0") },
        type_oid: pg_sys::NAMEOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"command_type\0") },
        type_oid: pg_sys::TEXTOID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"hit_count\0") },
        type_oid: pg_sys::INT4OID,
    },
    Column {
        name: unsafe { CStr::from_bytes_with_nul_unchecked(b"is_approved\0") },
        type_oid: pg_sys::BOOLOID,
    },
];

fn extension_oid() -> Option<pg_sys::Oid> {
    let oid = unsafe { pg_sys::get_extension_oid(EXT_NAME.as_ptr(), true) };
    if oid == pg_sys::InvalidOid {
        None
    } else {
        Some(oid)
    }
}

fn in_own_extension_script(ext: Option<pg_sys::Oid>) -> bool {
    unsafe {
        let creating = std::ptr::addr_of!(pg_sys::creating_extension).read();
        if !creating {
            return false;
        }
        let current = std::ptr::addr_of!(pg_sys::CurrentExtensionObject).read();
        if current == pg_sys::InvalidOid {
            return false;
        }
        if ext == Some(current) {
            return true;
        }
        let raw = pg_sys::get_extension_name(current);
        if raw.is_null() {
            return false;
        }
        let ours = CStr::from_ptr(raw).to_bytes() == b"sql_firewall";
        pg_sys::pfree(raw.cast());
        ours
    }
}

fn unavailable_relation(
    ext: pg_sys::Oid,
    relname: &CStr,
    columns: &[Column],
) -> Option<&'static str> {
    let label = relation_label(relname);
    unsafe {
        let nsp = pg_sys::get_namespace_oid(PUBLIC_NSP.as_ptr(), true);
        if nsp == pg_sys::InvalidOid {
            return Some(label);
        }
        // Table SELECT does not imply the caller can resolve the schema.
        // A missing USAGE privilege makes the internal policy query fail;
        // that is an unavailable catalog, not a pass and not a native error
        // to surface from the firewall's own statement.
        let usage = pg_sys::object_aclcheck(
            pg_sys::NamespaceRelationId,
            nsp,
            pg_sys::GetUserId(),
            pg_sys::ACL_USAGE as pg_sys::AclMode,
        );
        if usage != pg_sys::AclResult::ACLCHECK_OK {
            return Some(label);
        }
        let rel = pg_sys::get_relname_relid(relname.as_ptr(), nsp);
        if rel == pg_sys::InvalidOid {
            return Some(label);
        }
        if pg_sys::getExtensionOfObject(pg_sys::RelationRelationId, rel) != ext {
            return Some(label);
        }
        if pg_sys::get_rel_relkind(rel) as u8 != pg_sys::RELKIND_RELATION {
            return Some(label);
        }
        let acl = pg_sys::pg_class_aclcheck(
            rel,
            pg_sys::GetUserId(),
            pg_sys::ACL_SELECT as pg_sys::AclMode,
        );
        if acl != pg_sys::AclResult::ACLCHECK_OK {
            return Some(label);
        }
        for column in columns {
            let attnum = pg_sys::get_attnum(rel, column.name.as_ptr());
            if attnum == 0 {
                return Some(label);
            }
            if pg_sys::get_atttype(rel, attnum) != column.type_oid {
                return Some(label);
            }
        }
    }
    None
}

fn relation_label(relname: &CStr) -> &'static str {
    match relname.to_bytes() {
        b"sql_firewall_command_approvals" => "sql_firewall_command_approvals",
        b"sql_firewall_regex_rules" => "sql_firewall_regex_rules",
        b"sql_firewall_query_fingerprints" => "sql_firewall_query_fingerprints",
        b"sql_firewall_policy_epoch" => "sql_firewall_policy_epoch",
        _ => "sql_firewall",
    }
}
