// Transaction boundary for one consumer event.
//
// pgrx 0.16.1 `BackgroundWorker::transaction` always calls
// `CommitTransactionCommand` after the closure returns. A `Result::Err` is
// therefore committed, not rolled back. A PostgreSQL ERROR becomes a Rust
// panic via `pg_guard`'s sigsetjmp bridge (`pg_guard_ffi_boundary`) and, if
// not caught, unwinds out of that helper before commit. `PgTryBuilder` calls
// `FlushErrorState` only after a catch handler returns; it does not abort the
// transaction. `StartTransactionCommand` leaves `TBLOCK_STARTED`, and
// `AbortCurrentTransaction` on that state runs `AbortTransaction` plus
// `CleanupTransaction` back to idle.
//
// This helper commits only after the SQL closure and `CommitTransactionCommand`
// both return. A caught ERROR, including one raised by commit itself, aborts.
// Rust panics and FATAL/PANIC are rethrown and are not retries. The owned
// event bytes live in Rust memory, so they remain valid after abort.

use pgrx::pg_sys;
use pgrx::pg_sys::panic::CaughtError;
use pgrx::PgLogLevel;
use pgrx::spi;
use pgrx::PgTryBuilder;
use std::ffi::CStr;
use std::panic::AssertUnwindSafe;

pub enum PersistAttempt {
    Committed,
    /// SQLSTATE when PostgreSQL reported one, otherwise an SPI status name.
    Retry { sqlstate: String },
}

pub fn persist_event_transaction<F>(work: F) -> PersistAttempt
where
    F: FnOnce() -> Result<(), spi::Error>,
{
    let work = AssertUnwindSafe(work);
    unsafe {
        pg_sys::SetCurrentStatementStartTimestamp();
        pg_sys::StartTransactionCommand();
        pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
    }

    let ran = PgTryBuilder::new(|| {
        // Schema-qualified extension objects still resolve. Unqualified
        // built-ins then come from pg_catalog, not a database search_path.
        if let Err(err) = spi::Spi::run(
            "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false)",
        ) {
            return WorkResult::Spi(err.to_string());
        }
        match work() {
            Ok(()) => WorkResult::Done,
            Err(err) => WorkResult::Spi(err.to_string()),
        }
    })
    .catch_others(classify_postgres_error)
    .execute();

    match ran {
        WorkResult::Done => finish_commit(),
        WorkResult::Spi(sqlstate) | WorkResult::Postgres(sqlstate) => {
            rollback_open_transaction();
            PersistAttempt::Retry { sqlstate }
        }
    }
}

enum WorkResult {
    Done,
    Spi(String),
    Postgres(String),
}

fn classify_postgres_error(err: CaughtError) -> WorkResult {
    if matches!(err, CaughtError::RustPanic { .. }) || fatal_or_worse(&err) {
        err.rethrow();
    }
    WorkResult::Postgres(current_sqlstate())
}

/// The caught report's own level (PostgreSQL 18 removed `geterrlevel`).
fn fatal_or_worse(err: &CaughtError) -> bool {
    let report = match err {
        CaughtError::PostgresError(report) | CaughtError::ErrorReport(report) => report,
        CaughtError::RustPanic { ereport, .. } => ereport,
    };
    report.level() >= PgLogLevel::FATAL
}

fn finish_commit() -> PersistAttempt {
    pop_snapshot();
    // Read SQLSTATE inside the catch, before PgTryBuilder calls FlushErrorState.
    let committed = PgTryBuilder::new(|| -> Result<(), String> {
        unsafe { pg_sys::CommitTransactionCommand() };
        Ok(())
    })
    .catch_others(|err| {
        if matches!(err, CaughtError::RustPanic { .. }) || fatal_or_worse(&err) {
            err.rethrow();
        }
        Err(current_sqlstate())
    })
    .execute();
    match committed {
        Ok(()) => PersistAttempt::Committed,
        Err(sqlstate) => {
            rollback_open_transaction();
            PersistAttempt::Retry { sqlstate }
        }
    }
}

fn current_sqlstate() -> String {
    unsafe {
        let code = pg_sys::geterrcode();
        let text = pg_sys::unpack_sql_state(code);
        if text.is_null() {
            return "00000".to_string();
        }
        CStr::from_ptr(text).to_string_lossy().into_owned()
    }
}

fn pop_snapshot() {
    unsafe {
        if pg_sys::ActiveSnapshotSet() {
            pg_sys::PopActiveSnapshot();
        }
    }
}

fn rollback_open_transaction() {
    pop_snapshot();
    unsafe { pg_sys::AbortCurrentTransaction() };
}
