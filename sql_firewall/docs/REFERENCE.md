# SQL Firewall reference

[Project overview](../../README.md) · [Documentation index](README.md)

Configuration, policy semantics, and operating procedures. Section numbers
are retained from the former README so existing source comments remain useful.

- [Architecture](#1-architecture)
- [Requirements and support boundaries](#3-requirements)
- [Installation](#4-installation)
- [Configuration](#5-configuration-gucs)
- [Policy and operational workflow](#6-operational-workflow)
- [Testing](#7-testing--validation)
- [Operations](#8-operations)
- [Troubleshooting and limits](#9-troubleshooting-and-known-limits)

`sql_firewall` is a PostgreSQL extension, written in Rust with pgrx, that
decides for every statement of an ordinary role whether it may run: command
approvals per role, fingerprint (query shape) approvals, keyword, built-in
tautology and regex rules, rate limits, quiet hours, and connection rules
(client address, application name). It records allowed and refused
statements and learns approvals in a learn mode.

Version `0.0.0`. Supported and release-tested: PostgreSQL 16, 17 and 18
(tested builds 16.15, 17.11, 18.6), UTF8 databases, Linux. Validation evidence
is linked in section 7; support limits are in section 9.

---
## 1. Architecture

| Layer | Source | Role |
|-------|--------|------|
| **Hooks** | `hooks.rs` | `ExecutorStart_hook` (planned statements), `ProcessUtility_hook` (utility statements) and `object_access_hook` (extension creation and removal). A refusal is an `ERROR` raised before the statement runs. |
| **Statement context** | `context.rs`, `port.rs`, `port_shim.c`, `encoding.rs` | Effective role, database, the connection's numeric client address, the startup `application_name`, the statement's own text (PostgreSQL's span inside a multi-statement message) and its parsed command family. |
| **Policy engine** | `firewall.rs`, `spi_checks.rs`, `fingerprints.rs`, `fingerprint_scan.c`, `sql_tokens.rs`, `regex_eval.c`, `rate_state.rs`, `policy_visibility.rs` | Session rules, quiet hours, rate limits, keyword and built-in checks on PostgreSQL lexer tokens, regex rules under a real deadline, command approvals, and SHA-256 fingerprint identities (6.2). Policy is read from the committed catalog or from a transaction-safe shared cache (6.1a). |
| **Shared memory** | `approval_cache.rs`, `fingerprint_cache.rs`, `rate_state.rs`, `pending_approvals.rs`, `activity_queue.rs`, `consumer_control.rs` | Approval cache (1024 entries), fingerprint cache (4096), rate counters (8192), event ring (1024 slots: learn observations, enforce-mode pending fingerprints, blocked statements), activity queue (`sql_firewall.activity_queue_size` records), worker control registry (128 installations). Sized at server start. |
| **Background workers** | `launcher.rs`, `approval_worker.rs`, `worker_persist.rs`, `consumer_checkpoint.rs`, `audit_retention.rs`, `alerts.rs` | One launcher per server and one consumer per database that has the extension. The consumer writes queued events and activity records, applies learning in decision order, sends `NOTIFY` after a blocked-query row commits, and prunes the audit logs. |
| **Catalog** | `sql/firewall_schema.sql` | Policy (kept by `pg_dump`): `sql_firewall_command_approvals`, `sql_firewall_query_fingerprints`, `sql_firewall_regex_rules`, `sql_firewall_regex_default_removals`, `sql_firewall_policy_history`. Audit: `sql_firewall_activity_log`, `sql_firewall_blocked_queries`. Runtime state (not dumped): `sql_firewall_policy_epoch`, `sql_firewall_consumer_checkpoint`, `sql_firewall_activity_checkpoint`, `sql_firewall_retention_status`. `sql_firewall_fingerprint_hits` is unused. |
| **Validation** | `qa/` | Isolated test runner and tests (section 7), performance driver `qa/perf/bench.sh`, PostgreSQL major-upgrade check `qa/pg_upgrade_check.sh`. |

Policy decisions are made synchronously in the backend that runs the
statement. Persistence (learned approvals, blocked-query rows, activity rows)
is asynchronous: the backend publishes to shared memory and the database's
consumer writes in its own transactions, so a refused or rolled-back
statement keeps its record and a failing audit write never fails a client
statement. The in-memory queues are not durable (3.1, 6.7).

`server_encoding` must be UTF8. `CREATE EXTENSION` and `ALTER EXTENSION
UPDATE` reject any other encoding with SQLSTATE `0A000` and `sql_firewall:
UTF8 database encoding is required; server_encoding is ...`. A database
without the extension is not inspected, whatever its encoding. Client
encodings that PostgreSQL converts into UTF8 remain usable. An installation
that already exists in an unsupported encoding is rejected at runtime with
the same diagnostic, before query bytes are decoded.

---
## 2. Feature Summary

- **Modes** (`sql_firewall.mode`, per server, database, role, or role in a
  database): `learn` allows statements and learns command and fingerprint
  approvals from committed transactions; `permissive` allows command and
  fingerprint approval violations and records them without learning;
  `enforce` refuses them. Regex, keyword, built-in, rate, quiet-hours and
  connection rules refuse in every mode (6.1c).
- **Command approvals** per role name and command family (`SELECT`,
  `INSERT`, `UPDATE`, `DELETE`, `MERGE`, utility families). The family is
  PostgreSQL's parsed command, also inside multi-statement messages, prepared
  statements, functions, and data-modifying CTEs (6.6a).
- **Fingerprints**: a 256-bit identity of the statement's canonical token
  sequence and its planned relation and object dependencies, bound to the
  installation (6.2). Learn approves an identity at
  `sql_firewall.fingerprint_learn_threshold` committed executions; an
  administrator can approve, block, or return it to learning.
- **Decision order and history**: an administrator's committed decision is
  never overridden by an older queued observation; every policy change is
  recorded in `sql_firewall_policy_history` (6.1b).
- **Keyword, built-in tautology, and regex checks** (6.6), regex under
  `sql_firewall.regex_timeout_ms` with its own timer and per-role exemptions
  (6.6b).
- **Rate limits** per database, role, and command family (6.4); **quiet
  hours** in a fixed policy time zone (6.3); **connection rules** on the
  numeric client address, role-to-address bindings, and `application_name`.
- **Audit**: every refusal in `sql_firewall_blocked_queries`, allowed
  statements in `sql_firewall_activity_log` (optional), decision and write
  times, optional `NOTIFY` and syslog alerts, bounded retention (6.5, 6.7,
  6.8).
- **Operations**: pause/resume/status of the consumer, queue statistics,
  recovery startup option, logical backup and restore of policy, extension
  update path, physical backup, hot standby and promotion, `pg_upgrade`
  (6.1d, 6.9–6.10, section 8).

---
## 3. Requirements

- PostgreSQL 16, 17, or 18 server with its development headers
  (`postgresqlNN-devel` on RHEL-family systems), UTF8 databases.
- Permission to set `shared_preload_libraries` and restart the server;
  superuser for `CREATE EXTENSION` and policy administration.
- Build: Rust (tested with 1.85.0), `cargo-pgrx` 0.16.1 (`cargo install
  --locked cargo-pgrx --version 0.16.1`), clang/libclang, a C compiler.
  On RHEL/Rocky/Alma: `dnf install clang llvm openssl-devel krb5-devel
  pkgconf-pkg-config` (CRB enabled).
- `max_worker_processes` large enough for one launcher plus one consumer per
  database that has the extension, on top of what the server already uses
  (parallel workers, logical replication, other extensions).

### 3.1 Support boundaries

| Area | Supported | Not supported or not guaranteed |
|---|---|---|
| PostgreSQL | 16, 17, 18 (each tested with its own build) | 13–15 feature flags exist in `Cargo.toml` for pgrx but are not tested or supported |
| Encoding | UTF8 server encoding | other server encodings (refused) |
| Topology | primary; hot standby enforcing replicated policy; promotion (6.10) | learning or audit persistence on a standby before promotion |
| Upgrades | in-place update to later versions with the package and `sql_firewall_upgrade` (`ALTER EXTENSION UPDATE`, 6.9a); `pg_upgrade` 16→17, 17→18, 16→18 (6.9b) | fingerprint approvals carried across `pg_upgrade` or a logical restore (they must be re-approved) |
| Queues | in-memory, counted loss | durable delivery after a postmaster restart or host crash |
| Identity | effective role, numeric client address | trusted `application_name`; Unix-socket peer identity policy |

---
## 4. Installation

### Ready package

Build one package per PostgreSQL major version against that server's
`pg_config` (needs Rust and `cargo-pgrx` 0.16.1; `cargo pgrx init` once per
major version):

```bash
cd sql_firewall
packaging/build-package.sh --pg-config /usr/pgsql-16/bin/pg_config
# -> target/dist/sql_firewall-0.0.0-pg16-linux-x86_64.tar.gz (+ .sha256)
```

The build goes through `qa/run.sh --build-only` (release profile, locked and
offline dependencies, C files checked against the selected server headers),
and its manifest is kept in the package as `BUILD-MANIFEST.txt`. The package
holds the library, the control file, the install script and every update
script, `install.sh`, the update tool `sql_firewall_upgrade` (6.9a),
`INSTALL.md`, `PACKAGE` (version, PostgreSQL major, source digest, library
checksum), and `SHA256SUMS`. On the server, as the installation owner or root:

```bash
tar -xzf sql_firewall-0.0.0-pg16-linux-x86_64.tar.gz
cd sql_firewall-0.0.0-pg16-linux-x86_64
sudo ./install.sh --pg-config /usr/pgsql-16/bin/pg_config
```

`install.sh` checks `SHA256SUMS` and that the package matches the server's
major version, and writes each file under a temporary name and renames it
into place, so a running server keeps the library it loaded at start.
Building with `cargo pgrx package --pg-config ... --no-default-features
--features pg16` directly also works; `build.rs` compiles the C files against
`PGRX_PG_CONFIG_PATH`, then `PG_CONFIG`, then the first `pg_config` on
`PATH`, so set `PGRX_PG_CONFIG_PATH` when several majors are installed.

### Preload, restart, create

Add the library to `postgresql.conf`, preserving any existing preload entries:

```ini
shared_preload_libraries = 'sql_firewall'
```

Restart PostgreSQL (use the service name for your installation):

```bash
sudo systemctl restart postgresql-16
```

Then, in each database to protect:

```sql
CREATE EXTENSION sql_firewall;
SELECT sql_firewall_status();   -- sql_firewall running in Learn mode
```

**Preload is required, and `CREATE EXTENSION` checks it.** Without preload
the library installs no hooks and no shared memory, and nothing would be
inspected, so `CREATE EXTENSION sql_firewall` is refused unless the running
server loaded the library at start:

```
ERROR:  sql_firewall: the library is not loaded through shared_preload_libraries; add sql_firewall to shared_preload_libraries, restart PostgreSQL, and run the command again
DETAIL:  shared_preload_libraries is '' in this server; the configuration sets 'sql_firewall', which takes effect only after a restart
```

The setting text alone is not enough: after `ALTER SYSTEM` and a reload, the
refusal stays until the restart (the `DETAIL` names the pending value). The
error rolls the whole statement back, so no extension, table, or function is
left behind, and the database keeps working. `pg_upgrade` is unaffected: it
restores an installed extension in binary-upgrade mode, where this check is
not run (6.9b).

Removing the preload later is a different case, which the library cannot
enforce because it is then not loaded: existing installations stay in place
and are not inspected. Any session that loads the library warns
`sql_firewall: the library is not loaded through shared_preload_libraries;
statements are not inspected and no firewall policy applies`, and
`SELECT sql_firewall_status()` returns `sql_firewall NOT ACTIVE: ...`. With
preload it returns `sql_firewall running in <mode> mode`, `disabled` when
`sql_firewall.enabled = off`, and names a hot standby (6.10).
`SELECT * FROM sql_firewall_library_version()` (superuser) shows the version
of the library this session runs and the version the server preloaded
(`running_version`, from shared memory; NULL without preload). A session uses
the library the server preloaded, so after a new package is installed both
still show the old version until the restart, while
`pg_available_extensions.default_version` already shows the new one; that
difference is what the update script and `sql_firewall_upgrade` check
(6.9a). Verified by
`qa/tests/111_install_matrix.sh` and `qa/package_upgrade_check.sh`.

The launcher connects to `sql_firewall.launcher_database` (default
`postgres`; restart required) to list databases. Set it when `postgres` does
not exist or does not allow connections; if the named database is missing,
the launcher fails to start (logged) and is retried every 5 s. In
binary-upgrade mode (`pg_upgrade`) the library starts nothing (6.9b).

To uninstall, run `DROP EXTENSION sql_firewall` in every database that has
it (its policy and audit tables go with it; take a `pg_dump` first if they
are needed), then remove `sql_firewall` from `shared_preload_libraries` and
restart. Removing the preload first leaves those databases uninspected
(`sql_firewall_status()` says `NOT ACTIVE`).

### 4.1 Safe starting settings

The installation defaults are permissive by design (mode `learn`, superuser
bypass on), so that installing the extension does not stop an application.
For production:

1. Decide who is inspected. Superusers are not inspected while
   `sql_firewall.allow_superuser_auth_bypass = on` (default). Keep it on for
   administration, restore, and upgrade work, and run applications as
   ordinary roles. If you turn it off, learn the recovery path first (6.1d).
2. Learn under controlled traffic only. In `learn`, unknown commands and
   shapes are approved automatically; an attacker active during that window
   is learned too. Run learn on a staging copy, or for application roles
   during a supervised window (`ALTER ROLE app IN DATABASE db SET
   sql_firewall.mode = 'learn'`), then review
   `sql_firewall_command_approvals` and `sql_firewall_query_fingerprints`
   (6.1).
3. Observe in `permissive`: approval violations are allowed and appear in
   the activity log with `decision = 'would_block'`; nothing is learned, and
   the other rules still refuse (6.1c).
4. Switch the roles to `enforce`. Keep `sql_firewall.enable_fingerprint_learning
   = on` (fingerprint checking) unless command-level control is enough.
5. Size the queues for the statement rate (section 8 and
   `docs/PERFORMANCE.md`): watch `sql_firewall_queue_statistics()` for
   activity overwrites, or turn activity logging off; refusals are always
   recorded.
6. Set retention (`sql_firewall.activity_log_retention_days`,
   `sql_firewall.retention_days`, `sql_firewall.activity_log_max_rows`) and
   alerts (6.8).

---
## 5. Configuration (GUCs)

All knobs live under `sql_firewall.*` and may be set via `ALTER SYSTEM`, `postgresql.conf`, `ALTER DATABASE`, or `ALTER ROLE ... IN DATABASE`. Every one is superuser-only (`SUSET`) or needs a restart (`postmaster`); an ordinary role cannot change them for its own session (6.1d).

| Category | GUC | Default | Description |
|----------|-----|---------|-------------|
| **Modes** | `sql_firewall.mode` | `learn` | Choose between `learn`, `permissive`, `enforce` (6.1c). |
| | `sql_firewall.enabled` | `on` | Kill switch; `off` inspects nothing. Set at connection with `-c` to recover (6.1d). |
| | `sql_firewall.allow_superuser_auth_bypass` | `on` | Superusers are not inspected. |
| **Quiet Hours** | `sql_firewall.enable_quiet_hours` | `off` | Master toggle. |
| | `sql_firewall.quiet_hours_start` / `sql_firewall.quiet_hours_end` | unset | HH:MM window, start inclusive, end exclusive; start later than end spans midnight; equal means all day (6.3). |
| | `sql_firewall.quiet_hours_timezone` | empty (`log_timezone`) | Time zone of the window; the session's `TimeZone` does not matter. |
| | `sql_firewall.quiet_hours_log` | `on` | Also write a WARNING-level server log line for each quiet-hours refusal (the refusal is recorded either way). |
| **Rate Limiting** | `sql_firewall.enable_rate_limiting` | `off` | Enables the global window, per database and role (6.4). |
| | `sql_firewall.rate_limit_count` / `sql_firewall.rate_limit_seconds` | `100` / `60` | Requests allowed inside global window. |
| | `sql_firewall.command_limit_seconds` | `60` | Window for verb limits (0 disables per-command caps). |
| | `sql_firewall.select_limit_count`, `insert_limit_count`, `update_limit_count`, `delete_limit_count` | `0` | Verb-specific caps per window. |
| **Approvals & Fingerprints** | `sql_firewall.enable_fingerprint_learning` | `on` | Check fingerprints in all modes; only Learn creates automatic fingerprint approvals. |
| | `sql_firewall.fingerprint_learn_threshold` | `5` | Hits required to auto-approve a fingerprint. |
| **Keyword / Regex** | `sql_firewall.enable_keyword_scan` | `on` | Keyword blacklist switch. |
| | `sql_firewall.blacklisted_keywords` | empty | Comma-separated list of blocked keywords. |
| | `sql_firewall.enable_builtin_injection_check` | `on` | Refuse `OR` tautologies such as `OR 1=1` (6.6). Independent of `enable_regex_scan`. |
| | `sql_firewall.enable_regex_scan` | `on` | Evaluate `sql_firewall_regex_rules` against the raw statement text (6.6). |
| | `sql_firewall.regex_timeout_ms` | `100` | Time limit for the regex rules of one statement; reaching it refuses the statement. |
| **Connection Policies** | `sql_firewall.enable_application_blocking` / `.blocked_applications` | `off` / empty | Deny by `application_name`. |
| | `sql_firewall.enable_ip_blocking` / `.blocked_ips` | `off` / empty | Deny client IP addresses, compared by value with the numeric address (6.1c). |
| | `sql_firewall.enable_role_ip_binding` / `.role_ip_bindings` | `off` / empty | Allow explicit `role@ip` pairs only; a bound role is refused over a Unix socket. |
| **Alerts** | `sql_firewall.enable_alert_notifications` | `off` | Emit NOTIFY events for blocks. |
| | `sql_firewall.alert_channel` | `sql_firewall_alerts` | Channel name for LISTEN/NOTIFY. |
| | `sql_firewall.syslog_alerts` | `off` | Mirror alerts to syslog for SIEM. |
| **Activity Logging** | `sql_firewall.enable_activity_logging` | `on` | Allowed-query activity logging switch. Blocked events are published separately regardless of this setting (6.7). |
| | `sql_firewall.activity_queue_size` | `4096` | Records the shared activity queue holds (about 3.2 kB each); `postmaster`, restart required. |
| | `sql_firewall.launcher_database` | empty (`postgres`) | Database the launcher connects to in order to list databases; `postmaster`, restart required. |
| **Retention** | `sql_firewall.activity_log_retention_days` | `30` | Age cutoff for activity rows. |
| | `sql_firewall.retention_days` | `30` | Age cutoff for blocked-query rows; `0` disables age pruning. |
| | `sql_firewall.activity_log_max_rows` | `1000000` | Activity row-count target. |
| | `sql_firewall.activity_log_prune_interval_seconds` | `300` | Worker cleanup interval; each delete transaction is capped at 1,000 rows, and consecutive transactions continue while rows remain (6.8). |

**Note:** The launcher spawns a dedicated worker per installed database and connects directly without `dblink`. Retained approvals and blocked-query events are written in their originating database; a full ring can overwrite events before a worker processes them.

The event ring has 1,024 slots in shared memory. A worker advances its
checkpoint only after its database transaction commits; a recoverable SQL
error retries the copied event, and a replacement worker can resume from a
checkpoint while the ring generation still exists. Pause or a stopped worker
can let the ring overwrite unread positions; resume reports the skipped
shared-stream range. `write_pos` counts publications and `slot_overwrites`
counts reused slots, not per-database lost events. A postmaster restart creates
a new ring, so unconsumed in-memory events do not survive it. Persisted rows
remain in the database. This is an overwrite buffer, not a durable queue or a
crash-loss guarantee.

### Approval worker maintenance
- `SELECT sql_firewall_pause_approval_worker();` stores a pause for this installation. `approval worker paused` means a live consumer has acknowledged it and is quiescent. `pause pending` means the request is stored but not yet acknowledged, including when no consumer is attached. Cancelling or rolling back the call does not withdraw a request for a committed installation. The record is released when a `DROP EXTENSION` or `DROP DATABASE` that removed its installation commits. A drop undone by `ROLLBACK`, `ROLLBACK TO SAVEPOINT`, or an exception block leaves the record and its acknowledgement in place. A request for an installation created in the same transaction is released if that creation rolls back, including by a savepoint. That ownership is recorded when the extension row is inserted, before the install script and `ddl_command_end` event triggers run, in the subtransaction that created it. The launcher also releases records whose database no longer appears in `pg_database`. `PREPARE TRANSACTION` is refused for a transaction that created or removed an installation holding such a record.
- `SELECT sql_firewall_resume_approval_worker();` clears that pause. `approval worker running` means the consumer is processing. `resume acknowledged` means the consumer accepted the request but is still waiting on checkpoint metadata or a retry. Resume does not repair or skip that metadata.
- `SELECT sql_firewall_approval_worker_status();` reports this installation's observed state: `paused`, `running`, `retrying`, `starting`, `stopping`, `pause pending`, `resume pending`, or `stopped`. A live acknowledgement includes the request epoch and consumer incarnation. `retrying` means the consumer is waiting: checkpoint metadata is missing, invalid, or ahead of the ring, or a copied event has not committed. A consumer that exits abnormally drops its acknowledgement and keeps a pause that was already requested.
- Workers are managed per database by the launcher and use regular SPI connections, so no external extensions such as `dblink` are required.

### Launcher and consumer processes
- The launcher (`backend_type` `sql_firewall_launcher`) connects to `sql_firewall.launcher_database` (default `postgres`) and starts one consumer (`sql_firewall_worker_<database oid>`) per database that allows connections and is UTF8; the consumer checks whether the extension is installed there. A database without the extension is probed again after 30 s, then after twice the previous wait, up to 10 minutes. A committed `CREATE EXTENSION` is announced to the launcher, which starts that database's consumer at its next scan (every 5 s). An installation committed with `PREPARE TRANSACTION` / `COMMIT PREPARED` is not announced and is picked up at the next probe.
- A configuration reload (`pg_reload_conf()`) reaches the running launcher and consumers; retention and alert settings apply without a restart.
- An ERROR in a consumer ends only that consumer (exit code 1); the launcher starts a new one. If the postmaster dies, the launcher and consumers exit on their own, so the data directory can be started again.
- After a crash of any server process, PostgreSQL reinitializes shared memory: the firewall's rings, caches, rate counters, and control records start empty (unconsumed events are lost, as after a restart) and the launcher is restarted 5 s later. A launcher stopped normally (server shutdown, or `pg_terminate_backend` by a superuser) is not restarted until the next server start.
- Verified by `qa/tests/90_worker_discovery.sh` and `qa/tests/110_worker_process.sh`.

---
## 6. Operational Workflow

### 6.1 Learn → Approve → Enforce
1. **Learn** – allows previously unseen commands and queues command approvals for the background worker. It records fingerprint hits and approves each fingerprint when its persisted hit count reaches the configured threshold. Only committed transactions are learned (6.1b). A queued approval authorizes nothing in enforce mode until the worker commits it (6.1a). Review learned approvals before moving to production enforcement.
2. **Review** – admins query activity log and approval tables in each database, verify legitimacy, and set `is_approved=true`.
3. **Enforce** – unknown or unapproved commands and fingerprints are blocked with `ERRCODE_INSUFFICIENT_PRIVILEGE` when fingerprint checking is enabled. `permissive` mode is available for staging: it logs command and fingerprint approval violations without blocking or changing approvals. Other enabled protections continue to block.

`sql_firewall_block_fingerprint` marks a fingerprint unapproved and disables its
automatic reapproval in Learn. Learn and permissive still allow approval
violations; enforce rejects the unapproved fingerprint. The administrator must
call `sql_firewall_approve_fingerprint` to approve it again. That call clears
the automatic-approval disable flag. The flag is policy data and is included
in a normal `pg_dump` of the current installation. Decision states, the order
between queued learning and administrator decisions, and the decision history
are described in 6.1b.

### 6.1a Policy Visibility and the Shared Caches

Command approvals and fingerprint approvals are cached in shared memory
(1024 and 4096 entries) so that most statements do not read the policy
tables. The caches follow PostgreSQL's transaction rules:

- **Committed changes apply at once.** Once COMMIT has returned, a change
  to `sql_firewall_command_approvals` or `sql_firewall_query_fingerprints`
  applies from the next inspected statement in every session, existing or
  new, in both directions (a revoke and an approval). This holds for the
  management functions, direct superuser `INSERT`, `UPDATE`, `DELETE`, and
  `TRUNCATE`, and the approval worker. No cache clear and no expiry is
  needed; `sql_firewall_clear_approval_cache()` still exists but is never
  required.
- **Latest committed policy, not the transaction snapshot.** A decision uses
  the latest committed policy when the statement is inspected, plus the
  deciding transaction's own uncommitted policy writes, like PostgreSQL's
  privilege checks. An open REPEATABLE READ or SERIALIZABLE transaction
  keeps its data snapshot, but a revocation committed after it began applies
  to its next inspected statement. A statement that was already past
  inspection when the change committed finishes under the decision it got.
- **Uncommitted writes stay private.** A transaction that writes a policy
  table (for example, an administrator who approves and then tests with
  `SET LOCAL ROLE`) sees its own writes. From the moment its writing
  statement begins, and for the rest of that transaction, it does not use or
  fill the shared caches, so nothing it read reaches another session. This
  covers policy read back from inside the writing statement itself, such as
  a function called in `RETURNING` or a user trigger on the policy table.
  Other sessions see the change only when it commits. A rollback, of the
  whole transaction or to a savepoint, leaves nothing behind.
- **One installation.** Cached decisions belong to one extension
  installation, database, role OID, and role name. After `DROP EXTENSION`
  and `CREATE EXTENSION`, nothing cached for the old installation is used.
  A rolled-back drop or re-create, including one rolled back to a savepoint,
  leaves the original installation and its policy in force. A renamed role
  does not keep the entries cached under its old name.
- **Learn mode.** The fingerprint memo records that a new identity was logged
  once. It does not grant approval or stop later hit events. Permissive and
  enforce decisions use committed catalog state.

How it works. Each cache keeps a generation counter per database. Two
`ENABLE ALWAYS` triggers on each policy table mark the writing transaction,
so they also fire with `session_replication_role = replica`:

- `sql_firewall_policy_changing`, statement-level `BEFORE INSERT OR UPDATE OR
  DELETE OR TRUNCATE`. Because it is `BEFORE`, the transaction is marked a
  writer before the statement changes any row. Anything the statement
  evaluates afterwards — a `RETURNING` expression, a user trigger on the
  policy table, a rule — therefore finds a writer and reads the catalog
  instead of the shared cache. An `AFTER` trigger would run too late: the row
  is already inserted when `RETURNING` is evaluated, so a policy lookup
  nested there could publish an uncommitted approval that another session
  would then use and a rollback could not withdraw.
- `sql_firewall_policy_changed`, row-level `AFTER INSERT OR UPDATE OR
  DELETE`. Logical replication apply fires row triggers but no statement
  triggers, so this keeps applied policy changes marked.

When the marked transaction commits (after the commit is visible, before
COMMIT returns to the client), the database's generation advances. A reader
reads the generation before it takes the snapshot for its catalog read,
publishes the result only if the generation has not moved, and uses an entry
only while its generation is current. `COMMIT PREPARED` and `ROLLBACK
PREPARED` advance both generations. A transaction that alters or drops any
trigger advances both generations when it commits.

The shared caches are bypassed, and every inspected statement reads the
catalog, when:
- the invalidation triggers are missing, disabled, or not in their installed
  form — both must be present, `ENABLE ALWAYS`, and carry no `WHEN` clause or
  column list;
- the server is a hot standby (replayed changes fire no triggers);
- the statement is inspected inside a parallel operation (it then uses the
  statement's snapshot);
- the transaction wrote a policy table or created or dropped the
  installation.

Bypassing costs one indexed catalog read per inspected statement; it never
changes a decision. A policy commit makes the cached entries of that
database's policy table unusable, so the next statements in that database
read the catalog once each to refill them.

**Installation checks.** Whether the extension is installed and its policy
relations are usable (6.1c) is checked against the catalogs and kept per
backend until a relevant catalog change is processed: `CREATE`/`DROP
EXTENSION`, a revoked privilege, a renamed or retyped column, a trigger
change, and `ALTER EXTENSION ... ADD/DROP` (which invalidates explicitly,
because it changes only `pg_depend`). Each inspected statement first handles
invalidations other sessions committed, so an existing session sees such a
change at its next statement, also inside an open transaction; a rolled-back
change has no effect. Verified by `qa/tests/70_database_activation.sh` and
`qa/tests/114_admin_boundary.sh` (`membership`).

**Installation.** This unreleased build ships a single fresh-install version,
`0.0.0`. The install script creates the policy invalidation triggers and
registers policy tables for `pg_dump`. A postmaster restart is required when
loading a changed shared-memory layout.

**Limits.** Disabling the invalidation triggers is still not a supported way
to bulk-load policy, but it does not produce stale decisions: while they are
disabled every inspected statement reads the catalog, and the `ALTER TABLE`
that disables them is itself a trigger change, so it advances both
generations when it commits and the entries cached before it become
unusable. Two schedules were tried against this build — another session
disabling the triggers and revoking while a transaction held the policy
table open, and the same with no intervening statement — and both denied the
next query correctly; a session inside an open transaction is not exempt,
because planning its own statement accepts the pending relation-cache
invalidations. An earlier version of this section claimed a stale-decision
window here; no schedule demonstrating one was found, so the claim is
withdrawn.

`BEGIN`/`START TRANSACTION` isolation and read-only options are applied by
PostgreSQL before firewall policy inspection. That inspection reads approval,
fingerprint, and regex policy with a fresh snapshot that does not establish
the transaction's first data snapshot. An approved `BEGIN` followed directly
by `SET TRANSACTION ISOLATION LEVEL` can therefore set REPEATABLE READ or
SERIALIZABLE before the first data query. An unapproved transaction command
still raises `42501`. The regex check retains its 100 ms limit. Activity
records of these statements go to the activity queue like every other record
(6.7); nothing is written in the transaction.

**Utilities before the first snapshot.** PostgreSQL runs some utilities
without a transaction snapshot (`PlannedStmtRequiresSnapshot`): `SHOW`,
`SET`/`SET LOCAL`/`RESET`, `SAVEPOINT`, `RELEASE`, `ROLLBACK TO`, `LOCK`,
`SET CONSTRAINTS`, and a few others (`LISTEN`, `NOTIFY`, `UNLISTEN`,
`FETCH`/`MOVE`, `CHECKPOINT`). Suppose one of them runs in a transaction that
has no snapshot yet. Its inspection then does not take one either:
- The statement is still inspected before it runs, so a `SET` cannot change
  a setting the firewall reads before it is authorized.
- It still needs its command approval, and it still gets fingerprint
  handling and the regex check. Policy is read with the same fresh snapshot
  as transaction control, and the regex check keeps its 100 ms limit.
- A later `SET TRANSACTION` or `BEGIN ISOLATION LEVEL`, and the first
  snapshot of a REPEATABLE READ or SERIALIZABLE transaction, then behave as
  they do without the extension.
- PostgreSQL's own rejections are unchanged. `SET TRANSACTION ISOLATION
  LEVEL` after a data query, or inside a savepoint (including after
  `ROLLBACK TO`, which stays in it), is still `25001`.

This applies to every kind of transaction. The end of a message is not
the end of a transaction:
- **Explicit block** (`BEGIN` ... `COMMIT`, `ROLLBACK`, or `PREPARE
  TRANSACTION`, possibly chained with `AND CHAIN`): it spans any number of
  messages of either protocol.
- **Simple-query message with several statements** and no `BEGIN`: PostgreSQL
  runs them in an implicit block that commits after the last statement. A
  `BEGIN` inside the message turns it into an explicit block that stays open
  after the message.
- **No block** (a single-statement simple-query message, or extended-protocol
  Parse/Bind/Execute messages): the transaction commits when the message ends
  (simple query) or at the next Sync (extended protocol). A pipeline can run
  several statements, and even a `BEGIN`, in that one transaction before its
  Sync.

Activity records of these statements, like every activity record, go to the
activity queue and are written by the worker (6.7), so recording them takes
no snapshot and is not tied to how the transaction ends. Learn observations
are published when the transaction commits (6.1b). A rejected statement's
syslog alert is sent at once when enabled. The consumer sends its NOTIFY
after the blocked-query row commits, so the rejected statement's rollback
does not discard the notification.

Records name the role whose policy decided the statement (the current role
at inspection), so a superuser's inspected `SET SESSION AUTHORIZATION`
(superuser bypass off) is attributed to the superuser that ran it.

### 6.1b Decision States, Decision Order, and History

**States.** Command approvals (`sql_firewall_command_approvals`, one row per
role name and command) and fingerprints (`sql_firewall_query_fingerprints`,
one row per identity, role name, and command):

| state | command row | fingerprint row | Learn | permissive | enforce |
|---|---|---|---|---|---|
| unknown | no row | no row | allowed; the observation is queued and learned (command: approved at once; fingerprint: pending row, hit 1) | allowed, logged | rejected |
| pending | — (not created by the firewall) | `is_approved = false`, `auto_approval_disabled = false` | allowed; each observation counts; approved when the persisted hit count reaches `sql_firewall.fingerprint_learn_threshold` | allowed, logged | rejected |
| approved | `is_approved = true` | `is_approved = true` | allowed | allowed | allowed |
| denied | `is_approved = false` | `is_approved = false`, `auto_approval_disabled = true` | allowed (a command also warns); observations of a fingerprint are counted; never approved by learning | allowed, logged | rejected |

- Learn only creates a command decision where there is none. It never
  changes an existing command row, so `is_approved = false` for a command is
  final for learning, whether an administrator revoked it or inserted it.
  `sql_firewall_revoke_command` records a denial also for a command that has
  no row yet.
- For fingerprints, `sql_firewall_block_fingerprint` and a direct
  `UPDATE ... SET is_approved = false` are both denials: an `UPDATE` that
  explicitly assigns `is_approved` without changing `auto_approval_disabled`
  sets the latter to `NOT is_approved`, even when a pending row is already
  `false` (trigger `sql_firewall_fingerprint_decision`). A direct
  approval therefore clears a denial, as `sql_firewall_approve_fingerprint`
  does. An `UPDATE` that changes `auto_approval_disabled` itself keeps the
  stated value. The worker's own hit updates do not count as direct decisions.
- To return a decision to learning, delete its row. The next observation
  starts again from unknown (fingerprint hit count 1).
- Mode-specific behaviour, including explicit denials in Learn, is the
  firewall mode's (6.1). This table is about which state a row is in.

**Order between learning and administrator decisions.** Learn events wait in
the shared-memory queue until the database's approval worker applies them.
An observation made before an administrator's decision must not override,
revive, or count against that decision:

- Each backend reads `sql_firewall_policy_epoch` in the same snapshot as the
  policy lookup that produced a learn event, and the event carries it.
- Every administrator transaction that writes a policy table (a management
  function, direct `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`, logical replication
  apply) advances that table's epoch once, before its statement changes any
  policy row, and holds the row lock until it commits or aborts. The values
  therefore follow commit order.
- The worker takes the epoch row `FOR SHARE` before it applies an event (it
  waits for an administrator transaction in progress), then discards the
  event if the decision history has an administrator change to the same key
  (role name, command, fingerprint), or a `TRUNCATE` of the table, with a
  later epoch. Changes to other keys do not discard it. A discarded event is
  logged at `LOG`: `discarded learn event for role "R" command C: an
  administrator changed this decision after the observation`.
- A discarded fingerprint hit is not counted. The next observation after the
  decision is applied normally.

**Only committed work is learned.** A learn observation (a command approval,
or a fingerprint hit with a learn threshold) is held in the backend with the
(sub)transaction that made it and published to the queue when the top-level
transaction commits:

- A failed or cancelled statement, `ROLLBACK`, `ROLLBACK TO SAVEPOINT`, a
  PL/pgSQL exception block that catches an error, and `PREPARE TRANSACTION`
  discard the observations made in what they undo. A prepared transaction's
  observations are never counted, also after `COMMIT PREPARED`.
- An observation is one inspected statement execution. Statements that a
  function or procedure runs are inspected, and counted, on their own; a
  `SELECT f()` that runs two statements makes three observations.
- Several executions of the same identity in one transaction are published
  as one event with that many hits; the threshold counts every execution.
  The mode at `COMMIT` does not matter: an observation made in learn mode
  counts if its transaction commits.
- One transaction holds at most 1024 distinct observations (the queue's
  capacity). Further ones are not recorded; the first one warns, and
  `sql_firewall_queue_statistics().learn_observations_dropped` counts them.
- Records of rejected statements (blocked queries, enforce-mode pending
  fingerprints) are published at once, because their transaction aborts.

`sql_firewall_queue_statistics()` (superuser) reports the cluster-wide queue
counters since the server started: write position, reused slots, capacity,
and publications per event type.

**Role names.** Policy rows name roles as text, so a policy survives a
logical restore, where role OIDs differ. The consequences:

- A queued learn event also carries the role's OID. The worker discards it,
  with a `LOG` line naming both OIDs, when the name now belongs to another
  role or to none (`DROP ROLE` and `CREATE ROLE` with the same name,
  `ALTER ROLE ... RENAME`).
- Rows already stored stay under the name. `DROP ROLE` leaves them; a role
  created later with the same name gets them, and a renamed role loses them.
  Delete or rename a role's rows in every database that has the extension
  when you drop or rename the role (roles are cluster-wide; policy is per
  database, and nothing runs in the other databases when a role changes).
- The shared caches are keyed by role OID and name (6.1a), so they never
  apply a decision cached for a different role.
- The firewall evaluates the current (effective) role of a statement:
  `SET ROLE` and `SECURITY DEFINER` functions change it.

**Who can read policy.** Every role can select the policy tables, because
the firewall reads them as the role it decides for. Row security limits
`sql_firewall_command_approvals` and `sql_firewall_query_fingerprints` to
the current role's own rows (including its own sample queries), which are
the only rows the firewall reads for it. Superusers, the tables' owner, and
members of `pg_read_all_data` see every row; grant `pg_read_all_data` to
auditors, or let them use a superuser. A write grant does not widen what a
role sees. `sql_firewall_regex_rules` applies across roles and stays
readable in full. The activity and blocked-query logs, the decision
history, and the runtime tables are not readable without a grant.

**Who can change policy.** Only a superuser session, and the firewall's own
background processes. The management functions check `session_user`, and
every table of the extension has an `ENABLE ALWAYS` trigger,
`sql_firewall_guard`, that refuses `INSERT`, `UPDATE`, `DELETE`, and
`TRUNCATE` from any other session with `42501` "sql_firewall: only a
superuser session can change <table>; table privileges granted to other
roles do not delegate firewall administration". So a `GRANT` on these
tables, membership in `pg_write_all_data`, or `BYPASSRLS` gives no role the
ability to approve itself, edit rules, erase history, forge audit rows, or
move a consumer's checkpoint. The guard is the first `BEFORE` statement
trigger of each table and, on the policy tables, also a `BEFORE` row
trigger, which logical replication apply fires: a subscription that
replicates firewall policy must be owned by a superuser. Keep the tables
owned by the superuser that created the extension (an owner can disable
triggers). Verified by `qa/tests/114_admin_boundary.sh` (every table, every
write command, explicit grants, `pg_write_all_data`, `BYPASSRLS`, row
visibility) and 103, 107.

**Decision history.** `sql_firewall_policy_history` records committed
decision changes in the writing transaction, so a rolled-back change leaves
no row:

- `source = 'administrator'`: every row change and `TRUNCATE` of either
  policy table by anything other than the approval worker, including the
  management functions, direct superuser DML, and a restore's own row
  loads. (Other sessions cannot write the tables; see above.)
- `source = 'learn'`: the approval worker's changes that alter a decision
  (a learned command approval, a fingerprint approved at its threshold). A
  discovered pending fingerprint and hit counting are not recorded.
- `session_role` and `effective_role` name who wrote the change (inside a
  `SECURITY DEFINER` management function the effective role is the function
  owner), `changed_at` is when (clock time of the change),
  `transaction_id` identifies the transaction (join
  `pg_xact_commit_timestamp()` when `track_commit_timestamp` is on),
  `old_*`/`new_*` hold the key and decision before and after, and
  `policy_epoch` the administrator epoch.
- Rows are identified within their installation (`system_identifier`,
  `database_oid`, `extension_oid`, `change_id`).
- Only superusers can read the table; grant `SELECT` explicitly for
  auditors. There is no automatic retention: delete old rows yourself if
  needed, but keep at least the rows newer than any learn event that may
  still be queued (a few minutes is ample while the worker runs), because
  the worker's order check reads them.
- Writes made with the policy triggers disabled (`ALTER TABLE ... DISABLE
  TRIGGER`) are neither recorded nor ordered; do not disable them.

### 6.1c Mode Behaviour

The mode is `sql_firewall.mode` of the session running the statement
(`SUSET`: set in `postgresql.conf`, `ALTER SYSTEM`, `ALTER DATABASE`,
`ALTER ROLE [IN DATABASE]`, or by a superuser; an ordinary role cannot change
it for itself). Sessions of one role can run in different modes at the same
time, and a change applies from the session's next statement. Commands are
PostgreSQL's command families (6.6a).

Command approval (with fingerprint checking off, or before it):

| command row | learn | permissive | enforce |
|---|---|---|---|
| none | allowed, `ALLOWED (LEARN MODE - AUTO)`; approval learned at commit | allowed, `ALLOWED (PERMISSIVE - UNAPPROVED)` | rejected `42501` "No rule found for command 'C' for role 'R'" |
| `is_approved = false` | allowed with a warning, `ALLOWED (LEARN MODE - PENDING)`; never learned | allowed with a warning, `ALLOWED (PERMISSIVE - PENDING)` | rejected `42501` "BLOCKED - Approval for command 'C' is pending for role 'R'" |
| `is_approved = true` | allowed, `ALLOWED` | allowed, `ALLOWED` | allowed, `ALLOWED` |

`OTHER` (the few utility commands without their own family) is allowed and
logged as `ALLOWED (OTHER)` in learn and permissive, and needs an approval in
enforce like any command.

Fingerprint approval, when `sql_firewall.enable_fingerprint_learning` is on
and the command itself was allowed (an approved command never replaces a
fingerprint approval):

| fingerprint row | learn | permissive | enforce |
|---|---|---|---|
| none | allowed; `LEARNED (FINGERPRINT AUTO)`; a pending row with one hit at commit (approved at once if the threshold is 1) | allowed, `ALLOWED (PERMISSIVE - FINGERPRINT)`; nothing stored | rejected `42501` "Fingerprint 'F' for role 'R' is pending approval"; a pending row is recorded |
| pending | allowed; the hit counts; approved when the count reaches the threshold | allowed, logged as above; not counted | rejected as above; the attempt is counted (never approves) |
| denied | allowed; the hit counts; never approved | allowed, logged as above | rejected as above; the attempt is counted |
| approved | allowed | allowed | allowed |

Other rules:
- Keyword, built-in injection, regex, rate-limit, quiet-hours, blocked
  IP/application, and role-IP rules reject in every mode, learn included,
  before the approval checks, and are
  recorded as blocked queries. Permissive relaxes only the approval checks
  (the operator's decision; the original plan's "all violations log-only"
  was not adopted).
- Rejected statements are recorded in `sql_firewall_blocked_queries` (the
  worker writes the row); allowed statements in the activity log when
  activity logging is on.
- `sql_firewall.fingerprint_learn_threshold` is 1..1000; 0 or a negative
  value is refused (`22023`).
- Superusers are not inspected while `sql_firewall.allow_superuser_auth_bypass`
  is on (the default). With it off they are inspected like any role.
- Where the extension is not installed nothing is inspected; an unusable
  policy catalog rejects in enforce (`55000`) and warns in the other modes.
- Verified by `qa/tests/105_mode_matrix.sh` (every cell above) and 10, 20, 30,
  103, 104.

**Who is inspected, as whom.**

| aspect | what the firewall uses |
|---|---|
| role | the current (effective) role of the statement: `SET ROLE` and `SECURITY DEFINER` functions change it; membership in another role grants nothing (6.1b) |
| superusers | not inspected while `sql_firewall.allow_superuser_auth_bypass` is on (the default) |
| application name | the `application_name` the client sent when it connected; a later `SET application_name` changes neither blocking nor records. It is client-supplied, not an authenticated identity |
| client address | the connection's numeric address, never a resolved host name (`log_hostname` does not matter). Listed addresses are compared by value (`::ffff:10.0.0.1` is `10.0.0.1`; `0:0:0:0:0:0:0:1` is `::1`); non-address entries are rejected when set. A Unix-socket connection has no address: `blocked_ips` does not apply to it, and a role with a `role_ip_bindings` entry is refused over it |
| background workers | exempt: the firewall's own launcher and consumers, parallel workers (their leader's statement was inspected), and logical replication workers. Every other background worker, such as pg_cron's job runners, is inspected as the role it runs as |

### 6.1d Recovery

- `ROLLBACK` (also `ABORT` and `AND CHAIN`) and `ROLLBACK TO SAVEPOINT` are
  never inspected: they need no approval and no rule can refuse them, so a
  session can always undo its own work. Statements after them in the same
  message are inspected as usual. `COMMIT`, `PREPARE TRANSACTION`, and
  `ROLLBACK PREPARED` are inspected.
- In a failed transaction PostgreSQL accepts only `ROLLBACK` and
  `ROLLBACK TO SAVEPOINT`, and nothing is inspected there either.
- A superuser locked out (enforce, no approvals, and
  `sql_firewall.allow_superuser_auth_bypass = off`) cannot use `SET` to turn
  the firewall off, because that `SET` is a statement and is inspected.
  Connect with a startup option instead, which takes effect before any
  statement: `PGOPTIONS='-c sql_firewall.enabled=off' psql ...` (or
  `-c sql_firewall.allow_superuser_auth_bypass=on`), then repair the policy
  or setting. Changing `postgresql.conf` and reloading the server works too.
- An ordinary role cannot do any of this: startup options, `SET`,
  `ALTER ROLE ... SET`, and `ALTER DATABASE ... SET` of `sql_firewall.*`
  fail with `permission denied to set parameter`, also for the database
  owner. Verified by `qa/tests/106_recovery.sh`.

### 6.2 Fingerprint Pipeline
- Every inspected statement's text (see 6.6a) is normalized (normalization version 2, below) and hashed.

#### Fingerprint normalization, version 2

The statement text chosen in 6.6a is tokenized by PostgreSQL's own core lexer
(`scanner_init`/`core_yylex`, the scanner PL/pgSQL and pg_stat_statements use)
through a small C shim, `src/fingerprint_scan.c`. Comments and whitespace are
not tokens, so they never join or split tokens. The canonical form is the
token sequence joined by single spaces:

| token | canonical form |
|---|---|
| keyword | upper case: `SELECT` |
| identifier | always double-quoted, `"` doubled inside. Unquoted names are folded and names of 64 bytes or more truncated exactly as PostgreSQL does: `Tbl`, `tbl` and `"tbl"` are one identifier, `"Tbl"` is another. Digits and `$` stay part of the name |
| `U&"..."` identifier | `U&"raw"`, escapes not decoded (so it differs from the plain spelling) |
| parameter | `$n` with its number; `$1 ... $1` and `$1 ... $2` differ |
| operator, punctuation, `::` `..` `:=` `=>` `<=` `>=` | as written; `!=` and `<>` are one token |
| integer literal that fits int4 (`5`, `0x1F`, `0o17`, `1_000`) | `?int` |
| other numeric literal (`1.5`, `1e3`, `.5`, an integer beyond int4) | `?num` |
| string: `'...'`, `E'...'`, dollar-quoted | `?str` |
| `U&'...'` string / `B'...'` bit string / `X'...'` hex string | `?ustr` / `?bits` / `?hex` |

Consequences:

- Only a literal's value is dropped. Its category, position, and the tokens
  around it stay: `-5` is `- ?int` and differs from `5`; `'1'` differs from
  `1`; `N'x'` is `NCHAR ?str`; `DATE '...'` is `"date" ?str`.
- No semantic rewrite: predicate order, IN-list length, `CAST(a AS int)`
  versus `a::int`, `int` versus `integer` all stay distinct. Distinctions
  that PostgreSQL treats as equivalent may remain; that is deliberate.
- Terminal `;` tokens are dropped. A `;` followed by another token is kept
  (texts that hold several statements, such as a rule action's whole-source
  text, keep their separators).
- Executable bodies are not placeholders. In `DO`, `CREATE [OR REPLACE]
  FUNCTION|PROCEDURE`, `COPY` (server file paths, `PROGRAM` commands), and
  `LOAD`, every literal keeps its value, written as `'value'`, `U&'raw'`,
  `B'...'`, `X'...'`, or the number. Two different bodies never share an
  identity; the same body in `$$...$$`, `'...'`, or `E'...'` quoting does.
  The statement kind is read from the leading keywords.
- The string after `UESCAPE` always keeps its value: it decides how the
  preceding `U&` text is decoded.
- `standard_conforming_strings` decides whether a backslash in a plain
  `'...'` string escapes the next character. A statement can be inspected
  under another setting than it was parsed with (`SET` earlier in the same
  message; `PREPARE` or Parse before a `SET`), and nothing records the
  setting PostgreSQL parsed with, so the normalizer never uses the session's
  current value. A text without a backslash reads the same either way, and
  `E'...'`, dollar-quoted, and `U&'...'` strings do not depend on the
  setting. A text with a backslash is read with the setting on and off
  (with `backslash_quote` on, which accepts everything either setting can
  accept, so PostgreSQL's reading is always among the accepted ones):
  - one accepted reading: it is the one PostgreSQL used, and it is the
    identity (`SELECT 'a\' AS p` is valid only with the setting on);
  - two accepted readings with the same canonical text: that text (a data
    string such as `'C:\\dir'`, whose value is a placeholder anyway);
  - two accepted readings that differ: the statement is refused with
    `0A000 sql_firewall: statement reads differently with
    standard_conforming_strings on and off; its fingerprint is ambiguous`;
  - no accepted reading: `XX000 sql_firewall: statement could not be
    tokenized for fingerprinting: ...`. PostgreSQL has already parsed every
    statement that reaches the hooks, so this is not expected in practice.

  Both errors are raised before any cache lookup, catalog lookup, or queue
  event: no identity is formed, and no approved or cached identity can be
  reused. There is no empty, zero, or combined identity.

  **Restriction.** While fingerprint processing runs for a statement (learn
  mode; permissive mode without a command approval), a plain `'...'` string
  whose backslash gives the statement a different structure under the two
  settings, such as `SELECT 'safe\' UNION ALL SELECT v FROM t --'`, is
  refused. So is a plain string with a backslash whose value is kept as
  identity (a body of `DO`/`CREATE FUNCTION`/`CREATE PROCEDURE`, a `COPY` or
  `LOAD` path), because its value differs between the readings. Write such
  strings as `E'...'` or with dollar quoting, or write quotes as `''`.
  Where fingerprint processing is disabled, this restriction does not apply.
  When enabled, an approved command in enforce mode still needs fingerprint
  authorization. Statements outside the currently inspected SQL forms have
  the limits described in section 6.6 below.
  Before this restriction, both readings of such a text were joined into one
  identity (`?scs_on ... ?scs_off ...`), which let the two different
  structures share one approval; no such identity is produced any more.
- The re-scan does not repeat PostgreSQL's NOTICE for a truncated identifier
  or its escape-string warnings. All scanner memory is in a context owned by
  one call and deleted on success and on error.

**Identity.** Version 3 uses the version 2 canonical token rules and a
SHA-256 digest, shown as 64 lowercase hex digits. The digest covers the
domain `"sql_firewall fingerprint v3 sha256" 0x00` and the complete canonical
text. Executor plans that depend on relations or catalog objects also add a
tagged, length-delimited list of the plan's relation OIDs and invalidation
items (sorted and deduplicated) before the digest is finalized. This keeps
identical unqualified text from sharing an approval after PostgreSQL replans
it against a different table or user-defined function. Utility statements
without an executor plan have no such binding list. The full digest is the key
in the policy table, ring event, and shared cache; no truncated digest is
used for an approval decision. The domain separates this identity from
earlier 64-bit identities, whose approvals are never matched or carried over.
`normalized_query` (`v3: ` followed by the canonical text) and
`sample_query` are display text: the queue keeps at most 1023 and 511 bytes
of them. Two statements that differ beyond those bytes have different
identities and can have identical stored text.

The digest also includes the cluster system identifier, database OID, and
`sql_firewall` extension OID. These bind every fingerprint, including
statements without planned object dependencies, to one installation. A
logical restore preserves fingerprint rows for review, but their old
approvals cannot authorize queries in the new installation, even if object
OIDs happen to be reused. Reobserve and approve new fingerprints before
enforcing them. Command and regex policy remains portable through the
documented restore process. A physical base backup retains the cluster
identity and OIDs.

**Boundaries.** A fingerprint describes the chosen SQL shape. It is not
evidence that every value of a literal is safe, nor does it cover SQL that a
function builds from its arguments at run time (`dblink`, `query_to_xml`,
`EXECUTE format(...)` in PL/pgSQL): those strings are data placeholders
outside the statements listed above. SHA-256 resists practical collision
attacks; it does not distinguish canonical forms that are intentionally
identical because their literal values were replaced.

**Compatibility and restart.** The digest, ring layout, and shared cache are
in the preloaded library, so a server restart is required. Existing 16-hex
version 1 or 2 rows remain in a development database but are never matched by
version 3 queries. Each statement shape must be learned or approved under
its new 64-hex identity; command approvals are unaffected. The SQL table
layout is unchanged. Version 3 rows carry `normalized_query` beginning with
`v3: `. This pre-release version has no supported migration from a prior
installation.
- Learn-mode hits are queued and counted in `sql_firewall_query_fingerprints`. The worker atomically increments the persisted count and approves on the configured hit; earlier hits remain unapproved.
- Permissive mode logs unapproved patterns without changing command or fingerprint approvals. Enforce mode requires both approvals when fingerprint checking is enabled.

### 6.3 Quiet Hours
- Enable with `sql_firewall.enable_quiet_hours = on` and set `sql_firewall.quiet_hours_start` and `sql_firewall.quiet_hours_end` (`HH:MM`). Statements are refused (`42501`, recorded as blocked) from the start minute up to, not including, the end minute.
- **Time zone.** The window is read in `sql_firewall.quiet_hours_timezone` (a zone name such as `Europe/Istanbul`, or a POSIX specification such as `UTC+03`); empty means the server's `log_timezone`. A session's `TimeZone` setting has no effect, so `SET TimeZone` cannot move the window. An unknown zone is rejected when set.
- **Across midnight.** A start later than the end (`22:00`–`06:00`) spans midnight. Equal start and end mean the whole day.
- **Daylight saving.** Times are local wall-clock times of the policy zone: on a spring-forward day the skipped hour does not occur, and on a fall-back day a repeated hour is inside the window both times.
- Malformed times are rejected when set. With quiet hours on, an unset or empty start or end refuses every inspected statement ("Quiet hours are enabled but quiet_hours_start and quiet_hours_end are not both set"), and so does a policy time zone that cannot be read: the window is never silently skipped. Superusers are not inspected while superuser bypass is on.
- `sql_firewall.quiet_hours_log = on` also writes a WARNING-level line for each refusal.

### 6.4 Rate Limits
- **Global** – `rate_limit_count` statements per `rate_limit_seconds` for each role (`enable_rate_limiting = on`).
- **Per command** – `command_limit_seconds` plus `select_limit_count`, `insert_limit_count`, `update_limit_count`, `delete_limit_count` (0 = no limit). These four families are the only per-command counters: `MERGE`, `COPY`, and utility statements count only against the global limit.
- **Scope.** One counter per database, role OID, and command family (the global limit has its own). A role's traffic in one database never consumes its allowance in another, and a dropped and recreated role (a new OID) starts fresh.
- **Window.** Fixed: it starts with the first counted attempt after the previous window ended and lasts the window length set when the attempt is checked, so a reload applies at once. It is measured with the monotonic clock, so a wall-clock change neither shortens nor extends it.
- **Counting.** Every inspected statement that reaches the rate check counts, whether it is then allowed or refused (by the rate limit or later by approval policy); an attempt refused by the global limit is not also counted against its command limit. Counts saturate instead of wrapping.
- **Capacity.** 8192 counters in shared memory. A counter whose window has ended is reused; an active one is never evicted, because resetting it would let its role exceed the limit. If no counter can be kept, the statement is refused with `53400` "Rate-limit state is full" (fail closed). Refusals are recorded as blocked queries.

### 6.5 Blocked Query Logging
- **Dedicated table** – Every statement the firewall rejects, whatever the reason (session rule, quiet hours, keyword, regex, rate limit, missing or pending approval, unapproved fingerprint, unusable policy catalog in enforce, a statement it cannot inspect), is stored in `sql_firewall_blocked_queries` with role, database, a query prefix, command, reason, client IP, and application name. The query prefix is capped at 2 KB and marked when truncated (`query_truncated`).
- **Times** – `blocked_at` is when the firewall rejected the statement; `recorded_at` is when the worker wrote the row. Queue waits, worker retries, and pauses change only `recorded_at`.
- **Asynchronous logging** – Blocked statements are published to shared memory at once and persisted by the background worker, so records survive even when the blocking transaction aborts—no `dblink` required.
- **Always enabled** – Blocked query logging is independent of `sql_firewall.enable_activity_logging` setting and cannot be disabled.
- **Query blocked queries**: `SELECT * FROM sql_firewall_blocked_queries ORDER BY blocked_at DESC LIMIT 10;`

### 6.6 Keyword, Built-in, and Regex Checks

Which text each check reads:

| check | reads | literals and comments |
|---|---|---|
| blacklisted keywords (`enable_keyword_scan`, `blacklisted_keywords`) | the statement's SQL tokens, as PostgreSQL's lexer reads them | not matched: a keyword inside a string (`'...'`, `E'...'`, `$tag$...$tag$`, `U&'...'`) or a comment (`--`, `/* */`, nested) does not count |
| built-in injection check (`enable_builtin_injection_check`, default on) | the same tokens, with literal values | a tautology counts only as SQL: `OR` followed by a literal, `=`, and the same literal (`OR 1=1`, `OR 'a'='a'`). `WHERE 1=1` and `AND 1=1`, which query builders generate, do not count |
| regex rules (`enable_regex_scan`, `sql_firewall_regex_rules`) | the raw statement text, case-insensitively (`~*`) | matched: patterns see literals and comments, as they always have (the inactive installation default also looks for `--`) |

- A keyword entry is one or more words, matched case-insensitively against
  consecutive keywords or identifier names, so `pg_sleep` also matches the
  quoted `"pg_sleep"`, and `union select` matches `UNION /* x */ SELECT`.
  A quoted identifier is matched by its name, not by its quotes.
- When backslashes give a statement two readings (the
  `standard_conforming_strings` ambiguity of 6.2), a check that matches
  either reading matches. When the lexer accepts no reading, the keyword and
  built-in checks fall back to the raw text.
- The installation default regex rule (`installation_default =
  'simple_sql_injection'`, pattern `(or|--|#)\s+name\s*=\s*value`) is
  installed **inactive**: on raw text it also matches ordinary SQL such as
  `WHERE a = 1 OR b = 2` and a comment like `-- ticket = 4711`. Activate it
  with `sql_firewall_toggle_regex_rule(id, true)` only after checking the
  traffic it would refuse (in every mode, 6.1c).
- Regex rules run under `sql_firewall.regex_timeout_ms` (default 100) with a
  timer of their own. The limit covers evaluating the rules, not a new
  session's one-time preparation of the rules query (catalog loading and
  planning), which happens before the timer starts when the rules table can
  be read without waiting. When the rules cannot be evaluated within it (a costly
  pattern on a long statement, or a lock on the rules table), the statement
  is refused (`42501`, "regex rules could not be evaluated within N ms") and
  recorded; nothing is allowed silently. PostgreSQL's regex engine notices a
  cancel only at some points, so an evaluation can run past the limit before
  it stops; it is refused all the same, also when it finishes without a
  match. A rule PostgreSQL rejects as an
  invalid expression refuses the statement too. The session's
  `statement_timeout`, `lock_timeout`, and a client's cancel are not changed
  and keep their own errors (`57014`).
- While an administrator holds a lock on `sql_firewall_regex_rules` that
  blocks reading it (DDL, `VACUUM FULL`), statements of roles with regex
  scan on are refused after the timeout.
- Rules are read with a fresh snapshot, like the other policy tables.
- When the committed rules table has no active rule (the installation
  default is inactive), a backend remembers that and skips the evaluation
  until a commit changes `sql_firewall_regex_rules`, the installation, or a
  trigger: the rules table has the same pair of invalidation triggers as the
  policy tables (6.1a), and such a commit advances the database's generation
  before it returns. A transaction that writes rules, a hot standby, and a
  parallel operation always evaluate.

### 6.6b Per-User Regex Exemptions
- The `sql_firewall_regex_rules` table includes an `allowed_roles text[]` column for fine-grained control.
- **NULL allowed_roles** – Rule applies to all users (blocks everyone matching the pattern).
- **Specified allowed_roles** – Only users NOT in the array are blocked; users in the array are exempt.
- **Example**: Pattern `DROP\s+TABLE` with `allowed_roles = ARRAY['postgres']::text[]` blocks DROP TABLE for all users except postgres.
- **Insert exemption rule**: `INSERT INTO sql_firewall_regex_rules (pattern, action, description, allowed_roles) VALUES ('dangerous_pattern', 'BLOCK', 'Description', ARRAY['admin_user']::text[]);`

### 6.6a Command Families and Statement Text

Each hook invocation evaluates one statement: a command family and that
statement's text. The same text feeds keyword and regex checks, rate limits,
approvals, fingerprints and their samples, the activity log, and the
blocked-query log for that invocation.

**Family.** The family comes from PostgreSQL's command tag for the parsed
statement (`CreateCommandTag` on the `PlannedStmt`), never from the query
text. Comments, whitespace, and capitalization do not change it.

| family | PostgreSQL command tags |
|---|---|
| SELECT | `SELECT`, `SELECT FOR UPDATE` / `NO KEY UPDATE` / `SHARE` / `KEY SHARE` (also `VALUES`, `TABLE`) |
| INSERT, UPDATE, DELETE, MERGE | the tag of the same name. MERGE needs PostgreSQL 15 or later |
| CREATE | every `CREATE ...` tag, `CREATE TABLE AS`, and `SELECT INTO` |
| ALTER, DROP | every `ALTER ...` / `DROP ...` tag (`DROP OWNED` is DROP; `ALTER ... RENAME` is ALTER) |
| TRUNCATE | `TRUNCATE TABLE` |
| GRANT, REVOKE | `GRANT`, `GRANT ROLE`; `REVOKE`, `REVOKE ROLE` |
| BEGIN | `BEGIN`, `START TRANSACTION` |
| COMMIT | `COMMIT` (also written `END`), `COMMIT PREPARED` |
| ROLLBACK | `ROLLBACK` (also written `ABORT`, and `ROLLBACK TO SAVEPOINT`), `ROLLBACK PREPARED` |
| PREPARE | SQL `PREPARE`, `PREPARE TRANSACTION` |
| COPY | `COPY`, `COPY FROM` |
| SET | `SET`, `SET CONSTRAINTS` (also `SET ROLE`, `SET SESSION AUTHORIZATION`, `SET TRANSACTION`) |
| DISCARD | `DISCARD`, `DISCARD ALL` / `PLANS` / `SEQUENCES` / `TEMP` |
| DEALLOCATE | `DEALLOCATE`, `DEALLOCATE ALL` |
| LOCK, REFRESH | `LOCK TABLE`; `REFRESH MATERIALIZED VIEW` |
| ANALYZE | `ANALYZE` (also spelled `ANALYSE`). `VACUUM ANALYZE` is VACUUM |
| same name | COMMENT, VACUUM, REINDEX, CLUSTER, SAVEPOINT, RELEASE, EXECUTE, SHOW, RESET, EXPLAIN, LISTEN, NOTIFY, UNLISTEN, CHECKPOINT, LOAD |
| OTHER | `CALL`, `DO`, `DECLARE CURSOR`, `FETCH`, `MOVE`, `CLOSE`, `SECURITY LABEL`, `REASSIGN OWNED`, `IMPORT FOREIGN SCHEMA`, and any tag not listed |

OTHER is not an allow path. In enforce mode it needs its own approval, and an
OTHER approval does not cover a statement PostgreSQL identifies as anything
else.

**Top-level classification.** A statement is classified by its top-level
command only. This is not complete enforcement of every write a statement
causes:

- A data-modifying CTE (`WITH d AS (INSERT ...) SELECT ...`) is inspected as
  its top-level family (SELECT) and, in addition, as each write family it
  plans (INSERT here), with the statement's text: a SELECT approval alone
  does not let it write.
- Sub-commands that PostgreSQL runs for a utility statement (the sequence and
  `OWNED BY` for a `serial` column, a foreign key added by `CREATE TABLE`,
  the elements of `CREATE SCHEMA`) are checked under the family and text of
  the statement the client sent.
- Rewrite-rule actions and trigger bodies are checked as the statements they
  are. A trigger function or non-inlined SQL function is inspected statement
  by statement, with its own text.
- An inner plan that the executor starts is inspected in addition to its
  wrapper: EXPLAIN (with or without ANALYZE) is EXPLAIN and its plan is, for
  example, SELECT or INSERT; `CREATE TABLE AS` / `SELECT INTO` are CREATE plus
  SELECT; `COPY (query)` is COPY plus the query's family; `DECLARE CURSOR` is
  OTHER plus SELECT. An EXPLAIN approval does not authorize `EXPLAIN ANALYZE
  INSERT`.

**Statement text.**

- The text is PostgreSQL's span for the statement: `stmt_location` and
  `stmt_len`, byte offsets into the source string that belongs to the plan
  (`QueryDesc.sourceText` in the executor, the utility's `queryString`).
  Nothing splits text at semicolons, so semicolons in literals, comments,
  quoted identifiers, and dollar-quoted bodies are not boundaries.
- A location of -1 means unknown: the whole source string of that plan is
  used. A length of 0 means through the end of the string. Offsets are
  checked for range and for UTF8 character boundaries; a bad span is an
  `XX000` error, never a skipped inspection.
- Lexer whitespace (space, tab, newline, carriage return, form feed, vertical
  tab) is trimmed from both edges, as `pg_stat_statements` does. Comments
  stay. The terminating `;` is not part of the span. A statement sent alone
  and the same statement later in a message therefore have the same text.
- **PostgreSQL 18 changed the span's start.** Up to 17 a statement's span
  starts at the beginning of the message or right after the previous `;`,
  so a comment before the first token is part of the text. From 18 it starts
  at the statement's first token: `/* x */ SELECT 1` is recorded as
  `SELECT 1`, and regex rules (which read the text) do not see comments
  before the first token. Comments inside or after the statement are kept
  on every version. The fingerprint identity ignores comments and is not
  affected. Verified version by version by `qa/tests/97_statement_classification.sh`.
- Only top-level statements get offsets from PostgreSQL. The inner query of
  EXPLAIN, `CREATE TABLE AS`, `SELECT INTO`, `CREATE MATERIALIZED VIEW`,
  `DECLARE CURSOR`, and the stored query of `REFRESH MATERIALIZED VIEW` are
  planned without offsets against the whole source string. While such a
  utility runs, its plan uses the utility's span when its source is that
  utility's text (`DECLARE CURSOR` plans on a byte-identical copy). `COPY
  (query)` and SQL `PREPARE` pass the enclosing statement's offsets
  themselves.
- SQL `PREPARE` saves the whole message text with the `PREPARE` statement's
  offsets. `EXECUTE` runs the plan with that saved text and those offsets, so
  the executed statement is recorded as its `PREPARE` statement; the
  `EXECUTE` statement itself is a separate EXECUTE inspection with the current
  text. Saved offsets are never applied to the current text.
- Extended protocol (Parse/Bind/Execute): the Parse text is the source.
- SQL functions and SPI (PL/pgSQL, triggers) carry their own source strings
  and offsets. The firewall's own SPI is skipped by its recursion guard;
  application statements run through functions are not.

**Known limitations.** PostgreSQL does not give rewrite-rule actions their
own source offset. In a multi-statement message, a rule action is attributed
to the unique modifying statement that could have caused it; if two such
statements are present, the action is refused with `0A000` instead of using
the whole message as a fingerprint. SQL-standard function bodies (`BEGIN
ATOMIC`) may reach the executor with no source text. A separate plan with no
source is refused with `0A000`; those bodies are not independently supported
until they can be inspected without inventing SQL text. These restrictions
can reject otherwise valid PostgreSQL statements.

**Compatibility (Phase 4A).** Before Phase 4A the utility hook took the family
from the first word of the whole query string, and both hooks inspected the
whole string. Consequences of the change:

- Statements after the first in a multi-statement message are now checked
  under their own family and text. Before, each was checked under the first
  statement's family (a `SHOW` approval let `SHOW ...; TRUNCATE ...` truncate)
  and every statement's text was the whole message.
- A statement with a leading comment, `SELECT INTO`, `MERGE`, and `ANALYSE`
  were OTHER. They are now their real families. An existing OTHER approval no
  longer covers them.
- Fingerprints are computed from the new text. The terminating `;` is no
  longer part of it (`SELECT v FROM t WHERE id = 1;` was normalized to
  `SELECT V FROM T WHERE ID = ?;`, fingerprint `8aeaf212cd039fd1`; it is now
  `SELECT V FROM T WHERE ID = ?`), and a batched statement no longer
  includes its neighbours. Existing fingerprint rows are not rewritten or
  copied: a statement whose text changed is a new fingerprint and needs
  approval again in enforce mode. Phase 4A did not change the normalizer or
  the hash; Phase 4B replaced both identities with version 2 (see 6.2).
- Activity and blocked-query rows record the statement span instead of the
  whole message.

Classification and statement selection are built and tested against
PostgreSQL 16, 17, and 18, each with its own build.

### 6.7 Activity Logging

`sql_firewall_activity_log` is a decision log of allowed statements. The
firewall publishes a record to the activity queue when it decides, and the
database's approval worker writes the row. Nothing is written in the client's
transaction:

- A failing, slow, or constrained activity write (a trigger on the table, a
  full disk) never fails or delays the client's statement or its commit, and
  works the same in read-only transactions, before a transaction's first
  snapshot, at `COMMIT`, `PREPARE TRANSACTION`, and an extended-protocol Sync.
- A record stays when its transaction later rolls back: the firewall did
  allow the statement.
- `log_time` is when the firewall decided; `recorded_at` when the row was
  written. `decision` classifies the allowance: `allowed` (policy satisfied),
  `learn` (allowed by learn mode), `would_block` (allowed by permissive mode;
  enforce would reject), `unchecked` (an `OTHER` command outside enforce).
  `action` and `reason` keep the detailed wording.
- The statement text is carried up to 2 KB (`query_truncated` marks a cut on
  a UTF-8 boundary).
- The queue holds `sql_firewall.activity_queue_size` records (default 4096,
  about 3.2 kB each; set at server start). It is separate from the event
  queue, so a burst of activity cannot displace blocked-query records or
  learn observations. The worker writes up to 256 records per transaction
  as one statement and keeps its position in
  `sql_firewall_activity_checkpoint`, in the same transaction, so a worker
  restart neither repeats nor skips records the queue still holds. After a
  failed batch it writes the next records one per transaction, so one bad
  record cannot block the rest.
- Publishing does not wake the worker. While records arrive it looks for
  new ones every 10 ms; after a quiet second, every 200 ms. A burst that
  starts while it is idle therefore overflows the default 4096-record queue
  only above about 20 000 records per second; a larger
  `sql_firewall.activity_queue_size` tolerates longer bursts. Sustained
  capacity on the reference host is in `docs/PERFORMANCE.md`.
- Losses are counted, never silent (`sql_firewall_queue_statistics()`):
  `activity_positions_skipped` (queue positions the worker found overwritten
  because it fell behind), `activity_records_rejected` (a record that failed
  to insert alone three times; the worker warns with its SQLSTATE and
  continues), `activity_publish_failed`. A paused worker writes nothing until
  it resumes.
- `sql_firewall.enable_activity_logging = off` stops publishing records.
  Blocked queries are recorded regardless.
- Reading the log right after a statement may not show its row yet. To wait
  for it, compare `sql_firewall_activity_checkpoint.next_position` with
  `sql_firewall_queue_statistics().activity_write_position`.
- `sql_firewall_internal_log_activity` is not used by the firewall and is
  superuser-only: no role can write rows that look like firewall decisions.

### 6.8 Alerts & Retention
- Set `sql_firewall.enable_alert_notifications = on`, `LISTEN sql_firewall_alerts;`, and consume JSON payloads after blocked-query rows commit. Worker retries roll back both row and NOTIFY. Ring overwrite can lose both; NOTIFY is a live signal, not a durable feed.
- PostgreSQL does not control who may `LISTEN`, so the payload is minimal: `{"event":"query_block","block_id":N,"command":"C"}`. Role, client address, application, and reason are in the `sql_firewall_blocked_queries` row, which only its authorized readers can select.
- Optional `sql_firewall.syslog_alerts = on` sends an immediate JSON payload with role, database, command, reason, application, and client address to syslog (a server-side channel). Statement text is not included.
- The database consumer starts cleanup every `sql_firewall.activity_log_prune_interval_seconds` (default 300). Each consumer pass first drains activity, then may run one small cleanup transaction: up to 1,000 rows for each age/row-limit deletion. When cleanup remains due it continues on the next pass without an idle wait, interleaved with activity and event processing. It rechecks live queue pressure before cleanup and defers it while at least a quarter of the activity ring remains unread. Row locks are skipped and a transaction-local 10 ms lock timeout prevents maintenance waiting behind a table lock; this is a lock-wait bound, not a guarantee on total deletion time. `sql_firewall.retention_days` controls blocked rows; `sql_firewall.activity_log_retention_days` and `sql_firewall.activity_log_max_rows` control activity rows. The row limit is a cleanup target, not a synchronous insert cap: records arriving between sweeps or during excessive load can exceed it. Policy tables, decision history and checkpoints are never pruned. Fingerprint rows are not automatically pruned. Supported sustained-load evidence is in `docs/PERFORMANCE.md`.
- `sql_firewall_retention_status` shows runs, failures, the last run, success, rows deleted, and the last failure's SQLSTATE and time.

### 6.9 Backup and Restore of Policy

An ordinary `pg_dump` of a database keeps its firewall policy. `CREATE
EXTENSION` registers the policy tables as extension configuration
(`pg_extension_config_dump`, all rows), so the dump contains their rows after
the `CREATE EXTENSION` line, and a restore loads them into the installation
that line creates.

**Kept.**
- `sql_firewall_command_approvals`, `sql_firewall_query_fingerprints`, and
  `sql_firewall_regex_rules`: every row, approved and pending, as stored. That
  includes ids, fingerprints and normalized text (`v3:` identifies the current
  digest format), role names, hit counts, timestamps, `is_active`,
  descriptions, and `allowed_roles`. Nothing is approved, reset, or replaced
  by a default. **Restored fingerprint approvals are historical rows, not
  effective approvals in the new installation.** Inspect them for provenance;
  then reobserve each required query and approve its new fingerprint. Do not
  copy the old `is_approved` values onto new identities without review.
- The positions of their id sequences, so new rows get ids after the
  restored ones. A sequence position is not part of pg_dump's snapshot: it
  is read when pg_dump reaches it, and is at or ahead of every dumped id
  unless it was set back by hand.
- `sql_firewall_regex_default_removals` (see *Installation defaults*).
- `sql_firewall_policy_history`, the decision history (6.1b), with its
  source installation identity. The restore's own loads of policy rows are
  recorded as administrator `INSERT` rows of the new installation, by the
  role that ran the restore. Its `change_id` sequence is not kept: change ids
  are numbered within an installation.
- Privileges on extension objects: the restore creates the installed
  defaults, and pg_dump adds any GRANT or REVOKE you made on them.

**Not kept.**
- Audit records: `sql_firewall_activity_log` and
  `sql_firewall_blocked_queries`. A restored database starts with empty logs.
  This is a policy backup, not an audit archive; export the logs separately
  (for example with `COPY`) if you need them.
- `sql_firewall_fingerprint_hits`. The current code neither reads nor writes
  it, so it holds no policy.
- Runtime state: `sql_firewall_consumer_checkpoint` is created uninitialized,
  and the destination's worker initializes it for its own installation and
  ring. `sql_firewall_policy_epoch` starts at 0; restored history rows belong
  to the source installation and do not take part in the destination's
  decision order (6.1b). The shared-memory ring and its pending events, the approval and
  fingerprint caches, pause requests, and worker identities belong to the
  source server and are not transferred.

**Installation defaults.** Every `CREATE EXTENSION` inserts the regex rule
`installation_default = 'simple_sql_injection'` (the injection pattern,
inactive; 6.6), so a fresh installation behaves the same, and so does the
installation a restore creates. The restore then loads the source's rules and removal records. It
loads the rows of a table in whatever order they were dumped, and the two
tables one after the other in either order, or at the same time with
`pg_restore --jobs`. The result matches the source in every order because
each loaded row settles the fresh copy of the default by itself:
- pg_dump names every column, so each loaded rule states its
  `installation_default` (NULL for an administrator's rule). A loaded rule
  takes the place of any installation default that it collides with on key,
  id, or pattern. In a restore into a new database, that can only be the
  fresh copy. An unchanged, edited, or deactivated default therefore arrives
  as dumped. An administrator's rule that took the default's original
  pattern or id loads without a duplicate key, before or after the default's
  own row.
- Deleting a default (`sql_firewall_delete_regex_rule`, `DELETE`, or
  `TRUNCATE`) records its key in `sql_firewall_regex_default_removals`. The
  dump carries that record, and loading it deletes the fresh copy, so a
  deleted default stays deleted.
- Taking a default's place during a load records no removal, so it cannot
  conflict with a removal record that another `--jobs` worker is loading.

In normal use:
- A statement that does not name `installation_default` adds an
  administrator rule, with the usual uniqueness: adding the default's pattern
  again fails with a duplicate key while the default has it. That covers
  `sql_firewall_add_regex_rule` and the `INSERT` examples in this README.
  (The column's default, `'(new rule)'`, marks such a statement; the trigger
  stores NULL.)
- A statement that names the column is treated as loading policy. Its rows
  take the place of colliding defaults, as above. With the key, it
  reinstates that default and clears its removal record.
- The key of an existing row cannot be changed.

These are `ENABLE ALWAYS` triggers on the two tables; do not disable them or
edit the removal records by hand.

**Destination prerequisites.**
- The same sql_firewall build installed on the destination server, with
  `shared_preload_libraries = 'sql_firewall'` and a restart. `server_encoding`
  must be UTF8.
- Roles. A single-database `pg_dump` contains no roles, and it is not a
  backup of anything cluster-wide. Recreate the roles first, for example from
  `pg_dumpall --roles-only`. Policy rows name roles as text, and any GRANT in
  the dump needs its role.
- Settings. `sql_firewall.*` values from `postgresql.conf` or `ALTER SYSTEM`
  are in no dump. `ALTER DATABASE ... SET` and `ALTER ROLE ... IN DATABASE
  ... SET` values (for example `sql_firewall.mode`) are included only by
  `pg_dump --create`. Otherwise, re-apply them to the new database before
  application traffic reaches it.
- A superuser runs the restore, because `CREATE EXTENSION sql_firewall`
  requires it. Superuser bypass (the default) keeps the firewall from
  inspecting the restore. If `sql_firewall.allow_superuser_auth_bypass` is
  off, restore with `PGOPTIONS='-c sql_firewall.enabled=off'`.
- A new, empty database. Do not create the extension there first: the dump
  does that.

```bash
pg_dumpall --roles-only -f roles.sql      # cluster-wide roles, restored first

# plain format
pg_dump -d mydb -f mydb.sql
createdb newdb
psql -X -v ON_ERROR_STOP=1 --single-transaction -d newdb -f mydb.sql

# custom format
pg_dump -Fc -d mydb -f mydb.dump
createdb newdb
pg_restore --exit-on-error -d newdb mydb.dump
```

`pg_dump` reads every table from one snapshot, so the worker does not need
to be paused. Rows the worker commits after the dump started are not in it.
Verified: plain format with `psql --single-transaction`, custom format with
serial `pg_restore`, with `pg_restore --jobs 4`, and with a `pg_restore -L`
list that loads the rules before the removal records.

**Not supported.**
- Restoring into a database whose sql_firewall already holds policy. A
  data-only restore or a second dump fails with duplicate keys. This is not a
  policy merge.
- `pg_restore --disable-triggers`, and dumps that leave out the extension
  (for example `-n` for other schemas only).

### 6.9a Updating the Extension

`0.0.0` is the first version; there is nothing older to update from. Later
versions ship `sql_firewall--<old>--<new>.sql` update scripts in their
package, and are installed in place, keeping rules, approvals, and history.
A preloaded library is replaced only by a restart, so an update needs a short
maintenance window.

**With the package and the update tool** (both from the new version's
package; 4):

```bash
sudo ./install.sh --pg-config /usr/pgsql-16/bin/pg_config   # 1. install; the running server is unaffected
sudo systemctl restart postgresql-16                          # 2. restart: the new library takes effect
./sql_firewall_upgrade -h /run/postgresql -U postgres --check # 3. what would be done, and is the server ready
./sql_firewall_upgrade -h /run/postgresql -U postgres --backup-dir /backup/sqlfw --yes
```

`sql_firewall_upgrade` (connects as a superuser; `--bindir` selects
`psql`/`pg_dump`/`pg_dumpall`/`pg_restore`, `--target` a version other than
the installed control file's default):

- lists every database that has the extension, its installed version, and
  the update path (`pg_extension_update_paths`) to the target;
- reports **NOT READY** (exit 3) and changes nothing when the library is not
  preloaded, when the server still runs the old library (installed but not
  restarted), or when a database has no update path;
- checks every database that allows connections, template databases
  included: an extension in `template1` is updated too, so databases created
  from it later get the new version (no consumer runs in a template, so none
  is expected there); databases that do not allow connections are listed as
  not checked;
- with `--yes`, backs up first (`pg_dumpall --roles-only` and one
  `pg_dump -Fc` per database to update, each checked with
  `pg_restore --list`, with `SHA256SUMS`; `--no-backup` skips this). The
  backup holds table data and role password hashes, so its directory is
  created 0700 and its files 0600 whatever the caller's umask;
- then updates each database in one `REPEATABLE READ` transaction that reads
  the policy (decisions of approvals, fingerprints, regex rules, removed
  defaults, and history) before and after the update script and commits only
  when they are equal; an update that changed the policy is rolled back
  before `COMMIT` and that database keeps its version. Live traffic does not
  disturb the comparison. After the commit it verifies the version,
  `sql_firewall_status()`, and a running consumer;
- exits 0 when done, ready, or nothing is left to update, 1 when an update or
  a verification failed (the other databases are still updated), 2 on usage
  or connection errors.

**By hand**: take a logical backup of each database that has the extension
(6.9); install the new package; restart PostgreSQL (the in-memory queues
start empty, as at any restart); then in every database that has the
extension, as a superuser, `ALTER EXTENSION sql_firewall UPDATE;` and check
`SELECT sql_firewall_status();` and
`SELECT sql_firewall_approval_worker_status();`.

Every update script starts by refusing to run until the server runs the new
library, so an `ALTER EXTENSION ... UPDATE` before the restart fails with
`sql_firewall: the server runs library 0.0.0, not 0.0.1; install the 0.0.1
package, restart PostgreSQL, and update again` and changes nothing:

```sql
SELECT public.sql_firewall_require_preload();
DO $$ BEGIN
    IF (SELECT running_version FROM public.sql_firewall_library_version()) IS DISTINCT FROM '<new>' THEN
        RAISE EXCEPTION 'sql_firewall: the server runs library %, not <new>; ...' USING ERRCODE = '55000';
    END IF;
END $$;
```

(`qa/fixtures/sql_firewall--0.0.0--0.0.1.sql` is the template.)

`ALTER EXTENSION ... UPDATE` keeps the installation: the extension OID, the
policy rows, the decision history, the consumer checkpoint, and therefore
every fingerprint identity and approval stay valid, and the consumer keeps
running without treating the update as a new installation. An update that
is rolled back changes nothing. **Do not upgrade by `DROP EXTENSION` and
`CREATE EXTENSION`**: that is a new installation, and restored fingerprint
approvals do not authorize it (6.9).

A release that changes fingerprint normalization (a new normalizer version,
6.2) changes the identity of existing fingerprints. Such a release is not an
ordinary update: it must document and ship its own migration of the
approved fingerprints, and its update tool must refuse a plain update until
that migration is designed. No such release exists.

Verified by `qa/tests/113_extension_update.sh`, which places a test update
script into the run's private installation, restarts, rolls one update back,
applies it, and compares the extension OID, the policy and history digest,
the checkpoint's installation, the command, fingerprint, regex, and refusal
decisions, and consumer progress before and after; and by
`qa/package_upgrade_check.sh`, which builds real 0.0.0 and 0.0.1 packages,
installs 0.0.1 into a running 0.0.0 server, checks that the tool and the
update script refuse before the restart, and runs the tool's backup, update,
and verification across two databases (QA README).

### 6.9b Physical Backups, Point-in-Time Recovery, and pg_upgrade

**Physical copies** (`pg_basebackup`, file-system snapshots, PITR, a
standby) keep everything: the same cluster system identifier, database and
extension OIDs, policy, audit rows, and checkpoints. Fingerprint approvals
stay valid on the copy. The in-memory queues are not part of a physical
copy; events the source had not written yet are not in it. Verified by
`qa/tests/112_standby.sh` (a `pg_basebackup` copy, promoted).

**PostgreSQL major upgrades with `pg_upgrade`** (tested 16→17, 17→18, and 16→18,
copy mode):

- Install the new major's build of the extension (same extension version)
  in the new server and set `shared_preload_libraries = 'sql_firewall'` in
  the new cluster's configuration before running `pg_upgrade`.
- `pg_upgrade --check` and the upgrade itself work with the library
  preloaded in both clusters. In binary-upgrade mode the library starts no
  launcher and installs no hooks (a launcher connected to `postgres` made
  `pg_upgrade` fail with "database "postgres" is being accessed by other
  users" before this was fixed).
- The extension version, command approvals, fingerprint rows, regex rules,
  default-rule removal records, and decision history arrive unchanged;
  `ALTER DATABASE`/`ALTER ROLE ... IN DATABASE` settings are carried by
  `pg_upgrade` as well. The consumer starts on the new cluster.
- **Fingerprint approvals do not carry over.** The new cluster has a new
  system identifier and the extension a new OID, so every statement gets a
  new identity, exactly as after a logical restore (6.9): in enforce, the
  first execution of each shape is refused and recorded as pending. Plan for
  re-approval: before switching application roles back to `enforce`, run
  them in `learn` under controlled traffic, or approve the newly recorded
  pending identities explicitly with `sql_firewall_approve_fingerprint`
  after checking each `sample_query` against the old approved rows. Command
  approvals and rules apply immediately.
- After a copy-mode upgrade the old cluster can still be started (roll
  back); its own approvals keep deciding there.

Verified by `qa/pg_upgrade_check.sh 16 17` and `qa/pg_upgrade_check.sh 17
18`, which build both majors' packages, upgrade a cluster with policy, and
check every point above.

### 6.10 Hot Standby and Promotion

A physical standby with the library preloaded and the extension installed
(replicated from the primary) enforces the replicated policy. During
recovery:

| aspect | behaviour on the standby |
|---|---|
| decisions | made as on the primary, from the replayed catalog: command approvals, fingerprint approvals (the same identities as on the primary), regex, keyword, built-in, rate, quiet-hours, and connection rules, in every mode |
| policy changes | apply once replayed. The shared caches are bypassed during recovery (replay fires no invalidation triggers), so each inspected statement reads the replicated catalog: a revoke committed on the primary refuses on the standby as soon as it is replayed |
| learn and permissive | statements run normally; learning cannot be written on the standby |
| writes | PostgreSQL's own read-only rules apply first-hand: an approved `INSERT` gets `25006` "cannot execute INSERT in a read-only transaction" |
| workers | the launcher and consumers start only when recovery ends (`BgWorkerStart_RecoveryFinished`); nothing is written during recovery |
| audit and learn events | published to the standby's own memory queues (`sql_firewall_queue_statistics()` counts them) and not written while it is a standby |
| status | `sql_firewall_status()` says `... on a hot standby: decisions use the replicated policy; ...` |

After promotion the launcher starts, the database's consumer starts, takes
over the replicated checkpoint (a different queue generation, so it starts
at the oldest event the promoted server still holds), and writes the
refusals, activity records, and learn observations made during recovery that
are still in its queues, once each. The caches are used again, so a revoke
on the promoted server applies at once. Fingerprint approvals made on the
old primary still apply (same installation identity).

Limits: events held by a standby are lost if it restarts before promotion,
or if they are overwritten (activity queue size, 1024-slot event ring)
before promotion; learn-mode traffic on a standby is learned only after
promotion and only while still queued. Run learning on the primary.

Verified by `qa/tests/112_standby.sh`: a `pg_basebackup -R` standby of the
test server, with checks during recovery (every row above), promotion, the
writes of held events, and the primary's consumer afterwards.

---
## 7. Testing & Validation

The supported path is the [isolated QA runner](../qa/README.md):

```bash
sql_firewall/qa/run.sh
QA_PG_CONFIG=/path/to/17/bin/pg_config sql_firewall/qa/run.sh
QA_PG_CONFIG=/path/to/18/bin/pg_config sql_firewall/qa/run.sh
```

The runner builds from the working tree, verifies the loaded library, and
uses a disposable cluster without modifying a shared installation. Probe
features are test-only and excluded from release builds.

See [performance measurements](PERFORMANCE.md) for the benchmark method and
results. Each QA run records its source digest, package and loaded-library
checksums, and per-test evidence in its run directory. Validation of an earlier
build does not automatically validate later source changes.

---
## 8. Operations

**What needs a restart.** `shared_preload_libraries`, a new library build or
package (the server runs the installed package's library when
`running_version` of `sql_firewall_library_version()` equals
`default_version` in `pg_available_extensions`),
`sql_firewall.activity_queue_size`, and `sql_firewall.launcher_database`. A
restart (and any crash-restart) empties the in-memory queues and caches;
policy in the tables is unaffected. Everything else is reloadable
(`pg_reload_conf()`), and `sql_firewall.*` settings can be set per database
and role.

**Health checks** (superuser, in each database with the extension):

| check | healthy | act on |
|---|---|---|
| `SELECT sql_firewall_status();` | `sql_firewall running in <mode> mode` | `NOT ACTIVE` (not preloaded), `disabled` |
| `SELECT sql_firewall_approval_worker_status();` | `running ...` | `retrying` for long, `stopped`, a forgotten `paused` |
| `pg_stat_activity` where `backend_type LIKE 'sql_firewall%'` | one `sql_firewall_launcher`, one `sql_firewall_worker_<db oid>` per installed database | missing consumer: check `max_worker_processes` and the server log |
| `SELECT * FROM sql_firewall_queue_statistics();` (cluster-wide, since start) | loss counters (`activity_positions_skipped`, `activity_records_rejected`, `activity_publish_failed`, `learn_observations_dropped`) not growing | rising loss counters need investigation; `slot_overwrites` and `activity_slot_overwrites` count slot reuse, including already consumed records, and do not by themselves prove loss |
| `SELECT * FROM sql_firewall_retention_status;` | `last_success_at` recent, `failures` not growing | `last_error_sqlstate` |
| server log | no `sql_firewall:` WARNING or ERROR from `sql_firewall_worker_*` | worker retries (with SQLSTATE), discarded events, rejected activity records |

**Sizing.** The consumer writes up to 256 activity records per transaction.
Measured throughput and the statement rate at which activity records start
to be overwritten are in `docs/PERFORMANCE.md`; above it, enlarge
`sql_firewall.activity_queue_size` (restart) or turn
`sql_firewall.enable_activity_logging` off for the busiest roles (blocked
statements are always recorded, through the 1024-slot event ring).

**Routine procedures.** Policy review and approval (6.1, 6.1b), recovery
from a lockout (6.1d), logical backup of policy (6.9), extension update
(6.9a), physical backup, PITR and `pg_upgrade` (6.9b), standby and promotion
(6.10), worker pause and resume (5, "Approval worker maintenance").

**Performance summary.** See `docs/PERFORMANCE.md` for the method, the
budgets fixed before measuring, and the results on the reference host.

---
## 9. Troubleshooting and Known Limits

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `FATAL: could not access file "sql_firewall"` at start | library missing from `pkglibdir`, or a typo in `shared_preload_libraries` | install the package for this major version, fix the setting, restart |
| `sql_firewall_status()` says `NOT ACTIVE` | not preloaded | add to `shared_preload_libraries`, restart (4) |
| `CREATE EXTENSION sql_firewall` fails with `the library is not loaded through shared_preload_libraries` (`55000`) | the running server did not preload the library; a setting changed by `ALTER SYSTEM` or a reload counts only after a restart (the `DETAIL` says so) | add to `shared_preload_libraries`, restart, run `CREATE EXTENSION` again; nothing was left behind (4) |
| `ALTER EXTENSION ... UPDATE` fails with `the server runs library X, not Y` (`55000`), or `sql_firewall_upgrade` says NOT READY | the new package is installed but the server still runs the old library | restart PostgreSQL, then update (6.9a) |
| everything refused for an application role after enabling enforce | no approvals for its commands or fingerprints | approve (6.1), or run that role in learn/permissive first (4.1) |
| fingerprints refused after a logical restore or `pg_upgrade` | new installation identity (6.9, 6.9b) | re-approve the newly recorded identities |
| a superuser is locked out | superuser bypass off and no approvals | connect with `PGOPTIONS='-c sql_firewall.enabled=off'` (6.1d) |
| no blocked or activity rows appear | consumer not running or paused; `max_worker_processes` exhausted; queue overwrites | health checks in 8; `sql_firewall_resume_approval_worker()` |
| `regex rules could not be evaluated within N ms` | an expensive pattern, a long statement, or a lock on `sql_firewall_regex_rules` | simplify the rule, raise `sql_firewall.regex_timeout_ms`, avoid long DDL on the rules table |
| `Rate-limit state is full` (`53400`) | more than 8192 active (database, role, command) counters | shorter windows or fewer limited roles |
| `pg_upgrade` fails with `database "postgres" is being accessed by other users` | a build older than the binary-upgrade fix | use this version's package in both clusters (6.9b) |
| after `SET ROLE x`, `RESET ROLE` (or another statement) is refused | statements are decided by the current role's policy, including `RESET ROLE` (6.1b) | approve `SET`/`RESET` (and their fingerprints) for the roles an application switches to |
| a non-superuser with table grants gets "only a superuser session can change ..." | policy and audit tables are written only by superuser sessions and the firewall itself (6.1b) | use a superuser session or the management functions |
| refusal text says "Approval ... is pending" for a revoked command | the enforce message is the same for any `is_approved = false` command row; 6.1b calls that state denied | none needed; `sql_firewall_approve_command` approves it |

**Known limits** (by design or not yet supported; see 3.1):
- In-memory queues: events are lost on a postmaster restart, a crash, or
  overwrite (counted); not a durable audit channel. Use PostgreSQL logging
  or `pgaudit` where a durable, complete statement log is mandatory.
- Fingerprint approvals do not survive a logical restore or `pg_upgrade`.
- The library cannot act when it is not loaded: removing it from
  `shared_preload_libraries` after installation leaves those databases
  uninspected (`sql_firewall_status()` says `NOT ACTIVE`; 4). Installing a
  new release needs a restart (6.9a).
- `application_name` is client-supplied; it is not an authenticated identity.
  Unix-socket connections have no address for address rules.
- `BEGIN ATOMIC` SQL-standard function bodies and rewrite rules with more
  than one possible DML parent are refused with `0A000` (6.6a).
- Regex rules are readable by every role (the firewall reads them on every
  statement); syslog alerts carry the full payload.
- Policy rows are bound to role **names**; a dropped and recreated role with
  the same name inherits them (6.1b).
- PostgreSQL 13–15 are not supported.
