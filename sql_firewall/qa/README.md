# SQL Firewall QA

[Project overview](../../README.md) · [Configuration reference](../docs/REFERENCE.md)

The runner builds a release library, stages a private PostgreSQL installation,
and tests it in a disposable cluster. It does not modify or restart existing
clusters. Supported targets are PostgreSQL 16, 17, and 18.

## Requirements

- Rust, `cargo-pgrx` 0.16.1, PostgreSQL development headers, and a C toolchain.
- A PostgreSQL installation initialized with `cargo pgrx init`, or an explicit
  `QA_PG_CONFIG` pointing to the target installation.
- Bash, coreutils, Python 3, and Linux `/proc`.
- Disk space for a private PostgreSQL installation and a reusable Cargo cache.

## Run

Commands below assume the repository root:

```bash
sql_firewall/qa/run.sh
QA_PG_CONFIG=/usr/pgsql-17/bin/pg_config sql_firewall/qa/run.sh
sql_firewall/qa/run.sh --only '102*'       # targeted checks
sql_firewall/qa/run.sh --build-only       # compile and record provenance
sql_firewall/qa/run.sh --no-tests         # build, stage, start, verify, stop
sql_firewall/qa/run.sh --keep             # retain the disposable cluster/install
```

The default `pg_config` is `$HOME/.pgrx/16.15/pgrx-install/bin/pg_config`.
Select `QA_PG_CONFIG` explicitly for other installations. Tests run as the
current operating-system user; PostgreSQL cannot be started as root.

| Variable | Purpose |
|---|---|
| `QA_PG_CONFIG` | PostgreSQL installation to build and test against |
| `QA_TARGET_DIR` | Reusable Cargo cache; use separate directories for different server builds |
| `QA_WORK_ROOT` | Parent directory for reports and disposable installations |
| `QA_SOCKET_ROOT` | Parent of the private Unix socket directory |
| `QA_BUILD_PROFILE` | `release` (default) or `debug` |
| `QA_SOURCE_DIR` | Alternate source tree, used by build-failure checks |

Do not edit source during a build or benchmark: it makes artifact provenance
ambiguous. Run performance measurements without other QA workloads.

## Additional checks

```bash
sql_firewall/qa/selftest_build_failure.sh
sql_firewall/qa/selftest_lifecycle.sh
sql_firewall/qa/tests/01_verdict_regressions.sh
sql_firewall/qa/pg_upgrade_check.sh 16 17
sql_firewall/qa/package_upgrade_check.sh /usr/pgsql-17/bin/pg_config
sql_firewall/qa/perf/bench.sh
PERF_ONLY=p4p7 sql_firewall/qa/perf/bench.sh
PERF_ONLY=p7 sql_firewall/qa/perf/bench.sh
python3 sql_firewall/qa/perf/test_budgets.py
```

`perf/bench.sh --quick` is a smoke run, not performance acceptance. See
[performance](../docs/PERFORMANCE.md) for workloads and thresholds.

Probe features expose test-only functions and must not be enabled in release
packages:

```bash
QA_CARGO_FEATURES=queue_probe QA_TEST_DIR=$PWD/sql_firewall/qa/probe sql_firewall/qa/run.sh --only '0[1-5]*'
QA_CARGO_FEATURES=fingerprint_probe QA_TEST_DIR=$PWD/sql_firewall/qa/probe sql_firewall/qa/run.sh --only '06*'
QA_CARGO_FEATURES=policy_probe QA_TEST_DIR=$PWD/sql_firewall/qa/probe sql_firewall/qa/run.sh --only '07*'
QA_CARGO_FEATURES=session_probe QA_TEST_DIR=$PWD/sql_firewall/qa/probe sql_firewall/qa/run.sh --only '08*'
```

## Coverage

| Tests | Scope |
|---|---|
| 00–01 | Harness and verdict regressions |
| 10–30, 103–106 | Approval gates, learning thresholds, mode matrix, decision order, rollback, and recovery |
| 40–50, 107, 114 | Administration boundaries, hostile name resolution, audit privacy, and catalog membership |
| 60–80 | Audit failure isolation, per-database activation, and encoding |
| 90–96, 110 | Worker discovery, queue publication, transaction retry, restart recovery, pause/resume, and process lifecycle |
| 97–100 | Statement classification, fingerprint identity, policy cache invalidation, and transaction startup |
| 101–102 | Policy backup/restore, alerts, retention, and backlog cleanup |
| 108–109 | Regex deadlines, quiet hours, session rules, IP identity, and rate limits |
| 111–113 | Preload requirement, standby/promotion, and extension updates |
| Probe 01–08 | Deterministic queue, checkpoint, cache publication, fingerprint, and rate-capacity races |

Historical SQL fixtures and their provenance are required for compatibility
and regression checks. They are test inputs, not supported old-name packages.

## Results and evidence

Only **PASS** is a pass. FAIL indicates an observed defect; INFRA indicates an
environment or prerequisite failure; INCONCLUSIVE means the available evidence
cannot establish the contract. UNSUPPORTED checks are not counted as passes.

Runner exit codes: 0 green; 1 test failure/non-green result; 2 infrastructure
failure; 3 build failure. A PostgreSQL error counts as the expected rejection
only when its SQLSTATE and diagnostic match the firewall contract.

The printed run directory contains `summary.md`, `results.tsv`, `manifest.txt`,
per-test `evidence/`, and logs. The manifest records the source digest, build
command, package/library hashes, mapped server library, and cleanup status.

Cleanup verifies process ownership before signalling anything. A green run
removes its private installation and data; reports remain. Failed runs and
`--keep` runs retain diagnostic files. A surviving process or changed shared
installation makes the result non-green. Cargo build caches are retained.

A delivered later canary proves consumer liveness, not delivery of every
previous event. Absence of an asynchronous effect is not by itself a pass;
checks need publication counters, committed state, or a deterministic probe.
