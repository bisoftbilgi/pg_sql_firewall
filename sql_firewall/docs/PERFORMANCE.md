# Performance

[Project overview](../../README.md) · [QA guide](../qa/README.md)

Measurements use an ordinary application role, release builds, and isolated
clusters. Results are specific to the reference host; they are not universal
throughput or loss-free delivery guarantees.

## Reference environment

- PGDG PostgreSQL 17.11, Linux, 8 vCPU, 16 GB RAM, virtual disk.
- `shared_buffers = 512MB`, `fsync = on`, `synchronous_commit = off`,
  `checkpoint_timeout = 15min`, `max_wal_size = 4GB`.
- pgbench scale 10, 15-second discarded warm-up, 60-second short runs.
  W1–W3 use three interleaved repetitions and median results.
- Performance uses a production PostgreSQL build. pgrx-managed installations
  built with `--enable-cassert` are suitable for correctness testing but their
  debug overhead is not a production performance claim.

## Configurations

| id | description |
|---|---|
| A | no `shared_preload_libraries` (native baseline) |
| B | library preloaded, extension installed, `sql_firewall.enabled = off` |
| C | learn mode, after learning converged (every command and fingerprint of the workload approved) |
| D | permissive mode, everything approved |
| E | enforce mode, everything approved, activity logging on (installation defaults otherwise) |
| F | E with `sql_firewall.enable_activity_logging = off` |
| G | F with fingerprint checking off (command approvals, regex, keyword checks only) |

The pgbench role is an ordinary role (not superuser), so it is inspected.

## Workloads

| id | workload |
|---|---|
| W1 | `pgbench -S` simple protocol: one indexed SELECT per transaction (worst case for a per-statement filter) |
| W2 | `pgbench` built-in TPC-B-like: BEGIN, 3 UPDATE, SELECT, INSERT, END (7 statements) |
| W3 | `pgbench -S -M prepared` (extended protocol, plan reused) |
| W4 | one SELECT with a ~8 kB text (an `IN` list of 1,000 literals) per transaction |
| W5 | `pgbench -S -C`: a new connection per transaction (cold backend caches) |

Measured run length 60 s (W1–W5) at 8 clients; the W1 concurrency sweep uses
1, 8 and 32 clients for A and E.

## Metrics

Throughput (TPS), latency p50/p95/p99 (from `pgbench --log` per-transaction
latencies), CPU seconds per 1,000 transactions (live process CPU plus exited-child
CPU accounted through the postmaster), WAL bytes per transaction (`pg_current_wal_lsn` difference),
`shared_memory_size`, consumer and backend RSS, activity queue statistics
(`sql_firewall_queue_statistics()`: overwrites, skips, rejected), and
activity write lag (`recorded_at - log_time` percentiles).

## Budgets (pass/fail)

| # | budget |
|---|---|
| P1 | B vs A: throughput loss ≤ 5% on W1 and W2 |
| P2 | E vs A on W2: throughput loss ≤ 30% and p99 latency ≤ 1.5 × A's p99 |
| P3 | F vs A on W1 and W3: throughput loss ≤ 40% |
| P4 | Activity completeness: E at an offered load of 2,000 statements/s (`pgbench -R`), 300 s: 0 skipped, rejected, or publish-failed activity records; write lag p99 ≤ 2 s. The highest loss-free offered rate is also reported (not a budget) |
| P5 | W5 (new connection per transaction), E vs A: average added latency per transaction ≤ 5 ms |
| P6 | Added `shared_memory_size` at installation defaults (B vs A) ≤ 64 MB |
| P7 | Long run: E on W2 at 4 clients for 30 minutes with `activity_log_max_rows = 200000` and `activity_log_prune_interval_seconds = 30`: no client error, no server ERROR from the firewall's processes, TPS of the last 5 minutes within 15% of the first 5 minutes, consumer RSS growth ≤ 20 MB, activity table row count bounded (≤ 200,000 + one prune interval of inserts) |
| P8 | W4 (8 kB statement), E vs A: throughput loss ≤ 50% |

A failed budget is reported as failed. It is either fixed in the product and
re-measured on the new library, or the user accepts it as a documented limit;
a budget is not changed after its measurement.

## Accepted measurements

The completed short-workload matrix was measured on library `5502d0e76ad86f9f…`.
Later retention scheduling changes were checked with P4/P6/P7 on the final
library. P1–P3, P5, and P8 were not rerun on that final library; the short-matrix
numbers below retain their original artifact scope.

| Budget | Result | Short-matrix measurement |
|---|---|---|
| P1 | PASS | Disabled firewall met the ≤5% throughput-loss budget |
| P2 | PASS | W2 throughput loss 5.4%; p99 latency ×1.02 |
| P3 | PASS | Activity off: W1 loss 29.9%; W3 loss 34.7% |
| P5 | PASS | New connection per transaction: +2.37 ms average latency |
| P8 | PASS | 8 kB statement: throughput loss 22.3% |

Final targeted runs on 2026-10-06 used source digest
`6589827d86f9b124250f7d0bfe0250ecec2ace7d51ab55ac889cdd49861c6adf`
and library SHA-256
`e9d47a4a88860882552c758f7db30fc0db343c03d7bec8bc7f548f90910b29fc`:

| Check | Result | Measurement |
|---|---|---|
| P4 | PASS | Offered 2,000 statements/s for 300 s; no lost activity records; p99 audit write lag 17 ms |
| P6 | PASS | +16 MB shared memory at defaults |
| P7 | PASS | First/final actual 300 s: 217.52 → 245.42 TPS (+12.8%, within ±15%); no failed transactions or server ERROR/PANIC; consumer memory +2.9 MB; peak 206,559 rows ≤250,565 bound |
| P7.audit | PASS | 3,033,928 published = 3,033,928 committed inserts; no skipped/rejected/publish-failed records; final backlog zero |

The final P7 workload ran for 1,800.080 seconds after a 15-second warm-up.
Retention completed 4,652 maintenance transactions without failure, deleted
2,833,928 rows, and left 200,000 rows. P4 was measured in an earlier run on
these same library bytes, not repeated in the P7-only run.

Earlier P7 attempts failed retention, audit completeness, or the ±15% TPS-change
criterion. They were not reclassified as passes and no threshold was relaxed.
The final successful run used a fresh cluster and omitted the earlier overload
sweep. Cache warming is consistent with observed buffer statistics, but the
warm-up change alone is not a proven explanation of earlier TPS drift.

## Capacity and interpretation

The final-library offered-rate sweep was loss-free at 5,000 and 10,000
statements/s. Higher rates lost records: 957 at 20,000/s, 10,792 at 30,000/s,
and 24,105 at 40,000/s. These are observations on this host, not product limits.

Slot-reuse counters are not loss counters. Audit completeness uses
`activity_positions_skipped + activity_records_rejected + activity_publish_failed`
after draining the queue. P7 also reconciles committed rows plus retention
deletes against publications, sampled in one snapshot.

Row limits are cleanup targets, not synchronous insert caps. Size the queue
for the workload, monitor loss counters, and disable allowed-query activity
logging for roles where its cost is unacceptable. Blocked-query events use
a separate in-memory ring; neither queue is a durable audit channel.

## Reproduce

```bash
QA_PG_CONFIG=/path/to/production/bin/pg_config sql_firewall/qa/perf/bench.sh
PERF_ONLY=p4p7 sql_firewall/qa/perf/bench.sh
PERF_ONLY=p7 sql_firewall/qa/perf/bench.sh
python3 sql_firewall/qa/perf/budgets.py RUN_DIR
```

The run directory contains `results.csv`, `manifest.txt`, `long_samples.csv`,
and pgbench logs, including the terminal workload summary. Missing evidence is
NOT VERIFIED. P4 requires 300 seconds; P7 requires 1,800 seconds and actual
first/final 300-second windows. Unmeasured budgets remain NOT MEASURED.
A quick smoke run does not close acceptance budgets.
