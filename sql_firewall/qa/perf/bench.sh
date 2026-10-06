#!/usr/bin/env bash
# sql_firewall performance acceptance driver (docs/PERFORMANCE.md, P9-06).
#
# Usage: qa/perf/bench.sh [--quick]
#   QA_PG_CONFIG   target PostgreSQL (default /usr/pgsql-17/bin/pg_config, a
#                  production build; the pgrx installations are cassert builds)
#   QA_TARGET_DIR  cargo target dir (default sql_firewall/target/qa-perf-<major>)
#   QA_WORK_ROOT   parent of the result directory
#   PERF_DURATION  measured seconds per run (default 60; --quick: 10)
#   PERF_REPS      repetitions of W1-W3 (default 3; --quick: 1)
#   PERF_LONG      long-run seconds for P7 (default 1800; --quick: 60)
#   PERF_ONLY      all (default), p7 (only the long run), or p4p7: the activity completeness runs
#                  and the long run, for a change that affects the consumer's
#                  writing and retention but not the statement path
#
# Builds the release package with run.sh --build-only --keep, stages a private
# copy of the installation, and measures configurations A-G
# (docs/PERFORMANCE.md) on one isolated cluster: A with the library not
# preloaded (a restart), B-G with it preloaded and the configuration applied
# as role-in-database settings of the ordinary benchmark role. Every run row
# goes to results.csv. Must not run at the same time as run.sh.
set -uo pipefail

PERF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
QA_DIR=$(dirname "$PERF_DIR")
EXT_DIR=$(dirname "$QA_DIR")
for v in $(compgen -e | grep -E '^PG'); do unset "$v"; done
QUICK=0
[[ ${1:-} == --quick ]] && QUICK=1
DUR=${PERF_DURATION:-$( ((QUICK)) && echo 10 || echo 60)}
REPS=${PERF_REPS:-$( ((QUICK)) && echo 1 || echo 3)}
LONG=${PERF_LONG:-$( ((QUICK)) && echo 60 || echo 1800)}
WARM=$( ((QUICK)) && echo 5 || echo 15)
ONLY=${PERF_ONLY:-all}
[[ $ONLY == all || $ONLY == p4p7 || $ONLY == p7 ]] || { echo "PERF_ONLY must be all, p4p7 or p7" >&2; exit 2; }
QA_PG_CONFIG=${QA_PG_CONFIG:-/usr/pgsql-17/bin/pg_config}
PG_MAJOR=$("$QA_PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
QA_TARGET_DIR=${QA_TARGET_DIR:-$EXT_DIR/target/qa-perf-$PG_MAJOR}
QA_WORK_ROOT=${QA_WORK_ROOT:-${TMPDIR:-/tmp}}
mkdir -p "$QA_WORK_ROOT" && OUT=$(mktemp -d "$QA_WORK_ROOT/sqlfw-perf.XXXXXX") || exit 2
mkdir -p "$OUT/logs" "$OUT/pgbench"
echo "result directory: $OUT"
log() { printf '%s %s\n' "$(date +%T)" "$*" | tee -a "$OUT/logs/driver.log"; }

# --- build and stage ------------------------------------------------------------
build_out=$(QA_TARGET_DIR=$QA_TARGET_DIR QA_WORK_ROOT=$OUT/build QA_ALLOW_OTHER_MAJOR=1 QA_PG_CONFIG=$QA_PG_CONFIG \
    "$QA_DIR/run.sh" --build-only --keep 2>&1)
build_run=$(sed -n 's/^run directory: //p' <<<"$build_out")
[[ -d $build_run/pkg ]] || { printf '%s\n' "$build_out" >&2; exit 3; }
SO_SHA=$(sed -n 's/^artifact_so_sha256=//p' "$build_run/manifest.txt")
INST=$OUT/inst
cp -a "$(dirname "$("$QA_PG_CONFIG" --bindir)")" "$INST" || exit 2
LIBDIR=$("$INST/bin/pg_config" --pkglibdir) SHAREDIR=$("$INST/bin/pg_config" --sharedir)
[[ $LIBDIR == "$INST"/* ]] || { echo "staged installation is not relocatable" >&2; exit 2; }
rm -f "$LIBDIR"/sql_firewall*.so "$SHAREDIR"/extension/sql_firewall*
cp "$build_run/pkg$("$QA_PG_CONFIG" --pkglibdir)/sql_firewall.so" "$LIBDIR/"
cp "$build_run/pkg$("$QA_PG_CONFIG" --sharedir)"/extension/sql_firewall* "$SHAREDIR/extension/"
BIN=$INST/bin
SOCK=$(mktemp -d /tmp/sfpf.XXXXXX) && chmod 700 "$SOCK"
PORT=$((28000 + RANDOM % 1000))
DATA=$OUT/pgdata
SU=bench_admin APP=bench_app DB=bench
{
    echo "started=$(date -Is)"
    echo "pg_version=$("$BIN/postgres" --version)"
    echo "pg_configure=$("$BIN/pg_config" --configure | head -c 300)"
    echo "so_sha256=$SO_SHA"
    echo "build_run=$build_run"
    echo "source_digest=$(sed -n 's/^source_digest=//p' "$build_run/manifest.txt")"
    echo "duration=$DUR reps=$REPS warmup=$WARM long=$LONG"
    echo "host=$(lscpu | sed -n 's/^Model name: *//p'), $(nproc) vCPU, $(free -g | awk '/Mem:/ {print $2}') GB, $(uname -r)"
} >"$OUT/manifest.txt"

psql_su() { "$BIN/psql" -X -q -A -t -v ON_ERROR_STOP=1 -h "$SOCK" -p "$PORT" -U "$SU" -d "${2:-$DB}" -c "$1"; }
start() { "$BIN/pg_ctl" -D "$DATA" -l "$OUT/logs/server.log" -w -t 120 start >>"$OUT/logs/pg_ctl.log" 2>&1; }
stop() { [[ -f $DATA/postmaster.pid ]] && "$BIN/pg_ctl" -D "$DATA" -m fast -w -t 120 stop >>"$OUT/logs/pg_ctl.log" 2>&1; }
cluster_pids() { # every process of this cluster, by executable
    local p
    for p in /proc/[0-9]*; do
        [[ $(readlink "$p/exe" 2>/dev/null) == "$BIN/postgres" ]] && echo "${p#/proc/}"
    done
}
finish() {
    stop
    local left
    left=$(cluster_pids | tr '\n' ' ')
    echo "surviving_processes=${left:-none}" >>"$OUT/manifest.txt"
    [[ -z $left ]] && rm -rf "$SOCK" "$DATA" "$INST" "$build_run/pkg"
    echo "finished=$(date -Is)" >>"$OUT/manifest.txt"
}
trap finish EXIT

PRELOADED=0
set_preload() { # on|off
    sed -i '/^shared_preload_libraries/d' "$DATA/postgresql.conf"
    [[ $1 == on ]] && echo "shared_preload_libraries = 'sql_firewall'" >>"$DATA/postgresql.conf"
    stop
    start || exit 2
    if [[ $1 == on ]]; then PRELOADED=1; else PRELOADED=0; fi
}

# --- cluster ----------------------------------------------------------------------
log "initdb"
"$BIN/initdb" -D "$DATA" -U "$SU" --auth=trust -E UTF8 --locale=C >"$OUT/logs/initdb.log" 2>&1 || exit 2
cat >>"$DATA/postgresql.conf" <<EOF
listen_addresses = ''
port = $PORT
unix_socket_directories = '$SOCK'
unix_socket_permissions = 0700
logging_collector = off
shared_buffers = 512MB
max_connections = 100
synchronous_commit = off
checkpoint_timeout = 15min
max_wal_size = 4GB
max_worker_processes = 16
lc_messages = 'C'
log_line_prefix = '%m [%p] %q%u@%d app=%a '
EOF
start || exit 2
psql_su "CREATE DATABASE $DB" postgres
"$BIN/pgbench" -i -s 10 -q -h "$SOCK" -p "$PORT" -U "$SU" "$DB" >"$OUT/logs/pgbench_init.log" 2>&1 || exit 2
psql_su "CREATE ROLE $APP LOGIN NOSUPERUSER"
psql_su "GRANT SELECT, INSERT, UPDATE ON pgbench_accounts, pgbench_branches, pgbench_tellers, pgbench_history TO $APP"
echo "shared_memory_size_A=$(psql_su 'SHOW shared_memory_size')" >>"$OUT/manifest.txt"
# W4: one ~8 kB statement.
{
    printf 'SELECT count(*) FROM pgbench_accounts WHERE aid IN ('
    seq -s, 100001 101000 | tr -d '\n'
    printf ');\n'
} >"$OUT/w4.sql"
echo "w4_bytes=$(wc -c <"$OUT/w4.sql")" >>"$OUT/manifest.txt"

# --- measurement helpers ------------------------------------------------------------
# CPU ticks of the whole cluster: user+system time of every live process,
# plus the postmaster's cumulative time of its children that have exited
# (cutime+cstime). Backends that start and end between two samples, such as
# every client connection of a run, are counted through the latter; a
# process alive at both samples contributes its own difference.
cluster_cpu_ticks() {
    local p total=0 f pm
    for p in $(cluster_pids); do
        f=$(awk '{print $14 + $15}' "/proc/$p/stat" 2>/dev/null) || continue
        total=$((total + ${f:-0}))
    done
    pm=$(head -1 "$DATA/postmaster.pid" 2>/dev/null)
    if [[ -n $pm ]]; then
        f=$(awk '{print $16 + $17}' "/proc/$pm/stat" 2>/dev/null)
        total=$((total + ${f:-0}))
    fi
    echo "$total"
}

# The CPU metric against a known load (regression review 2026-10-05, R3): four
# clients running a CPU-bound statement keep four backends busy, so the
# cluster should account for about four CPU-seconds per second, with
# persistent connections and with a new connection per transaction.
validate_cpu() {
    echo "SELECT count(*) FROM generate_series(1, 300000);" >"$OUT/cpu.sql"
    local mode cpu0 cpu1 t0 t1 ratio label
    for mode in "" "-C"; do
        label=${mode:-persistent}
        cpu0=$(cluster_cpu_ticks); t0=$(date +%s.%N)
        "$BIN/pgbench" -n -h "$SOCK" -p "$PORT" -U "$SU" -c 4 -j 4 -T 10 $mode -f "$OUT/cpu.sql" "$DB" >"$OUT/pgbench/cpu-validation$mode.out" 2>&1
        cpu1=$(cluster_cpu_ticks); t1=$(date +%s.%N)
        ratio=$(python3 -c "print(round(($cpu1 - $cpu0) / $(getconf CLK_TCK) / (4 * ($t1 - $t0)), 3))")
        echo "cpu_validation_${label#-}=$ratio (cluster CPU-seconds per second / 4 busy clients)" >>"$OUT/manifest.txt"
        log "cpu validation ($label): $ratio"
    done
}
consumer_anon_kb() { # private (anonymous) memory of the consumers; shared buffers excluded
    local p total=0 kb
    for p in $(cluster_pids); do
        tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -q 'sql_firewall_worker' || continue
        kb=$(awk '/^RssAnon:/ {print $2}' "/proc/$p/status" 2>/dev/null)
        total=$((total + ${kb:-0}))
    done
    echo "$total"
}
queue_loss() { # skipped,rejected,publish_failed,ring_overwrites
    psql_su "SELECT activity_positions_skipped || ',' || activity_records_rejected || ',' || activity_publish_failed || ',' || slot_overwrites FROM public.sql_firewall_queue_statistics()"
}
caught_up() { # the consumer wrote everything published so far
    local _
    for _ in $(seq 1 600); do
        [[ $(psql_su "SELECT (SELECT activity_write_position FROM public.sql_firewall_queue_statistics()) <= coalesce((SELECT next_position FROM public.sql_firewall_activity_checkpoint), 0)") == t ]] && return 0
        sleep 0.5
    done
    return 1
}
settle() { # consumer caught up, logs truncated, checkpoint
    if ((PRELOADED)); then
        caught_up || { echo "consumer did not catch up before settling" >&2; exit 2; }
        psql_su "SELECT public.sql_firewall_truncate_logs()" >/dev/null
    fi
    psql_su "CHECKPOINT" >/dev/null
}
apply_config() { # A..G, L (learning)
    psql_su "ALTER ROLE $APP IN DATABASE $DB RESET ALL" >/dev/null
    local s=() x
    case $1 in
        A) ;;
        B) s=("sql_firewall.enabled = off") ;;
        C) s=("sql_firewall.mode = 'learn'") ;;
        D) s=("sql_firewall.mode = 'permissive'") ;;
        E) s=("sql_firewall.mode = 'enforce'") ;;
        F) s=("sql_firewall.mode = 'enforce'" "sql_firewall.enable_activity_logging = off") ;;
        G) s=("sql_firewall.mode = 'enforce'" "sql_firewall.enable_activity_logging = off" "sql_firewall.enable_fingerprint_learning = off") ;;
        L) s=("sql_firewall.mode = 'learn'" "sql_firewall.fingerprint_learn_threshold = 1") ;;
    esac
    for x in "${s[@]}"; do psql_su "ALTER ROLE $APP IN DATABASE $DB SET $x" >/dev/null; done
}
workload_args() {
    case $1 in
        W1) echo "-S" ;;
        W2) echo "" ;;
        W3) echo "-S -M prepared" ;;
        W4) echo "-f $OUT/w4.sql" ;;
        W5) echo "-S -C" ;;
    esac
}

echo "config,workload,clients,rate,rep,duration,tps,lat_avg_ms,p50_ms,p95_ms,p99_ms,failed,cpu_ms_per_1k_tx,wal_bytes_per_tx,act_skipped,act_rejected,act_publish_failed,ring_overwrites,act_rows,act_lag_p50_s,act_lag_p99_s,consumer_anon_kb" >"$OUT/results.csv"

run() { # CONFIG WORKLOAD CLIENTS REP [RATE] [DURATION]
    local cfg=$1 w=$2 c=$3 rep=$4 rate=${5:-} dur=${6:-$DUR} args tag
    args=$(workload_args "$w")
    tag="$cfg.$w.c$c.r$rep${rate:+.rate$rate}"
    apply_config "$cfg"
    # shellcheck disable=SC2086
    "$BIN/pgbench" -n -h "$SOCK" -p "$PORT" -U "$APP" -c "$c" -j "$c" -T "$WARM" $args ${rate:+-R $rate} "$DB" \
        >"$OUT/pgbench/$tag.warm.out" 2>&1
    settle
    local wal0 cpu0 q0="0,0,0,0" wal1 cpu1 q1 qd="0,0,0,0"
    wal0=$(psql_su "SELECT pg_current_wal_lsn()")
    if ((PRELOADED)); then q0=$(queue_loss) || exit 2; fi
    cpu0=$(cluster_cpu_ticks)
    rm -f "$OUT/pgbench/$tag".log*
    # shellcheck disable=SC2086
    "$BIN/pgbench" -n -h "$SOCK" -p "$PORT" -U "$APP" -c "$c" -j "$c" -T "$dur" $args ${rate:+-R $rate} \
        --log --log-prefix="$OUT/pgbench/$tag.log" --sampling-rate=0.2 "$DB" >"$OUT/pgbench/$tag.out" 2>&1
    cpu1=$(cluster_cpu_ticks)
    wal1=$(psql_su "SELECT pg_current_wal_lsn()")
    local tps tx failed lat walb cpu_per lag="," rows="" anon
    tps=$(sed -nE 's/^tps = ([0-9.]+).*/\1/p' "$OUT/pgbench/$tag.out" | head -1)
    tx=$(sed -nE 's/^number of transactions actually processed: ([0-9]+).*/\1/p' "$OUT/pgbench/$tag.out")
    failed=$(sed -nE 's/^number of failed transactions: ([0-9]+).*/\1/p' "$OUT/pgbench/$tag.out")
    grep -q "aborted\|ERROR" "$OUT/pgbench/$tag.out" && failed="${failed:-0}+aborts"
    lat=$(cat "$OUT/pgbench/$tag".log* 2>/dev/null | python3 "$PERF_DIR/latency.py")
    walb=$(psql_su "SELECT round(pg_wal_lsn_diff('$wal1', '$wal0') / greatest(${tx:-0}, 1))")
    cpu_per=$(python3 -c "print(round(($cpu1 - $cpu0) * 1000 / $(getconf CLK_TCK) * 1000 / max(${tx:-0}, 1), 3))")
    if ((PRELOADED)); then
        if [[ $cfg == C || $cfg == D || $cfg == E ]]; then
            caught_up || { echo "consumer did not catch up after $tag" >&2; exit 2; }
            rows=$(psql_su "SELECT count(*) FROM public.sql_firewall_activity_log")
            lag=$(psql_su "SELECT coalesce(round(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM recorded_at - log_time))::numeric, 3)::text, '') || ',' || coalesce(round(percentile_cont(0.99) WITHIN GROUP (ORDER BY extract(epoch FROM recorded_at - log_time))::numeric, 3)::text, '') FROM public.sql_firewall_activity_log")
        fi
        q1=$(queue_loss) || exit 2
        qd=$(python3 -c "a='$q0'.split(','); b='$q1'.split(','); print(','.join(str(int(y)-int(x)) for x, y in zip(a, b)))")
    fi
    anon=$(consumer_anon_kb)
    echo "$cfg,$w,$c,${rate:-},$rep,$dur,$tps,$lat,${failed:-0},$cpu_per,$walb,$qd,$rows,$lag,$anon" >>"$OUT/results.csv"
    log "$tag tps=$tps lat(avg,p50,p95,p99)=$lat failed=${failed:-0} cpu_ms/1k=$cpu_per wal/tx=$walb loss(skip,rej,pubfail,ringovw)=$qd rows=$rows lag=$lag anon_kb=$anon"
    rm -f "$OUT/pgbench/$tag".log*
}

validate_cpu

# --- learning (once, preloaded) -------------------------------------------------------
set_preload on
psql_su "CREATE EXTENSION sql_firewall"
echo "shared_memory_size_B=$(psql_su 'SHOW shared_memory_size')" >>"$OUT/manifest.txt"
log "learning the workload (threshold 1)"
apply_config L
for w in W1 W2 W3 W4 W5; do
    # shellcheck disable=SC2046
    "$BIN/pgbench" -n -h "$SOCK" -p "$PORT" -U "$APP" -c 2 -j 2 -t 50 $(workload_args "$w") "$DB" >"$OUT/pgbench/learn.$w.out" 2>&1
done
sleep 5
psql_su "SELECT string_agg(command_type || ':' || is_approved, ' ' ORDER BY command_type) FROM public.sql_firewall_command_approvals WHERE role_name = '$APP'" >"$OUT/learned_commands.txt"
psql_su "SELECT count(*) || ' fingerprints, ' || count(*) FILTER (WHERE NOT is_approved) || ' unapproved' FROM public.sql_firewall_query_fingerprints WHERE role_name = '$APP'" >"$OUT/learned_fingerprints.txt"
log "learned: $(cat "$OUT/learned_commands.txt"); $(cat "$OUT/learned_fingerprints.txt")"

# --- W1-W3, interleaved repetitions -------------------------------------------------------
echo "perf_only=$ONLY" >>"$OUT/manifest.txt"
[[ $ONLY == all ]] && for rep in $(seq 1 "$REPS"); do
    log "repetition $rep: A (not preloaded)"
    set_preload off
    for w in W1 W2 W3; do run A "$w" 8 "$rep"; done
    set_preload on
    for cfg in B C D E F G; do
        for w in W1 W2 W3; do run "$cfg" "$w" 8 "$rep"; done
    done
done

# --- W4, W5, concurrency sweep ---------------------------------------------------------
if [[ $ONLY == all ]]; then
    set_preload off
    for w in W4 W5; do run A "$w" 8 1; done
    for c in 1 32; do run A W1 "$c" 1; done
    set_preload on
    for cfg in B C D E F G; do
        for w in W4 W5; do run "$cfg" "$w" 8 1; done
    done
    for c in 1 32; do run E W1 "$c" 1; done
fi

# --- P4: activity completeness at offered rates -----------------------------------------
if [[ $ONLY != p7 ]]; then
    run E W1 8 1 2000 "$( ((QUICK)) && echo 20 || echo 300)"
    for r in 5000 10000 20000 30000 40000; do run E W1 8 1 "$r" "$( ((QUICK)) && echo 10 || echo 60)"; done
fi

# --- P7: long run ------------------------------------------------------------------------
log "long run ${LONG}s"
psql_su "ALTER SYSTEM SET sql_firewall.activity_log_max_rows = 200000" >/dev/null
psql_su "ALTER SYSTEM SET sql_firewall.activity_log_prune_interval_seconds = 30" >/dev/null
psql_su "SELECT pg_reload_conf()" >/dev/null
apply_config E
log "long warm-up ${WARM}s (discarded)"
"$BIN/pgbench" -n -h "$SOCK" -p "$PORT" -U "$APP" -c 4 -j 4 -T "$WARM" "$DB" >"$OUT/pgbench/long.warm.out" 2>&1 || {
    echo "long workload warm-up failed" >&2
    exit 2
}
echo "long_warmup_seconds=$WARM" >>"$OUT/manifest.txt"
settle
anon0=$(consumer_anon_kb)
# Keep each sample in one MVCC snapshot: rows plus deleted rows measures
# committed inserts even while retention runs. Superuser sampling emits no
# application activity events. Capture terminal counters after draining too.
long_sample() {
    psql_su "SELECT pg_catalog.date_part('epoch', pg_catalog.clock_timestamp())::bigint || ',' ||
      (SELECT count(*) FROM public.sql_firewall_activity_log) || ',' ||
      q.activity_positions_skipped || ',' || q.activity_records_rejected || ',' || q.activity_publish_failed || ',' || q.slot_overwrites || ',' ||
      q.activity_write_position || ',' || coalesce(c.next_position, 0) || ',' || r.total_activity_deleted || ',' || r.runs || ',' || r.failures || ',' ||
      (SELECT coalesce(sum(reads), 0) FROM pg_catalog.pg_stat_io WHERE backend_type = 'client backend' AND context = 'normal' AND object = 'relation') || ',' ||
      (SELECT coalesce(sum(hits), 0) FROM pg_catalog.pg_stat_io WHERE backend_type = 'client backend' AND context = 'normal' AND object = 'relation')
      FROM public.sql_firewall_queue_statistics() q
      CROSS JOIN public.sql_firewall_activity_checkpoint c CROSS JOIN public.sql_firewall_retention_status r"
}
start_sample=$(long_sample) || exit 2
long_started=$(date +%s.%N)
(
    "$BIN/pgbench" -n -h "$SOCK" -p "$PORT" -U "$APP" -c 4 -j 4 -T "$LONG" -P 60 "$DB" >"$OUT/pgbench/long.out" 2>&1
    bench_rc=$?
    date +%s.%N >"$OUT/long_finished_epoch"
    exit "$bench_rc"
) &
bench_pid=$!
echo "epoch,activity_rows,skipped,rejected,publish_failed,ring_overwrites,published,checkpoint,deleted,retention_runs,retention_failures,client_reads,client_hits,consumer_anon_kb" >"$OUT/long_samples.csv"
echo "$start_sample,$anon0" >>"$OUT/long_samples.csv"
while kill -0 "$bench_pid" 2>/dev/null; do
    sample=$(long_sample) || exit 2
    echo "$sample,$(consumer_anon_kb)" >>"$OUT/long_samples.csv"
    sleep 30
done
wait "$bench_pid" || { echo "long workload failed" >&2; exit 2; }
long_caught_up=no
if caught_up; then long_caught_up=yes; fi
end_sample=$(long_sample) || exit 2
echo "$end_sample,$(consumer_anon_kb)" >>"$OUT/long_samples.csv"
# shellcheck disable=SC2129
echo "long_caught_up=$long_caught_up" >>"$OUT/manifest.txt"
python3 - "$start_sample" "$end_sample" "$long_started" "$(cat "$OUT/long_finished_epoch")" >>"$OUT/manifest.txt" <<'PY'
import sys
a, b = [list(map(int, x.split(','))) for x in sys.argv[1:3]]
print(f"long_runtime_seconds={float(sys.argv[4])-float(sys.argv[3]):.6f}")
print('long_loss_delta=' + ','.join(str(b[i]-a[i]) for i in (2, 3, 4)))
print(f"long_published_delta={b[6]-a[6]}")
print(f"long_written={b[1]-a[1]+b[8]-a[8]}")
print(f"long_backlog={max(0,b[6]-b[7])}")
PY
echo "long_consumer_anon_kb=$anon0->$(consumer_anon_kb)" >>"$OUT/manifest.txt"
echo "retention=$(psql_su "SELECT 'runs=' || runs || ' failures=' || failures || ' total_activity_deleted=' || total_activity_deleted || ' last_error=' || coalesce(last_error_sqlstate, '-') FROM public.sql_firewall_retention_status")" >>"$OUT/manifest.txt"
echo "server_errors=$(grep -cE 'ERROR|PANIC|terminated by signal' "$OUT/logs/server.log")" >>"$OUT/manifest.txt"
log "done"
