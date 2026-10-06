#!/usr/bin/env bash
# sql_firewall isolated validation runner.
#
# Builds the extension from the current working tree, stages it into a private
# copy of a PostgreSQL installation, runs the tests in tests/ against a fresh
# disposable cluster on a private Unix socket, and writes a report. It never
# touches ~/.pgrx data directories, shared installations or running clusters.
#
# Usage: qa/run.sh [--build-only | --no-tests] [--keep] [--only GLOB]
# See qa/README.md for environment variables, result categories and exit codes.
set -uo pipefail

QA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EXT_DIR=$(dirname "$QA_DIR")
# shellcheck source=lib.sh
source "$QA_DIR/lib.sh"

BUILD_ONLY=0 NO_TESTS=0 KEEP=0 ONLY='*'
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only) BUILD_ONLY=1 ;;
        --no-tests) NO_TESTS=1 ;; # build, stage, start, verify, stop (lifecycle only)
        --keep) KEEP=1 ;;
        --only) ONLY=$2; shift ;;
        -h | --help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

# Never inherit libpq/pgrx connection or build settings from the caller.
for v in $(compgen -e | grep -E '^PG'); do unset "$v"; done

QA_PG_CONFIG=${QA_PG_CONFIG:-$HOME/.pgrx/16.15/pgrx-install/bin/pg_config}
QA_SOURCE_DIR=$(cd "${QA_SOURCE_DIR:-$EXT_DIR}" && pwd)
QA_BUILD_PROFILE=${QA_BUILD_PROFILE:-release}
QA_WORK_ROOT=${QA_WORK_ROOT:-${TMPDIR:-/tmp}}
QA_SOCKET_ROOT=${QA_SOCKET_ROOT:-/tmp}
QA_SUPERUSER=qa_admin
# Test-only fault injection (see selftest_lifecycle.sh):
#   start_bad_config | start_fail_after_spawn | stop_fail | stale_pidfile
QA_FAULT_INJECT=${QA_FAULT_INJECT:-}

EXIT_OK=0 EXIT_FAILURES=1 EXIT_INFRA=2 EXIT_BUILD=3

die_infra() { echo "INFRA: $*" >&2; [[ -n ${MANIFEST:-} ]] && m infra_abort "$*"; exit $EXIT_INFRA; }

# ---------------------------------------------------------------------------
# Run directory (owned by this run; identified by the marker file)
# ---------------------------------------------------------------------------
mkdir -p "$QA_WORK_ROOT" || die_infra "cannot create $QA_WORK_ROOT"
QA_RUN_DIR=$(mktemp -d "$QA_WORK_ROOT/sqlfw-qa.XXXXXX") || die_infra "mktemp failed"
QA_RUN_ID=$(basename "$QA_RUN_DIR")
echo "$QA_RUN_ID" >"$QA_RUN_DIR/.sqlfw-qa-owner"
QA_RESULTS=$QA_RUN_DIR/results.tsv
MANIFEST=$QA_RUN_DIR/manifest.txt
QA_SERVER_LOG=$QA_RUN_DIR/logs/server.log
STAGE=$QA_RUN_DIR/pginstall
PGDATA_DIR=$QA_RUN_DIR/pgdata
QA_SOCK=""
QA_PM_PID=""
mkdir -p "$QA_RUN_DIR/logs" "$QA_RUN_DIR/evidence"
: >"$QA_RESULTS"
touch "$QA_RUN_DIR/.start-stamp"

m() { printf '%s=%s\n' "$1" "$2" >>"$MANIFEST"; }

echo "run directory: $QA_RUN_DIR"
m run_id "$QA_RUN_ID"
m started_at "$(date -Is)"
m run_dir "$QA_RUN_DIR"
m mode "$( ((BUILD_ONLY)) && echo build-only || { ((NO_TESTS)) && echo no-tests || echo full; })"
[[ -n $QA_FAULT_INJECT ]] && m fault_inject "$QA_FAULT_INJECT"

# QA files used for this run.
(cd "$QA_DIR" && find . -type f -not -name '.*' | LC_ALL=C sort | xargs sha256sum) >"$QA_RUN_DIR/qa_files.sha256"
m qa_dir "$QA_DIR"
m qa_digest "$(sha256sum <"$QA_RUN_DIR/qa_files.sha256" | cut -d' ' -f1)"

# ---------------------------------------------------------------------------
# Process ownership. A process belongs to this run only if it executes this
# run's staged postgres binary (a path unique to the run directory) and runs
# under our uid. The postmaster is the owned process whose argv names this
# run's data directory. PID files and recorded PIDs are cross-checked against
# that, never trusted alone.
# ---------------------------------------------------------------------------
owned_dir() { [[ -f $1/.sqlfw-qa-owner && $(cat "$1/.sqlfw-qa-owner") == "$QA_RUN_ID" ]]; }

owned_processes() {
    local p exe uid me
    me=$(id -u)
    for p in /proc/[0-9]*; do
        exe=$(readlink "$p/exe" 2>/dev/null) || continue
        [[ $exe == "$STAGE/bin/postgres" || $exe == "$STAGE/bin/postgres (deleted)" ]] || continue
        uid=$(awk '/^Uid:/ { print $2 }' "$p/status" 2>/dev/null)
        [[ $uid == "$me" ]] && echo "${p#/proc/}"
    done
}

find_owned_postmaster() {
    local pid
    for pid in $(owned_processes); do
        tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -qxF -- "$PGDATA_DIR" && echo "$pid"
    done
}

wait_owned_gone() { # SECONDS
    local deadline=$((SECONDS + $1))
    while [[ -n $(owned_processes) ]]; do
        ((SECONDS >= deadline)) && return 1
        sleep 0.2
    done
}

pg_ctl_stop() { # MODE
    if [[ $QA_FAULT_INJECT == stop_fail ]]; then
        echo "fault-injected: pg_ctl stop -m $1 suppressed" >>"$QA_RUN_DIR/logs/pg_ctl.log"
        return 1
    fi
    "$STAGE/bin/pg_ctl" -D "$PGDATA_DIR" -m "$1" -w -t 30 stop >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1
}

signal_postmaster() { # PID SIGNAL  (PID already verified as this run's postmaster)
    if [[ $QA_FAULT_INJECT == stop_fail ]]; then
        echo "fault-injected: kill -$2 $1 suppressed" >>"$QA_RUN_DIR/logs/pg_ctl.log"
        return 1
    fi
    kill -"$2" "$1" 2>/dev/null
}

# Returns 0 only when no owned process remains. On failure STOP_REASON says why
# and QA_PM_PID is kept.
STOP_REASON=""
stop_owned_server() {
    local owned pm pidfile_pid=""
    owned=$(owned_processes | tr '\n' ' ')
    [[ -z $owned ]] && { QA_PM_PID=""; return 0; }
    [[ -f $PGDATA_DIR/postmaster.pid ]] && pidfile_pid=$(head -1 "$PGDATA_DIR/postmaster.pid")
    pm=$(find_owned_postmaster)
    if [[ -z $pm || $pm == *$'\n'* ]]; then
        STOP_REASON="owned processes ($owned) but no unique owned postmaster; nothing signalled"
        return 1
    fi
    if [[ -n $QA_PM_PID && $QA_PM_PID != "$pm" ]]; then
        if kill -0 "$QA_PM_PID" 2>/dev/null; then
            STOP_REASON="recorded postmaster pid $QA_PM_PID is not the owned postmaster $pm; nothing signalled"
            return 1
        fi
        # A test restarted this data directory. The recorded pid is gone.
        QA_PM_PID=$pm
    fi
    if [[ -n $pidfile_pid && $pidfile_pid != "$pm" ]]; then
        STOP_REASON="postmaster.pid names pid $pidfile_pid, not this run's postmaster $pm; refused pg_ctl (it would signal $pidfile_pid) and signalled nothing"
        return 1
    fi
    if [[ -n $pidfile_pid ]]; then
        pg_ctl_stop fast || pg_ctl_stop immediate
    else # startup before the pid file exists: signal the verified postmaster
        signal_postmaster "$pm" INT
    fi
    wait_owned_gone 30 || { signal_postmaster "$pm" QUIT; wait_owned_gone 15; }
    owned=$(owned_processes | tr '\n' ' ')
    if [[ -n $owned ]]; then
        STOP_REASON="owned processes still running after fast and immediate stop: $owned"
        return 1
    fi
    QA_PM_PID=""
    return 0
}

# ---------------------------------------------------------------------------
# Shared-state guard: fingerprints of everything this run must not modify.
# ---------------------------------------------------------------------------
shared_state() {
    local p
    # Both names: a shared install may still hold the historical
    # sql_firewall_rs files, or the current sql_firewall files. Either
    # changing is an isolation failure. Globs stay specific so an unrelated
    # sql_firewall_rs path is not treated as the new library, and vice versa.
    for p in "$HOME"/.pgrx/*/pgrx-install/lib/postgresql/sql_firewall.so \
        "$HOME"/.pgrx/*/pgrx-install/lib/postgresql/sql_firewall_rs.so \
        "$HOME"/.pgrx/*/pgrx-install/share/postgresql/extension/sql_firewall.control \
        "$HOME"/.pgrx/*/pgrx-install/share/postgresql/extension/sql_firewall--* \
        "$HOME"/.pgrx/*/pgrx-install/share/postgresql/extension/sql_firewall_rs* \
        "$HOME"/.pgrx/config.toml "$HOME"/.pgrx/data-*/postgresql*.conf \
        "$HOME"/.pgrx/data-*/postmaster.pid; do
        [[ -e $p ]] && sha256sum "$p"
    done
    # postgres processes that are not this run's (by executable path)
    local pid exe others=""
    for pid in $(pgrep -u "$(id -u)" -x postgres 2>/dev/null); do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        [[ $exe == "$STAGE/bin/postgres"* ]] || others+="$pid:$exe;"
    done
    echo "other postgres processes: ${others:-none}"
}

# ---------------------------------------------------------------------------
# Finalization: runs on every exit path (normal, die, build failure, signal).
# It never hides the original failure and never lets a cleanup or isolation
# failure leave a green verdict.
# ---------------------------------------------------------------------------
count() { awk -F'\t' -v s="$1" -v p="$2" '$1 == s && $2 ~ p' "$QA_RESULTS" | wc -l; }

finalize() {
    local rc=$1 problems=() survivors=""
    set +e
    trap - INT TERM
    if ! stop_owned_server; then
        problems+=("server stop failed: $STOP_REASON")
    fi
    survivors=$(owned_processes | tr '\n' ' ')
    survivors=${survivors% }
    m surviving_processes "${survivors:-none}"
    if [[ -n $survivors ]]; then
        # shellcheck disable=SC2086
        ps -o pid,ppid,user,lstart,args -p ${survivors// /,} >"$QA_RUN_DIR/logs/survivors.txt" 2>&1
        problems+=("owned processes survive: $survivors (logs/survivors.txt)")
    fi

    if [[ -f $QA_RUN_DIR/shared_state.before ]]; then
        shared_state >"$QA_RUN_DIR/shared_state.after"
        find "$HOME/.pgrx" ${PG_PREFIX:+"$PG_PREFIX"} -newer "$QA_RUN_DIR/.start-stamp" -print \
            >"$QA_RUN_DIR/shared_modified_paths.txt" 2>/dev/null
        if diff -u "$QA_RUN_DIR/shared_state.before" "$QA_RUN_DIR/shared_state.after" \
            >"$QA_RUN_DIR/shared_state.diff" && [[ ! -s $QA_RUN_DIR/shared_modified_paths.txt ]]; then
            m shared_state_unchanged yes
        else
            m shared_state_unchanged no
            problems+=("shared installation/cluster state changed (shared_state.diff, shared_modified_paths.txt)")
        fi
    fi

    local green_so_far=0
    [[ $rc -eq 0 && ${#problems[@]} -eq 0 ]] && green_so_far=1
    if [[ -z $survivors ]]; then
        [[ -n $QA_SOCK ]] && owned_dir "$QA_SOCK" && rm -rf -- "$QA_SOCK"
        if ((green_so_far)) && [[ $(count PASS .) -gt 0 || $BUILD_ONLY -eq 1 || $NO_TESTS -eq 1 ]] &&
            [[ $(awk -F'\t' '$1 != "PASS"' "$QA_RESULTS" | wc -l) -eq 0 && $KEEP -eq 0 ]] &&
            owned_dir "$QA_RUN_DIR"; then
            rm -rf -- "$PGDATA_DIR" "$STAGE" "$QA_RUN_DIR/pkg"
            m cleanup_status "OK (cluster, staged install and package removed)"
        else
            m cleanup_status "OK (server stopped; cluster/install retained for diagnostics)"
        fi
    else
        m cleanup_status "FAILED: owned processes alive; retained socket=$QA_SOCK data=$PGDATA_DIR stage=$STAGE"
    fi

    local p
    for p in "${problems[@]}"; do qa_record INFRA lifecycle.finalize "$p" >/dev/null; done

    local P F_PROD F_HARN F_OTHER I C U
    P=$(count PASS .) F_PROD=$(count FAIL '^baseline[.]') F_HARN=$(count FAIL '^selftest[.]')
    F_OTHER=$(($(count FAIL .) - F_PROD - F_HARN)) I=$(count INFRA .) C=$(count INCONCLUSIVE .) U=$(count UNSUPPORTED .)
    local totals="PASS=$P FAIL(product)=$F_PROD FAIL(harness)=$F_HARN FAIL(other)=$F_OTHER INFRA=$I INCONCLUSIVE=$C UNSUPPORTED=$U"

    local final=$rc
    if [[ $rc -eq 0 || $rc -eq $EXIT_FAILURES ]]; then
        if ((I > 0)); then
            final=$EXIT_INFRA
        elif ((F_PROD + F_HARN + F_OTHER + C + U > 0)); then
            final=$EXIT_FAILURES
        elif ((P == 0 && BUILD_ONLY == 0 && NO_TESTS == 0)); then
            final=$EXIT_INFRA # nothing ran is never green
        else
            final=$EXIT_OK
        fi
    elif ((${#problems[@]} > 0)); then
        m additional_failures "$(printf '%s; ' "${problems[@]}")"
    fi

    {
        echo "# sql_firewall QA run $QA_RUN_ID"
        echo
        echo "$totals"
        echo
        echo "exit code: $final (original status $rc); cleanup: $(sed -n 's/^cleanup_status=//p' "$MANIFEST" | tail -1)"
        echo
        echo '| status | id | detail |'
        echo '|---|---|---|'
        awk -F'\t' '{ gsub(/\|/, "\\|", $3); printf "| %s | %s | %s |\n", $1, $2, $3 }' "$QA_RESULTS"
        echo
        echo "Evidence: evidence/*.md  Manifest: manifest.txt  Server log: logs/server.log  SQL transcripts: logs/sql/"
    } >"$QA_RUN_DIR/summary.md"
    m totals "$totals"
    m final_exit_code "$final"
    m finished_at "$(date -Is)"
    echo
    echo "$totals"
    ((${#problems[@]})) && printf 'FINALIZE PROBLEM: %s\n' "${problems[@]}"
    echo "report: $QA_RUN_DIR/summary.md (exit $final)"
    exit "$final"
}
trap 'finalize $?' EXIT
trap 'exit 130' INT TERM

shared_state >"$QA_RUN_DIR/shared_state.before"

# ---------------------------------------------------------------------------
# Toolchain and PostgreSQL target
# ---------------------------------------------------------------------------
[[ -x $QA_PG_CONFIG ]] || die_infra "pg_config not found: $QA_PG_CONFIG"
PG_VERSION=$("$QA_PG_CONFIG" --version) || die_infra "pg_config --version failed"
PG_MAJOR=$(sed -E 's/^PostgreSQL ([0-9]+).*/\1/' <<<"$PG_VERSION")
PG_FEATURE=pg$PG_MAJOR
PG_BINDIR=$("$QA_PG_CONFIG" --bindir)
PG_PKGLIBDIR=$("$QA_PG_CONFIG" --pkglibdir)
PG_SHAREDIR=$("$QA_PG_CONFIG" --sharedir)
PG_INCLUDE_SERVER=$("$QA_PG_CONFIG" --includedir-server)
PG_PREFIX=$(dirname "$PG_BINDIR")
[[ $PG_MAJOR == 16 || $PG_MAJOR == 17 || $PG_MAJOR == 18 || ${QA_ALLOW_OTHER_MAJOR:-0} == 1 ]] ||
    die_infra "supported targets are PostgreSQL 16, 17 and 18; $QA_PG_CONFIG is $PG_VERSION (set QA_ALLOW_OTHER_MAJOR=1 to override)"
grep -qE "^$PG_FEATURE = " "$QA_SOURCE_DIR/Cargo.toml" || die_infra "Cargo.toml has no feature $PG_FEATURE"
EXT_VERSION=$(sed -nE "s/^default_version = '([^']+)'/\1/p" "$QA_SOURCE_DIR/sql_firewall.control")

m pg_config "$QA_PG_CONFIG"
m pg_version "$PG_VERSION"
m pg_feature "$PG_FEATURE"
m pg_includedir_server "$PG_INCLUDE_SERVER"
m cargo "$(cargo --version 2>&1)"
m rustc "$(rustc --version 2>&1)"
m cargo_pgrx "$(cargo pgrx --version 2>&1)"
m pgrx_lock "$(grep -A1 '^name = "pgrx"$' "$QA_SOURCE_DIR/Cargo.lock" | sed -n 's/^version = //p' | tr -d '"')"

# ---------------------------------------------------------------------------
# Source state
# ---------------------------------------------------------------------------
{
    git -C "$QA_SOURCE_DIR" rev-parse HEAD 2>/dev/null | sed 's/^/git_head=/'
    git -C "$QA_SOURCE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null | sed 's/^/git_branch=/'
    echo "git_diff_head_sha256=$(git -C "$QA_SOURCE_DIR" diff HEAD -- . 2>/dev/null | sha256sum | cut -d' ' -f1)"
} >>"$MANIFEST"
git -C "$QA_SOURCE_DIR" status --porcelain=v1 -uall -- . >"$QA_RUN_DIR/source_status.txt" 2>&1
# Digest over every build input, including uncommitted and untracked changes.
(cd "$QA_SOURCE_DIR" && find src sql Cargo.toml Cargo.lock build.rs sql_firewall.control .cargo \
    -type f 2>/dev/null | LC_ALL=C sort | xargs sha256sum) >"$QA_RUN_DIR/source_files.sha256"
m source_dir "$QA_SOURCE_DIR"
m source_digest "$(sha256sum <"$QA_RUN_DIR/source_files.sha256" | cut -d' ' -f1)"

# ---------------------------------------------------------------------------
# Build (never falls back to an existing artifact)
# ---------------------------------------------------------------------------
# cargo-pgrx does not pass --pg-config to build.rs, which otherwise compiles the
# C shim against whatever pg_config is first on PATH. Pin it explicitly, and
# use a per-major target directory because build.rs does not declare these
# variables with rerun-if-env-changed (a cached shim would not be rebuilt).
QA_TARGET_DIR=${QA_TARGET_DIR:-$EXT_DIR/target/qa-$PG_FEATURE${QA_CARGO_FEATURES:+-$QA_CARGO_FEATURES}}
PKG_DIR=$QA_RUN_DIR/pkg
PROFILE_ARGS=()
PROFILE_DIR=release
case $QA_BUILD_PROFILE in
    release) ;;
    debug) PROFILE_ARGS=(--debug); PROFILE_DIR=debug ;;
    *) die_infra "QA_BUILD_PROFILE must be release or debug" ;;
esac
BUILD_ENV=(CARGO_TARGET_DIR="$QA_TARGET_DIR" PGRX_PG_CONFIG_PATH="$QA_PG_CONFIG" PG_CONFIG="$QA_PG_CONFIG"
    PATH="$PG_BINDIR:$PATH" CC_ENABLE_DEBUG_OUTPUT=1 CARGO_NET_OFFLINE=true PGRX_BUILD_FLAGS=--locked)
QA_FEATURES=$PG_FEATURE
[[ -n ${QA_CARGO_FEATURES:-} ]] && QA_FEATURES="$QA_FEATURES,$QA_CARGO_FEATURES"
BUILD_CMD=(cargo pgrx package --manifest-path "$QA_SOURCE_DIR/Cargo.toml" --pg-config "$QA_PG_CONFIG"
    --no-default-features --features "$QA_FEATURES" "${PROFILE_ARGS[@]}" --out-dir "$PKG_DIR")
m cargo_features "$QA_FEATURES"
m build_profile "$QA_BUILD_PROFILE"
m build_profile_dir "$PROFILE_DIR"
m build_env "${BUILD_ENV[*]}"
m build_command "${BUILD_CMD[*]}"
m cargo_target_dir "$QA_TARGET_DIR"

build_failed() {
    m build_status FAILED
    m build_failure "$1"
    echo "BUILD FAILED: $1 (log: $QA_RUN_DIR/logs/build.log)" >&2
    exit $EXIT_BUILD
}

echo "building $PG_FEATURE ($QA_BUILD_PROFILE) from $QA_SOURCE_DIR ..."
touch "$QA_RUN_DIR/.build-stamp"
sleep 1 # mtime granularity: artifacts must be strictly newer than the stamp
(cd "$QA_SOURCE_DIR" && env "${BUILD_ENV[@]}" "${BUILD_CMD[@]}") >"$QA_RUN_DIR/logs/build.log" 2>&1
BUILD_RC=$?
m build_exit_code "$BUILD_RC"
[[ $BUILD_RC -eq 0 ]] || build_failed "cargo pgrx package exited $BUILD_RC"

ART_SO=$PKG_DIR$PG_PKGLIBDIR/sql_firewall.so
ART_CONTROL=$PKG_DIR$PG_SHAREDIR/extension/sql_firewall.control
ART_SQL=$PKG_DIR$PG_SHAREDIR/extension/sql_firewall--$EXT_VERSION.sql
for f in "$ART_SO" "$ART_CONTROL" "$ART_SQL"; do
    [[ -f $f ]] || build_failed "expected artifact missing: $f"
    [[ $f -nt $QA_RUN_DIR/.build-stamp ]] || build_failed "artifact not produced by this build: $f"
done
# One fresh-install script, for this version; any other script must be an
# update script (sql_firewall--OLD--NEW.sql, README 6.9a).
mapfile -t PACKAGE_SQL < <(find "$PKG_DIR$PG_SHAREDIR/extension" -maxdepth 1 -type f -name 'sql_firewall--*.sql' | LC_ALL=C sort)
UPDATE_SQL=()
for f in "${PACKAGE_SQL[@]}"; do
    [[ $f == "$ART_SQL" ]] && continue
    [[ $(basename "$f") == sql_firewall--?*--?*.sql ]] ||
        build_failed "package script $(basename "$f") is neither the sql_firewall--$EXT_VERSION.sql install script nor an update script"
    UPDATE_SQL+=("$f")
done
[[ " ${PACKAGE_SQL[*]} " == *" $ART_SQL "* ]] || build_failed "package lacks the sql_firewall--$EXT_VERSION.sql install script"
m package_update_scripts "$(for f in "${UPDATE_SQL[@]}"; do basename "$f"; done | tr '\n' ' ')"

# Header provenance: the C shim compile line recorded by cc (CC_ENABLE_DEBUG_OUTPUT).
# Match sql_firewall-<hash> only. sql_firewall-* also matches leftover
# sql_firewall_rs-<hash> build directories, which are historical evidence.
SHIM_OUTPUTS=()
for shim_dir in "$QA_TARGET_DIR/$PROFILE_DIR"/build/sql_firewall-* "$QA_TARGET_DIR/debug"/build/sql_firewall-*; do
    [[ -d $shim_dir ]] || continue
    [[ $(basename "$shim_dir") == sql_firewall_rs-* ]] && continue
    [[ -f $shim_dir/output ]] && SHIM_OUTPUTS+=("$shim_dir/output")
done
# Every C source is checked: fingerprint_scan.c depends on the lexer's
# struct layout in the server headers.
SHIM_INCLUDES=""
for shim_src in port_shim fingerprint_scan; do
    src_includes=""
    if [[ ${#SHIM_OUTPUTS[@]} -gt 0 ]]; then
        src_includes=$(cat "${SHIM_OUTPUTS[@]}" |
            grep -E "^running: .*\"src/$shim_src\\.c\"" | grep -oE '"-I" "[^"]+"' | sed -E 's/"-I" "(.*)"/\1/' | sort -u)
    fi
    [[ -n $src_includes ]] || build_failed "no recorded $shim_src.c compile line under $QA_TARGET_DIR; remove that directory and rebuild"
    SHIM_INCLUDES+="$src_includes"$'\n'
done
SHIM_INCLUDES=$(sort -u <<<"$SHIM_INCLUDES" | sed '/^$/d')
grep -qxF "$PG_INCLUDE_SERVER" <<<"$SHIM_INCLUDES" || build_failed "C shim not compiled against $PG_INCLUDE_SERVER: $SHIM_INCLUDES"
FOREIGN=$(grep -E '/include/postgresql/server$|/include/server$' <<<"$SHIM_INCLUDES" | grep -vxF "$PG_INCLUDE_SERVER")
[[ -z $FOREIGN ]] || build_failed "C shim compiled against another PostgreSQL's headers: $FOREIGN"
m shim_includes "$(tr '\n' ' ' <<<"$SHIM_INCLUDES")"

m build_status OK
m artifact_so "$ART_SO"
m artifact_so_sha256 "$(sha256sum "$ART_SO" | cut -d' ' -f1)"
m artifact_control_sha256 "$(sha256sum "$ART_CONTROL" | cut -d' ' -f1)"
m artifact_sql_sha256 "$(sha256sum "$ART_SQL" | cut -d' ' -f1)"
m target_library "$QA_TARGET_DIR/$PROFILE_DIR/libsql_firewall.so"
echo "build OK: $(sha256sum "$ART_SO" | cut -d' ' -f1)  sql_firewall.so"

((BUILD_ONLY)) && exit $EXIT_OK

# ---------------------------------------------------------------------------
# Stage a private copy of the PostgreSQL installation. PostgreSQL resolves
# $libdir and the extension directory relative to its own executable, so the
# copy loads only the artifacts placed into it.
# ---------------------------------------------------------------------------
echo "staging $PG_PREFIX -> $STAGE"
cp -a "$PG_PREFIX" "$STAGE" || die_infra "copy of $PG_PREFIX failed"
echo "$QA_RUN_ID" >"$STAGE/.sqlfw-qa-owner"
S_PKGLIBDIR=$("$STAGE/bin/pg_config" --pkglibdir)
S_SHAREDIR=$("$STAGE/bin/pg_config" --sharedir)
[[ $S_PKGLIBDIR == "$STAGE"/* && $S_SHAREDIR == "$STAGE"/* ]] ||
    die_infra "staged installation is not relocatable (pkglibdir=$S_PKGLIBDIR)"
# Whatever firewall files the source installation held are not ours.
# Remove both the historical name and the current name from this private copy
# only. The shared installation is not modified.
rm -f -- "$S_PKGLIBDIR"/sql_firewall.so "$S_PKGLIBDIR"/sql_firewall_rs.so \
    "$S_SHAREDIR"/extension/sql_firewall.control \
    "$S_SHAREDIR"/extension/sql_firewall--* \
    "$S_SHAREDIR"/extension/sql_firewall_rs*
cp "$ART_SO" "$S_PKGLIBDIR/" && cp "$ART_CONTROL" "$ART_SQL" "${UPDATE_SQL[@]}" "$S_SHAREDIR/extension/" ||
    die_infra "staging artifacts failed"
STAGED_SO=$S_PKGLIBDIR/sql_firewall.so
cmp -s "$ART_SO" "$STAGED_SO" || die_infra "staged library differs from artifact"
cmp -s "$ART_SQL" "$S_SHAREDIR/extension/sql_firewall--$EXT_VERSION.sql" || die_infra "staged install script differs from artifact"
m staged_install "$STAGE"
m staged_so "$STAGED_SO"
QA_PSQL=$STAGE/bin/psql

# ---------------------------------------------------------------------------
# Disposable cluster on a private socket, no TCP listener.
# ---------------------------------------------------------------------------
QA_SOCK=$(mktemp -d "$QA_SOCKET_ROOT/sfqa.XXXXXX") || die_infra "mktemp (socket dir) failed"
echo "$QA_RUN_ID" >"$QA_SOCK/.sqlfw-qa-owner"
chmod 700 "$QA_SOCK"
m socket_dir "$QA_SOCK"
QA_PORT=$((20000 + RANDOM % 8000))
"$STAGE/bin/initdb" -D "$PGDATA_DIR" -U "$QA_SUPERUSER" --auth=trust --no-sync -E UTF8 --locale=C \
    >"$QA_RUN_DIR/logs/initdb.log" 2>&1 || die_infra "initdb failed (logs/initdb.log)"
cat >>"$PGDATA_DIR/postgresql.conf" <<EOF

# --- sql_firewall QA (disposable cluster, run $QA_RUN_ID) ---
listen_addresses = ''
port = $QA_PORT
unix_socket_directories = '$QA_SOCK'
unix_socket_permissions = 0700
shared_preload_libraries = 'sql_firewall'
# One consumer per installed database, plus the launcher, autovacuum, and
# the logical replication launcher. 24, and later 64, was below that once
# the suite had created every database, so later databases never received a
# worker ("consumer registration failed"; seen with 64 after tests 112 and
# 113 were added, run sqlfw-qa.LfG17j).
max_worker_processes = 128
# tests/100 prepares transactions (PREPARE TRANSACTION, COMMIT/ROLLBACK
# PREPARED). Enabled in this disposable cluster only.
max_prepared_transactions = 10
lc_messages = 'C'
fsync = off
# The server log is the file pg_ctl -l names, which tests read. Distribution
# packages (PGDG) turn the logging collector on in postgresql.conf, which
# moves the log to pgdata/log (seen: every log-based check of the first
# PGDG 17 run failed, sqlfw-qa.T1sJ52).
logging_collector = off
log_line_prefix = '%m [%p] %q%u@%d app=%a '
EOF
[[ $QA_FAULT_INJECT == start_bad_config ]] && echo "shared_buffers = 'fault-injected'" >>"$PGDATA_DIR/postgresql.conf"
m port "$QA_PORT"

START_RC=0
"$STAGE/bin/pg_ctl" -D "$PGDATA_DIR" -l "$QA_SERVER_LOG" -w -t 60 start >"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 || START_RC=$?
if [[ $QA_FAULT_INJECT == start_fail_after_spawn ]]; then
    echo "fault-injected: start reported as failed (real rc $START_RC)" >>"$QA_RUN_DIR/logs/pg_ctl.log"
    START_RC=97
fi
if [[ $START_RC -ne 0 ]]; then
    m startup_status "FAILED rc=$START_RC"
    m startup_owned_processes "$(owned_processes | tr '\n' ' ')"
    die_infra "server start failed (pg_ctl rc $START_RC; logs/server.log, logs/pg_ctl.log); finalization stops any owned process"
fi
QA_PM_PID=$(find_owned_postmaster)
[[ -n $QA_PM_PID && $QA_PM_PID == "$(head -1 "$PGDATA_DIR/postmaster.pid")" ]] ||
    die_infra "started server not positively identified (owned postmaster '$QA_PM_PID', pid file '$(head -1 "$PGDATA_DIR/postmaster.pid")')"
m startup_status OK
m postmaster_pid "$QA_PM_PID"
if [[ $QA_FAULT_INJECT == stale_pidfile ]]; then
    [[ ${QA_FAULT_DECOY_PID:-} =~ ^[0-9]+$ ]] || die_infra "stale_pidfile fault needs QA_FAULT_DECOY_PID"
    sed -i "1s/.*/$QA_FAULT_DECOY_PID/" "$PGDATA_DIR/postmaster.pid"
    m fault_decoy_pid "$QA_FAULT_DECOY_PID"
fi

# Runtime provenance: the library mapped by the postmaster is the staged artifact.
# The filename match is sql_firewall.so, which does not match sql_firewall_rs.so.
if grep -qE '/sql_firewall_rs\.so( |$)' "/proc/$QA_PM_PID/maps"; then
    die_infra "postmaster mapped sql_firewall_rs.so; the old and new libraries must not both be loaded"
fi
MAPPED=$(qa_mapped_extension_so "$QA_PM_PID") || die_infra "postmaster did not map sql_firewall.so"
m runtime_mapped_library "$MAPPED"
[[ $MAPPED == "$STAGED_SO" ]] || die_infra "postmaster mapped '$MAPPED', expected $STAGED_SO"
m runtime_mapped_library_sha256 "$(sha256sum "$MAPPED" | cut -d' ' -f1)"

export QA_RUN_DIR QA_RESULTS QA_PSQL QA_SOCK QA_PORT QA_SUPERUSER QA_SERVER_LOG QA_PM_PID
qa_admin postgres "SELECT current_setting('server_version_num')" \
    "SELECT setting FROM pg_config WHERE name = 'PKGLIBDIR'" \
    "CREATE ROLE $QA_CANARY_ROLE LOGIN NOSUPERUSER" || die_infra "$QA_INFRA_REASON"
m runtime_server_version_num "${QA_STEP_OUT[1]}"
m runtime_pkglibdir "${QA_STEP_OUT[2]}"
[[ ${QA_STEP_OUT[2]} == "$S_PKGLIBDIR" ]] || die_infra "server pkglibdir ${QA_STEP_OUT[2]} is not the staged one"

# The launcher is registered from _PG_init. Startup success is not enough:
# its process must map the staged sql_firewall.so.
LAUNCH_PID=""
for _ in $(seq 1 20); do
    qa_admin postgres "SELECT coalesce(pid::text, '') FROM pg_stat_activity WHERE backend_type = 'sql_firewall_launcher'" ||
        die_infra "$QA_INFRA_REASON"
    LAUNCH_PID=${QA_STEP_OUT[1]}
    [[ -n $LAUNCH_PID ]] && break
    sleep 0.25
done
[[ -n $LAUNCH_PID ]] || die_infra "sql_firewall_launcher did not appear in pg_stat_activity"
LAUNCH_MAP=$(qa_mapped_extension_so "$LAUNCH_PID") ||
    die_infra "${QA_INFRA_REASON:-launcher pid $LAUNCH_PID did not map sql_firewall.so}"
[[ $LAUNCH_MAP == "$STAGED_SO" ]] || die_infra "launcher mapped '$LAUNCH_MAP', expected $STAGED_SO"
m launcher_pid "$LAUNCH_PID"
m launcher_mapped_library "$LAUNCH_MAP"

((NO_TESTS)) && exit $EXIT_OK

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
QA_TEST_ROOT=${QA_TEST_DIR:-$QA_DIR/tests}
for t in "$QA_TEST_ROOT"/$ONLY.sh; do
    [[ -f $t ]] || continue
    name=$(basename "$t" .sh)
    echo "--- $name"
    before=$(wc -l <"$QA_RESULTS")
    bash "$t" 2>"$QA_RUN_DIR/logs/$name.stderr"
    rc=$?
    after=$(wc -l <"$QA_RESULTS")
    if [[ $rc -ne 0 || $after -eq $before ]]; then
        qa_record INFRA "$name" "test script exited $rc after recording $((after - before)) result(s); see logs/$name.stderr"
    fi
    if ! kill -0 "$QA_PM_PID" 2>/dev/null; then
        # A test may restart this disposable postmaster. Adopt the replacement
        # when it is the unique owned postmaster named by this data directory.
        pm=$(find_owned_postmaster)
        pidfile_pid=""
        [[ -f $PGDATA_DIR/postmaster.pid ]] && pidfile_pid=$(head -1 "$PGDATA_DIR/postmaster.pid")
        if [[ -n $pm && $pm != *$'\n'* && $pm == "$pidfile_pid" ]]; then
            QA_PM_PID=$pm
        else
            qa_record INFRA "$name.server" "postmaster is no longer running; remaining tests skipped"
            break
        fi
    fi
done

exit $EXIT_OK # finalize() derives the verdict from the results
