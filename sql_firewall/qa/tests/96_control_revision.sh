#!/usr/bin/env bash
# Phase 3D revisions: control records follow installation lifecycle across
# savepoints, cancelled waits, and database removal; a fatal exit clears its
# acknowledgement; checkpoint stalls report retrying; the registry's capacity
# is accounted exactly.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.control_revision
EV=control_revision
KEEP=qa_ctl_keep
CHURN=qa_ctl_churn
FATAL=qa_ctl_fatal
STALL=qa_ctl_stall
SP=qa_ctl_sp
OBL=qa_ctl_obl
OBL2=qa_ctl_obl2
TMPL=qa_ctl_tmpl
DBC=qa_ctl_dbc
EVT=qa_ctl_evt

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Control records are released when the transaction that removed or created their installation resolves, including savepoints and cancelled waits, and when their database is dropped. A fatal worker exit clears that incarnation's acknowledgement. Checkpoint stalls are reported as retrying. 128 valid owners fill the registry exactly." ""

qa_create_db "$KEEP" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$CHURN" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$FATAL" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$STALL" sql_firewall.mode=learn sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$SP" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE DATABASE $OBL" \
    "CREATE DATABASE $OBL2" \
    "CREATE ROLE qa_ctl_keep LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_ctl_churn LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_ctl_fatal LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_ctl_stall LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_ctl_learn LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_ctl_sp_app LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $KEEP TO qa_ctl_keep" \
    "GRANT CONNECT ON DATABASE $CHURN TO qa_ctl_churn" \
    "GRANT CONNECT ON DATABASE $FATAL TO qa_ctl_fatal" \
    "GRANT CONNECT ON DATABASE $STALL TO qa_ctl_stall, qa_ctl_learn" \
    "GRANT CONNECT ON DATABASE $SP TO qa_ctl_sp_app" \
    "ALTER ROLE qa_ctl_keep IN DATABASE $KEEP SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_ctl_churn IN DATABASE $CHURN SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_ctl_fatal IN DATABASE $FATAL SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_ctl_stall IN DATABASE $STALL SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_ctl_learn IN DATABASE $STALL SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE qa_ctl_sp_app IN DATABASE $SP SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

launcher_pid() {
    qa_admin postgres \
        "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE backend_type OPERATOR(pg_catalog.=) 'sql_firewall_launcher'" ||
        return $?
    QA_LAUNCHER=${QA_STEP_OUT[1]}
}

worker_pid() {
    qa_admin "$1" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_WORKER_PID=${QA_STEP_OUT[1]}
}

# Every consumer process in the cluster, as "pid:database".
all_workers() {
    qa_admin postgres \
        "SELECT coalesce(string_agg(a.pid::text || ':' || a.datid::text, ',' ORDER BY a.pid), '') FROM pg_catalog.pg_stat_activity a WHERE a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_ALL_WORKERS=${QA_STEP_OUT[1]}
}

# run_script DB FILE: one psql session; FILE.out and FILE.err hold the output.
run_script() {
    env PGAPPNAME=qa_ctl_script PGCONNECT_TIMEOUT=10 timeout 900 \
        "$QA_PSQL" -X -A -t -v ON_ERROR_STOP=0 -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" \
        -d "$1" -f "$2" >"$2.out" 2>"$2.err"
}

# cap_script FILE PREFIX FIRST LAST: create each database from the template,
# then issue a pause with an 80ms statement timeout. With no consumer the
# timeout cancels the wait after the request is stored.
cap_script() {
    local file=$1 prefix=$2 first=$3 last=$4 i
    for ((i = first; i <= last; i++)); do
        printf 'CREATE DATABASE %s_%d TEMPLATE %s;\n' "$prefix" "$i" "$TMPL"
        printf '\\c %s_%d\n' "$prefix" "$i"
        printf "SET statement_timeout = '80ms';\n"
        printf '\\echo @@CAP %d\n' "$i"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf '\\echo @@RES %d :ERROR :SQLSTATE\n' "$i"
        printf '\\c postgres\n'
    done >"$file"
}

# parse_caps FILE.out: a stored request is a cancelled wait (57014) or a
# pause result; Full is the product's registry-full result.
parse_caps() {
    local line cur=0 text= sawfull=0
    CAP_STORED=0 CAP_FULL=0 CAP_OTHER=0 CAP_SEEN=0 CAP_ORDER=ok CAP_DETAIL= CAP_LAST_STORED=0
    while IFS= read -r line; do
        if [[ $line =~ ^@@CAP\ ([0-9]+)$ ]]; then
            cur=${BASH_REMATCH[1]}
            text=
        elif [[ $line =~ ^@@RES\ ([0-9]+)\ (true|false)\ ([0-9A-Z]{5})$ ]]; then
            CAP_SEEN=$((CAP_SEEN + 1))
            if [[ ${BASH_REMATCH[2]} == true && ${BASH_REMATCH[3]} == 57014 ]] ||
                [[ $text == pause\ pending\ epoch=* || $text == approval\ worker\ paused\ epoch=* ]]; then
                CAP_STORED=$((CAP_STORED + 1))
                CAP_LAST_STORED=${BASH_REMATCH[1]}
                [[ $sawfull -eq 1 ]] && CAP_ORDER=bad
            elif [[ ${BASH_REMATCH[2]} == false && $text == "control registry is full" ]]; then
                CAP_FULL=$((CAP_FULL + 1))
                sawfull=1
            else
                CAP_OTHER=$((CAP_OTHER + 1))
                CAP_DETAIL+="[${BASH_REMATCH[1]} ${BASH_REMATCH[3]} '$text']"
            fi
            cur=0
        elif ((cur > 0)); then
            text+=$line
        fi
    done <"$1"
}

# expect_timeouts FILE N: exactly N pause waits were cancelled (57014), and
# the session reported no other error.
expect_timeouts() {
    local got errors
    got=$(grep -c '^@@R [0-9]* true 57014$' "$1.out")
    errors=$(grep -cE '^psql:.*:[0-9]+: ERROR:' "$1.err")
    EXPECT_DETAIL="cancelled=$got errors=$errors (expected $2)"
    [[ $got -eq $2 && $errors -eq $2 ]]
}

extension_count() {
    qa_admin "$1" "SELECT count(*)::text FROM pg_catalog.pg_extension WHERE extname OPERATOR(pg_catalog.=) 'sql_firewall'" ||
        return $?
    QA_EXT_COUNT=${QA_STEP_OUT[1]}
}

# Template with the extension installed. Created while the launcher is
# stopped and then closed to connections, so no consumer ever attaches to it.
launcher_pid || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
kill -STOP "$QA_LAUNCHER" || { infra "$ID" "could not stop the launcher"; exit 0; }
qa_admin postgres "CREATE DATABASE $TMPL" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$TMPL" "CREATE EXTENSION sql_firewall" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "ALTER DATABASE $TMPL IS_TEMPLATE true" "ALTER DATABASE $TMPL ALLOW_CONNECTIONS false" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID" "$QA_INFRA_REASON"; exit 0; }
kill -CONT "$QA_LAUNCHER" || { infra "$ID" "could not continue the launcher"; exit 0; }

# 0. A DROP rolled back by a savepoint, a nested savepoint, an outer
# rollback, or a PL/pgSQL exception block keeps the installation's
# acknowledged pause on the same live consumer.
if ! qa_wait_worker_live "$SP" 60; then
    fail "$ID.savepoint.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$SP" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=*\ incarnation=* ]]; then
    fail "$ID.savepoint.pause" "pause returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
sp_paused=${QA_STEP_OUT[1]#approval worker }
sp_inc=${sp_paused##*incarnation=}
sp_ext() {
    qa_admin "$SP" "SELECT coalesce((SELECT e.oid::text FROM pg_catalog.pg_extension e WHERE e.extname OPERATOR(pg_catalog.=) 'sql_firewall'), '')" ||
        return $?
    SP_EXT=${QA_STEP_OUT[1]}
}
sp_ext || { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
sp_ext_before=$SP_EXT
worker_pid "$SP" || { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
sp_pid=$QA_WORKER_PID
if [[ -z $sp_pid || $sp_pid == *,* ]]; then
    infra "$ID.savepoint" "expected one consumer, found '$sp_pid'"
    exit 0
fi
SP_TRANSCRIPT="before: extension=$sp_ext_before pid=$sp_pid status='$sp_paused'"
sp_check() {
    local label=$1 status again
    shift
    qa_admin "$SP" "$@" || { infra "$ID.savepoint.$label" "$QA_INFRA_REASON"; exit 0; }
    sp_ext || { infra "$ID.savepoint.$label" "$QA_INFRA_REASON"; exit 0; }
    worker_pid "$SP" || { infra "$ID.savepoint.$label" "$QA_INFRA_REASON"; exit 0; }
    qa_admin "$SP" "SELECT public.sql_firewall_approval_worker_status()" ||
        { infra "$ID.savepoint.$label" "$QA_INFRA_REASON"; exit 0; }
    status=${QA_STEP_OUT[1]}
    qa_admin "$SP" "SELECT public.sql_firewall_pause_approval_worker()" ||
        { infra "$ID.savepoint.$label" "$QA_INFRA_REASON"; exit 0; }
    again=${QA_STEP_OUT[1]}
    SP_TRANSCRIPT+="; $label: extension=$SP_EXT pid=$QA_WORKER_PID status='$status' pause='$again'"
    if [[ $SP_EXT != "$sp_ext_before" || $QA_WORKER_PID != "$sp_pid" || $status != "$sp_paused" ||
        $again != "approval worker $sp_paused" ]]; then
        fail "$ID.savepoint.$label" "extension $SP_EXT (was $sp_ext_before), pid $QA_WORKER_PID (was $sp_pid), status '$status', pause '$again'; expected '$sp_paused'"
        exit 0
    fi
}
sp_check exact "BEGIN" "SAVEPOINT review_sp" "DROP EXTENSION sql_firewall" \
    "ROLLBACK TO SAVEPOINT review_sp" "COMMIT"
sp_check nested "BEGIN" "SAVEPOINT a" "SAVEPOINT b" "DROP EXTENSION sql_firewall" \
    "RELEASE SAVEPOINT b" "ROLLBACK TO SAVEPOINT a" "COMMIT"
sp_check deep "BEGIN" "SAVEPOINT a" "SAVEPOINT b" "SAVEPOINT c" "DROP EXTENSION sql_firewall" \
    "RELEASE SAVEPOINT c" "RELEASE SAVEPOINT b" "ROLLBACK TO SAVEPOINT a" "COMMIT"
sp_check outer_abort "BEGIN" "SAVEPOINT a" "DROP EXTENSION sql_firewall" \
    "RELEASE SAVEPOINT a" "ROLLBACK"
sp_check plpgsql \
    "DO \$\$ BEGIN DROP EXTENSION sql_firewall; RAISE EXCEPTION 'qa_ctl_undo'; EXCEPTION WHEN raise_exception THEN NULL; END \$\$"
qa_evidence "$EV" "" "- savepoint transcript: $SP_TRANSCRIPT"
qa_admin "$SP" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ running\ epoch=*\ incarnation=${sp_inc} ]]; then
    fail "$ID.savepoint.resume" "resume returned '${QA_STEP_OUT[1]}', expected incarnation $sp_inc"
    exit 0
fi
sp_resumed=${QA_STEP_OUT[1]}
qa_sql_steps qa_ctl_sp_app "$SP" qa_ctl "SELECT 'qa_ctl_sp_event'" || true
if ! qa_poll "$SP" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_sp_event') > 0" \
    1 20; then
    fail "$ID.savepoint.event" "qa_ctl_sp_event was not delivered after resume (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.savepoint" "five rolled-back DROP variants kept extension $sp_ext_before, consumer $sp_pid and '$sp_paused'; '$sp_resumed' then delivered qa_ctl_sp_event"

# A DROP released from its savepoint and committed removes the record; the
# next installation does not inherit the pause.
qa_admin "$SP" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* ]]; then
    fail "$ID.savepoint.repause" "pause returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$SP" "BEGIN" "SAVEPOINT a" "DROP EXTENSION sql_firewall" "RELEASE SAVEPOINT a" "COMMIT" ||
    { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 20))
while ((SECONDS < deadline)); do
    worker_pid "$SP" || { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
    [[ -z $QA_WORKER_PID ]] && break
    sleep 0.2
done
if [[ -n $QA_WORKER_PID ]]; then
    fail "$ID.savepoint.drop" "consumer $QA_WORKER_PID did not exit after the committed DROP"
    exit 0
fi
qa_admin "$SP" "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
sp_ext || { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$SP" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.savepoint" "$QA_INFRA_REASON"; exit 0; }
if [[ $SP_EXT == "$sp_ext_before" || ${QA_STEP_OUT[1]} == paused* || ${QA_STEP_OUT[1]} == pause\ pending* ]]; then
    fail "$ID.savepoint.recreate" "extension $SP_EXT (was $sp_ext_before) reported '${QA_STEP_OUT[1]}'"
    exit 0
fi
sp_new_status=${QA_STEP_OUT[1]}
if ! qa_wait_worker_live "$SP" 60; then
    fail "$ID.savepoint.recreate_ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_sql_steps qa_ctl_sp_app "$SP" qa_ctl "SELECT 'qa_ctl_sp_after'" || true
if ! qa_poll "$SP" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_sp_after') > 0" \
    1 20; then
    fail "$ID.savepoint.after" "qa_ctl_sp_after was not delivered (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.savepoint.commit" "a committed DROP released from its savepoint stopped the paused consumer; extension $SP_EXT started as '$sp_new_status' and delivered qa_ctl_sp_after"

# 1. Abandoned pause records are reclaimed after DROP, without a consumer.
# Consumers the launcher already started for these databases are stopped,
# and the stopped launcher cannot start new ones.
launcher_pid || { infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
kill -STOP "$QA_LAUNCHER" || { infra "$ID.reclaim" "could not stop the launcher"; exit 0; }
sleep 2
deadline=$((SECONDS + 20))
absent=0
while ((SECONDS < deadline)); do
    absent=1
    for db in "$KEEP" "$CHURN"; do
        worker_pid "$db" || { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
        if [[ -n $QA_WORKER_PID ]]; then
            absent=0
            qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(p::pg_catalog.int4) FROM pg_catalog.unnest(pg_catalog.string_to_array('$QA_WORKER_PID', ',')) AS p" || true
        fi
    done
    [[ $absent -eq 1 ]] && break
    sleep 0.2
done
if [[ $absent -ne 1 ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    infra "$ID.reclaim" "consumers for $KEEP or $CHURN did not exit"
    exit 0
fi
qa_admin "$KEEP" "SET statement_timeout = '80ms'" "SELECT public.sql_firewall_pause_approval_worker()" || true
qa_admin "$KEEP" "SELECT public.sql_firewall_approval_worker_status()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != pause\ pending\ epoch=* ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.reclaim.keep" "kept installation status '${QA_STEP_OUT[1]}'"
    exit 0
fi
keep_status=${QA_STEP_OUT[1]}
{
    for i in $(seq 1 130); do
        printf 'DROP EXTENSION IF EXISTS sql_firewall;\n'
        printf 'CREATE EXTENSION sql_firewall;\n'
        printf "SET statement_timeout = '80ms';\n"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf 'RESET statement_timeout;\n'
    done
    printf 'DROP EXTENSION sql_firewall;\n'
} >"$QA_RUN_DIR/churn.sql"
env PGAPPNAME=qa_churn "$QA_PSQL" -X -q -v ON_ERROR_STOP=0 -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$CHURN" \
    -f "$QA_RUN_DIR/churn.sql" >"$QA_RUN_DIR/churn.out" 2>"$QA_RUN_DIR/churn.err" || true
if grep -F "control registry is full" "$QA_RUN_DIR/churn.out" "$QA_RUN_DIR/churn.err" >/dev/null; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.reclaim.full" "dropped installations exhausted the control registry"
    exit 0
fi
qa_admin "$CHURN" "DROP EXTENSION IF EXISTS sql_firewall" "CREATE EXTENSION sql_firewall" \
    "SELECT public.sql_firewall_approval_worker_status()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[3]} == *full* ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.reclaim.fresh" "fresh installation saw '${QA_STEP_OUT[3]}'"
    exit 0
fi
qa_admin "$KEEP" "SELECT public.sql_firewall_approval_worker_status()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != "$keep_status" ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.reclaim.preserve" "cleanup changed the kept pause from '$keep_status' to '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$KEEP" "BEGIN; DROP EXTENSION sql_firewall; ROLLBACK" \
    "SELECT public.sql_firewall_approval_worker_status()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[2]} != "$keep_status" ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.reclaim.rollback_drop" "rolled-back DROP changed status to '${QA_STEP_OUT[2]}'"
    exit 0
fi
qa_admin "$CHURN" "BEGIN; DROP EXTENSION sql_firewall; CREATE EXTENSION sql_firewall; SELECT public.sql_firewall_pause_approval_worker(); ROLLBACK" || true
qa_admin "$CHURN" "DROP EXTENSION IF EXISTS sql_firewall" "CREATE EXTENSION sql_firewall" \
    "SELECT public.sql_firewall_resume_approval_worker()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[3]} == *full* ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.reclaim.rollback_create" "rolled-back CREATE left the registry full: '${QA_STEP_OUT[3]}'"
    exit 0
fi
kill -CONT "$QA_LAUNCHER" || { infra "$ID.reclaim" "could not continue the launcher"; exit 0; }
qa_admin postgres \
    "CREATE ROLE qa_ctl_churn_app LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $CHURN TO qa_ctl_churn_app" \
    "ALTER ROLE qa_ctl_churn_app IN DATABASE $CHURN SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.reclaim" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_ctl_churn_app "$CHURN" qa_ctl "SELECT 'qa_ctl_after_churn'" || true
if ! qa_poll "$CHURN" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_after_churn') > 0" \
    1 40; then
    fail "$ID.reclaim.event" "fresh installation did not process qa_ctl_after_churn (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.reclaim" "130 dropped pause records were reclaimed; $keep_status survived; qa_ctl_after_churn persisted"

# 2. FATAL exit clears the old acknowledgement. A later pause is honored.
if ! qa_wait_worker_live "$FATAL" 40; then
    fail "$ID.fatal.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$FATAL" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
running=${QA_STEP_OUT[1]}
[[ $running == approval\ worker\ running\ epoch=*\ incarnation=* ]] ||
    { fail "$ID.fatal.ack" "resume returned '$running'"; exit 0; }
old_inc=${running##*incarnation=}
pg_config=$(dirname "$QA_PSQL")/pg_config
inc_server=$("$pg_config" --includedir-server)
inc_top=$("$pg_config" --includedir)
cat >"$QA_RUN_DIR/fatal.c" <<'EOF'
#include "postgres.h"
#include "fmgr.h"
PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(qa_ctl_fatal);
Datum qa_ctl_fatal(PG_FUNCTION_ARGS) {
    ereport(FATAL, (errmsg("qa_ctl controlled fatal worker exit")));
    PG_RETURN_VOID();
}
EOF
cc -shared -fPIC -I"$inc_server" -I"$inc_top" -o "$QA_RUN_DIR/fatal.so" "$QA_RUN_DIR/fatal.c" ||
    { infra "$ID.fatal" "could not build the fatal helper"; exit 0; }
launcher_pid || { infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
kill -STOP "$QA_LAUNCHER" || { infra "$ID.fatal" "could not stop the launcher"; exit 0; }
qa_admin "$FATAL" \
    "CREATE FUNCTION public.qa_ctl_fatal() RETURNS void AS '$QA_RUN_DIR/fatal.so', 'qa_ctl_fatal' LANGUAGE C" \
    "CREATE FUNCTION public.qa_ctl_fatal_trg() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF strpos(NEW.query_text, 'qa_ctl_fatal_event') > 0 THEN PERFORM public.qa_ctl_fatal(); END IF; RETURN NEW; END \$\$" \
    "CREATE TRIGGER qa_ctl_fatal BEFORE INSERT ON public.sql_firewall_blocked_queries FOR EACH ROW EXECUTE FUNCTION public.qa_ctl_fatal_trg()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE qa_ctl_fatal_app LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $FATAL TO qa_ctl_fatal_app" \
    "ALTER ROLE qa_ctl_fatal_app IN DATABASE $FATAL SET sql_firewall.mode = 'enforce'" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_ctl_fatal_app "$FATAL" qa_ctl "SELECT 'qa_ctl_fatal_event'" || true
deadline=$((SECONDS + 15))
gone=0
while ((SECONDS < deadline)); do
    worker_pid "$FATAL" || { infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
    [[ -z $QA_WORKER_PID ]] && gone=1 && break
    sleep 0.2
done
if [[ $gone -ne 1 ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.fatal.exit" "worker did not leave pg_stat_activity"
    exit 0
fi
qa_admin "$FATAL" "SELECT public.sql_firewall_approval_worker_status()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
dead_status=${QA_STEP_OUT[1]}
if [[ $dead_status == *incarnation=${old_inc} || $dead_status == running\ * ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.fatal.status" "dead worker still reported '$dead_status'"
    exit 0
fi
qa_admin "$FATAL" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} == approval\ worker\ running\ *incarnation=${old_inc} ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.fatal.resume" "resume accepted the dead incarnation: '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$FATAL" "SET statement_timeout = '80ms'" "SELECT public.sql_firewall_pause_approval_worker()" || true
qa_admin "$FATAL" "SELECT public.sql_firewall_approval_worker_status()" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != pause\ pending\ epoch=* ]]; then
    kill -CONT "$QA_LAUNCHER" 2>/dev/null || true
    fail "$ID.fatal.pending" "pause while dead returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$FATAL" "DROP TRIGGER qa_ctl_fatal ON public.sql_firewall_blocked_queries" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
kill -CONT "$QA_LAUNCHER" || { infra "$ID.fatal" "could not continue the launcher"; exit 0; }
deadline=$((SECONDS + 90))
paused_ok=0
while ((SECONDS < deadline)); do
    qa_admin "$FATAL" "SELECT public.sql_firewall_approval_worker_status()" ||
        { infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
    if [[ ${QA_STEP_OUT[1]} == paused\ epoch=*\ incarnation=* && ${QA_STEP_OUT[1]} != *incarnation=${old_inc} ]]; then
        paused_ok=1
        break
    fi
    sleep 0.2
done
if [[ $paused_ok -ne 1 ]]; then
    fail "$ID.fatal.replace" "replacement did not honor the pending pause (last '${QA_STEP_OUT[1]:-}')"
    exit 0
fi
qa_sql_steps qa_ctl_fatal_app "$FATAL" qa_ctl "SELECT 'qa_ctl_fatal_later'" || true
qa_admin "$FATAL" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_fatal_later') > 0" ||
    { infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.fatal.held" "replacement applied qa_ctl_fatal_later while paused"
    exit 0
fi
qa_admin "$FATAL" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.fatal" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$FATAL" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_fatal_later') > 0" \
    1 30; then
    fail "$ID.fatal.recover" "retained event was not recovered after resume (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.fatal" "incarnation $old_inc was not reported running after FATAL; the replacement stayed paused and then recovered qa_ctl_fatal_later"

# 3. Checkpoint stalls are visible, and repair resumes the same consumer.
if ! qa_wait_worker_live "$STALL" 40; then
    fail "$ID.stall.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin postgres \
    "CREATE ROLE qa_ctl_stall_app LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $STALL TO qa_ctl_stall_app" \
    "ALTER ROLE qa_ctl_stall_app IN DATABASE $STALL SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_ctl_learn "$STALL" qa_ctl "SELECT 'qa_ctl_fp_token'" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$STALL" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_ctl_learn'::name AND strpos(sample_query, 'qa_ctl_fp_token') > 0" \
    1 20; then
    fail "$ID.stall.fp" "fingerprint was not stored (${QA_INFRA_REASON:-})"
    exit 0
fi
worker_pid "$STALL" || { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
live_pid=$QA_WORKER_PID
qa_admin "$STALL" "SELECT coalesce(next_position::text, '') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
saved_next=${QA_STEP_OUT[1]}
qa_admin "$STALL" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = 10000000000000000000 WHERE singleton = 1" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_ctl_stall_app "$STALL" qa_ctl "SELECT 'qa_ctl_stalled'" || true
deadline=$((SECONDS + 20))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "not acknowledging" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.stall.live" "live consumer did not report the ahead checkpoint"; exit 0; }
qa_admin "$STALL" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != retrying\ epoch=* ]]; then
    fail "$ID.stall.status" "status during the stall was '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$STALL" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_stalled') > 0" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.stall.row" "stalled event was applied"
    exit 0
fi
qa_admin "$STALL" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != resume\ acknowledged\ epoch=* ]]; then
    fail "$ID.stall.resume" "resume during the stall returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$STALL" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* ]]; then
    fail "$ID.stall.pause" "pause during the stall returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$STALL" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_stalled') > 0" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.stall.paused" "paused stall applied the event"
    exit 0
fi
qa_admin "$STALL" "SELECT public.sql_firewall_resume_approval_worker()" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = ${saved_next} WHERE singleton = 1" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$STALL" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_stalled') > 0" \
    1 20; then
    fail "$ID.stall.repair" "event was not processed after metadata repair (${QA_INFRA_REASON:-})"
    exit 0
fi
worker_pid "$STALL" || { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_WORKER_PID != "$live_pid" ]]; then
    fail "$ID.stall.pid" "repair used pid $QA_WORKER_PID instead of $live_pid"
    exit 0
fi
qa_admin "$STALL" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_ctl_learn'::name AND strpos(sample_query, 'qa_ctl_fp_token') > 0" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.stall.fpcount" "hit_count is ${QA_STEP_OUT[1]}"
    exit 0
fi
qa_admin "$STALL" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != running\ epoch=* ]]; then
    fail "$ID.stall.recovered" "status after repair was '${QA_STEP_OUT[1]}'"
    exit 0
fi
ok "$ID.stall.live" "pid $live_pid reported retrying while the checkpoint was ahead, then processed qa_ctl_stalled once after repair"
qa_admin "$STALL" "SELECT coalesce(next_position::text, '') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
saved_next=${QA_STEP_OUT[1]}

# Startup stall: replacement sees invalid/ahead metadata before processing.
launcher_pid || { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
kill -STOP "$QA_LAUNCHER" || { infra "$ID.stall" "could not stop the launcher"; exit 0; }
worker_pid "$STALL" || { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${QA_WORKER_PID})" || true
qa_admin "$STALL" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = 10000000000000000000 WHERE singleton = 1" ||
    { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
kill -CONT "$QA_LAUNCHER" || { infra "$ID.stall" "could not continue the launcher"; exit 0; }
deadline=$((SECONDS + 40))
startup_retry=0
while ((SECONDS < deadline)); do
    qa_admin "$STALL" "SELECT public.sql_firewall_approval_worker_status()" ||
        { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
    if [[ ${QA_STEP_OUT[1]} == retrying\ epoch=* ]]; then
        startup_retry=1
        break
    fi
    sleep 0.2
done
if [[ $startup_retry -ne 1 ]]; then
    fail "$ID.stall.startup" "replacement status was '${QA_STEP_OUT[1]:-}' instead of retrying"
    exit 0
fi
qa_sql_steps qa_ctl_stall_app "$STALL" qa_ctl "SELECT 'qa_ctl_startup_stall'" || true
qa_admin "$STALL" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_startup_stall') > 0" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.stall.startup_row" "startup stall applied the event"
    exit 0
fi
qa_admin "$STALL" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = ${saved_next} WHERE singleton = 1" ||
    { infra "$ID.stall" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$STALL" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_startup_stall') > 0" \
    1 20; then
    fail "$ID.stall.startup_repair" "startup stall did not recover after repair (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.stall.startup" "a replacement reported retrying for an ahead checkpoint and then processed qa_ctl_startup_stall once"


# 4. Databases holding stored pause requests are dropped without any
# consumer releasing them. The launcher keeps running, because DROP DATABASE
# waits for every process, including the launcher, to absorb a barrier.
mark=$(qa_server_log_offset)
{
    for i in $(seq 1 130); do
        printf 'CREATE DATABASE %s TEMPLATE %s;\n' "$DBC" "$TMPL"
        printf '\\c %s\n' "$DBC"
        printf "SET statement_timeout = '80ms';\n"
        printf '\\echo @@CAP %d\n' "$i"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf '\\echo @@RES %d :ERROR :SQLSTATE\n' "$i"
        printf '\\c postgres\n'
        printf 'DROP DATABASE %s WITH (FORCE);\n' "$DBC"
        printf '\\echo @@DROP %d :ERROR :SQLSTATE\n' "$i"
    done
} >"$QA_RUN_DIR/dbchurn.sql"
run_script postgres "$QA_RUN_DIR/dbchurn.sql" || true
parse_caps "$QA_RUN_DIR/dbchurn.sql.out"
drops_ok=$(grep -c '^@@DROP [0-9]* false 00000$' "$QA_RUN_DIR/dbchurn.sql.out")
if [[ $CAP_SEEN -ne 130 || $drops_ok -ne 130 || $CAP_OTHER -ne 0 ]]; then
    infra "$ID.dbchurn" "churn did not complete: requests=$CAP_SEEN drops=$drops_ok other=$CAP_OTHER $CAP_DETAIL"
    exit 0
fi
if [[ $CAP_FULL -ne 0 || $CAP_STORED -ne 130 ]]; then
    fail "$ID.dbchurn.full" "dropped databases exhausted the registry: stored=$CAP_STORED full=$CAP_FULL"
    exit 0
fi
launcher_released=$(tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -c "released control record for removed database oid")
FRESH=${DBC}_fresh
qa_admin postgres \
    "CREATE DATABASE $FRESH TEMPLATE $TMPL" \
    "ALTER DATABASE $FRESH SET sql_firewall.mode = 'enforce'" \
    "GRANT CONNECT ON DATABASE $FRESH TO $QA_CANARY_ROLE" \
    "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $FRESH SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.dbchurn" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$FRESH" 60; then
    fail "$ID.dbchurn.fresh" "no consumer delivered an event in a fresh database: $QA_INFRA_REASON"
    exit 0
fi
fresh_token=$QA_CANARY_TOKEN
qa_admin "$FRESH" "SELECT public.sql_firewall_pause_approval_worker()" \
    "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.dbchurn" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* || ${QA_STEP_OUT[2]} != approval\ worker\ running\ epoch=* ]]; then
    fail "$ID.dbchurn.control" "fresh installation returned '${QA_STEP_OUT[1]}' then '${QA_STEP_OUT[2]}'"
    exit 0
fi
ok "$ID.dbchurn" "130 databases each held a stored pause and were dropped with no Full result; the launcher released $launcher_released of them itself; a fresh consumer delivered $fresh_token and answered '${QA_STEP_OUT[1]}' then '${QA_STEP_OUT[2]}'"

# 4b. An event trigger on CREATE EXTENSION runs before ProcessUtility
# returns. A pause it stores is still owned by the creating subtransaction.
qa_admin "$KEEP" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
keep_evt=${QA_STEP_OUT[1]}
[[ $keep_evt == paused\ epoch=* || $keep_evt == pause\ pending\ epoch=* ]] ||
    { fail "$ID.event.keep" "$KEEP status '$keep_evt' is not a stored pause"; exit 0; }
qa_admin postgres \
    "CREATE DATABASE $EVT" \
    "CREATE ROLE qa_ctl_evt_app LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $EVT TO qa_ctl_evt_app" \
    "ALTER ROLE qa_ctl_evt_app IN DATABASE $EVT SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$EVT" \
    "CREATE FUNCTION public.qa_ctl_evt_pause() RETURNS event_trigger LANGUAGE plpgsql AS \$fn\$ DECLARE result text; BEGIN IF TG_TAG = 'CREATE EXTENSION' THEN result := public.sql_firewall_pause_approval_worker(); RAISE NOTICE 'qa_ctl pause result: %', result; RAISE EXCEPTION 'qa_ctl abort after pause'; END IF; END \$fn\$" \
    "CREATE EVENT TRIGGER qa_ctl_evt_create ON ddl_command_end WHEN TAG IN ('CREATE EXTENSION') EXECUTE FUNCTION public.qa_ctl_evt_pause()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
{
    # The timer starts with the statement. The install script finishes first
    # (well under 2s, also on a cassert build under load); 2s still expires
    # during the pause wait (5s), after the request is stored.
    printf "SET statement_timeout = '2s';\n"
    for i in $(seq 1 130); do
        printf '\\echo @@EVT %d\n' "$i"
        printf 'CREATE EXTENSION sql_firewall;\n'
        printf '\\echo @@EVR %d :ERROR :SQLSTATE\n' "$i"
    done
    printf 'RESET statement_timeout;\n'
} >"$QA_RUN_DIR/event_timeout.sql"
run_script "$EVT" "$QA_RUN_DIR/event_timeout.sql" || true
evt_timeouts=$(grep -c '^@@EVR [0-9]* true 57014$' "$QA_RUN_DIR/event_timeout.sql.out")
evt_during=$(grep -c 'function qa_ctl_evt_pause()' "$QA_RUN_DIR/event_timeout.sql.err")
evt_seen=$(grep -c '^@@EVR ' "$QA_RUN_DIR/event_timeout.sql.out")
if [[ $evt_seen -ne 130 || $evt_timeouts -ne 130 || $evt_during -lt 120 ]]; then
    infra "$ID.event" "timeout run: completed $evt_seen, cancelled $evt_timeouts, during the trigger $evt_during"
    exit 0
fi
if grep -F "control registry is full" "$QA_RUN_DIR/event_timeout.sql.out" "$QA_RUN_DIR/event_timeout.sql.err" >/dev/null; then
    fail "$ID.event.full" "cancelled CREATE EXTENSION exhausted the control registry"
    exit 0
fi
extension_count "$EVT" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_EXT_COUNT != 0 ]]; then
    fail "$ID.event.installed" "timed-out CREATE left $QA_EXT_COUNT installations"
    exit 0
fi

# The pause call returns, having stored the request, and the trigger then
# errors. No statement timeout: the wait ends on its own.
qa_admin "$EVT" \
    "CREATE OR REPLACE FUNCTION public.qa_ctl_evt_pause() RETURNS event_trigger LANGUAGE plpgsql AS \$fn\$ DECLARE result text; BEGIN IF TG_TAG = 'CREATE EXTENSION' THEN result := public.sql_firewall_pause_approval_worker(); RAISE EXCEPTION 'qa_ctl abort after pause: %', result; END IF; END \$fn\$" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps "$QA_SUPERUSER" "$EVT" qa_ctl_evt "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_ERR[1]} != true || ${QA_STEP_MSG[1]} != *qa_ctl\ abort\ after\ pause:* || ${QA_STEP_MSG[1]} == *full* ]]; then
    fail "$ID.event.raise" "trigger error was '${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}'"
    exit 0
fi
extension_count "$EVT" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_EXT_COUNT == 0 ]] || { fail "$ID.event.raise_installed" "extension count $QA_EXT_COUNT"; exit 0; }

# The trigger catches the cancellation in an inner block, so CREATE finishes.
# The request stays with the installation: outer rollback releases it, commit keeps it.
qa_admin "$EVT" \
    "CREATE OR REPLACE FUNCTION public.qa_ctl_evt_pause() RETURNS event_trigger LANGUAGE plpgsql AS \$fn\$ BEGIN IF TG_TAG <> 'CREATE EXTENSION' THEN RETURN; END IF; BEGIN PERFORM public.sql_firewall_pause_approval_worker(); EXCEPTION WHEN query_canceled THEN PERFORM pg_catalog.set_config('statement_timeout', '0', true); END; END \$fn\$" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
# 3s: the install script must finish before the timer expires; the timer then
# expires during the pause wait (5s), where the trigger catches it.
qa_admin "$EVT" "SET statement_timeout = '3s'" "BEGIN" "CREATE EXTENSION sql_firewall" \
    "SELECT public.sql_firewall_approval_worker_status()" "ROLLBACK" "RESET statement_timeout" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[4]} != pause\ pending\ epoch=* && ${QA_STEP_OUT[4]} != paused\ epoch=* ]]; then
    fail "$ID.event.catch" "status inside the creating transaction was '${QA_STEP_OUT[4]}'"
    exit 0
fi
evt_caught=${QA_STEP_OUT[4]}
extension_count "$EVT" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_EXT_COUNT == 0 ]] || { fail "$ID.event.rollback" "rolled-back CREATE left the extension"; exit 0; }
qa_admin "$EVT" "SET statement_timeout = '3s'" "BEGIN" "CREATE EXTENSION sql_firewall" \
    "SELECT public.sql_firewall_approval_worker_status()" "COMMIT" "RESET statement_timeout" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$EVT" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
evt_committed=${QA_STEP_OUT[1]}
if [[ $evt_committed != pause\ pending\ epoch=* && $evt_committed != paused\ epoch=* ]]; then
    fail "$ID.event.commit" "committed CREATE reported '$evt_committed'"
    exit 0
fi
qa_admin "$KEEP" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != "$keep_evt" ]]; then
    fail "$ID.event.keep_after" "$KEEP changed from '$keep_evt' to '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$EVT" "DROP EVENT TRIGGER qa_ctl_evt_create" "DROP EXTENSION sql_firewall" \
    "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 40))
evt_live=0
while ((SECONDS < deadline)); do
    worker_pid "$EVT" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $QA_WORKER_PID ]]; then
        evt_live=1
        break
    fi
    sleep 0.2
done
[[ $evt_live -eq 1 ]] || { fail "$ID.event.fresh_worker" "no consumer for the fresh installation"; exit 0; }
qa_admin "$EVT" "SELECT public.sql_firewall_pause_approval_worker()" \
    "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* || ${QA_STEP_OUT[2]} != approval\ worker\ running\ epoch=* ]]; then
    fail "$ID.event.fresh" "fresh installation returned '${QA_STEP_OUT[1]}' then '${QA_STEP_OUT[2]}'"
    exit 0
fi
evt_pause=${QA_STEP_OUT[1]}
evt_resume=${QA_STEP_OUT[2]}
qa_sql_steps qa_ctl_evt_app "$EVT" qa_ctl "SELECT 'qa_ctl_evt_event'" || true
if ! qa_poll "$EVT" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_ctl_evt_event') > 0" \
    1 20; then
    fail "$ID.event.deliver" "qa_ctl_evt_event was not delivered (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin postgres "DROP DATABASE $EVT WITH (FORCE)" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.event" "130 timed-out CREATE EXTENSION calls and a trigger error after a stored pause left no installation and no full registry; a caught cancellation stored '$evt_caught', outer rollback removed it, commit kept '$evt_committed'; $KEEP stayed '$keep_evt'; the fresh installation returned '$evt_pause' then '$evt_resume' and delivered qa_ctl_evt_event"

# 5. Exact capacity. The launcher is stopped so the set of consumers cannot
# change; DROP DATABASE is not used while it is stopped.
for db in "$CHURN" "$FATAL" "$STALL" "$SP" "$FRESH"; do
    qa_wait_worker_live "$db" 60 || { infra "$ID.capacity" "$db: $QA_INFRA_REASON"; exit 0; }
done
# KEEP's consumer honors the pause stored in section 1.
deadline=$((SECONDS + 60))
keep_before=
while ((SECONDS < deadline)); do
    qa_admin "$KEEP" "SELECT public.sql_firewall_approval_worker_status()" ||
        { infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
    if [[ ${QA_STEP_OUT[1]} == paused\ epoch=*\ incarnation=* ]]; then
        keep_before=${QA_STEP_OUT[1]}
        break
    fi
    sleep 0.5
done
[[ -n $keep_before ]] || { infra "$ID.capacity" "$KEEP never acknowledged its pause (last '${QA_STEP_OUT[1]}')"; exit 0; }
launcher_pid || { infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
kill -STOP "$QA_LAUNCHER" || { infra "$ID.capacity" "could not stop the launcher"; exit 0; }
cont() { kill -CONT "$QA_LAUNCHER" 2>/dev/null || true; }
sleep 3
all_workers || { cont; infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
workers_before=$QA_ALL_WORKERS

cap_script "$QA_RUN_DIR/fill.sql" qa_ctl_cap 1 140
run_script postgres "$QA_RUN_DIR/fill.sql" || true
parse_caps "$QA_RUN_DIR/fill.sql.out"
filled=$CAP_STORED
if [[ $CAP_SEEN -ne 140 || $CAP_OTHER -ne 0 || $CAP_ORDER != ok || $filled -lt 40 || $CAP_FULL -ne $((140 - filled)) ]]; then
    cont
    infra "$ID.capacity" "fill: seen=$CAP_SEEN stored=$filled full=$CAP_FULL order=$CAP_ORDER other=$CAP_OTHER $CAP_DETAIL"
    exit 0
fi
{
    for i in $(seq 1 25); do
        printf '\\c qa_ctl_cap_%d\n' "$i"
        printf 'DROP EXTENSION sql_firewall;\n'
        printf '\\echo @@DROPX %d :ERROR :SQLSTATE\n' "$i"
    done
} >"$QA_RUN_DIR/free.sql"
run_script postgres "$QA_RUN_DIR/free.sql" || true
if [[ $(grep -c '^@@DROPX [0-9]* false 00000$' "$QA_RUN_DIR/free.sql.out") -ne 25 ]]; then
    cont
    infra "$ID.capacity" "could not drop the extension in 25 filled databases"
    exit 0
fi

# 5a. More than 16 obligations in one transaction, committed.
lifecycle_block() { # N: create, cancel a pause in a savepoint, drop
    local i
    for ((i = 1; i <= $1; i++)); do
        printf 'CREATE EXTENSION sql_firewall;\n'
        printf 'SAVEPOINT s;\n'
        printf "SET statement_timeout = '80ms';\n"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf '\\echo @@R %d :ERROR :SQLSTATE\n' "$i"
        printf 'ROLLBACK TO SAVEPOINT s;\n'
        printf 'RELEASE SAVEPOINT s;\n'
        printf 'DROP EXTENSION sql_firewall;\n'
    done
}
{ printf 'BEGIN;\n'; lifecycle_block 20; printf 'COMMIT;\n'; } >"$QA_RUN_DIR/many_commit.sql"
{ printf 'BEGIN;\n'; lifecycle_block 20; printf 'ROLLBACK;\n'; } >"$QA_RUN_DIR/many_abort.sql"
# 5c. Cancel the wait after CREATE in an uncommitted transaction.
{
    for i in $(seq 1 30); do
        printf 'BEGIN;\nCREATE EXTENSION sql_firewall;\n'
        printf "SET statement_timeout = '80ms';\n"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf '\\echo @@R %d :ERROR :SQLSTATE\n' "$i"
        printf 'ROLLBACK;\n'
    done
} >"$QA_RUN_DIR/cancel_create.sql"
# 5d. CREATE inside a savepoint that rolls back; the outer transaction commits.
{
    for i in $(seq 1 30); do
        printf 'BEGIN;\nSAVEPOINT a;\nCREATE EXTENSION sql_firewall;\nSAVEPOINT b;\n'
        printf "SET statement_timeout = '80ms';\n"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf '\\echo @@R %d :ERROR :SQLSTATE\n' "$i"
        printf 'ROLLBACK TO SAVEPOINT b;\nROLLBACK TO SAVEPOINT a;\nCOMMIT;\n'
    done
} >"$QA_RUN_DIR/sub_create.sql"
# 5e. CREATE and DROP each committed from nested savepoints.
{
    for i in $(seq 1 5); do
        printf 'BEGIN;\nSAVEPOINT a;\nCREATE EXTENSION sql_firewall;\nSAVEPOINT b;\n'
        printf "SET statement_timeout = '80ms';\n"
        printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
        printf '\\echo @@R %d :ERROR :SQLSTATE\n' "$i"
        printf 'ROLLBACK TO SAVEPOINT b;\nRELEASE SAVEPOINT a;\n'
        printf 'SAVEPOINT c;\nDROP EXTENSION sql_firewall;\nRELEASE SAVEPOINT c;\nCOMMIT;\n'
    done
} >"$QA_RUN_DIR/sub_commit.sql"
# 5f. CREATE committed from a savepoint, DROP rolled back: a valid owner.
{
    printf 'BEGIN;\nSAVEPOINT a;\nCREATE EXTENSION sql_firewall;\nRELEASE SAVEPOINT a;\nSAVEPOINT b;\n'
    printf "SET statement_timeout = '80ms';\n"
    printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
    printf '\\echo @@R 1 :ERROR :SQLSTATE\n'
    printf 'ROLLBACK TO SAVEPOINT b;\nSAVEPOINT d;\nDROP EXTENSION sql_firewall;\nROLLBACK TO SAVEPOINT d;\nCOMMIT;\n'
} >"$QA_RUN_DIR/keep_owner.sql"

lifecycle_case() { # LABEL DB FILE CANCELLED EXTENSIONS_AFTER
    run_script "$2" "$3" || { cont; infra "$ID.capacity.$1" "psql failed ($3)"; exit 0; }
    if ! expect_timeouts "$3" "$4"; then
        cont
        infra "$ID.capacity.$1" "$EXPECT_DETAIL; see $3.err"
        exit 0
    fi
    extension_count "$2" || { cont; infra "$ID.capacity.$1" "$QA_INFRA_REASON"; exit 0; }
    if [[ $QA_EXT_COUNT != "$5" ]]; then
        cont
        infra "$ID.capacity.$1" "extension count $QA_EXT_COUNT, expected $5"
        exit 0
    fi
    CASES+="$1: $EXPECT_DETAIL; "
}
CASES=
lifecycle_case many_commit "$OBL" "$QA_RUN_DIR/many_commit.sql" 20 0
lifecycle_case many_abort "$OBL" "$QA_RUN_DIR/many_abort.sql" 20 0
lifecycle_case cancel_create "$OBL" "$QA_RUN_DIR/cancel_create.sql" 30 0
lifecycle_case sub_create "$OBL" "$QA_RUN_DIR/sub_create.sql" 30 0
lifecycle_case sub_commit "$OBL" "$QA_RUN_DIR/sub_commit.sql" 5 0
lifecycle_case keep_owner "$OBL2" "$QA_RUN_DIR/keep_owner.sql" 1 1
qa_evidence "$EV" "" "- lifecycle cases: $CASES"
qa_admin "$OBL2" "SELECT public.sql_firewall_approval_worker_status()" ||
    { cont; infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != "pause pending epoch=1" ]]; then
    cont
    fail "$ID.capacity.keep_owner" "committed installation with a rolled-back DROP reported '${QA_STEP_OUT[1]}'"
    exit 0
fi
keep_owner_status=${QA_STEP_OUT[1]}
pending_dbs="qa_ctl_cap_26 qa_ctl_cap_${filled}"
for db in qa_ctl_cap_26 "qa_ctl_cap_${filled}"; do
    qa_admin "$db" "SELECT public.sql_firewall_approval_worker_status()" ||
        { cont; infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
    if [[ ${QA_STEP_OUT[1]} != "pause pending epoch=1" ]]; then
        cont
        fail "$ID.capacity.pending" "$db: a cancelled pause on a committed installation became '${QA_STEP_OUT[1]}'"
        exit 0
    fi
done
qa_admin "$KEEP" "SELECT public.sql_firewall_approval_worker_status()" ||
    { cont; infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != "$keep_before" ]]; then
    cont
    fail "$ID.capacity.keep" "cleanup changed $KEEP from '$keep_before' to '${QA_STEP_OUT[1]}'"
    exit 0
fi

# 25 records were freed and one valid owner was added: exactly 24 remain.
cap_script "$QA_RUN_DIR/refill.sql" qa_ctl_capx 1 30
run_script postgres "$QA_RUN_DIR/refill.sql" || true
parse_caps "$QA_RUN_DIR/refill.sql.out"
all_workers || { cont; infra "$ID.capacity" "$QA_INFRA_REASON"; exit 0; }
workers_after=$QA_ALL_WORKERS
cont
if [[ $CAP_SEEN -ne 30 || $CAP_OTHER -ne 0 ]]; then
    infra "$ID.capacity" "refill: seen=$CAP_SEEN other=$CAP_OTHER $CAP_DETAIL"
    exit 0
fi
if [[ $workers_after != "$workers_before" ]]; then
    infra "$ID.capacity" "the consumer set changed while the launcher was stopped ($workers_before -> $workers_after)"
    exit 0
fi
if [[ $CAP_STORED -ne 24 || $CAP_FULL -ne 6 || $CAP_ORDER != ok ]]; then
    fail "$ID.capacity.exact" "after freeing 25 records and adding one owner, refill stored $CAP_STORED (expected 24), full $CAP_FULL, order $CAP_ORDER"
    exit 0
fi
ok "$ID.capacity" "fill stored $filled then reported Full; 25 committed drops freed 25 records; ${CASES}left no record; $OBL2 kept '$keep_owner_status'; $pending_dbs kept 'pause pending epoch=1'; refill stored exactly 24, then 128 valid owners returned 'control registry is full'"

# Best effort: keep the retained cluster small.
{
    for i in $(seq 1 140); do printf 'DROP DATABASE IF EXISTS qa_ctl_cap_%d WITH (FORCE);\n' "$i"; done
    for i in $(seq 1 30); do printf 'DROP DATABASE IF EXISTS qa_ctl_capx_%d WITH (FORCE);\n' "$i"; done
} >"$QA_RUN_DIR/cleanup.sql"
run_script postgres "$QA_RUN_DIR/cleanup.sql" || true

exit 0
