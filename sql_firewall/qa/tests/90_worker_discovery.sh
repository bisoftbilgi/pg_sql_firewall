#!/usr/bin/env bash
# Phase 3A: fair worker discovery and OID routing.
#
# A scan may register at most a small batch, then waits one launcher interval
# (5s) before the next scan. The observation window is 30s: six scans, enough
# for one rotation of a handful of eligible databases plus worker startup.
# Failure to place a consumer on an eligible installed database inside that
# window is a product failure.
#
# Readiness for measured events is a delivered canary. The canary is not
# evidence that any earlier event arrived. Each measured row is polled on its
# own identity. Startup-cursor races before readiness are outside this test.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.worker_discovery
EV=worker_discovery
ROLE=qa_w3a_app
WINDOW=30

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Discovery rotates through eligible databases. Routing uses FirewallEvent.db_oid. Worker backend_type is sql_firewall_worker_<oid>." ""

qa_admin postgres "CREATE ROLE $ROLE LOGIN NOSUPERUSER" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

worker_rows() {
    qa_admin postgres \
        "SELECT coalesce(string_agg(d.datname || '=' || d.oid::text || ':' || a.pid::text, ',' ORDER BY d.oid), '') FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_database d ON d.oid OPERATOR(pg_catalog.=) a.datid WHERE a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_WORKER_ROWS=${QA_STEP_OUT[1]}
}

db_oid() {
    qa_admin postgres "SELECT oid::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) '$1'" || return $?
    QA_DB_OID=${QA_STEP_OUT[1]}
}

# Poll until db has a sql_firewall_worker_* backend. Timeout is a product miss.
wait_consumer() {
    local db=$1 deadline=$((SECONDS + WINDOW)) rows
    while ((SECONDS < deadline)); do
        worker_rows || { infra "$ID.observe" "$QA_INFRA_REASON"; return 1; }
        rows=$QA_WORKER_ROWS
        if [[ ,$rows, == *,"$db"=* ]]; then
            QA_DB_PID=${rows#*"$db"=}
            QA_DB_PID=${QA_DB_PID#*:}
            QA_DB_PID=${QA_DB_PID%%,*}
            return 0
        fi
        sleep 1
    done
    QA_DB_PID=
    return 1
}

count_consumers() {
    qa_admin postgres \
        "SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE datid OPERATOR(pg_catalog.=) $1::oid AND backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_CONSUMER_COUNT=${QA_STEP_OUT[1]}
}

# ---------------------------------------------------------------------------
# A. Lower-OID distractions must not starve later installed databases.
# ---------------------------------------------------------------------------
qa_admin postgres \
    "CREATE DATABASE qa_w3a_none" \
    "CREATE DATABASE qa_w3a_latin5 WITH TEMPLATE template0 ENCODING 'LATIN5' LC_COLLATE 'C' LC_CTYPE 'C'" ||
    { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
qa_create_db qa_w3a_p1 sql_firewall.mode=learn || { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
qa_create_db qa_w3a_p2 sql_firewall.mode=learn || { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
db_oid qa_w3a_none || { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
oid_none=$QA_DB_OID
db_oid qa_w3a_latin5 || { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
oid_latin=$QA_DB_OID
db_oid qa_w3a_p1 || { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
oid_p1=$QA_DB_OID
db_oid qa_w3a_p2 || { infra "$ID.fair" "$QA_INFRA_REASON"; exit 0; }
oid_p2=$QA_DB_OID
qa_evidence "$EV" "- oids none=$oid_none latin5=$oid_latin p1=$oid_p1 p2=$oid_p2"
pid_p1=
pid_p2=
if wait_consumer qa_w3a_p1; then
    pid_p1=$QA_DB_PID
fi
if wait_consumer qa_w3a_p2; then
    pid_p2=$QA_DB_PID
fi
if [[ -n $pid_p1 && -n $pid_p2 ]]; then
    ok "$ID.fair" "consumers p1 oid=$oid_p1 pid=$pid_p1; p2 oid=$oid_p2 pid=$pid_p2 within ${WINDOW}s"
else
    worker_rows || true
    fail "$ID.fair" "protected databases had no consumer within ${WINDOW}s (oids p1=$oid_p1 p2=$oid_p2 pids '$pid_p1' '$pid_p2'; observed '${QA_WORKER_ROWS:-}')"
fi

# ---------------------------------------------------------------------------
# B. postgres itself is eligible when the extension is installed.
# ---------------------------------------------------------------------------
qa_admin postgres \
    "CREATE EXTENSION sql_firewall" \
    "ALTER DATABASE postgres SET sql_firewall.mode = 'learn'" \
    "GRANT CONNECT ON DATABASE postgres TO $QA_CANARY_ROLE" \
    "ALTER ROLE $QA_CANARY_ROLE IN DATABASE postgres SET sql_firewall.mode = 'enforce'" \
    "CREATE ROLE ${ROLE}_pg LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE postgres TO ${ROLE}_pg" \
    "CREATE ROLE ${ROLE}_learn_a LOGIN NOSUPERUSER" \
    "CREATE ROLE ${ROLE}_block_a LOGIN NOSUPERUSER" \
    "CREATE ROLE ${ROLE}_learn_b LOGIN NOSUPERUSER" \
    "CREATE ROLE ${ROLE}_block_b LOGIN NOSUPERUSER" \
    "CREATE ROLE ${ROLE}_learn_m LOGIN NOSUPERUSER" \
    "CREATE ROLE ${ROLE}_block_m LOGIN NOSUPERUSER" ||
    { infra "$ID.postgres" "$QA_INFRA_REASON"; exit 0; }
db_oid postgres || { infra "$ID.postgres" "$QA_INFRA_REASON"; exit 0; }
oid_pg=$QA_DB_OID
if ! wait_consumer postgres; then
    worker_rows || true
    fail "$ID.postgres.worker" "no consumer on postgres oid=$oid_pg within ${WINDOW}s (observed '${QA_WORKER_ROWS:-}')"
else
        ok "$ID.postgres.worker" "postgres oid=$oid_pg consumer pid=$QA_DB_PID"
    if ! qa_worker_progress postgres 20; then
        fail "$ID.postgres.ready" "$QA_INFRA_REASON"
    else
        marker=qa_w3a_pg_$RANDOM
        qa_check_success "${ROLE}_pg" postgres qa_w3a "SELECT '$marker'" "$marker"
        if [[ $QA_VERDICT != PASS ]]; then
            infra "$ID.postgres.event" "learn select did not run: $QA_DETAIL"
        else
            if qa_poll postgres \
                "SELECT count(*) > 0 FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) '${ROLE}_pg'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text" \
                t 20; then
                ok "$ID.postgres.event" "approval for ${ROLE}_pg SELECT persisted in postgres oid=$oid_pg"
            else
                fail "$ID.postgres.event" "approval for ${ROLE}_pg was not persisted in postgres within 20s"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# C. A database probed while uninstalled is serviced after CREATE EXTENSION.
# ---------------------------------------------------------------------------
qa_admin postgres "CREATE DATABASE qa_w3a_late" || { infra "$ID.late" "$QA_INFRA_REASON"; exit 0; }
db_oid qa_w3a_late || { infra "$ID.late" "$QA_INFRA_REASON"; exit 0; }
oid_late=$QA_DB_OID
late_deadline=$((SECONDS + WINDOW))
probed=0
while ((SECONDS < late_deadline)); do
    if tail -c +1 "$QA_SERVER_LOG" | grep -F "Extension NOT installed in DB OID $oid_late" >/dev/null; then
        probed=1
        break
    fi
    sleep 1
done
if [[ $probed -ne 1 ]]; then
    fail "$ID.late.probe" "database oid=$oid_late was not probed as uninstalled within ${WINDOW}s"
else
    ok "$ID.late.probe" "worker exited for uninstalled database oid=$oid_late"
fi
qa_admin qa_w3a_late "CREATE EXTENSION sql_firewall" \
    "ALTER DATABASE qa_w3a_late SET sql_firewall.mode = 'learn'" \
    "GRANT CONNECT ON DATABASE qa_w3a_late TO $QA_CANARY_ROLE" \
    "ALTER ROLE $QA_CANARY_ROLE IN DATABASE qa_w3a_late SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.late.install" "$QA_INFRA_REASON"; exit 0; }
installed_at=$SECONDS
if ! wait_consumer qa_w3a_late; then
    worker_rows || true
    fail "$ID.late.worker" "oid=$oid_late was not serviced within ${WINDOW}s after CREATE EXTENSION (observed '${QA_WORKER_ROWS:-}')"
else
    ok "$ID.late.worker" "oid=$oid_late consumer pid=$QA_DB_PID after CREATE EXTENSION, postmaster not restarted"
    # The probe put the database in its wait (30 s); the committed
    # installation is announced to the launcher, which serves it at its next
    # scan (5 s) instead.
    took=$((SECONDS - installed_at))
    if ((took <= 15)); then
        ok "$ID.late.prompt" "consumer present ${took}s after CREATE EXTENSION committed, inside the uninstalled database's wait"
    else
        fail "$ID.late.prompt" "consumer appeared ${took}s after CREATE EXTENSION (expected within one or two scans)"
    fi
fi

# ---------------------------------------------------------------------------
# C2. A database without the extension waits between probes. Its consumer
# exits without an installation; the next one comes after 30 s (doubling up
# to 10 min), not at every scan.
# ---------------------------------------------------------------------------
qa_admin postgres "CREATE DATABASE qa_w3a_idle" || { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
db_oid qa_w3a_idle || { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
oid_idle=$QA_DB_OID
idle_deadline=$((SECONDS + WINDOW))
idle_seen=""
while ((SECONDS < idle_deadline)); do
    if grep -qF "Extension NOT installed in DB OID $oid_idle" "$QA_SERVER_LOG"; then
        idle_seen=$(qa_server_log_offset)
        break
    fi
    sleep 1
done
if [[ -z $idle_seen ]]; then
    fail "$ID.idle.backoff" "database oid=$oid_idle was not probed within ${WINDOW}s"
else
    sleep 24
    again=$(tail -c +"$((idle_seen + 1))" "$QA_SERVER_LOG" | grep -cF "Extension NOT installed in DB OID $oid_idle")
    if [[ $again == 0 ]]; then
        ok "$ID.idle.backoff" "database oid=$oid_idle without the extension was probed once and not again in the next 24s"
    else
        fail "$ID.idle.backoff" "database oid=$oid_idle was probed $again more time(s) within 24s of the first probe"
    fi
fi
qa_admin postgres "DROP DATABASE qa_w3a_idle WITH (FORCE)" >/dev/null || true

# ---------------------------------------------------------------------------
# D. Long and multibyte names. Routing is by OID, not the worker name.
# ---------------------------------------------------------------------------
long_prefix=$(printf 'a%.0s' {1..62})
DB_A=${long_prefix}1
DB_B=${long_prefix}2
DB_M='qa_w3a_ış'
qa_admin postgres \
    "CREATE DATABASE \"$DB_A\"" \
    "CREATE DATABASE \"$DB_B\"" \
    "CREATE DATABASE \"$DB_M\"" ||
    { infra "$ID.route" "$QA_INFRA_REASON"; exit 0; }
setup_route_db() { # db tag
    local db=$1 tag=$2
    qa_admin "$db" "CREATE EXTENSION sql_firewall" \
        "ALTER DATABASE \"$db\" SET sql_firewall.mode = 'learn'" \
        "GRANT CONNECT ON DATABASE \"$db\" TO $QA_CANARY_ROLE" \
        "ALTER ROLE $QA_CANARY_ROLE IN DATABASE \"$db\" SET sql_firewall.mode = 'enforce'" \
        "GRANT CONNECT ON DATABASE \"$db\" TO ${ROLE}_learn_${tag}" \
        "GRANT CONNECT ON DATABASE \"$db\" TO ${ROLE}_block_${tag}" \
        "ALTER ROLE ${ROLE}_block_${tag} IN DATABASE \"$db\" SET sql_firewall.mode = 'enforce'" ||
        { infra "$ID.route" "$db: $QA_INFRA_REASON"; return 1; }
}
setup_route_db "$DB_A" a || exit 0
setup_route_db "$DB_B" b || exit 0
setup_route_db "$DB_M" m || exit 0

route_one() { # db tag
    local db=$1 tag=$2
    db_oid "$db" || { infra "$ID.route.$tag" "$QA_INFRA_REASON"; return 1; }
    local oid=$QA_DB_OID
    if ! wait_consumer "$db"; then
        worker_rows || true
        fail "$ID.route.$tag.worker" "no consumer for oid=$oid within ${WINDOW}s (observed '${QA_WORKER_ROWS:-}')"
        return 0
    fi
    local pid=$QA_DB_PID
    if ! qa_worker_progress "$db" 20; then
        fail "$ID.route.$tag.ready" "worker pid=$pid did not consume a readiness canary: $QA_INFRA_REASON"
        return 0
    fi
    local appr=qa_w3a_appr_$tag fp=qa_w3a_fp_$tag blk=qa_w3a_blk_$tag
    qa_check_success "${ROLE}_learn_${tag}" "$db" qa_w3a "SELECT '$fp'" "$fp"
    if [[ $QA_VERDICT != PASS ]]; then
        infra "$ID.route.$tag.emit" "learn select: $QA_DETAIL"
        return 0
    fi
    qa_check_rejection "${ROLE}_block_${tag}" "$db" qa_w3a "SELECT '$blk'" 42501 \
        "^sql_firewall: No rule found for command 'SELECT' for role '${ROLE}_block_${tag}'$"
    if [[ $QA_VERDICT != PASS ]]; then
        infra "$ID.route.$tag.emit" "block select: $QA_DETAIL"
        return 0
    fi
    if ! qa_poll "$db" \
        "SELECT (SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) '${ROLE}_learn_${tag}'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text) > 0" \
        t 20; then
        fail "$ID.route.$tag.approval" "approval for ${ROLE}_learn not in oid=$oid pid=$pid"
        return 0
    fi
    if ! qa_poll "$db" \
        "SELECT count(*) > 0 FROM public.sql_firewall_query_fingerprints WHERE strpos(sample_query, '$fp') > 0" \
        t 20; then
        fail "$ID.route.$tag.fingerprint" "fingerprint sample $fp not in oid=$oid pid=$pid"
        return 0
    fi
    if ! qa_poll "$db" \
        "SELECT count(*) > 0 FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '$blk') > 0" \
        t 20; then
        fail "$ID.route.$tag.blocked" "blocked query $blk not in oid=$oid pid=$pid"
        return 0
    fi
    ok "$ID.route.$tag.delivered" "oid=$oid pid=$pid delivered approval ${ROLE}_learn_${tag}, fingerprint $fp, blocked $blk"
    QA_ROUTE_OID[$tag]=$oid
    QA_ROUTE_APPR[$tag]=${ROLE}_learn_${tag}
    QA_ROUTE_FP[$tag]=$fp
    QA_ROUTE_BLK[$tag]=$blk
}

declare -A QA_ROUTE_OID QA_ROUTE_APPR QA_ROUTE_FP QA_ROUTE_BLK
route_one "$DB_A" a || exit 0
route_one "$DB_B" b || exit 0
route_one "$DB_M" m || exit 0

cross_clean() { # db tag other_tag
    local db=$1 tag=$2 other=$3
    [[ -n ${QA_ROUTE_FP[$tag]:-} && -n ${QA_ROUTE_FP[$other]:-} ]] || return 0
    qa_admin "$db" \
        "SELECT count(*)::text FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) '${QA_ROUTE_APPR[$other]}'::name" \
        "SELECT count(*)::text FROM public.sql_firewall_query_fingerprints WHERE strpos(sample_query, '${QA_ROUTE_FP[$other]}') > 0" \
        "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '${QA_ROUTE_BLK[$other]}') > 0" ||
        { infra "$ID.route.cross" "$QA_INFRA_REASON"; return 1; }
    if [[ ${QA_STEP_OUT[1]} == 0 && ${QA_STEP_OUT[2]} == 0 && ${QA_STEP_OUT[3]} == 0 ]]; then
        ok "$ID.route.cross.$tag" "oid=${QA_ROUTE_OID[$tag]} has none of $other identities"
    else
        fail "$ID.route.cross.$tag" "misrouted into $db: approval=${QA_STEP_OUT[1]} fingerprint=${QA_STEP_OUT[2]} blocked=${QA_STEP_OUT[3]}"
    fi
}
cross_clean "$DB_A" a b || exit 0
cross_clean "$DB_B" b a || exit 0
cross_clean "$DB_M" m a || exit 0

# ---------------------------------------------------------------------------
# E. One active consumer per database, and replacement after SIGTERM.
# ---------------------------------------------------------------------------
if [[ -n ${pid_p1:-} ]]; then
    stable=1
    deadline=$((SECONDS + 12))
    while ((SECONDS < deadline)); do
        count_consumers "$oid_p1" || { infra "$ID.dup" "$QA_INFRA_REASON"; exit 0; }
        if [[ $QA_CONSUMER_COUNT != 1 ]]; then
            stable=0
            break
        fi
        sleep 1
    done
    if [[ $stable -eq 1 ]]; then
        ok "$ID.dup" "oid=$oid_p1 kept a single consumer across repeated scans (pid=$pid_p1)"
    else
        fail "$ID.dup" "oid=$oid_p1 consumer count=$QA_CONSUMER_COUNT"
    fi
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend($pid_p1)" ||
        { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
    repl_deadline=$((SECONDS + WINDOW))
    replaced=0
    while ((SECONDS < repl_deadline)); do
        if wait_consumer qa_w3a_p1; then
            if [[ $QA_DB_PID != "$pid_p1" ]]; then
                replaced=1
                break
            fi
        fi
        sleep 1
    done
    if [[ $replaced -eq 1 ]]; then
        ok "$ID.replace" "oid=$oid_p1 replaced pid=$pid_p1 with pid=$QA_DB_PID"
    else
        fail "$ID.replace" "oid=$oid_p1 was not replaced within ${WINDOW}s after SIGTERM (last pid=${QA_DB_PID:-none})"
    fi
else
    fail "$ID.dup" "no initial consumer pid for qa_w3a_p1"
fi

# ---------------------------------------------------------------------------
# F. OIDs above the signed 32-bit boundary remain eligible.
# int4 would turn 2147483648 into -2147483648 and 3000000000 into
# -1294967296, and a positive cursor would then skip them.
# ---------------------------------------------------------------------------
high_oid_one() { # db oid tag
    local db=$1 oid=$2 tag=$3
    local role=${ROLE}_oid_${tag} marker=qa_w3a_oid_evt_${tag}
    qa_admin postgres \
        "CREATE DATABASE \"$db\" WITH OID = $oid" \
        "ALTER DATABASE \"$db\" SET sql_firewall.mode = 'learn'" \
        "GRANT CONNECT ON DATABASE \"$db\" TO $QA_CANARY_ROLE" \
        "ALTER ROLE $QA_CANARY_ROLE IN DATABASE \"$db\" SET sql_firewall.mode = 'enforce'" \
        "CREATE ROLE ${role} LOGIN NOSUPERUSER" \
        "GRANT CONNECT ON DATABASE \"$db\" TO ${role}" ||
        { infra "$ID.highoid.$tag" "$db: $QA_INFRA_REASON"; return 1; }
    qa_admin "$db" "CREATE EXTENSION sql_firewall" ||
        { infra "$ID.highoid.$tag" "$db extension: $QA_INFRA_REASON"; return 1; }
    qa_admin postgres \
        "SELECT oid::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) '$db'" \
        "SELECT oid::pg_catalog.int4::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) '$db'" ||
        { infra "$ID.highoid.$tag" "$QA_INFRA_REASON"; return 1; }
    if [[ ${QA_STEP_OUT[1]} != "$oid" ]]; then
        fail "$ID.highoid.$tag.catalog" "oid::text=${QA_STEP_OUT[1]} expected $oid (int4 text=${QA_STEP_OUT[2]})"
        return 0
    fi
    local int4_text=${QA_STEP_OUT[2]}
    qa_admin "$db" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname OPERATOR(pg_catalog.=) 'sql_firewall'::name" ||
        { infra "$ID.highoid.$tag" "$QA_INFRA_REASON"; return 1; }
    if [[ ${QA_STEP_OUT[1]} != 0.0.0 ]]; then
        fail "$ID.highoid.$tag.install" "extversion='${QA_STEP_OUT[1]}' in oid=$oid"
        return 0
    fi
    if ! wait_consumer "$db"; then
        worker_rows || true
        fail "$ID.highoid.$tag.worker" "no consumer for oid=$oid within ${WINDOW}s (observed '${QA_WORKER_ROWS:-}')"
        return 0
    fi
    local pid=$QA_DB_PID
    qa_admin postgres \
        "SELECT a.backend_type FROM pg_catalog.pg_stat_activity a WHERE a.pid OPERATOR(pg_catalog.=) ${pid}::integer AND a.datid OPERATOR(pg_catalog.=) ${oid}::oid" ||
        { infra "$ID.highoid.$tag" "$QA_INFRA_REASON"; return 1; }
    if [[ ${QA_STEP_OUT[1]} != "sql_firewall_worker_${oid}" ]]; then
        fail "$ID.highoid.$tag.identity" "pid=$pid datid=$oid backend_type='${QA_STEP_OUT[1]}' expected sql_firewall_worker_${oid}"
        return 0
    fi
    count_consumers "$oid" || { infra "$ID.highoid.$tag" "$QA_INFRA_REASON"; return 1; }
    if [[ $QA_CONSUMER_COUNT != 1 ]]; then
        fail "$ID.highoid.$tag.dup" "oid=$oid consumer count=$QA_CONSUMER_COUNT pid=$pid"
        return 0
    fi
    if ! qa_worker_progress "$db" 20; then
        fail "$ID.highoid.$tag.ready" "$QA_INFRA_REASON"
        return 0
    fi
    qa_check_success "$role" "$db" qa_w3a "SELECT '$marker'" "$marker"
    if [[ $QA_VERDICT != PASS ]]; then
        infra "$ID.highoid.$tag.emit" "learn select: $QA_DETAIL"
        return 0
    fi
    if ! qa_poll "$db" \
        "SELECT count(*) > 0 FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) '${role}'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text" \
        t 20; then
        fail "$ID.highoid.$tag.event" "approval for ${role} not in oid=$oid pid=$pid"
        return 0
    fi
    ok "$ID.highoid.$tag.delivered" "oid=$oid (int4 text=$int4_text) pid=$pid backend_type=sql_firewall_worker_${oid} delivered $marker"
    QA_HIGH_PID[$tag]=$pid
    return 0
}

declare -A QA_HIGH_PID
high_oid_one qa_w3a_oid_maxpos 2147483647 maxpos || exit 0
high_oid_one qa_w3a_oid_boundary 2147483648 boundary || exit 0
high_oid_one qa_w3a_oid_high 3000000000 high || exit 0

if [[ -n ${QA_HIGH_PID[maxpos]:-} && -n ${QA_HIGH_PID[boundary]:-} && -n ${QA_HIGH_PID[high]:-} ]]; then
    stable=1
    dup_deadline=$((SECONDS + 6))
    while ((SECONDS < dup_deadline)); do
        for oid in 2147483647 2147483648 3000000000; do
            count_consumers "$oid" || { infra "$ID.highoid.dup" "$QA_INFRA_REASON"; exit 0; }
            if [[ $QA_CONSUMER_COUNT != 1 ]]; then
                stable=0
                break
            fi
        done
        [[ $stable -eq 0 ]] && break
        sleep 1
    done
    if [[ $stable -eq 1 ]]; then
        ok "$ID.highoid.dup" "oids 2147483647, 2147483648, and 3000000000 each kept one consumer across a scan interval"
    else
        fail "$ID.highoid.dup" "oid=$oid consumer count=$QA_CONSUMER_COUNT"
    fi
fi

# With fewer than 32 eligible databases the candidate list ends on the wrapped
# low OIDs, so the stored cursor can rest there while the same scan already
# included the high OIDs. Replacement of both sides is the wrap observation.
if [[ -n ${QA_HIGH_PID[high]:-} ]] && wait_consumer qa_w3a_p1; then
    low_before=$QA_DB_PID
    high_before=${QA_HIGH_PID[high]}
    qa_admin postgres \
        "SELECT pg_catalog.pg_terminate_backend($low_before)" \
        "SELECT pg_catalog.pg_terminate_backend($high_before)" ||
        { infra "$ID.highoid.wrap" "$QA_INFRA_REASON"; exit 0; }
    wrap_deadline=$((SECONDS + WINDOW))
    low_after=
    high_after=
    while ((SECONDS < wrap_deadline)); do
        if [[ -z $low_after ]] && wait_consumer qa_w3a_p1 && [[ $QA_DB_PID != "$low_before" ]]; then
            low_after=$QA_DB_PID
        fi
        if [[ -z $high_after ]] && wait_consumer qa_w3a_oid_high && [[ $QA_DB_PID != "$high_before" ]]; then
            high_after=$QA_DB_PID
        fi
        [[ -n $low_after && -n $high_after ]] && break
        sleep 1
    done
    count_consumers 3000000000 || { infra "$ID.highoid.wrap" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $low_after && -n $high_after && $QA_CONSUMER_COUNT == 1 ]]; then
        ok "$ID.highoid.wrap" "low oid replaced pid=$low_before with $low_after and oid=3000000000 replaced pid=$high_before with $high_after (count=1)"
    else
        fail "$ID.highoid.wrap" "low pid ${low_after:-none} (was $low_before), high pid ${high_after:-none} (was $high_before), high count=${QA_CONSUMER_COUNT:-none}"
    fi
else
    fail "$ID.highoid.wrap" "no live low-OID and high-OID consumers to exercise cursor wrap"
fi

exit 0
