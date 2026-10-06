#!/usr/bin/env bash
# Phase 5: transaction-safe policy caching (release build).
#
# Decisions use the latest committed policy plus the deciding transaction's
# own writes; the shared caches never hold anything else. Each scenario runs
# in qa/policy_cache.py over separate libpq connections from one process, so
# the order of statements across sessions is explicit: an application session
# warms the cache, an administrator commits (or does not commit) a change,
# and the same and new sessions are then checked by SQLSTATE and message.
# Catalog state is read on an independent superuser connection.
#
# Enforce-mode checks use the command approval path. Fingerprint checks use
# permissive mode with a false SELECT command approval: every fingerprint
# lookup then runs, and one that is not approved writes one synchronous
# 'ALLOWED (PERMISSIVE - FINGERPRINT)' activity row, an approved one none.
# The command-path checks isolate command policy from fingerprint policy.
# Worker-originated changes are made deterministic with pause/resume.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.policy_cache
EV=policy_cache
DB=qa_pcache
DB2=qa_pcache_other
DBL=qa_pcache_life
EXPECTED=21 # driver checks; .release is recorded below

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Separate libpq connections in one process; each step shows [connection] (transaction status before -> after), the statement, and the result or SQLSTATE and message." \
    "Databases: $DB and $DB2 (enforce), $DBL (enforce; DROP/CREATE EXTENSION). Fingerprint checks: permissive roles with a false SELECT approval." ""

for db in "$DB" "$DB2" "$DBL"; do
    qa_create_db "$db" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=off ||
        { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
done
qa_wait_worker_live "$DB" 90 || { infra "$ID.ready" "$QA_INFRA_REASON"; exit 0; }

LIBPQ=$(dirname "$QA_PSQL")/../lib/libpq.so.5
[[ -f $LIBPQ ]] || { infra "$ID" "libpq not found at $LIBPQ"; exit 0; }

seen=0
while IFS=$'\t' read -r status check detail; do
    [[ -n $status ]] || continue
    qa_record "$status" "$ID.$check" "$detail"
    seen=$((seen + 1))
done < <(QA_LIBPQ=$LIBPQ QA_PC_SUPERUSER=$QA_SUPERUSER QA_PC_SOCK=$QA_SOCK QA_PC_PORT=$QA_PORT \
    QA_PC_DB=$DB QA_PC_DB2=$DB2 QA_PC_DBL=$DBL QA_PC_EVIDENCE="$QA_RUN_DIR/evidence/$EV.md" \
    timeout 900 python3 "$(dirname "$0")/../policy_cache.py" 2>"$QA_RUN_DIR/logs/policy_cache.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/policy_cache.stderr")"
fi

# The race probe (qa/probe/07, policy_probe build) is not in the release package.
# The staged installation's own layout: lib/postgresql for a source build,
# lib for the PGDG packages (a fixed path read missing files there,
# sqlfw-qa.Z2urDT).
STAGE_PGC=$(dirname "$QA_PSQL")/pg_config
SO=$("$STAGE_PGC" --pkglibdir)/sql_firewall.so
SQL=$("$STAGE_PGC" --sharedir)/extension/sql_firewall--0.0.0.sql
if [[ ! -f $SO || ! -f $SQL ]]; then
    infra "$ID.release" "staged files not found: $SO $SQL"
elif qa_admin "$DB" "SELECT count(*) FROM pg_catalog.pg_proc WHERE proname::text LIKE 'sql_firewall_%probe%'"; then
    in_so=$(grep -c -e sql_firewall_policy_probe -e sql_firewall_probe.hold_publish "$SO")
    in_sql=$(grep -c -e sql_firewall_policy_probe -e hold_publish "$SQL")
    if [[ ${QA_STEP_OUT[1]} == 0 && $in_so == 0 && $in_sql == 0 ]]; then
        qa_record PASS "$ID.release" "no probe function in pg_proc, and no policy probe function or hold setting in the staged library or install script"
    else
        qa_record FAIL "$ID.release" "pg_proc=${QA_STEP_OUT[1]} library=$in_so script=$in_sql"
    fi
else
    infra "$ID.release" "$QA_INFRA_REASON"
fi
exit 0
