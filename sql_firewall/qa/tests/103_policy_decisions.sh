#!/usr/bin/env bash
# Phase 5: decision order, state model, history, and role lifecycle (release
# build).
#
# A learn event is queued while the database's approval worker is paused, an
# administrator commits a decision, and the worker is resumed. The worker must
# not let the queued observation override, revive, or count against a decision
# the administrator made after it (P5-01), a manual denial must stay final for
# learning (P5-02), committed decision changes are recorded with their source,
# roles, and before/after values while rolled-back ones are not (P5-03), and an
# event queued for a role must not authorize a different role that now has its
# name (P5-04). A discarded event is established by a later delivered canary
# together with the worker's LOG line naming the event, never by absence alone.
# The scenarios run in qa/policy_decisions.py over separate libpq connections.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.policy_decisions
EV=policy_decisions
DB=qa_pdec
EXPECTED=12

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Separate libpq connections in one process; each step shows [connection] (transaction status before -> after), the statement, and the result or SQLSTATE and message." \
    "Database: $DB (enforce by default; the scenario roles run in learn mode through ALTER ROLE ... IN DATABASE)." ""

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID.ready" "$QA_INFRA_REASON"; exit 0; }

LIBPQ=$(dirname "$QA_PSQL")/../lib/libpq.so.5
[[ -f $LIBPQ ]] || { infra "$ID" "libpq not found at $LIBPQ"; exit 0; }

seen=0
while IFS=$'\t' read -r status check detail; do
    [[ -n $status ]] || continue
    qa_record "$status" "$ID.$check" "$detail"
    seen=$((seen + 1))
done < <(QA_LIBPQ=$LIBPQ QA_PC_SUPERUSER=$QA_SUPERUSER QA_PC_SOCK=$QA_SOCK QA_PC_PORT=$QA_PORT \
    QA_PC_DB=$DB QA_PC_DB2=$DB QA_PC_DBL=$DB QA_PC_EVIDENCE="$QA_RUN_DIR/evidence/$EV.md" \
    QA_PD_SERVER_LOG="$QA_SERVER_LOG" PYTHONPATH="$(dirname "$0")/.." PYTHONDONTWRITEBYTECODE=1 \
    timeout 900 python3 "$(dirname "$0")/../policy_decisions.py" 2>"$QA_RUN_DIR/logs/policy_decisions.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/policy_decisions.stderr")"
fi
exit 0
