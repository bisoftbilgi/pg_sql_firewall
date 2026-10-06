#!/usr/bin/env bash
# Phase 6: learn observations count only committed transactions (release
# build).
#
# A learn observation (a command approval or a fingerprint hit with a learn
# threshold) is published when its top-level transaction commits. ROLLBACK, a
# failed or cancelled statement, ROLLBACK TO SAVEPOINT, an exception block,
# and PREPARE TRANSACTION publish none. The threshold boundary, several
# executions in one transaction, concurrent sessions, and the per-transaction
# observation limit are checked against the persisted hit count. Absence is
# established with the cluster-wide publication counters of
# sql_firewall_queue_statistics() (this test is the only client; canaries are
# blocked-query events), each with a positive control. The scenarios run in
# qa/learn_observations.py over separate libpq connections.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.learn_observations
EV=learn_observations
DB=qa_learnobs
EXPECTED=6

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Separate libpq connections in one process; each step shows [connection] (transaction status before -> after), the statement, and the result or SQLSTATE and message." \
    "Database: $DB (enforce by default, activity logging off; scenario roles run in learn mode through ALTER ROLE ... IN DATABASE)." ""

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=off sql_firewall.enable_fingerprint_learning=off ||
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
    PYTHONPATH="$(dirname "$0")/.." PYTHONDONTWRITEBYTECODE=1 \
    timeout 900 python3 "$(dirname "$0")/../learn_observations.py" 2>"$QA_RUN_DIR/logs/learn_observations.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/learn_observations.stderr")"
fi
exit 0
