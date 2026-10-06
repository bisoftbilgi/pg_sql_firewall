#!/usr/bin/env bash
# Phase 6: mode behaviour matrix (release
# build).
#
# Each cell of the README 6.1c table (mode x command state, mode x
# fingerprint state) runs one statement as a role in exactly that state and
# checks the outcome, the activity rows, the policy row after the worker, and
# the blocked-query rows. Also: sessions of one role in different modes, a mode
# change inside a transaction, the threshold range, and settings an ordinary
# role cannot change. The scenarios run in qa/mode_matrix.py.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.mode_matrix
EV=mode_matrix
DB=qa_modemx
EXPECTED=5

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Separate libpq connections in one process; each step shows [connection] (transaction status before -> after), the statement, and the result or SQLSTATE and message." \
    "Database: $DB (enforce by default, activity logging on; each cell role has its own mode, fingerprint setting, and threshold through ALTER ROLE ... IN DATABASE)." ""

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
    PYTHONPATH="$(dirname "$0")/.." PYTHONDONTWRITEBYTECODE=1 \
    timeout 900 python3 "$(dirname "$0")/../mode_matrix.py" 2>"$QA_RUN_DIR/logs/mode_matrix.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/mode_matrix.stderr")"
fi
exit 0
