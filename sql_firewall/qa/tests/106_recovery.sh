#!/usr/bin/env bash
# Phase 6: recovery paths (release build).
#
# ROLLBACK, ABORT, ROLLBACK AND CHAIN, and ROLLBACK TO SAVEPOINT work without
# an approval in healthy and failed transactions, while a statement after
# them in the same message is still inspected. A superuser locked out by
# enforce, an empty policy, and allow_superuser_auth_bypass = off recovers
# through a connection with the startup option sql_firewall.enabled=off. An
# ordinary role, also as the database owner, cannot use that path or ALTER
# ROLE / ALTER DATABASE / SET to turn the firewall off or change its mode.
# The scenarios run in qa/recovery.py.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.recovery
EV=recovery
DB=qa_recovery
EXPECTED=3

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Separate libpq connections in one process; each step shows [connection] (transaction status before -> after), the statement, and the result or SQLSTATE and message." \
    "Database: $DB (enforce, empty policy, fingerprint checking off)." ""

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
    timeout 900 python3 "$(dirname "$0")/../recovery.py" 2>"$QA_RUN_DIR/logs/recovery.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/recovery.stderr")"
fi
exit 0
