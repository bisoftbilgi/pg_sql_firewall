#!/usr/bin/env bash
# Phase 8: regex deadline, SQL-token keyword and built-in checks, quiet hours
# in the policy time zone, rate-limit scope and concurrency, the application
# name policy uses, parallel workers, and the no-active-rule regex memo
# (release build). The scenarios run in
# qa/session_policies.py over separate libpq connections; roles get their
# settings through ALTER ROLE ... IN DATABASE.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.session_policies
EV=session_policies
DB=qa_sesspol
DB2=qa_sesspol2
EXPECTED=7

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Separate libpq connections in one process; each step shows [connection] (transaction status before -> after), the statement, and the result or SQLSTATE and message." \
    "Databases: $DB and $DB2 (enforce, fingerprint checking off, regex scan off unless a role turns it on)." ""

for db in "$DB" "$DB2"; do
    qa_create_db "$db" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=off \
        sql_firewall.enable_regex_scan=off sql_firewall.enable_activity_logging=off ||
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
    QA_PC_DB=$DB QA_PC_DB2=$DB2 QA_PC_DBL=$DB QA_PC_EVIDENCE="$QA_RUN_DIR/evidence/$EV.md" \
    PYTHONPATH="$(dirname "$0")/.." PYTHONDONTWRITEBYTECODE=1 \
    timeout 900 python3 "$(dirname "$0")/../session_policies.py" 2>"$QA_RUN_DIR/logs/session_policies.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/session_policies.stderr")"
fi
exit 0
