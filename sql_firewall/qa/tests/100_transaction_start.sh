#!/usr/bin/env bash
# Transaction characteristics must be applied before firewall policy SPI
# acquires a user-data snapshot. Exercise real libpq sessions, including an
# interleaved commit from another session and actual SQLSTATEs.
#
# Snapshot-free utilities (SHOW, SET, savepoints, LOCK) inside a transaction
# block are compared with the same sequences in a database of this cluster
# without sql_firewall (native reference), and their activity and learning
# records are checked on COMMIT, ROLLBACK, savepoint rollback, and errors.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.transaction_start
DB=qa_txstart
NATIVE_DB=qa_txstart_native
EV=transaction_start
EXPECTED=58

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on || {
    qa_record INFRA "$ID.setup" "$QA_INFRA_REASON"
    exit 0
}
qa_admin postgres "CREATE DATABASE $NATIVE_DB" || {
    qa_record INFRA "$ID.setup" "native database: $QA_INFRA_REASON"
    exit 0
}
# The learning checks need a consumer attached before their events.
qa_wait_worker_live "$DB" 90 || {
    qa_record INFRA "$ID.setup" "worker: $QA_INFRA_REASON"
    exit 0
}

LIBPQ=$(dirname "$QA_PSQL")/../lib/libpq.so.5
if [[ ! -f $LIBPQ ]]; then
    qa_record INFRA "$ID.setup" "libpq not found at $LIBPQ"
    exit 0
fi

qa_evidence "$EV" "# $ID" "" \
    "An ordinary enforce-mode role begins a transaction; a separate administrator commits a row before the first data SELECT. SQLSTATE, transaction status, isolation, read-only state and row visibility are recorded per step." ""

seen=0
while IFS=$'\t' read -r status check detail; do
    [[ -n $status ]] || continue
    qa_record "$status" "$ID.$check" "$detail"
    seen=$((seen + 1))
done < <(QA_LIBPQ=$LIBPQ QA_PC_SUPERUSER=$QA_SUPERUSER QA_PC_SOCK=$QA_SOCK QA_PC_PORT=$QA_PORT \
    QA_PC_DB=$DB QA_PC_DB2=$DB QA_PC_DBL=$DB QA_PC_EVIDENCE="$QA_RUN_DIR/evidence/$EV.md" \
    QA_TX_NATIVE_DB=$NATIVE_DB \
    timeout 300 python3 "$(dirname "$0")/../transaction_start.py" \
    2>"$QA_RUN_DIR/logs/transaction_start.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    qa_record INFRA "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/transaction_start.stderr")"
fi
exit 0
