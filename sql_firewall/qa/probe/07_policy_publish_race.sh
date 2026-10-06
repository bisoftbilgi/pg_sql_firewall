#!/usr/bin/env bash
# A reader racing a policy commit: the shared caches never keep a decision
# read before a policy commit that finished before the reader published it.
#
# Run with the policy_probe build only:
#   QA_CARGO_FEATURES=policy_probe QA_TEST_DIR=sql_firewall/qa/probe \
#       sql_firewall/qa/run.sh --only '07*'
# A session with sql_firewall_probe.hold_publish = approvals|fingerprints
# stops between its catalog read and the cache publication until it can take
# a shared advisory lock that the test holds (src/policy_probe.rs). The test
# waits for pg_locks to show the reader waiting there, commits a policy
# change, releases the reader, then inspects the cache entry with the probe
# functions and checks new sessions. The probe functions are superuser-only
# and absent from the release library (tests/99 checks that).
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.policy_publish_race
EV=policy_publish_race
DB=qa_prace
EXPECTED=4

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "This run is the policy_probe build, not the release library. Steps are shown as in tests/99 (policy_cache)." ""

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=on ||
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
    timeout 300 python3 "$(dirname "$0")/policy_race.py" 2>"$QA_RUN_DIR/logs/policy_race.stderr")
rc=$?
if ((rc != 0 || seen < EXPECTED)); then
    infra "$ID.driver" "driver exit $rc after $seen of $EXPECTED checks: $(head -c 400 "$QA_RUN_DIR/logs/policy_race.stderr")"
fi
