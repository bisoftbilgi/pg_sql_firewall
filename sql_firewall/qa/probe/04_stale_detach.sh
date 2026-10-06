#!/usr/bin/env bash
# A detach for an old incarnation must not clear the replacement.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.control_probe
EV=control_probe
DB=qa_stale_detach

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "queue_probe build. detach_keep_request for a previous incarnation leaves the current one in place." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == approval\ worker\ running\ epoch=*\ incarnation=* ]] ||
    { fail "$ID.ready" "resume '${QA_STEP_OUT[1]}'"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
status=${QA_STEP_OUT[1]}
[[ $status == running\ epoch=*\ incarnation=* ]] ||
    { fail "$ID.ready" "status '$status'"; exit 0; }
old_inc=${status##*incarnation=}
qa_admin postgres \
    "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE backend_type OPERATOR(pg_catalog.=) 'sql_firewall_launcher'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
launcher=${QA_STEP_OUT[1]}
kill -STOP "$launcher" || { infra "$ID" "could not stop the launcher"; exit 0; }
qa_admin "$DB" \
    "SELECT pid::text FROM pg_catalog.pg_stat_activity WHERE backend_type LIKE 'sql_firewall_worker_%' AND datid OPERATOR(pg_catalog.=) (SELECT oid FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) current_database())" ||
    { kill -CONT "$launcher" 2>/dev/null || true; infra "$ID" "$QA_INFRA_REASON"; exit 0; }
old_pid=${QA_STEP_OUT[1]}
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${old_pid})" || true
kill -CONT "$launcher" || { infra "$ID" "could not continue the launcher"; exit 0; }
deadline=$((SECONDS + 30))
new_status=
while ((SECONDS < deadline)); do
    qa_admin "$DB" "SELECT public.sql_firewall_approval_worker_status()" ||
        { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
    if [[ ${QA_STEP_OUT[1]} == running\ epoch=*\ incarnation=* && ${QA_STEP_OUT[1]} != *incarnation=${old_inc} ]]; then
        new_status=${QA_STEP_OUT[1]}
        break
    fi
    sleep 0.2
done
[[ -n $new_status ]] || { fail "$ID.replace" "replacement status did not appear (last '${QA_STEP_OUT[1]:-}')"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_stale_detach(${old_inc})" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != "$new_status" ]]; then
    fail "$ID.stale" "stale detach changed status from '$new_status' to '${QA_STEP_OUT[1]}'"
    exit 0
fi
ok "$ID.stale" "detach of incarnation $old_inc left $new_status in place"

exit 0
