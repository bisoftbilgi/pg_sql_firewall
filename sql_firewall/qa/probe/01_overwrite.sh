#!/usr/bin/env bash
# Overwrite and sequence checks for the queue_probe build only.
# The probe functions are not in the release library. Holding the consumer
# uses a shared-memory flag observed outside the ring spinlock.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.queue_probe
EV=queue_probe
DB=qa_probe

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

release_hold() {
    qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_hold(false)" || true
}
trap release_hold EXIT

qa_evidence "$EV" "# $ID" "" \
    "This run is the queue_probe build, not the release library. Measured events are published only after the target consumer acknowledges that it is in the hold branch and will not read the ring." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi

qa_admin "$DB" \
    "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.hold" "$QA_INFRA_REASON"; exit 0; }
target_pid=${QA_STEP_OUT[1]}
[[ $target_pid =~ ^[0-9]+$ ]] ||
    { infra "$ID.hold" "expected one consumer pid, saw '${target_pid}'"; exit 0; }

qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_arm(${target_pid})" ||
    { infra "$ID.hold" "$QA_INFRA_REASON"; exit 0; }
armed=${QA_STEP_OUT[1]}
[[ $armed == armed\ pid=${target_pid}\ db=*\ epoch=* ]] ||
    { fail "$ID.hold" "arm returned '${armed}'"; exit 0; }

hold_deadline=$((SECONDS + 10))
quiescent=
while ((SECONDS < hold_deadline)); do
    qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_status()" ||
        { infra "$ID.hold" "$QA_INFRA_REASON"; exit 0; }
    case ${QA_STEP_OUT[1]} in
        quiescent\ pid=${target_pid}\ db=*\ epoch=*)
            quiescent=${QA_STEP_OUT[1]}
            break
            ;;
        exited\ *)
            infra "$ID.hold" "target consumer pid ${target_pid} exited before acknowledging hold (${QA_STEP_OUT[1]})"
            exit 0
            ;;
        waiting\ pid=${target_pid}\ *)
            ;;
        *)
            infra "$ID.hold" "unexpected hold status '${QA_STEP_OUT[1]}'"
            exit 0
            ;;
    esac
    sleep 0.2
done
[[ -n $quiescent ]] ||
    { infra "$ID.hold" "consumer pid ${target_pid} did not acknowledge hold within 10s (last '${QA_STEP_OUT[1]:-}')"; exit 0; }
ok "$ID.hold" "consumer quiesced before measured publication: ${quiescent}"

qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_stats()" ||
    { infra "$ID.stats" "$QA_INFRA_REASON"; exit 0; }
stats=${QA_STEP_OUT[1]}
start=${stats#publications=}
start=${start%% *}
cap=${stats#*capacity=}
overs_before=${stats#*slot_overwrites=}
overs_before=${overs_before%% *}
[[ $start =~ ^[0-9]+$ && $cap =~ ^[0-9]+$ ]] || { infra "$ID.stats" "unparsed stats '$stats'"; exit 0; }

qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(1, 'qa_probe_first')" ||
    { infra "$ID.first" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_read($start::bigint)" ||
    { infra "$ID.first" "$QA_INFRA_REASON"; exit 0; }
first=${QA_STEP_OUT[1]}
case $first in
    ready\ blocked\ *\ qa_probe_first-0)
        ok "$ID.first" "position $start published as a complete blocked event ($first)"
        ;;
    *)
        fail "$ID.first" "position $start read '$first'"
        exit 0
        ;;
esac
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_read($((start + 1))::bigint)" ||
    { infra "$ID.not_yet" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} == not_yet ]]; then
    ok "$ID.not_yet" "position $((start + 1)) is not yet published"
else
    fail "$ID.not_yet" "position $((start + 1)) read '${QA_STEP_OUT[1]}'"
fi

# One event is already at `start`. Filling `cap` more events reuses that slot.
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill($cap, 'qa_probe_more')" ||
    { infra "$ID.fill" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "SELECT public.sql_firewall_queue_probe_read($start::bigint)" \
    "SELECT public.sql_firewall_queue_probe_read($((start + 1))::bigint)" \
    "SELECT public.sql_firewall_queue_probe_stats()" ||
    { infra "$ID.overwrite" "$QA_INFRA_REASON"; exit 0; }
over_read=${QA_STEP_OUT[1]}
kept_read=${QA_STEP_OUT[2]}
stats2=${QA_STEP_OUT[3]}
retained=$((start + 1))
overs_after=${stats2#*slot_overwrites=}
overs_after=${overs_after%% *}
if [[ $over_read == "overwritten $retained" && $kept_read == ready\ blocked\ *\ qa_probe_more-0 ]]; then
    ok "$ID.overwrite" "position $start overwritten, retained position $retained still readable ($kept_read)"
else
    fail "$ID.overwrite" "start read '$over_read', next read '$kept_read', stats '$stats2'"
    exit 0
fi
if [[ $overs_after =~ ^[0-9]+$ && $overs_after -gt $overs_before ]]; then
    ok "$ID.overwrites" "slot_overwrites advanced from $overs_before to $overs_after (reused slots, not per-database losses)"
else
    fail "$ID.overwrites" "slot_overwrites did not advance ('$overs_before' -> '$overs_after')"
fi

release_hold
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_probe_more-0') > 0" \
    1 30; then
    fail "$ID.resume" "retained event qa_probe_more-0 was not persisted after the consumer resumed (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_probe_first-0') > 0" ||
    { infra "$ID.resume" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.resume" "overwritten marker qa_probe_first-0 was persisted"
    exit 0
fi
if ! grep -F "skipped shared-stream positions [$start, $retained)" "$QA_SERVER_LOG" >/dev/null; then
    fail "$ID.gap" "server log has no gap diagnostic for positions [$start, $retained)"
    exit 0
fi
ok "$ID.resume" "after release, retained marker was persisted, overwritten marker was not, and the gap log names [$start, $retained)"

exit 0
