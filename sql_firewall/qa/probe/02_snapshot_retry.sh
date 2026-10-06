#!/usr/bin/env bash
# Phase 3C1 probe: a copied event survives ring overwrite, and a malformed
# event is skipped once. This build is queue_probe, not the release library.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.worker_retry_probe
EV=worker_retry_probe
DB=qa_c1_probe

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

release_hold() {
    qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_hold(false)" || true
}
trap release_hold EXIT

qa_evidence "$EV" "# $ID" "" \
    "queue_probe build. The failing event is copied, its ring slot is overwritten, then the copied event commits. The following gap starts after that position." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE qa_c1_probe_app LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_c1_probe_app" \
    "ALTER ROLE qa_c1_probe_app IN DATABASE $DB SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi

qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_bad_approval()" ||
    { infra "$ID.malformed" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(1, 'qa_c1_after_bad')" ||
    { infra "$ID.malformed" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_after_bad-0') > 0" \
    1 20; then
    fail "$ID.malformed.progress" "a valid event after a malformed approval was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
if ! grep -F "skip malformed database oid" "$QA_SERVER_LOG" | grep -F "type approval" >/dev/null; then
    fail "$ID.malformed.skip" "malformed approval was not skipped"
    exit 0
fi
ok "$ID.malformed" "invalid approval was skipped once and the following blocked event was persisted"

qa_admin "$DB" \
    "CREATE TABLE public.qa_c1_fail (id integer PRIMARY KEY, blocked boolean NOT NULL)" \
    "INSERT INTO public.qa_c1_fail VALUES (1, true)" \
    "CREATE FUNCTION public.qa_c1_block() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c1_fail WHERE id = 1 AND blocked) THEN RAISE EXCEPTION 'qa_c1 blocked' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END \$\$" \
    "CREATE TRIGGER qa_c1_block BEFORE INSERT ON public.sql_firewall_blocked_queries FOR EACH ROW EXECUTE FUNCTION public.qa_c1_block()" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }

qa_admin "$DB" \
    "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
target_pid=${QA_STEP_OUT[1]}
[[ $target_pid =~ ^[0-9]+$ ]] || { infra "$ID.snapshot" "worker pid '$target_pid'"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_arm(${target_pid})" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
hold_deadline=$((SECONDS + 10))
quiescent=
while ((SECONDS < hold_deadline)); do
    qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_status()" ||
        { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
    case ${QA_STEP_OUT[1]} in
        quiescent\ pid=${target_pid}\ *)
            quiescent=${QA_STEP_OUT[1]}
            break
            ;;
        exited\ *)
            infra "$ID.snapshot" "worker exited before the snapshot case (${QA_STEP_OUT[1]})"
            exit 0
            ;;
    esac
    sleep 0.2
done
[[ -n $quiescent ]] || { infra "$ID.snapshot" "worker did not quiesce"; exit 0; }

qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_stats()" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
stats=${QA_STEP_OUT[1]}
start=${stats#publications=}
start=${start%% *}
cap=${stats#*capacity=}
[[ $start =~ ^[0-9]+$ && $cap =~ ^[0-9]+$ ]] || { infra "$ID.snapshot" "stats '$stats'"; exit 0; }
release_hold

qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(1, 'qa_c1_snap')" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
snap_deadline=$((SECONDS + 15))
saw_retry=0
while ((SECONDS < snap_deadline)); do
    if grep -F "retry database oid" "$QA_SERVER_LOG" | grep -F "position ${start} " | grep -F "type blocked_query" | grep -F "SQLSTATE P0001" >/dev/null; then
        saw_retry=1
        break
    fi
    sleep 0.2
done
if [[ $saw_retry -ne 1 ]]; then
    fail "$ID.snapshot.attempt" "position $start was not retried with SQLSTATE P0001"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_snap-0') > 0" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.snapshot.rollback" "snapshot marker was visible before repair"
    exit 0
fi

extra=$((cap + 5))
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(${extra}, 'qa_c1_pad')" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "UPDATE public.qa_c1_fail SET blocked = false WHERE id = 1" ||
    { infra "$ID.snapshot" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_snap-0') > 0" \
    1 20; then
    fail "$ID.snapshot.persist" "copied event was not persisted after its ring slot was overwritten (${QA_INFRA_REASON:-})"
    exit 0
fi
gap_from=$((start + 1))
if ! grep -F "skipped shared-stream positions [${gap_from}," "$QA_SERVER_LOG" >/dev/null; then
    fail "$ID.snapshot.gap" "no gap starting at position ${gap_from} after the copied event committed"
    exit 0
fi
if grep -F "skipped shared-stream positions [${start}," "$QA_SERVER_LOG" >/dev/null; then
    fail "$ID.snapshot.gap" "gap included the successfully handled position ${start}"
    exit 0
fi
ok "$ID.snapshot" "position ${start} committed from the copied event after overwrite; gap starts at ${gap_from} (${quiescent})"

exit 0
