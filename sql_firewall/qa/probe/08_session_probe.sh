#!/usr/bin/env bash
# session_probe build only (16-entry rate table; a background worker of this
# library that runs one statement as a role). Run with:
#   QA_CARGO_FEATURES=session_probe QA_TEST_DIR=sql_firewall/qa/probe \
#     sql_firewall/qa/run.sh --only '08*'
#
# Contract:
#   rate.full       with every counter active, a new role's attempt is
#                   refused (fail closed) instead of evicting a counter
#   rate.no_evict   a role at its limit stays at its limit while the table is
#                   full (its counter was not reset)
#   rate.reuse      after the windows end, expired counters are reused
#   rate.mixed_windows a short-window collision cannot evict an active long
#                      window belonging to another role
#   worker          a background worker that is not the firewall's launcher
#                   or consumer (like pg_cron's job runners) is inspected: its
#                   unapproved statement is refused and recorded, and runs
#                   once approved
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.session_probe
EV=session_probe
DB=qa_sprobe

ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }

qa_evidence "$EV" "# $ID" ""
qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=off sql_firewall.enable_regex_scan=off ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT count(*) FROM pg_proc WHERE proname = 'sql_firewall_session_probe_worker'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == 1 ]] || { infra "$ID" "not a session_probe build"; exit 0; }

steps=("CREATE TABLE public.sp_t (id integer)")
for i in $(seq 1 17); do
    r=qa_spr_$i
    steps+=("CREATE ROLE $r LOGIN NOSUPERUSER" "GRANT CONNECT ON DATABASE $DB TO $r" "GRANT SELECT ON public.sp_t TO $r"
        "ALTER ROLE $r IN DATABASE $DB SET sql_firewall.command_limit_seconds = '4'"
        "ALTER ROLE $r IN DATABASE $DB SET sql_firewall.select_limit_count = '$([[ $i == 1 ]] && echo 1 || echo 100)'"
        "SELECT public.sql_firewall_approve_command('$r', 'SELECT')")
done
qa_admin "$DB" "${steps[@]}" || { infra "$ID.rate" "$QA_INFRA_REASON"; exit 0; }

q="SELECT count(*) FROM public.sp_t"
outcome() { # ROLE -> OUT (allow | SQLSTATE:message)
    qa_sql_steps "$1" "$DB" qa_sprobe "$q" || { OUT="infra: $QA_INFRA_REASON"; return; }
    if [[ ${QA_STEP_ERR[1]} == false ]]; then OUT=allow; else OUT="${QA_STEP_STATE[1]}:${QA_STEP_MSG[1]:-}"; fi
}
FULL="53400:sql_firewall: Rate-limit state is full; the statement of role 'qa_spr_17' was not counted and is refused."
LIMIT1="53400:sql_firewall: Rate limit for command 'SELECT' exceeded for role 'qa_spr_1'"
fills=""
for i in $(seq 1 16); do outcome qa_spr_$i; fills+="$OUT "; done
outcome qa_spr_1; at_limit=$OUT
outcome qa_spr_17; full=$OUT
outcome qa_spr_1; still=$OUT
qa_evidence "$EV" "- 16 roles: $fills" "- qa_spr_1 again: $at_limit" "- qa_spr_17: $full" "- qa_spr_1 while full: $still"
if [[ $fills == "$(printf 'allow %.0s' $(seq 1 16))" && $full == "$FULL" ]]; then
    ok "$ID.rate.full" "16 counters in use; the 17th role was refused: $full"
else
    fail "$ID.rate.full" "fills: $fills; 17th: $full"
fi
if [[ $at_limit == "$LIMIT1" && $still == "$LIMIT1" ]]; then
    ok "$ID.rate.no_evict" "qa_spr_1 at its limit of 1 stayed refused while the table was full: its counter was not evicted"
else
    fail "$ID.rate.no_evict" "qa_spr_1: $at_limit, then $still"
fi
sleep 4.3
outcome qa_spr_17; reuse=$OUT
if [[ $reuse == allow ]]; then
    ok "$ID.rate.reuse" "after the 4 s windows ended the 17th role was counted in a reused slot"
else
    fail "$ID.rate.reuse" "17th role after the windows: $reuse"
fi

# Seventeen new role OIDs guarantee a collision in the 16-slot probe table.
# Exercise the real hash and collision path after earlier 4 s entries expire.
sleep 4.3
steps=()
for i in $(seq 1 17); do
    r=qa_spr_col_$i
    steps+=("CREATE ROLE $r LOGIN NOSUPERUSER" "GRANT CONNECT ON DATABASE $DB TO $r"
        "GRANT SELECT ON public.sp_t TO $r" "SELECT public.sql_firewall_approve_command('$r', 'SELECT')")
done
qa_admin "$DB" "${steps[@]}" \
    "SELECT oid::text || '|' || rolname FROM pg_catalog.pg_roles WHERE rolname ~ '^qa_spr_col_[0-9]+$' ORDER BY oid" \
    "SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname = current_database()" ||
    { infra "$ID.rate.mixed_windows" "$QA_INFRA_REASON"; exit 0; }
roles=${QA_STEP_OUT[${#steps[@]}+1]}
db_oid=${QA_STEP_OUT[${#steps[@]}+2]}
pair=$(QA_COLLISION_ROLES="$roles" QA_COLLISION_DB="$db_oid" python3 -c '
import os
seen = {}
db = int(os.environ["QA_COLLISION_DB"])
for line in os.environ["QA_COLLISION_ROLES"].splitlines():
    oid, name = line.split("|", 1)
    h = 0xcbf29ce484222325
    for b in db.to_bytes(4, "little") + int(oid).to_bytes(4, "little") + bytes([1]):
        h = ((h ^ b) * 0x100000001b3) & ((1 << 64) - 1)
    bucket = h % 16
    if bucket in seen:
        print(seen[bucket], name)
        break
    seen[bucket] = name
')
read -r victim intruder <<<"$pair"
[[ -n $victim && -n $intruder ]] || { infra "$ID.rate.mixed_windows" "no collision found for 17 roles"; exit 0; }
qa_admin "$DB" "ALTER ROLE $victim IN DATABASE $DB SET sql_firewall.select_limit_count = '1'" \
    "ALTER ROLE $victim IN DATABASE $DB SET sql_firewall.command_limit_seconds = '3600'" \
    "ALTER ROLE $intruder IN DATABASE $DB SET sql_firewall.select_limit_count = '10'" \
    "ALTER ROLE $intruder IN DATABASE $DB SET sql_firewall.command_limit_seconds = '1'" ||
    { infra "$ID.rate.mixed_windows" "$QA_INFRA_REASON"; exit 0; }
outcome "$victim"; first=$OUT
outcome "$victim"; refused=$OUT
sleep 1.2
outcome "$intruder"; other=$OUT
outcome "$victim"; after=$OUT
qa_evidence "$EV" "- collision: $victim / $intruder" "- before/after: $first / $refused / $other / $after"
if [[ $first == allow && $refused == "53400:sql_firewall: Rate limit for command 'SELECT' exceeded for role '$victim'" &&
      $other == allow && $after == "$refused" ]]; then
    ok "$ID.rate.mixed_windows" "the short-window role did not erase $victim's active 3600 s counter"
else
    fail "$ID.rate.mixed_windows" "first=$first, refused=$refused, other=$other, after=$after"
fi

# A background worker that is not the firewall's own is inspected.
LOG0=$(qa_server_log_offset)
qa_admin "$DB" "CREATE ROLE qa_spr_job LOGIN NOSUPERUSER" "GRANT SELECT ON public.sp_t TO qa_spr_job" \
    "SELECT public.sql_firewall_session_probe_worker('qa_spr_job', 'SELECT count(*) FROM public.sp_t')" ||
    { infra "$ID.worker" "$QA_INFRA_REASON"; exit 0; }
first=$(tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG" | grep -o 'sql_firewall session probe: role=qa_spr_job .*' | tail -1)
qa_poll "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE role_name = 'qa_spr_job'" 1 20 ||
    { infra "$ID.worker" "blocked row: $QA_INFRA_REASON"; exit 0; }
LOG1=$(qa_server_log_offset)
qa_admin "$DB" "SELECT public.sql_firewall_approve_command('qa_spr_job', 'SELECT')" \
    "SELECT public.sql_firewall_session_probe_worker('qa_spr_job', 'SELECT count(*) FROM public.sp_t')" ||
    { infra "$ID.worker" "$QA_INFRA_REASON"; exit 0; }
second=$(tail -c +"$((LOG1 + 1))" "$QA_SERVER_LOG" | grep -o 'sql_firewall session probe: role=qa_spr_job .*' | tail -1)
qa_evidence "$EV" "- worker, unapproved: $first" "- worker, approved: $second"
if [[ $first == *'outcome=ERROR 42501'* && $second == *'outcome=OK'* ]]; then
    ok "$ID.worker" "a non-firewall background worker's statement was refused (42501, recorded as a blocked query) until the role's SELECT was approved"
else
    fail "$ID.worker" "unapproved: '$first'; approved: '$second'"
fi
exit 0
