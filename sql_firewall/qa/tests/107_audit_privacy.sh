#!/usr/bin/env bash
# Phase 7: who can read policy and audit data, and who can write audit rows.
#
# Contract (README 6.1b "Who can read policy", 6.7, 6.8):
#   rls        an ordinary role selects only its own command approvals and
#              fingerprints (its own sample queries), not another role's,
#              and its own policy still decides its statements
#   readers    a member of pg_read_all_data and a superuser see every row; a
#              role granted UPDATE on the table sees only its own rows
#   write_grant that UPDATE grant does not let the role change policy
#              (sql_firewall_guard, README 6.1b)
#   logs       an ordinary role cannot read the activity log, the
#              blocked-query log, the decision history, or the runtime tables
#   forgery    an ordinary role cannot call sql_firewall_internal_log_activity
#              or write the audit tables, so no row can look like a firewall
#              decision it did not make
#   notify     the NOTIFY payload carries the event, the blocked row's id, and
#              the command family only; the id names the committed row
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.audit_privacy
EV=audit_privacy
DB=qa_privacy
A=qa_priv_a B=qa_priv_b AUD=qa_priv_auditor WR=qa_priv_writer

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" "Row security on the policy tables, audit table privileges, forgery, and the NOTIFY payload." ""

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=on \
    sql_firewall.enable_alert_notifications=on sql_firewall.alert_channel=qa_priv_events ||
    { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE $A LOGIN NOSUPERUSER" "CREATE ROLE $B LOGIN NOSUPERUSER" \
    "CREATE ROLE $AUD LOGIN NOSUPERUSER" "CREATE ROLE $WR LOGIN NOSUPERUSER" \
    "GRANT pg_read_all_data TO $AUD" \
    "GRANT CONNECT ON DATABASE $DB TO $A, $B, $AUD, $WR" \
    "ALTER ROLE $A IN DATABASE $DB SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE $A IN DATABASE $DB SET sql_firewall.fingerprint_learn_threshold = 1" \
    "ALTER ROLE $B IN DATABASE $DB SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE $B IN DATABASE $DB SET sql_firewall.fingerprint_learn_threshold = 1" \
    "ALTER ROLE $AUD IN DATABASE $DB SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE $WR IN DATABASE $DB SET sql_firewall.mode = 'learn'" ||
    { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "CREATE TABLE public.qa_priv_t (id integer, secret text)" \
    "INSERT INTO public.qa_priv_t VALUES (1, 'x')" \
    "GRANT SELECT ON public.qa_priv_t TO $A, $B" \
    "GRANT UPDATE ON public.sql_firewall_command_approvals TO $WR" ||
    { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }

# Each learn role leaves an approval and a fingerprint with its own sample.
for role in $A $B; do
    qa_sql_steps "$role" "$DB" qa_priv "SELECT secret FROM public.qa_priv_t WHERE secret = 'sample_of_$role'" ||
        { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
done
qa_poll "$DB" "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name IN ('$A', '$B')" 2 30 ||
    { infra "$ID.setup" "learned rows: $QA_INFRA_REASON"; exit 0; }

# Rows of A and B only: the reading roles run in learn mode and add rows of
# their own, and those readings' samples do not start with the probed text.
visible() { # ROLE -> VISIBLE "approval roles|fingerprint roles|samples"
    qa_sql_steps "$1" "$DB" qa_priv \
        "SELECT coalesce(string_agg(DISTINCT role_name::text, ',' ORDER BY role_name::text), '') FROM public.sql_firewall_command_approvals WHERE role_name IN ('$A', '$B')" \
        "SELECT coalesce(string_agg(DISTINCT role_name::text, ',' ORDER BY role_name::text), '') FROM public.sql_firewall_query_fingerprints WHERE role_name IN ('$A', '$B')" \
        "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE sample_query LIKE 'SELECT secret FROM public.qa_priv_t%'" || return
    VISIBLE="${QA_STEP_OUT[1]}|${QA_STEP_OUT[2]}|${QA_STEP_OUT[3]}"
    VISIBLE_ERR="${QA_STEP_ERR[1]}${QA_STEP_ERR[2]}${QA_STEP_ERR[3]}"
}

if visible $A; then
    qa_evidence "$EV" "- $A sees: $VISIBLE"
    if [[ $VISIBLE_ERR == falsefalsefalse && $VISIBLE == "$A|$A|1" ]]; then
        ok "$ID.rls" "$A saw only its own approval and fingerprint rows (and its own sample), not $B's"
    else
        fail "$ID.rls" "$A saw '$VISIBLE' (errors $VISIBLE_ERR)"
    fi
else
    infra "$ID.rls" "$QA_INFRA_REASON"
fi

# Its own policy still decides: in enforce, A's learned SELECT is allowed and
# an unlearned command is not.
qa_admin postgres "ALTER ROLE $A IN DATABASE $DB SET sql_firewall.mode = 'enforce'" || { infra "$ID.rls_policy" "$QA_INFRA_REASON"; exit 0; }
qa_check_success $A "$DB" qa_priv "SELECT secret FROM public.qa_priv_t WHERE secret = 'sample_of_$A'"
own=$QA_VERDICT
qa_check_rejection $A "$DB" qa_priv "DELETE FROM public.qa_priv_t" 42501 "^sql_firewall: No rule found for command 'DELETE' for role '$A'\$"
other=$QA_VERDICT
if [[ $own == PASS && $other == PASS ]]; then
    ok "$ID.rls_policy" "under row security $A's learned SELECT and fingerprint allowed it in enforce, and an unlearned DELETE was rejected"
else
    fail "$ID.rls_policy" "own statement: $own; unlearned DELETE: $other ($QA_DETAIL)"
fi

readers=""
for role in $AUD $WR; do
    visible $role || { infra "$ID.readers" "$QA_INFRA_REASON"; exit 0; }
    readers+="$role=$VISIBLE;"
done
qa_admin "$DB" "SELECT count(DISTINCT role_name) FROM public.sql_firewall_query_fingerprints WHERE role_name IN ('$A', '$B')" ||
    { infra "$ID.readers" "$QA_INFRA_REASON"; exit 0; }
su_fp=${QA_STEP_OUT[1]}
qa_evidence "$EV" "- readers: $readers superuser fingerprint roles=$su_fp"
if [[ $readers == *"$AUD=$A,$B|$A,$B|2;"* && $readers == *"$WR=||0;"* && $su_fp == 2 ]]; then
    ok "$ID.readers" "a pg_read_all_data member saw every approval and fingerprint row, a role granted UPDATE on approvals saw none of the other roles' rows, and the superuser saw all"
else
    fail "$ID.readers" "readers: $readers superuser=$su_fp"
fi
# The UPDATE grant does not let that role change policy either (README 6.1b).
qa_check_rejection $WR "$DB" qa_priv "UPDATE public.sql_firewall_command_approvals SET is_approved = true" 42501 \
    "^sql_firewall: only a superuser session can change sql_firewall_command_approvals; "
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.write_grant" "a role granted UPDATE on the approvals table was refused by sql_firewall_guard: $QA_DETAIL"
else
    qa_record "$QA_VERDICT" "$ID.write_grant" "$QA_DETAIL"
fi

denied=""
for rel in sql_firewall_activity_log sql_firewall_blocked_queries sql_firewall_policy_history sql_firewall_consumer_checkpoint sql_firewall_activity_checkpoint sql_firewall_retention_status; do
    qa_sql_steps $B "$DB" qa_priv "SELECT count(*) FROM public.$rel" || { infra "$ID.logs" "$QA_INFRA_REASON"; exit 0; }
    [[ ${QA_STEP_ERR[1]} == true && ${QA_STEP_STATE[1]} == 42501 && ${QA_STEP_MSG[1]} == "permission denied for table $rel" ]] || denied+=" $rel:${QA_STEP_STATE[1]}"
done
if [[ -z $denied ]]; then
    ok "$ID.logs" "an ordinary role got native 42501 for the activity and blocked-query logs, the decision history, and the three runtime tables"
else
    fail "$ID.logs" "readable or other outcome:$denied"
fi

qa_sql_steps $B "$DB" qa_priv \
    "SELECT public.sql_firewall_internal_log_activity('$A', '$DB', 'forged', NULL, NULL, 'SELECT', 'ALLOWED', 'forged')" \
    "INSERT INTO public.sql_firewall_activity_log (role_name, query_text, action) VALUES ('$A', 'forged', 'ALLOWED')" \
    "INSERT INTO public.sql_firewall_blocked_queries (role_name, query_text) VALUES ('$A', 'forged')" ||
    { infra "$ID.forgery" "$QA_INFRA_REASON"; exit 0; }
f1="${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}" f2="${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-}" f3="${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
qa_admin "$DB" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text = 'forged'" \
    "SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE query_text = 'forged'" || { infra "$ID.forgery" "$QA_INFRA_REASON"; exit 0; }
if [[ $f1 == "42501 permission denied for function sql_firewall_internal_log_activity" &&
    $f2 == "42501 permission denied for table sql_firewall_activity_log" &&
    $f3 == "42501 permission denied for table sql_firewall_blocked_queries" &&
    ${QA_STEP_OUT[1]} == 0 && ${QA_STEP_OUT[2]} == 0 ]]; then
    ok "$ID.forgery" "an ordinary role could neither call the activity-log function nor insert audit rows (native 42501); no forged row exists"
else
    fail "$ID.forgery" "function: $f1; activity insert: $f2; blocked insert: $f3; forged rows ${QA_STEP_OUT[1]}/${QA_STEP_OUT[2]}"
fi

# NOTIFY: an ordinary role can LISTEN; the payload is minimal.
listen_sql="$QA_RUN_DIR/privacy-listen.sql"
listen_out="$QA_RUN_DIR/privacy-listen.out"
cat >"$listen_sql" <<'SQL'
LISTEN qa_priv_events;
\echo QA_LISTEN_READY
SELECT pg_catalog.pg_sleep(6);
SQL
env PGAPPNAME=qa_priv_listener PGCONNECT_TIMEOUT=10 timeout 15 "$QA_PSQL" -X -A -t -h "$QA_SOCK" -p "$QA_PORT" \
    -U $B -d "$DB" -f "$listen_sql" >"$listen_out" 2>"$listen_out.err" &
listener=$!
deadline=$((SECONDS + 5))
until grep -q QA_LISTEN_READY "$listen_out" || ((SECONDS >= deadline)); do sleep 0.1; done
qa_check_rejection $A "$DB" qa_priv "DELETE FROM public.qa_priv_t WHERE id = 42" 42501 "^sql_firewall: No rule found for command 'DELETE' for role '$A'\$"
wait "$listener" || true
qa_poll "$DB" "SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE query_text = 'DELETE FROM public.qa_priv_t WHERE id = 42'" 1 20 ||
    { infra "$ID.notify" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT block_id FROM public.sql_firewall_blocked_queries WHERE query_text = 'DELETE FROM public.qa_priv_t WHERE id = 42'" ||
    { infra "$ID.notify" "$QA_INFRA_REASON"; exit 0; }
block_id=${QA_STEP_OUT[1]}
payload=$(grep -o '{"event":[^}]*}' "$listen_out" | head -1)
qa_evidence "$EV" "- listener ($B) output: $(tr '\n' ' ' <"$listen_out" | head -c 400)"
if [[ $payload == "{\"event\":\"query_block\",\"block_id\":$block_id,\"command\":\"DELETE\"}" ]]; then
    ok "$ID.notify" "an ordinary listener received only $payload; role, client, application, and reason stay in row $block_id"
else
    fail "$ID.notify" "payload '$payload' (block_id $block_id)"
fi
exit 0
