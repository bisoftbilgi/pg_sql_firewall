#!/usr/bin/env bash
# Baseline 4: an ordinary role cannot administer the firewall.
#
# Contract:
#   A. With no extra grants, every superuser-only management call is denied
#      with SQLSTATE 42501 and "permission denied for function ...". Both
#      pg_user shadows (default search_path, and search_path starting at
#      pg_temp) are denied the same way. Seeded rows that an update or delete
#      would change stay unchanged.
#   B. After GRANT EXECUTE to the test role only, the same shadows are still
#      denied by the function body (SQLSTATE 42501, "Only superusers ...").
#      Those grants exist only in the disposable database.
#   C. A superuser still performs the operations while its session has a
#      hostile search_path and a lying temporary pg_user. Catalog rows change.
#   D. A fresh install reports version 0.0.0 and rejects the original attacks.
#
# A missing function, a firewall-policy error, or a failed attack setup is
# INFRA, never PASS. An allowed call, or a seeded row that changes, is FAIL.
# Runs only inside the disposable cluster.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.admin_privilege_boundary
DB=qa_privilege
BODY_DB=qa_privilege_body
SUPER_DB=qa_privilege_super
ROLE=qa_attacker
TARGET=qa_priv_target
APP=qa_attacker_client
EV=admin_privilege_boundary
SHADOW="CREATE TEMP VIEW pg_user AS SELECT '$ROLE'::name AS usename, true AS usesuper"
PATH_SET="SET search_path = pg_temp, pg_catalog, public"
HOSTILE_VIEW="CREATE TEMP VIEW pg_user AS SELECT '${QA_SUPERUSER}'::name AS usename, false AS usesuper"
HOSTILE_PATH="SET search_path = pg_temp, public"

infra() { qa_record INFRA "$1" "$2"; qa_evidence $EV "" "**$1: INFRA** - $2"; }

qa_evidence $EV "# $ID" "" \
    "Ordinary logins are denied (42501 permission denied for function) even if they shadow pg_user. With EXECUTE granted, the body still denies (42501 Only superusers...). A superuser succeeds under a hostile search_path. The fresh 0.0.0 installation preserves seeded rows." ""

# Stable view of rows an attacker must not be able to change. Limited to the
# seeded markers so unrelated worker output cannot move the snapshot.
CATALOG_SQL="SELECT concat_ws(E'\n',
  'approvals=' || coalesce((SELECT string_agg(role_name || ':' || command_type || '=' || is_approved::text, ',' ORDER BY role_name, command_type) FROM public.sql_firewall_command_approvals WHERE role_name = '$TARGET'), ''),
  'fingerprints=' || coalesce((SELECT string_agg(fingerprint || '=' || is_approved::text || ':' || hit_count::text, ',' ORDER BY fingerprint) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$TARGET'), ''),
  'rules=' || coalesce((SELECT string_agg(pattern || '=' || is_active::text, ',' ORDER BY pattern) FROM public.sql_firewall_regex_rules WHERE pattern LIKE 'qa_phase2a%'), ''),
  'activity=' || coalesce((SELECT string_agg(query_text, ',' ORDER BY query_text) FROM public.sql_firewall_activity_log WHERE query_text LIKE 'QA_%'), ''),
  'blocked=' || coalesce((SELECT string_agg(query_text, ',' ORDER BY query_text) FROM public.sql_firewall_blocked_queries WHERE query_text LIKE 'QA_%'), ''))"

snap_catalog() { # DB -> CATALOG_NOW, or return INFRA
    CATALOG_NOW=
    qa_admin "$1" "$CATALOG_SQL" || return $?
    CATALOG_NOW=${QA_STEP_OUT[1]}
}

seed_markers() { # DB -> RULE_ID
    local db=$1
    RULE_ID=
    qa_admin "$db" \
        "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$TARGET', 'UPDATE', true)" \
        "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('qa-fp-approved', 'SELECT QA_APPROVED', '$TARGET', 'SELECT', 'select qa_approved', 3, true), ('qa-fp-pending', 'SELECT QA_PENDING', '$TARGET', 'SELECT', 'select qa_pending', 1, false)" \
        "INSERT INTO public.sql_firewall_regex_rules (pattern, description, is_active) VALUES ('qa_phase2a_seed_pattern', 'seed', true) RETURNING id::text" \
        "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) VALUES (now() - interval '400 days', '$TARGET', current_database(), 'QA_OLD_ACTIVITY', 'SELECT', 'ALLOWED', 'seed-old'), (now(), '$TARGET', current_database(), 'QA_NEW_ACTIVITY', 'SELECT', 'ALLOWED', 'seed-new')" \
        "INSERT INTO public.sql_firewall_blocked_queries (blocked_at, role_name, database_name, query_text, command_type, reason) VALUES (now() - interval '400 days', '$TARGET', current_database(), 'QA_OLD_BLOCKED', 'SELECT', 'seed-old'), (now(), '$TARGET', current_database(), 'QA_NEW_BLOCKED', 'SELECT', 'seed-new')" ||
        return $?
    RULE_ID=${QA_STEP_OUT[3]}
    [[ $RULE_ID =~ ^[0-9]+$ ]] || { QA_INFRA_REASON="regex seed id not numeric: '$RULE_ID'"; return 10; }
}

# Meaningful seed: an update/delete that ran would change at least one marker.
seed_ok() {
    local s=$1
    [[ $s == *$'approvals='"$TARGET:UPDATE=true"* &&
        $s == *'qa-fp-approved=true:3'* && $s == *'qa-fp-pending=false:1'* &&
        $s == *'qa_phase2a_seed_pattern=true'* &&
        $s == *'QA_OLD_ACTIVITY'* && $s == *'QA_NEW_ACTIVITY'* &&
        $s == *'QA_OLD_BLOCKED'* && $s == *'QA_NEW_BLOCKED'* ]]
}

# name|sql|body message   (RULE_ID must already be set)
management_calls() {
    cat <<EOF
approve_command|SELECT public.sql_firewall_approve_command('$TARGET', 'DROP')|Only superusers can approve commands
revoke_command|SELECT public.sql_firewall_revoke_command('$TARGET', 'UPDATE')|Only superusers can revoke commands
approve_fingerprint|SELECT public.sql_firewall_approve_fingerprint('qa-fp-pending', '$TARGET', 'SELECT')|Only superusers can approve fingerprints
block_fingerprint|SELECT public.sql_firewall_block_fingerprint('qa-fp-approved', '$TARGET', 'SELECT')|Only superusers can block fingerprints
add_regex_rule|SELECT public.sql_firewall_add_regex_rule('qa_phase2a_attacker_pattern', 'x')|Only superusers can add regex rules
delete_regex_rule|SELECT public.sql_firewall_delete_regex_rule($RULE_ID)|Only superusers can delete regex rules
toggle_regex_rule|SELECT public.sql_firewall_toggle_regex_rule($RULE_ID, false)|Only superusers can modify regex rules
cleanup_activity_log|SELECT public.sql_firewall_cleanup_activity_log('1 day')|Only superusers can cleanup firewall logs
cleanup_blocked_queries|SELECT public.sql_firewall_cleanup_blocked_queries('1 day')|Only superusers can cleanup firewall logs
cleanup_all_logs|SELECT public.sql_firewall_cleanup_all_logs('1 day', '1 day')|Only superusers can cleanup firewall logs
truncate_logs|SELECT public.sql_firewall_truncate_logs()|Only superusers can truncate firewall logs
internal_upsert_approval|SELECT public.sql_firewall_internal_upsert_approval('$TARGET', 'COMMENT', true)|Only superusers can use this internal function
EOF
}

# run_denied DB ID_PREFIX MODE SETUP...
# MODE=acl    expect 42501 permission denied for function (body must not run)
# MODE=body   expect 42501 and that function's "Only superusers" message
run_denied() {
    local db=$1 id_prefix=$2 mode=$3
    shift 3
    local -a setup=("$@") names=() sqls=() msgs=()
    local line n s m
    while IFS='|' read -r n s m; do
        names+=("$n"); sqls+=("$s"); msgs+=("$m")
    done < <(management_calls)
    local ran=0
    if ((${#setup[@]})); then
        qa_sql_steps "$ROLE" "$db" "$APP" "${setup[@]}" "${sqls[@]}" && ran=1
    else
        qa_sql_steps "$ROLE" "$db" "$APP" "${sqls[@]}" && ran=1
    fi
    if ((ran == 0)); then
        infra "$id_prefix" "$QA_INFRA_REASON"
        return
    fi
    local i setup_n=${#setup[@]}
    for ((i = 1; i <= setup_n; i++)); do
        if [[ ${QA_STEP_ERR[i]} == true ]]; then
            infra "$id_prefix" "attack setup step $i failed: ${QA_STEP_STATE[i]} ${QA_STEP_MSG[i]:-}"
            return
        fi
    done
    local j idx st msg want
    for ((j = 0; j < ${#names[@]}; j++)); do
        idx=$((setup_n + j + 1))
        st=${QA_STEP_STATE[idx]}
        msg=${QA_STEP_MSG[idx]:-}
        if [[ $mode == acl ]]; then
            want="^permission denied for function sql_firewall_${names[j]}\$"
        else
            want="^${msgs[j]}\$"
        fi
        qa_judge_rejection "$idx" 42501 "$want"
        if [[ $mode == acl && $QA_VERDICT == INFRA && $msg == Only\ superusers* ]]; then
            QA_VERDICT=FAIL
            QA_DETAIL="function body ran ($st $msg); PUBLIC EXECUTE was not revoked"
        elif [[ $mode == body && $QA_VERDICT == INFRA && $msg == permission\ denied\ for\ function* ]]; then
            QA_VERDICT=INFRA
            QA_DETAIL="body check not reached ($st $msg); EXECUTE grant did not take effect"
        fi
        qa_evidence $EV "## $ID.$id_prefix.${names[j]}" \
            "- call: \`${sqls[j]}\`" "- outcome: $QA_DETAIL"
        qa_record "$QA_VERDICT" "$ID.$id_prefix.${names[j]}" "$QA_DETAIL"
    done
    if ! snap_catalog "$db"; then
        infra "$ID.$id_prefix.catalog" "catalog verification failed: $QA_INFRA_REASON"
        return
    fi
    qa_evidence $EV "## $ID.$id_prefix.catalog" "- snapshot:" '```' "$CATALOG_NOW" '```'
    if [[ $CATALOG_NOW != "$CATALOG_BEFORE" ]]; then
        qa_record FAIL "$ID.$id_prefix.catalog" "seeded catalog changed: [$CATALOG_BEFORE] -> [$CATALOG_NOW]"
    elif ! seed_ok "$CATALOG_NOW"; then
        infra "$ID.$id_prefix.catalog" "seed markers missing from snapshot: $CATALOG_NOW"
    else
        qa_record PASS "$ID.$id_prefix.catalog" "seeded approvals, fingerprints, regex rule, and log rows unchanged"
    fi
}

# ---------------------------------------------------------------------------
# Fresh 0.0.0 install
# ---------------------------------------------------------------------------
qa_create_db $DB sql_firewall.mode=learn || { infra "$ID" "setup: $QA_INFRA_REASON"; exit 0; }
qa_admin $DB \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" \
    "CREATE ROLE $TARGET NOLOGIN" \
    "SELECT extversion FROM pg_extension WHERE extname = 'sql_firewall'" \
    "SELECT rolsuper::text FROM pg_roles WHERE rolname = '$ROLE'" \
    "SELECT has_database_privilege('$ROLE', '$DB', 'TEMP')::text" ||
    { infra "$ID" "setup: $QA_INFRA_REASON"; exit 0; }
qa_evidence $EV "- fresh install extversion=${QA_STEP_OUT[3]} $ROLE rolsuper=${QA_STEP_OUT[4]} TEMP=${QA_STEP_OUT[5]}"
if [[ ${QA_STEP_OUT[3]} != 0.0.0 || ${QA_STEP_OUT[4]} != false || ${QA_STEP_OUT[5]} != true ]]; then
    infra "$ID" "precondition not met (extversion=${QA_STEP_OUT[3]} rolsuper=${QA_STEP_OUT[4]} TEMP=${QA_STEP_OUT[5]})"
    exit 0
fi
if ! qa_verify_mode_context $DB $ROLE learn; then
    infra "$ID" "$QA_INFRA_REASON"
    exit 0
fi

META_SQL="SELECT string_agg(proname || '|' || pg_get_function_identity_arguments(oid) || '|' || prosecdef::text || '|' || coalesce(proconfig[1], '') || '|' || has_function_privilege('public', oid, 'EXECUTE')::text, E'\n' ORDER BY proname)
FROM pg_proc
WHERE pronamespace = 'public'::regnamespace
  AND proname IN (
    'sql_firewall_approve_command','sql_firewall_revoke_command',
    'sql_firewall_approve_fingerprint','sql_firewall_block_fingerprint',
    'sql_firewall_add_regex_rule','sql_firewall_delete_regex_rule','sql_firewall_toggle_regex_rule',
    'sql_firewall_cleanup_activity_log','sql_firewall_cleanup_blocked_queries',
    'sql_firewall_cleanup_all_logs','sql_firewall_truncate_logs',
    'sql_firewall_internal_upsert_approval','sql_firewall_internal_log_activity',
    'sql_firewall_internal_log_blocked_query','sql_firewall_internal_upsert_fingerprint')"
META_EXPECT=$(cat <<'EOF'
sql_firewall_add_regex_rule|p_pattern text, p_description text|true|search_path=pg_catalog, pg_temp|false
sql_firewall_approve_command|p_role_name name, p_command_type text|true|search_path=pg_catalog, pg_temp|false
sql_firewall_approve_fingerprint|p_fingerprint text, p_role_name name, p_command_type text|true|search_path=pg_catalog, pg_temp|false
sql_firewall_block_fingerprint|p_fingerprint text, p_role_name name, p_command_type text|true|search_path=pg_catalog, pg_temp|false
sql_firewall_cleanup_activity_log|p_retention_interval interval|true|search_path=pg_catalog, pg_temp|false
sql_firewall_cleanup_all_logs|p_activity_retention interval, p_blocked_retention interval|true|search_path=pg_catalog, pg_temp|false
sql_firewall_cleanup_blocked_queries|p_retention_interval interval|true|search_path=pg_catalog, pg_temp|false
sql_firewall_delete_regex_rule|p_rule_id integer|true|search_path=pg_catalog, pg_temp|false
sql_firewall_internal_log_activity|p_role_name name, p_database_name name, p_query_text text, p_application_name text, p_client_ip text, p_command_type text, p_action text, p_reason text|true|search_path=pg_catalog, public|false
sql_firewall_internal_log_blocked_query|p_role_name name, p_database_name name, p_query_text text, p_application_name text, p_client_ip text, p_command_type text, p_block_reason text|true||false
sql_firewall_internal_upsert_approval|p_role_name name, p_command_type text, p_is_approved boolean|true|search_path=pg_catalog, pg_temp|false
sql_firewall_internal_upsert_fingerprint|p_fingerprint text, p_normalized_query text, p_role_name name, p_command_type text, p_sample_query text, p_is_approved boolean|true||false
sql_firewall_revoke_command|p_role_name name, p_command_type text|true|search_path=pg_catalog, pg_temp|false
sql_firewall_toggle_regex_rule|p_rule_id integer, p_is_active boolean|true|search_path=pg_catalog, pg_temp|false
sql_firewall_truncate_logs||true|search_path=pg_catalog, pg_temp|false
EOF
)

check_meta() { # DB ID
    if ! qa_admin "$1" "$META_SQL" \
        "SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname IN ('sql_firewall_approve_command','sql_firewall_revoke_command','sql_firewall_approve_fingerprint','sql_firewall_block_fingerprint','sql_firewall_add_regex_rule','sql_firewall_delete_regex_rule','sql_firewall_toggle_regex_rule','sql_firewall_cleanup_activity_log','sql_firewall_cleanup_blocked_queries','sql_firewall_cleanup_all_logs','sql_firewall_truncate_logs','sql_firewall_internal_upsert_approval') AND prosrc LIKE '%pg_catalog.pg_authid%' AND prosrc NOT LIKE '%FROM pg_user%' AND prosrc LIKE '%session_user%'"; then
        infra "$2" "$QA_INFRA_REASON"
        return
    fi
    qa_evidence $EV "## $2" '```' "${QA_STEP_OUT[1]}" '```' "- authid bodies: ${QA_STEP_OUT[2]}"
    if [[ ${QA_STEP_OUT[1]} == "$META_EXPECT" && ${QA_STEP_OUT[2]} == 12 ]]; then
        qa_record PASS "$2" "search_path, SECURITY DEFINER, PUBLIC execute, and catalog-qualified session_user checks match"
    else
        qa_record FAIL "$2" "function settings or privileges differ (authid bodies=${QA_STEP_OUT[2]})"
    fi
}
check_meta "$DB" "$ID.fresh.function_settings"

if ! seed_markers "$DB"; then
    infra "$ID.seed" "seed: $QA_INFRA_REASON"
    exit 0
fi
if ! snap_catalog "$DB"; then
    infra "$ID.seed" "snapshot: $QA_INFRA_REASON"
    exit 0
fi
CATALOG_BEFORE=$CATALOG_NOW
qa_evidence $EV "## seed $DB" "- rule id $RULE_ID" '```' "$CATALOG_BEFORE" '```'
if ! seed_ok "$CATALOG_BEFORE"; then
    infra "$ID.seed" "seed snapshot missing markers: $CATALOG_BEFORE"
    exit 0
fi
qa_record PASS "$ID.seed" "seeded an approved command, both fingerprint states, an active regex rule, and old log rows (rule id $RULE_ID)"

# Historical approve_command cases, now expecting the privilege denial.
# Commands differ so a bypass would show up as a specific catalog row.
hist_attempt() { # ID_SUFFIX COMMAND SETUP...
    local suffix=$1 cmd=$2
    shift 2
    local call="SELECT public.sql_firewall_approve_command('$TARGET', '$cmd')"
    if ! qa_sql_steps "$ROLE" "$DB" "$APP" "$@" "$call"; then
        infra "$ID.$suffix" "$QA_INFRA_REASON"
        return
    fi
    local n=$# i
    for ((i = 1; i <= n; i++)); do
        if [[ ${QA_STEP_ERR[i]} == true ]]; then
            infra "$ID.$suffix" "attack setup step $i failed: ${QA_STEP_STATE[i]} ${QA_STEP_MSG[i]:-}"
            return
        fi
    done
    local step=$((n + 1))
    qa_judge_rejection "$step" 42501 "^permission denied for function sql_firewall_approve_command\$"
    if [[ $QA_VERDICT == INFRA && ${QA_STEP_MSG[step]:-} == Only\ superusers* ]]; then
        QA_VERDICT=FAIL
        QA_DETAIL="function body ran (${QA_STEP_MSG[step]}); PUBLIC EXECUTE was not revoked"
    fi
    local fn_verdict=$QA_VERDICT fn_detail=$QA_DETAIL
    local row=unknown
    qa_admin "$DB" "SELECT coalesce((SELECT 'is_approved=' || is_approved::text FROM public.sql_firewall_command_approvals WHERE role_name = '$TARGET' AND command_type = '$cmd'), 'none')" &&
        row=${QA_STEP_OUT[1]}
    qa_evidence $EV "## $ID.$suffix" "- command $cmd" "- outcome: $fn_detail" "- catalog row: $row"
    if [[ $row == unknown ]]; then
        infra "$ID.$suffix" "catalog verification failed: $QA_INFRA_REASON"
    elif [[ $row != none ]]; then
        qa_record FAIL "$ID.$suffix" "DEFECT: $ROLE created approval ($TARGET, $cmd) -> $row; $fn_detail"
    elif [[ $fn_verdict == PASS ]]; then
        qa_record PASS "$ID.$suffix" "call rejected ($fn_detail); no catalog row for $cmd"
    else
        qa_record "$fn_verdict" "$ID.$suffix" "$fn_detail"
    fi
}
hist_attempt control_direct_call DROP
hist_attempt temp_view_shadow DELETE \
    "$SHADOW" \
    "SELECT current_setting('search_path')"
hist_attempt search_path_shadow TRUNCATE \
    "$SHADOW" \
    "$PATH_SET"

run_denied "$DB" direct acl
run_denied "$DB" temp_view_shadow acl "$SHADOW" "SELECT current_setting('search_path')"
run_denied "$DB" search_path_shadow acl "$SHADOW" "$PATH_SET"

# ---------------------------------------------------------------------------
# Body check, after an explicit EXECUTE grant that is not part of the install
# ---------------------------------------------------------------------------
qa_create_db $BODY_DB sql_firewall.mode=learn || { infra "$ID.body" "setup: $QA_INFRA_REASON"; exit 0; }
if ! qa_admin "$BODY_DB" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_approve_command(name, text) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_revoke_command(name, text) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_approve_fingerprint(text, name, text) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_block_fingerprint(text, name, text) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_add_regex_rule(text, text) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_delete_regex_rule(integer) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_toggle_regex_rule(integer, boolean) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_cleanup_activity_log(interval) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_cleanup_blocked_queries(interval) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_cleanup_all_logs(interval, interval) TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_truncate_logs() TO $ROLE" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_internal_upsert_approval(name, text, boolean) TO $ROLE" \
    "SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname IN ('sql_firewall_approve_command','sql_firewall_revoke_command','sql_firewall_approve_fingerprint','sql_firewall_block_fingerprint','sql_firewall_add_regex_rule','sql_firewall_delete_regex_rule','sql_firewall_toggle_regex_rule','sql_firewall_cleanup_activity_log','sql_firewall_cleanup_blocked_queries','sql_firewall_cleanup_all_logs','sql_firewall_truncate_logs','sql_firewall_internal_upsert_approval') AND has_function_privilege('$ROLE', p.oid, 'EXECUTE') AND NOT has_function_privilege('public', p.oid, 'EXECUTE')"; then
    infra "$ID.body" "grant: $QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_OUT[13]} != 12 ]]; then
    infra "$ID.body" "EXECUTE grant did not apply to all 12 functions (count=${QA_STEP_OUT[13]})"
    exit 0
fi
if ! seed_markers "$BODY_DB"; then
    infra "$ID.body.seed" "$QA_INFRA_REASON"
    exit 0
fi
if ! snap_catalog "$BODY_DB" || ! seed_ok "$CATALOG_NOW"; then
    infra "$ID.body.seed" "snapshot: ${QA_INFRA_REASON:-$CATALOG_NOW}"
    exit 0
fi
CATALOG_BEFORE=$CATALOG_NOW
qa_evidence $EV "## body grants" "- $ROLE has EXECUTE on 12 functions; PUBLIC does not" "- rule id $RULE_ID"
run_denied "$BODY_DB" body_temp_view body "$SHADOW" "SELECT current_setting('search_path')"
run_denied "$BODY_DB" body_search_path body "$SHADOW" "$PATH_SET"

# ---------------------------------------------------------------------------
# Superuser positive controls under a hostile search_path
# ---------------------------------------------------------------------------
qa_create_db $SUPER_DB sql_firewall.mode=learn || { infra "$ID.super" "setup: $QA_INFRA_REASON"; exit 0; }
if ! qa_admin "$SUPER_DB" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('qa-fp-approved', 'SELECT QA_APPROVED', '$TARGET', 'SELECT', 'select qa_approved', 3, true), ('qa-fp-pending', 'SELECT QA_PENDING', '$TARGET', 'SELECT', 'select qa_pending', 1, false)" \
    "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) VALUES (now() - interval '400 days', '$TARGET', current_database(), 'QA_OLD_ACTIVITY', 'SELECT', 'ALLOWED', 'seed-old'), (now(), '$TARGET', current_database(), 'QA_NEW_ACTIVITY', 'SELECT', 'ALLOWED', 'seed-new')" \
    "INSERT INTO public.sql_firewall_blocked_queries (blocked_at, role_name, database_name, query_text, command_type, reason) VALUES (now() - interval '400 days', '$TARGET', current_database(), 'QA_OLD_BLOCKED', 'SELECT', 'seed-old'), (now(), '$TARGET', current_database(), 'QA_NEW_BLOCKED', 'SELECT', 'seed-new')"; then
    infra "$ID.super.seed" "$QA_INFRA_REASON"
    exit 0
fi

# super_op ID SQL EXPECTED_OUT VERIFY_SQL EXPECTED_VERIFY
super_op() {
    local id=$1 sql=$2 exp_out=$3 verify=$4 exp_ver=$5
    if ! qa_sql_steps "$QA_SUPERUSER" "$SUPER_DB" qa_admin "$HOSTILE_VIEW" "$HOSTILE_PATH" "$sql"; then
        infra "$ID.$id" "$QA_INFRA_REASON"
        return
    fi
    if [[ ${QA_STEP_ERR[1]} == true || ${QA_STEP_ERR[2]} == true ]]; then
        infra "$ID.$id" "hostile session setup failed: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-} / ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-}"
        return
    fi
    local st=${QA_STEP_STATE[3]} msg=${QA_STEP_MSG[3]:-} out=${QA_STEP_OUT[3]}
    if [[ ${QA_STEP_ERR[3]} == true ]]; then
        if [[ $st == 42501 ]]; then
            qa_record FAIL "$ID.$id" "superuser denied under hostile search_path: $st $msg"
        else
            infra "$ID.$id" "unexpected error $st: $msg"
        fi
        return
    fi
    if [[ -n $exp_out && $out != "$exp_out" ]]; then
        infra "$ID.$id" "returned '$out' (expected '$exp_out')"
        return
    fi
    if ! qa_admin "$SUPER_DB" "$verify"; then
        infra "$ID.$id" "catalog read failed: $QA_INFRA_REASON"
        return
    fi
    qa_evidence $EV "## $ID.$id" "- call: \`$sql\`" "- returned: ${out:-<void>}" "- catalog: ${QA_STEP_OUT[1]}"
    if [[ ${QA_STEP_OUT[1]} == "$exp_ver" ]]; then
        qa_record PASS "$ID.$id" "superuser call changed the catalog to ${QA_STEP_OUT[1]}"
    else
        qa_record FAIL "$ID.$id" "superuser call returned but catalog is '${QA_STEP_OUT[1]}' (expected '$exp_ver')"
    fi
}

super_op super.approve_command \
    "SELECT public.sql_firewall_approve_command('$TARGET', 'INSERT')" "" \
    "SELECT coalesce((SELECT is_approved::text FROM public.sql_firewall_command_approvals WHERE role_name = '$TARGET' AND command_type = 'INSERT'), 'none')" \
    true
super_op super.revoke_command \
    "SELECT public.sql_firewall_revoke_command('$TARGET', 'INSERT')" "" \
    "SELECT coalesce((SELECT is_approved::text FROM public.sql_firewall_command_approvals WHERE role_name = '$TARGET' AND command_type = 'INSERT'), 'none')" \
    false
super_op super.approve_fingerprint \
    "SELECT public.sql_firewall_approve_fingerprint('qa-fp-pending', '$TARGET', 'SELECT')" "" \
    "SELECT is_approved::text || ':' || hit_count::text FROM public.sql_firewall_query_fingerprints WHERE fingerprint = 'qa-fp-pending' AND role_name = '$TARGET'" \
    "true:1"
super_op super.block_fingerprint \
    "SELECT public.sql_firewall_block_fingerprint('qa-fp-approved', '$TARGET', 'SELECT')" "" \
    "SELECT is_approved::text || ':' || hit_count::text FROM public.sql_firewall_query_fingerprints WHERE fingerprint = 'qa-fp-approved' AND role_name = '$TARGET'" \
    "false:3"
super_op super.add_regex_rule \
    "SELECT (public.sql_firewall_add_regex_rule('qa_phase2a_super_pattern', 'added') IS NOT NULL)::text" "true" \
    "SELECT is_active::text FROM public.sql_firewall_regex_rules WHERE pattern = 'qa_phase2a_super_pattern'" \
    true
if qa_admin "$SUPER_DB" "SELECT id::text FROM public.sql_firewall_regex_rules WHERE pattern = 'qa_phase2a_super_pattern'"; then
    SUPER_RULE=${QA_STEP_OUT[1]}
else
    SUPER_RULE=
    infra "$ID.super.rule_id" "$QA_INFRA_REASON"
fi
if [[ $SUPER_RULE =~ ^[0-9]+$ ]]; then
    super_op super.toggle_regex_rule \
        "SELECT public.sql_firewall_toggle_regex_rule($SUPER_RULE, false)" "" \
        "SELECT is_active::text FROM public.sql_firewall_regex_rules WHERE id = $SUPER_RULE" \
        false
    super_op super.delete_regex_rule \
        "SELECT public.sql_firewall_delete_regex_rule($SUPER_RULE)" "" \
        "SELECT count(*)::text FROM public.sql_firewall_regex_rules WHERE id = $SUPER_RULE" \
        0
fi
super_op super.cleanup_activity_log \
    "SELECT deleted_count::text FROM public.sql_firewall_cleanup_activity_log('1 day')" "1" \
    "SELECT coalesce(string_agg(query_text, ',' ORDER BY query_text), '') FROM public.sql_firewall_activity_log WHERE query_text LIKE 'QA_%'" \
    "QA_NEW_ACTIVITY"
super_op super.cleanup_blocked_queries \
    "SELECT deleted_count::text FROM public.sql_firewall_cleanup_blocked_queries('1 day')" "1" \
    "SELECT coalesce(string_agg(query_text, ',' ORDER BY query_text), '') FROM public.sql_firewall_blocked_queries WHERE query_text LIKE 'QA_%'" \
    "QA_NEW_BLOCKED"
if ! qa_admin "$SUPER_DB" \
    "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) VALUES (now() - interval '400 days', '$TARGET', current_database(), 'QA_OLD_ACTIVITY_2', 'SELECT', 'ALLOWED', 'seed-old')" \
    "INSERT INTO public.sql_firewall_blocked_queries (blocked_at, role_name, database_name, query_text, command_type, reason) VALUES (now() - interval '400 days', '$TARGET', current_database(), 'QA_OLD_BLOCKED_2', 'SELECT', 'seed-old')"; then
    infra "$ID.super.reseed" "$QA_INFRA_REASON"
else
    super_op super.cleanup_all_logs \
        "SELECT activity_deleted::text || ',' || blocked_deleted::text || ',' || total_deleted::text FROM public.sql_firewall_cleanup_all_logs('1 day', '1 day')" \
        "1,1,2" \
        "SELECT (SELECT coalesce(string_agg(query_text, ',' ORDER BY query_text), '') FROM public.sql_firewall_activity_log WHERE query_text LIKE 'QA_%') || '|' || (SELECT coalesce(string_agg(query_text, ',' ORDER BY query_text), '') FROM public.sql_firewall_blocked_queries WHERE query_text LIKE 'QA_%')" \
        "QA_NEW_ACTIVITY|QA_NEW_BLOCKED"
fi
super_op super.truncate_logs \
    "SELECT status FROM public.sql_firewall_truncate_logs()" \
    "All firewall logs truncated successfully" \
    "SELECT (SELECT count(*) FROM public.sql_firewall_activity_log)::text || ',' || (SELECT count(*) FROM public.sql_firewall_blocked_queries)::text" \
    "0,0"
super_op super.internal_upsert_approval \
    "SELECT public.sql_firewall_internal_upsert_approval('$TARGET', 'COMMENT', true)" "" \
    "SELECT is_approved::text FROM public.sql_firewall_command_approvals WHERE role_name = '$TARGET' AND command_type = 'COMMENT'" \
    true

exit 0
