#!/usr/bin/env bash
# Per-database activation and unavailable policy catalogs.
#
# shared_preload_libraries is server-wide. Inspection runs only where
# CREATE EXTENSION sql_firewall has installed the extension.
#
# Diagnostics:
#   not installed: the statement follows PostgreSQL. No sql_firewall error.
#   installed, healthy, enforce, no approval:
#     42501 sql_firewall: No rule found for command '...' for role '...'
#   installed, required policy catalog unavailable or not the extension's
#   object (missing, inaccessible, or incompatible):
#     enforce: 55000
#       sql_firewall: required policy catalog is unavailable: <relation>
#     learn and permissive: statement succeeds, and the same sentence is a
#       WARNING. No approval is manufactured. Absence of a worker row is not
#       the proof; a newly written approval row is a failure.
#
# This is not a migration test. Setup failures are INFRA.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.database_activation
EV=database_activation
ROLE=qa_act_app
APP=qa_act_app
ON=qa_act_on
OFF=qa_act_off
LIFE=qa_act_life
UNAVAIL='sql_firewall: required policy catalog is unavailable: sql_firewall_command_approvals'
UNAVAIL_FP='sql_firewall: required policy catalog is unavailable: sql_firewall_query_fingerprints'

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

# app_step/app_close talk to a coproc started in the test body. A coproc
# started inside a function is closed when that function returns.
app_close() {
    if [[ -n ${QA_APP_FD:-} ]]; then
        exec {QA_APP_FD}>&- || true
        QA_APP_FD=
    fi
    if [[ -n ${QA_APP_PID:-} ]]; then
        wait "$QA_APP_PID" || true
        QA_APP_PID=
    fi
}

app_step() { # sql
    local sql=$1 n=$QA_APP_N line cur=0 got=0
    [[ $sql =~ \;[[:space:]]*$ ]] || sql="$sql;"
    QA_APP_N=$((QA_APP_N + 1))
    n=$QA_APP_N
    QA_STEP_ERR[n]= QA_STEP_STATE[n]= QA_STEP_MSG[n]= QA_STEP_OUT[n]=
    printf '\\echo @@QA_BEGIN %d\n%s\n\\echo @@QA_END %d :ERROR :SQLSTATE\n\\if :ERROR\n\\echo @@QA_MSG %d :LAST_ERROR_MESSAGE\n\\endif\n' \
        "$n" "$sql" "$n" "$n" >&"$QA_APP_FD"
    while IFS= read -r -t 5 line <&"$QA_APP_OUT"; do
        if [[ $line =~ ^@@QA_BEGIN\ ([0-9]+)$ ]]; then
            cur=${BASH_REMATCH[1]}
            QA_STEP_OUT[cur]=
        elif [[ $line =~ ^@@QA_END\ ([0-9]+)\ (true|false)\ ([0-9A-Z]{5})$ ]]; then
            QA_STEP_ERR[BASH_REMATCH[1]]=${BASH_REMATCH[2]}
            QA_STEP_STATE[BASH_REMATCH[1]]=${BASH_REMATCH[3]}
            if [[ ${BASH_REMATCH[1]} == "$n" && ${BASH_REMATCH[2]} == false ]]; then
                got=1
                break
            fi
        elif [[ $line =~ ^@@QA_MSG\ ([0-9]+)\ (.*)$ ]]; then
            QA_STEP_MSG[BASH_REMATCH[1]]=${BASH_REMATCH[2]}
            if [[ ${BASH_REMATCH[1]} == "$n" ]]; then
                got=1
                break
            fi
        elif ((cur == n)); then
            QA_STEP_OUT[cur]+="${QA_STEP_OUT[cur]:+$'\n'}$line"
        fi
    done
    if [[ $got != 1 ]]; then
        QA_INFRA_REASON="application step $n did not finish: $(head -c 300 "$QA_APP_DIR/err")"
        return 1
    fi
}

qa_evidence "$EV" "# $ID" "" \
    "Inspection follows CREATE EXTENSION in the current database. A missing installation is not a missing approval. An installed but unusable policy catalog is not 'no rule'." ""

qa_admin postgres \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" \
    "CREATE DATABASE $OFF" \
    "ALTER DATABASE $OFF SET sql_firewall.mode = 'enforce'" \
    "GRANT CONNECT ON DATABASE $OFF TO $ROLE" \
    "GRANT CONNECT ON DATABASE $OFF TO $QA_CANARY_ROLE" \
    "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $OFF SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "off database: $QA_INFRA_REASON"; exit 0; }

qa_create_db "$ON" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID" "on database: $QA_INFRA_REASON"; exit 0; }
qa_admin "$ON" \
    "GRANT CONNECT ON DATABASE $ON TO $ROLE" \
    "CREATE TABLE public.qa_act_t (id integer)" \
    "GRANT SELECT, INSERT, UPDATE ON public.qa_act_t TO $ROLE" \
    "INSERT INTO public.qa_act_t VALUES (1)" \
    "CREATE TABLE public.qa_act_secret (id integer)" \
    "SELECT extname || ':' || extversion FROM pg_extension WHERE extname = 'sql_firewall'" ||
    { infra "$ID" "on setup: $QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[6]} != sql_firewall:0.0.0 ]]; then
    infra "$ID" "installed database extension is '${QA_STEP_OUT[6]}'"
    exit 0
fi

# Native permission still applies in the database that has no extension.
qa_admin "$OFF" "CREATE TABLE public.qa_act_secret (id integer)" ||
    { infra "$ID" "off secret: $QA_INFRA_REASON"; exit 0; }

# ---------------------------------------------------------------------------
# A. Same server, ordinary role, installed vs not installed
# ---------------------------------------------------------------------------
qa_check_success "$ROLE" "$OFF" "$APP" "SELECT 'qa_phase2d_off'" "qa_phase2d_off"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.not_installed.allows" "$QA_DETAIL"
else
    fail "$ID.not_installed.allows" "$QA_DETAIL"
fi
qa_check_rejection "$ROLE" "$OFF" "$APP" "SELECT id FROM public.qa_act_secret" 42501 '^permission denied for table qa_act_secret$'
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.not_installed.native_privilege" "$QA_DETAIL"
else
    # A firewall diagnostic here means the uninstalled database was inspected.
    if [[ $QA_DETAIL == rejected:*sql_firewall:* || $QA_DETAIL == *sql_firewall:* ]]; then
        fail "$ID.not_installed.native_privilege" "$QA_DETAIL"
    else
        infra "$ID.not_installed.native_privilege" "$QA_DETAIL"
    fi
fi
qa_check_rejection "$ROLE" "$ON" "$APP" "SELECT 'qa_phase2d_on'" 42501 "^sql_firewall: No rule found for command 'SELECT' for role '$ROLE'$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.installed.enforce_rejects" "$QA_DETAIL"
else
    fail "$ID.installed.enforce_rejects" "$QA_DETAIL"
fi

# ---------------------------------------------------------------------------
# B. Same backend sees install, committed drop, and rolled-back lifecycle
# ---------------------------------------------------------------------------
qa_admin postgres \
    "CREATE DATABASE $LIFE" \
    "ALTER DATABASE $LIFE SET sql_firewall.mode = 'enforce'" \
    "GRANT CONNECT ON DATABASE $LIFE TO $ROLE" ||
    { infra "$ID.lifecycle" "$QA_INFRA_REASON"; exit 0; }

# SET LOCAL ROLE is reverted at transaction end. A session-level SET ROLE
# cannot be reset afterwards: RESET ROLE is itself inspected for the
# non-superuser and rejected in enforce mode.
if ! qa_sql_steps "$QA_SUPERUSER" "$LIFE" qa_admin \
    "SELECT pg_backend_pid()" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_before'" \
    "COMMIT" \
    "CREATE EXTENSION sql_firewall" \
    "SELECT extname || ':' || extversion FROM pg_extension WHERE extname = 'sql_firewall'" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_after_create'" \
    "ROLLBACK" \
    "BEGIN" \
    "DROP EXTENSION sql_firewall" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_during_drop'" \
    "ROLLBACK" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_after_drop_rollback'" \
    "ROLLBACK" \
    "DROP EXTENSION sql_firewall" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_after_drop'" \
    "COMMIT" \
    "BEGIN" \
    "CREATE EXTENSION sql_firewall" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_during_create'" \
    "ROLLBACK" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 'qa_phase2d_life_after_create_rollback'" \
    "COMMIT" \
    "SELECT pg_backend_pid()"; then
    infra "$ID.lifecycle" "$QA_INFRA_REASON"
    exit 0
fi
# 1 pid, 2 BEGIN, 3 SET LOCAL, 4 SELECT before, 5 COMMIT,
# 6 CREATE, 7 extname, 8 BEGIN, 9 SET LOCAL, 10 SELECT after create, 11 ROLLBACK,
# 12 BEGIN, 13 DROP, 14 SET LOCAL, 15 SELECT during drop, 16 ROLLBACK,
# 17 BEGIN, 18 SET LOCAL, 19 SELECT after drop rollback, 20 ROLLBACK,
# 21 DROP, 22 BEGIN, 23 SET LOCAL, 24 SELECT after drop commit, 25 COMMIT,
# 26 BEGIN, 27 CREATE, 28 SET LOCAL, 29 SELECT during create, 30 ROLLBACK,
# 31 BEGIN, 32 SET LOCAL, 33 SELECT after create rollback, 34 COMMIT, 35 pid
pid1=${QA_STEP_OUT[1]}
pid2=${QA_STEP_OUT[35]}
qa_evidence "$EV" "- lifecycle pid $pid1 -> $pid2" \
    "- before=${QA_STEP_ERR[4]}/${QA_STEP_OUT[4]}" \
    "- after create=${QA_STEP_STATE[10]} ${QA_STEP_MSG[10]:-}" \
    "- during drop drop_err=${QA_STEP_ERR[13]} select=${QA_STEP_OUT[15]}" \
    "- after drop rollback=${QA_STEP_STATE[19]} ${QA_STEP_MSG[19]:-}" \
    "- after drop commit drop_err=${QA_STEP_ERR[21]} select=${QA_STEP_OUT[24]}" \
    "- during create=${QA_STEP_STATE[29]} ${QA_STEP_MSG[29]:-}" \
    "- after create rollback=${QA_STEP_OUT[33]}"
if [[ -z $pid1 || $pid1 != "$pid2" ]]; then
    infra "$ID.lifecycle.same_backend" "pids '$pid1' and '$pid2'"
else
    ok "$ID.lifecycle.same_backend" "same backend pid $pid1"
fi
if [[ ${QA_STEP_ERR[4]} == false && ${QA_STEP_OUT[4]} == qa_phase2d_life_before ]]; then
    ok "$ID.lifecycle.before_create" "uninstalled select allowed in pid $pid1"
else
    fail "$ID.lifecycle.before_create" "err=${QA_STEP_ERR[4]} state=${QA_STEP_STATE[4]} msg=${QA_STEP_MSG[4]:-} out=${QA_STEP_OUT[4]}"
fi
if [[ ${QA_STEP_ERR[6]} == true || ${QA_STEP_OUT[7]} != sql_firewall:0.0.0 ]]; then
    infra "$ID.lifecycle.create" "create err=${QA_STEP_ERR[6]} ${QA_STEP_MSG[6]:-} ext=${QA_STEP_OUT[7]}"
else
    ok "$ID.lifecycle.create" "CREATE EXTENSION sql_firewall reached 0.0.0 in pid $pid1"
fi
if [[ ${QA_STEP_ERR[10]} == true && ${QA_STEP_STATE[10]} == 42501 && ${QA_STEP_MSG[10]:-} == "sql_firewall: No rule found for command 'SELECT' for role '$ROLE'" ]]; then
    ok "$ID.lifecycle.after_create" "same backend rejected after CREATE EXTENSION: ${QA_STEP_STATE[10]} ${QA_STEP_MSG[10]}"
else
    fail "$ID.lifecycle.after_create" "err=${QA_STEP_ERR[10]} state=${QA_STEP_STATE[10]} msg=${QA_STEP_MSG[10]:-}"
fi
if [[ ${QA_STEP_ERR[13]} == false && ${QA_STEP_ERR[15]} == false && ${QA_STEP_OUT[15]} == qa_phase2d_life_during_drop ]]; then
    ok "$ID.lifecycle.during_drop" "select allowed after DROP EXTENSION before rollback"
else
    fail "$ID.lifecycle.during_drop" "drop_err=${QA_STEP_ERR[13]} ${QA_STEP_MSG[13]:-} select_err=${QA_STEP_ERR[15]} state=${QA_STEP_STATE[15]} msg=${QA_STEP_MSG[15]:-} out=${QA_STEP_OUT[15]}"
fi
if [[ ${QA_STEP_ERR[19]} == true && ${QA_STEP_STATE[19]} == 42501 && ${QA_STEP_MSG[19]:-} == sql_firewall:* ]]; then
    ok "$ID.lifecycle.drop_rollback" "rollback restored inspection: ${QA_STEP_STATE[19]} ${QA_STEP_MSG[19]}"
else
    fail "$ID.lifecycle.drop_rollback" "err=${QA_STEP_ERR[19]} state=${QA_STEP_STATE[19]} msg=${QA_STEP_MSG[19]:-}"
fi
if [[ ${QA_STEP_ERR[21]} == false && ${QA_STEP_ERR[24]} == false && ${QA_STEP_OUT[24]} == qa_phase2d_life_after_drop ]]; then
    ok "$ID.lifecycle.drop_commit" "committed DROP EXTENSION stopped inspection"
else
    fail "$ID.lifecycle.drop_commit" "drop_err=${QA_STEP_ERR[21]} ${QA_STEP_MSG[21]:-} select_err=${QA_STEP_ERR[24]} state=${QA_STEP_STATE[24]} msg=${QA_STEP_MSG[24]:-} out=${QA_STEP_OUT[24]}"
fi
if [[ ${QA_STEP_ERR[27]} == true ]]; then
    infra "$ID.lifecycle.create_rollback" "CREATE EXTENSION inside the transaction failed: ${QA_STEP_STATE[27]} ${QA_STEP_MSG[27]:-}"
elif [[ ${QA_STEP_ERR[29]} == true && ${QA_STEP_STATE[29]} == 42501 && ${QA_STEP_MSG[29]:-} == sql_firewall:* ]]; then
    ok "$ID.lifecycle.during_create" "select rejected after CREATE EXTENSION before rollback"
else
    fail "$ID.lifecycle.during_create" "err=${QA_STEP_ERR[29]} state=${QA_STEP_STATE[29]} msg=${QA_STEP_MSG[29]:-}"
fi
if [[ ${QA_STEP_ERR[33]} == false && ${QA_STEP_OUT[33]} == qa_phase2d_life_after_create_rollback ]]; then
    ok "$ID.lifecycle.create_rollback" "rolled-back CREATE EXTENSION did not leave inspection on"
else
    fail "$ID.lifecycle.create_rollback" "err=${QA_STEP_ERR[33]} state=${QA_STEP_STATE[33]} msg=${QA_STEP_MSG[33]:-} out=${QA_STEP_OUT[33]}"
fi

# ---------------------------------------------------------------------------
# C/D/E. Damaged policy catalog, cold and warm cache, then restore
# ---------------------------------------------------------------------------
qa_admin "$ON" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true)" \
    "SELECT extname || ':' || extversion FROM pg_extension WHERE extname = 'sql_firewall'" ||
    { infra "$ID.catalog" "$QA_INFRA_REASON"; exit 0; }

# Cold: approvals relation renamed. No successful lookup has cached SELECT yet
# for a different command; UPDATE was never approved or cached.
qa_admin "$ON" "ALTER TABLE public.sql_firewall_command_approvals RENAME TO sql_firewall_command_approvals_qa2d" ||
    { infra "$ID.catalog.rename" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$ON" "SELECT extname || ':' || extversion FROM pg_extension WHERE extname = 'sql_firewall'" ||
    { infra "$ID.catalog.registration" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != sql_firewall:0.0.0 ]]; then
    infra "$ID.catalog.registration" "extension row is '${QA_STEP_OUT[1]}' after rename"
else
    ok "$ID.catalog.registration" "pg_extension still sql_firewall 0.0.0 while approvals is renamed"
fi
qa_check_rejection "$ROLE" "$ON" "$APP" "UPDATE public.qa_act_t SET id = 2" 55000 "^${UNAVAIL}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.catalog.cold_enforce" "$QA_DETAIL"
elif [[ $QA_DETAIL == *No\ rule\ found* || $QA_DETAIL == *does\ not\ exist* ]]; then
    fail "$ID.catalog.cold_enforce" "$QA_DETAIL"
else
    infra "$ID.catalog.cold_enforce" "$QA_DETAIL"
fi

# Warm: restore, let this backend cache an approved SELECT, then revoke
# SELECT on the policy table and repeat the statement without reconnecting.
# SET LOCAL ROLE ends with the transaction, so REVOKE still runs as the superuser.
qa_admin "$ON" "ALTER TABLE public.sql_firewall_command_approvals_qa2d RENAME TO sql_firewall_command_approvals" ||
    { infra "$ID.catalog.restore_name" "$QA_INFRA_REASON"; exit 0; }
# COMMIT/ROLLBACK while SET LOCAL ROLE would be inspected as the ordinary
# role. The approved SELECT warms the cache, then 1/0 aborts that transaction
# so ROLLBACK is not inspected and the session user is the superuser again.
if ! qa_sql_steps "$QA_SUPERUSER" "$ON" qa_admin \
    "SELECT pg_backend_pid()" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT id FROM public.qa_act_t" \
    "SELECT 1/0" \
    "ROLLBACK" \
    "REVOKE SELECT ON TABLE public.sql_firewall_command_approvals FROM PUBLIC" \
    "SELECT extname FROM pg_extension WHERE extname = 'sql_firewall'" \
    "BEGIN" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT id FROM public.qa_act_t" \
    "ROLLBACK" \
    "SELECT pg_backend_pid()"; then
    infra "$ID.catalog.warm" "$QA_INFRA_REASON"
    exit 0
fi
# 1 pid, 2 BEGIN, 3 SET LOCAL, 4 SELECT seed, 5 SELECT 1/0, 6 ROLLBACK,
# 7 REVOKE, 8 extname, 9 BEGIN, 10 SET LOCAL, 11 SELECT, 12 ROLLBACK, 13 pid
if [[ ${QA_STEP_ERR[4]} == true ]]; then
    infra "$ID.catalog.warm_seed" "approved SELECT was not allowed: ${QA_STEP_STATE[4]} ${QA_STEP_MSG[4]:-}"
elif [[ ${QA_STEP_ERR[5]} == false || ${QA_STEP_STATE[5]} != 22012 ]]; then
    infra "$ID.catalog.warm" "transaction was not aborted after the warm SELECT: ${QA_STEP_STATE[5]} ${QA_STEP_MSG[5]:-}"
elif [[ ${QA_STEP_ERR[7]} == true ]]; then
    infra "$ID.catalog.warm" "REVOKE failed: ${QA_STEP_STATE[7]} ${QA_STEP_MSG[7]:-}"
elif [[ ${QA_STEP_OUT[1]} != "${QA_STEP_OUT[13]}" ]]; then
    infra "$ID.catalog.warm" "backend changed from ${QA_STEP_OUT[1]} to ${QA_STEP_OUT[13]}"
elif [[ ${QA_STEP_OUT[8]} != sql_firewall ]]; then
    infra "$ID.catalog.revoke_reg" "extension row is '${QA_STEP_OUT[8]}'"
elif [[ ${QA_STEP_ERR[11]} == true && ${QA_STEP_STATE[11]} == 55000 && ${QA_STEP_MSG[11]:-} == "$UNAVAIL" ]]; then
    ok "$ID.catalog.warm_enforce" "pid ${QA_STEP_OUT[1]} rejected with warm cache: ${QA_STEP_STATE[11]} ${QA_STEP_MSG[11]}"
elif [[ ${QA_STEP_ERR[11]} == false ]]; then
    fail "$ID.catalog.warm_enforce" "warm cache allowed SELECT after REVOKE in pid ${QA_STEP_OUT[1]}"
else
    fail "$ID.catalog.warm_enforce" "err=${QA_STEP_ERR[11]} state=${QA_STEP_STATE[11]} msg=${QA_STEP_MSG[11]:-}"
fi

# Incompatible column, still the extension's table.
qa_admin "$ON" \
    "GRANT SELECT ON TABLE public.sql_firewall_command_approvals TO PUBLIC" \
    "ALTER TABLE public.sql_firewall_command_approvals ALTER COLUMN is_approved TYPE text USING is_approved::text" ||
    { infra "$ID.catalog.incompatible" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$ON" "$APP" "INSERT INTO public.qa_act_t VALUES (3)" 55000 "^${UNAVAIL}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.catalog.incompatible" "$QA_DETAIL"
elif [[ $QA_DETAIL == *No\ rule\ found* ]]; then
    fail "$ID.catalog.incompatible" "$QA_DETAIL"
else
    infra "$ID.catalog.incompatible" "$QA_DETAIL"
fi
qa_admin "$ON" \
    "ALTER TABLE public.sql_firewall_command_approvals ALTER COLUMN is_approved TYPE boolean USING is_approved::boolean" ||
    { infra "$ID.catalog.retype" "$QA_INFRA_REASON"; exit 0; }

# A same-named table that is not a member of the extension is not the policy catalog.
qa_admin "$ON" \
    "ALTER TABLE public.sql_firewall_command_approvals RENAME TO sql_firewall_command_approvals_qa2d" \
    "CREATE TABLE public.sql_firewall_command_approvals (role_name name, command_type text, is_approved boolean)" \
    "GRANT SELECT ON TABLE public.sql_firewall_command_approvals TO PUBLIC" ||
    { infra "$ID.catalog.decoy" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$ON" "SELECT extname || ':' || extversion FROM pg_extension WHERE extname = 'sql_firewall'" ||
    { infra "$ID.catalog.decoy_reg" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != sql_firewall:0.0.0 ]]; then
    infra "$ID.catalog.decoy_reg" "extension row is '${QA_STEP_OUT[1]}' while a decoy approvals table exists"
else
    ok "$ID.catalog.decoy_reg" "pg_extension still sql_firewall 0.0.0 while a same-named table is not an extension member"
fi
qa_check_rejection "$ROLE" "$ON" "$APP" "SELECT 'qa_phase2d_decoy'" 55000 "^${UNAVAIL}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.catalog.decoy" "$QA_DETAIL"
elif [[ $QA_DETAIL == *No\ rule\ found* || $QA_DETAIL == *does\ not\ exist* ]]; then
    fail "$ID.catalog.decoy" "$QA_DETAIL"
else
    infra "$ID.catalog.decoy" "$QA_DETAIL"
fi
qa_admin "$ON" \
    "DROP TABLE public.sql_firewall_command_approvals" \
    "ALTER TABLE public.sql_firewall_command_approvals_qa2d RENAME TO sql_firewall_command_approvals" ||
    { infra "$ID.catalog.decoy_restore" "$QA_INFRA_REASON"; exit 0; }

# Learn and permissive: degradation warning, statement allowed, no new approval.
log_at=$(qa_server_log_offset)
qa_admin "$ON" "ALTER TABLE public.sql_firewall_command_approvals RENAME TO sql_firewall_command_approvals_qa2d" ||
    { infra "$ID.degrade.rename" "$QA_INFRA_REASON"; exit 0; }
before=$(qa_admin "$ON" "SELECT count(*) FROM public.sql_firewall_command_approvals_qa2d" && echo "${QA_STEP_OUT[1]}")
if [[ -z ${before:-} ]]; then
    infra "$ID.degrade.count" "$QA_INFRA_REASON"
    exit 0
fi
# Mode is set while superuser bypass is still on. Turning bypass off first
# would leave the session in enforce and reject the mode change itself.
if ! qa_sql_steps "$QA_SUPERUSER" "$ON" qa_admin \
    "SET sql_firewall.mode = 'learn'" \
    "SET sql_firewall.allow_superuser_auth_bypass = off" \
    "SELECT 'qa_phase2d_learn'"; then
    infra "$ID.degrade.learn" "$QA_INFRA_REASON"
    exit 0
fi
learn_warn=0
if tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -F "$UNAVAIL" >/dev/null; then
    learn_warn=1
fi
if [[ ${QA_STEP_ERR[3]} == false && ${QA_STEP_OUT[3]} == qa_phase2d_learn && $learn_warn == 1 ]]; then
    ok "$ID.degrade.learn" "learn select succeeded with WARNING: $UNAVAIL"
elif [[ ${QA_STEP_ERR[3]} == true ]]; then
    fail "$ID.degrade.learn" "learn select blocked: ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
else
    fail "$ID.degrade.learn" "err=${QA_STEP_ERR[3]} out=${QA_STEP_OUT[3]} warning=$learn_warn"
fi
after=$(qa_admin "$ON" "SELECT count(*) FROM public.sql_firewall_command_approvals_qa2d" && echo "${QA_STEP_OUT[1]}")
if [[ -n ${after:-} && $after != "$before" ]]; then
    fail "$ID.degrade.learn_no_approval" "approval count changed $before -> $after during learn degradation"
else
    qa_evidence "$EV" "- learn approval count before=$before after=${after:-unset} (a change would be a manufactured approval; an unchanged count is not delivery proof)"
fi

log_at=$(qa_server_log_offset)
if ! qa_sql_steps "$QA_SUPERUSER" "$ON" qa_admin \
    "SET sql_firewall.mode = 'permissive'" \
    "SET sql_firewall.allow_superuser_auth_bypass = off" \
    "SELECT 'qa_phase2d_permissive'"; then
    infra "$ID.degrade.permissive" "$QA_INFRA_REASON"
    exit 0
fi
perm_warn=0
if tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -F "$UNAVAIL" >/dev/null; then
    perm_warn=1
fi
if [[ ${QA_STEP_ERR[3]} == false && ${QA_STEP_OUT[3]} == qa_phase2d_permissive && $perm_warn == 1 ]]; then
    ok "$ID.degrade.permissive" "permissive select succeeded with WARNING: $UNAVAIL"
elif [[ ${QA_STEP_ERR[3]} == true ]]; then
    fail "$ID.degrade.permissive" "permissive select blocked: ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
else
    fail "$ID.degrade.permissive" "err=${QA_STEP_ERR[3]} out=${QA_STEP_OUT[3]} warning=$perm_warn"
fi

# Fingerprint cache must not authorize learn traffic when that catalog is renamed.
qa_admin "$ON" "ALTER TABLE public.sql_firewall_command_approvals_qa2d RENAME TO sql_firewall_command_approvals" ||
    { infra "$ID.fingerprint.restore" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "ALTER DATABASE $ON SET sql_firewall.enable_fingerprint_learning = on" ||
    { infra "$ID.fingerprint.enable" "$QA_INFRA_REASON"; exit 0; }
if ! qa_sql_steps "$QA_SUPERUSER" "$ON" qa_admin \
    "SET sql_firewall.mode = 'learn'" \
    "SET sql_firewall.allow_superuser_auth_bypass = off" \
    "SELECT 'qa_phase2d_fp_warm'"; then
    infra "$ID.fingerprint.warm_seed" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[3]} == true ]]; then
    infra "$ID.fingerprint.warm_seed" "learn seed blocked: ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
    exit 0
fi
qa_admin "$ON" "ALTER TABLE public.sql_firewall_query_fingerprints RENAME TO sql_firewall_query_fingerprints_qa2d" ||
    { infra "$ID.fingerprint.rename" "$QA_INFRA_REASON"; exit 0; }
log_at=$(qa_server_log_offset)
if ! qa_sql_steps "$QA_SUPERUSER" "$ON" qa_admin \
    "SET sql_firewall.mode = 'learn'" \
    "SET sql_firewall.allow_superuser_auth_bypass = off" \
    "SELECT 'qa_phase2d_fp_warm'"; then
    infra "$ID.fingerprint.degrade" "$QA_INFRA_REASON"
    exit 0
fi
fp_warn=0
if tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -F "$UNAVAIL_FP" >/dev/null; then
    fp_warn=1
fi
if [[ ${QA_STEP_ERR[3]} == false && $fp_warn == 1 ]]; then
    ok "$ID.fingerprint.warm_learn" "learn select succeeded with WARNING: $UNAVAIL_FP"
elif [[ ${QA_STEP_ERR[3]} == true ]]; then
    fail "$ID.fingerprint.warm_learn" "learn select blocked: ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
else
    fail "$ID.fingerprint.warm_learn" "err=${QA_STEP_ERR[3]} warning=$fp_warn"
fi
qa_admin "$ON" "ALTER TABLE public.sql_firewall_query_fingerprints_qa2d RENAME TO sql_firewall_query_fingerprints" ||
    { infra "$ID.fingerprint.restore2" "$QA_INFRA_REASON"; exit 0; }

# ---------------------------------------------------------------------------
# R1. Fingerprint catalog is required in enforce when fingerprint checking
# is enabled, including after the command-approval cache is warm.
# ---------------------------------------------------------------------------
FPDB=qa_act_fp
qa_create_db "$FPDB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID.fp" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$FPDB" \
    "GRANT CONNECT ON DATABASE $FPDB TO $ROLE" \
    "CREATE TABLE public.qa_act_t (id integer)" \
    "GRANT SELECT ON public.qa_act_t TO $ROLE" \
    "INSERT INTO public.qa_act_t VALUES (1)" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true)" \
    "SELECT current_setting('sql_firewall.enable_fingerprint_learning')" \
    "SELECT extname || ':' || extversion FROM pg_extension WHERE extname = 'sql_firewall'" ||
    { infra "$ID.fp" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[6]} != on || ${QA_STEP_OUT[7]} != sql_firewall:0.0.0 ]]; then
    infra "$ID.fp" "learning='${QA_STEP_OUT[6]}' extension='${QA_STEP_OUT[7]}'"
    exit 0
fi
qa_admin "$FPDB" "ALTER TABLE public.sql_firewall_query_fingerprints RENAME TO sql_firewall_query_fingerprints_qa2d" ||
    { infra "$ID.fp.cold" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$FPDB" "$APP" "SELECT id FROM public.qa_act_t" 55000 "^${UNAVAIL_FP}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.fp.cold_enforce" "$QA_DETAIL"
elif [[ $QA_VERDICT == FAIL ]]; then
    fail "$ID.fp.cold_enforce" "$QA_DETAIL"
else
    infra "$ID.fp.cold_enforce" "$QA_DETAIL"
fi
qa_admin "$FPDB" "ALTER TABLE public.sql_firewall_query_fingerprints_qa2d RENAME TO sql_firewall_query_fingerprints" ||
    { infra "$ID.fp.restore" "$QA_INFRA_REASON"; exit 0; }
# With the catalog restored, the new fingerprint must still be explicitly
# approved before this command-approved role can warm the fingerprint cache.
qa_check_rejection "$ROLE" "$FPDB" "$APP" "SELECT id FROM public.qa_act_t" 42501 \
    "^sql_firewall: Fingerprint '[0-9a-f]{64}' for role '$ROLE' is pending approval"
if [[ $QA_VERDICT != PASS ]]; then
    infra "$ID.fp.pending_seed" "$QA_DETAIL"
    exit 0
fi
if ! qa_worker_progress "$FPDB" 30 || ! qa_fp_identify "$FPDB" "$ROLE" SELECT "SELECT id FROM public.qa_act_t"; then
    infra "$ID.fp.pending_seed" "pending fingerprint event: $QA_INFRA_REASON"
    exit 0
fi
if [[ $QA_FP_STATE != found ]]; then
    infra "$ID.fp.pending_seed" "pending fingerprint not identified: $QA_FP_STATE"
    exit 0
fi
qa_admin "$FPDB" "SELECT public.sql_firewall_approve_fingerprint('$QA_FP_FINGERPRINT', '$ROLE', 'SELECT')" ||
    { infra "$ID.fp.pending_seed" "approve fingerprint: $QA_INFRA_REASON"; exit 0; }
qa_check_success "$ROLE" "$FPDB" "$APP" "SELECT id FROM public.qa_act_t" "1"
if [[ $QA_VERDICT != PASS ]]; then
    infra "$ID.fp.warm_seed" "$QA_DETAIL"
    exit 0
fi
qa_admin "$FPDB" "ALTER TABLE public.sql_firewall_query_fingerprints RENAME TO sql_firewall_query_fingerprints_qa2d" ||
    { infra "$ID.fp.warm" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$FPDB" "$APP" "SELECT id FROM public.qa_act_t" 55000 "^${UNAVAIL_FP}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.fp.warm_enforce" "$QA_DETAIL"
elif [[ $QA_VERDICT == FAIL ]]; then
    fail "$ID.fp.warm_enforce" "$QA_DETAIL"
else
    infra "$ID.fp.warm_enforce" "$QA_DETAIL"
fi
qa_admin "$FPDB" \
    "ALTER TABLE public.sql_firewall_query_fingerprints_qa2d RENAME TO sql_firewall_query_fingerprints" \
    "SELECT extname FROM pg_extension WHERE extname = 'sql_firewall'" ||
    { infra "$ID.fp.reg" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[2]} == sql_firewall ]]; then
    ok "$ID.fp.registration" "extension row remained sql_firewall"
else
    infra "$ID.fp.registration" "extension row is '${QA_STEP_OUT[2]}'"
fi

# ---------------------------------------------------------------------------
# R2. Schema USAGE is part of policy-object usability. Table SELECT stays granted.
# ---------------------------------------------------------------------------
USAGEDB=qa_act_usage
qa_create_db "$USAGEDB" sql_firewall.mode=enforce ||
    { infra "$ID.usage" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$USAGEDB" \
    "GRANT CONNECT ON DATABASE $USAGEDB TO $ROLE" \
    "CREATE TABLE public.qa_act_secret (id integer)" \
    "REVOKE USAGE ON SCHEMA public FROM PUBLIC" \
    "SELECT has_table_privilege('$ROLE', 'public.sql_firewall_command_approvals', 'SELECT')" \
    "SELECT has_table_privilege('$ROLE', 'public.sql_firewall_regex_rules', 'SELECT')" \
    "SELECT has_schema_privilege('$ROLE', 'public', 'USAGE')" ||
    { infra "$ID.usage" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[4]} != t || ${QA_STEP_OUT[5]} != t || ${QA_STEP_OUT[6]} != f ]]; then
    infra "$ID.usage.privileges" "table approvals=${QA_STEP_OUT[4]} regex=${QA_STEP_OUT[5]} schema=${QA_STEP_OUT[6]}"
    exit 0
fi
ok "$ID.usage.privileges" "table SELECT remains granted and schema USAGE is absent"
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $USAGEDB SET sql_firewall.mode = 'learn'" ||
    { infra "$ID.usage.learn" "$QA_INFRA_REASON"; exit 0; }
log_at=$(qa_server_log_offset)
qa_check_success "$ROLE" "$USAGEDB" "$APP" "SELECT 27" "27"
learn_usage_warn=0
if tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -F "$UNAVAIL" >/dev/null; then
    learn_usage_warn=1
fi
if [[ $QA_VERDICT == PASS && $learn_usage_warn == 1 ]]; then
    ok "$ID.usage.learn" "SELECT 27 allowed with WARNING: $UNAVAIL"
elif [[ $QA_VERDICT == FAIL ]]; then
    fail "$ID.usage.learn" "$QA_DETAIL"
else
    fail "$ID.usage.learn" "$QA_DETAIL warning=$learn_usage_warn"
fi
qa_check_rejection "$ROLE" "$USAGEDB" "$APP" "SELECT id FROM public.qa_act_secret" 42501 '^permission denied for schema public$'
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.usage.learn_native" "$QA_DETAIL"
elif [[ $QA_DETAIL == *sql_firewall:* ]]; then
    fail "$ID.usage.learn_native" "$QA_DETAIL"
else
    infra "$ID.usage.learn_native" "$QA_DETAIL"
fi
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $USAGEDB SET sql_firewall.mode = 'permissive'" ||
    { infra "$ID.usage.permissive" "$QA_INFRA_REASON"; exit 0; }
log_at=$(qa_server_log_offset)
qa_check_success "$ROLE" "$USAGEDB" "$APP" "SELECT 27" "27"
perm_usage_warn=0
if tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -F "$UNAVAIL" >/dev/null; then
    perm_usage_warn=1
fi
if [[ $QA_VERDICT == PASS && $perm_usage_warn == 1 ]]; then
    ok "$ID.usage.permissive" "SELECT 27 allowed with WARNING: $UNAVAIL"
elif [[ $QA_VERDICT == FAIL ]]; then
    fail "$ID.usage.permissive" "$QA_DETAIL"
else
    fail "$ID.usage.permissive" "$QA_DETAIL warning=$perm_usage_warn"
fi
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $USAGEDB SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.usage.enforce" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$USAGEDB" "$APP" "SELECT 27" 55000 "^${UNAVAIL}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.usage.enforce" "$QA_DETAIL"
elif [[ $QA_DETAIL == *permission\ denied\ for\ schema* ]]; then
    fail "$ID.usage.enforce" "$QA_DETAIL"
else
    infra "$ID.usage.enforce" "$QA_DETAIL"
fi
qa_admin "$USAGEDB" "GRANT USAGE ON SCHEMA public TO PUBLIC" ||
    { infra "$ID.usage.restore" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$USAGEDB" "$APP" "SELECT 27" 42501 "^sql_firewall: No rule found for command 'SELECT' for role '$ROLE'$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.usage.restore" "$QA_DETAIL"
elif [[ $QA_DETAIL == *permission\ denied\ for\ schema* || $QA_DETAIL == *unavailable* ]]; then
    fail "$ID.usage.restore" "$QA_DETAIL"
else
    infra "$ID.usage.restore" "$QA_DETAIL"
fi

# ---------------------------------------------------------------------------
# R3. A degraded fingerprint lookup must not record an ordinary ALLOWED row.
# The activity insert is synchronous in the hook. This is not a worker-queue proof.
# ---------------------------------------------------------------------------
DEGDB=qa_act_deg
qa_create_db "$DEGDB" sql_firewall.mode=learn sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID.degraded_lookup" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DEGDB" \
    "GRANT CONNECT ON DATABASE $DEGDB TO $ROLE" \
    "CREATE TABLE public.qa_t (id integer, v text)" \
    "INSERT INTO public.qa_t VALUES (1, 'row')" \
    "GRANT SELECT ON public.qa_t TO $ROLE" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true)" ||
    { infra "$ID.degraded_lookup" "$QA_INFRA_REASON"; exit 0; }
qa_check_success "$ROLE" "$DEGDB" "$APP" "SELECT 1" "1"
if [[ $QA_VERDICT != PASS ]]; then
    infra "$ID.degraded_lookup.control" "$QA_DETAIL"
    exit 0
fi
control=$(qa_admin "$DEGDB" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$ROLE' AND query_text = 'SELECT 1' AND action = 'ALLOWED'" && echo "${QA_STEP_OUT[1]}")
if [[ ${control:-0} -lt 1 ]]; then
    infra "$ID.degraded_lookup.control" "healthy SELECT 1 wrote ${control:-0} ALLOWED rows"
    exit 0
fi
ok "$ID.degraded_lookup.control" "healthy learn SELECT logged ALLOWED ($control)"
# The malformed row must carry the fingerprint the product computes for the
# statement, or the lookup never reaches it. A hardcoded identity went stale
# once statement selection dropped the terminating ';' ('8aeaf212cd039fd1'
# is 'SELECT V FROM QA_T WHERE ID = ?;'). A helper role runs the same
# statement here in learn mode; the worker persists its fingerprint row, found
# by exact sample_query (qa_fp_identify) without re-implementing the
# normaliser. A separate role keeps ROLE's shared fingerprint cache cold.
DEG_STMT="SELECT v FROM qa_t WHERE id = 1"
DEG_PROBE=qa_act_fp_probe
qa_admin "$DEGDB" \
    "CREATE ROLE $DEG_PROBE LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" \
    "GRANT CONNECT ON DATABASE $DEGDB TO $DEG_PROBE" \
    "GRANT SELECT ON public.qa_t TO $DEG_PROBE" ||
    { infra "$ID.degraded_lookup.fixture" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DEGDB" 90 || { infra "$ID.degraded_lookup.fixture" "worker liveness: $QA_INFRA_REASON"; exit 0; }
qa_check_success "$DEG_PROBE" "$DEGDB" "$APP" "$DEG_STMT" "row"
[[ $QA_VERDICT == PASS ]] || { infra "$ID.degraded_lookup.fixture" "identity probe: $QA_DETAIL"; exit 0; }
QA_FP_STATE=""
for ((attempt = 0; attempt < 100; attempt++)); do
    qa_fp_identify "$DEGDB" "$DEG_PROBE" SELECT "$DEG_STMT" ||
        { infra "$ID.degraded_lookup.fixture" "$QA_INFRA_REASON"; exit 0; }
    [[ $QA_FP_STATE == absent ]] || break
    sleep 0.2
done
if [[ $QA_FP_STATE != found ]]; then
    infra "$ID.degraded_lookup.fixture" "identity probe row is $QA_FP_STATE: $QA_FP_DUMP"
    exit 0
fi
DEG_FP=$QA_FP_FINGERPRINT DEG_NORM=$QA_FP_NORMALIZED
qa_evidence "$EV" "- degraded_lookup fixture identity from the production path: $DEG_FP '$DEG_NORM' (helper $DEG_PROBE)"
qa_admin "$DEGDB" \
    "ALTER TABLE public.sql_firewall_query_fingerprints ALTER COLUMN hit_count DROP NOT NULL" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ($(qa_sql_quote "$DEG_FP"), $(qa_sql_quote "$DEG_NORM"), '$ROLE', 'SELECT', $(qa_sql_quote "$DEG_STMT"), NULL, false)" ||
    { infra "$ID.degraded_lookup.fixture" "$QA_INFRA_REASON"; exit 0; }
before_allowed=$(qa_admin "$DEGDB" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$ROLE' AND query_text = $(qa_sql_quote "$DEG_STMT") AND action = 'ALLOWED'" && echo "${QA_STEP_OUT[1]}")
log_at=$(qa_server_log_offset)
qa_check_success "$ROLE" "$DEGDB" "$APP" "$DEG_STMT" "row"
deg_warn=0
if tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -F "$UNAVAIL_FP" >/dev/null; then
    deg_warn=1
fi
after_allowed=$(qa_admin "$DEGDB" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$ROLE' AND query_text = $(qa_sql_quote "$DEG_STMT") AND action = 'ALLOWED'" && echo "${QA_STEP_OUT[1]}")
# A LEARNED row means the lookup found no row: the fixture was not reached.
learned=$(qa_admin "$DEGDB" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$ROLE' AND query_text = $(qa_sql_quote "$DEG_STMT") AND action = 'LEARNED (FINGERPRINT AUTO)'" && echo "${QA_STEP_OUT[1]}")
if [[ $QA_VERDICT == PASS && $deg_warn == 1 && ${before_allowed:-} == "${after_allowed:-}" ]]; then
    ok "$ID.degraded_lookup" "statement returned row with WARNING and ALLOWED count stayed ${after_allowed}"
elif [[ ${after_allowed:-} != "${before_allowed:-}" ]]; then
    fail "$ID.degraded_lookup" "ALLOWED rows $before_allowed -> $after_allowed; verdict=$QA_VERDICT warning=$deg_warn learned=${learned:-?} ${QA_DETAIL:-}"
elif [[ $QA_VERDICT == FAIL ]]; then
    fail "$ID.degraded_lookup" "$QA_DETAIL warning=$deg_warn learned=${learned:-?}"
else
    fail "$ID.degraded_lookup" "$QA_DETAIL warning=$deg_warn allowed=$after_allowed learned=${learned:-?}"
fi

# ---------------------------------------------------------------------------
# R4. The application backend that saw the unavailable catalog recovers,
# waits while another connection repairs it, and is inspected again.
# ---------------------------------------------------------------------------
qa_admin "$ON" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'BEGIN', true), ('$ROLE', 'SAVEPOINT', true), ('$ROLE', 'ROLLBACK', true) ON CONFLICT (role_name, command_type) DO NOTHING" \
    "GRANT SELECT ON TABLE public.sql_firewall_command_approvals TO PUBLIC" ||
    { infra "$ID.resume" "$QA_INFRA_REASON"; exit 0; }
# This session starts with fingerprint enforcement enabled. Its first PID
# query, BEGIN, and SAVEPOINT therefore need committed fingerprint approvals
# as well as the command approvals above (ROLLBACK and ROLLBACK TO SAVEPOINT
# are not inspected, README 6.1d). Learn them with threshold 1 in a separate
# session, in a transaction that commits (only committed work is learned,
# README 6.1b), then restore enforce before opening the measured session.
qa_admin postgres \
    "ALTER ROLE $ROLE IN DATABASE $ON SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE $ROLE IN DATABASE $ON SET sql_firewall.fingerprint_learn_threshold = 1" ||
    { infra "$ID.resume.seed" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps "$ROLE" "$ON" "$APP" \
    "SELECT pg_backend_pid()" "BEGIN" "SAVEPOINT qa_r4" \
    "RELEASE SAVEPOINT qa_r4" "COMMIT" ||
    { infra "$ID.resume.seed" "$QA_INFRA_REASON"; exit 0; }
for i in 1 2 3 4 5; do
    if [[ ${QA_STEP_ERR[$i]} == true ]]; then
        infra "$ID.resume.seed" "step $i: ${QA_STEP_STATE[$i]} ${QA_STEP_MSG[$i]:-}"
        exit 0
    fi
done
qa_poll "$ON" "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$ROLE' AND is_approved AND sample_query IN ('SELECT pg_backend_pid()', 'BEGIN', 'SAVEPOINT qa_r4')" 3 30 ||
    { infra "$ID.resume.seed" "transaction-control fingerprints: $QA_INFRA_REASON"; exit 0; }
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $ON SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.resume.seed" "$QA_INFRA_REASON"; exit 0; }
QA_STEP_ERR=() QA_STEP_STATE=() QA_STEP_MSG=() QA_STEP_OUT=()
command -v stdbuf >/dev/null || { infra "$ID.resume" "stdbuf is required to hold an application session"; exit 0; }
QA_APP_DIR=$(mktemp -d "$QA_RUN_DIR/app-session.XXXXXX")
coproc APPSESS {
    env PGAPPNAME="$APP" \
        stdbuf -oL -eL "$QA_PSQL" -X -q -A -t -v ON_ERROR_STOP=0 -v VERBOSITY=default \
        -h "$QA_SOCK" -p "$QA_PORT" -U "$ROLE" -d "$ON" 2>"$QA_APP_DIR/err"
}
QA_APP_OUT=${APPSESS[0]}
QA_APP_FD=${APPSESS[1]}
QA_APP_PID=$APPSESS_PID
QA_APP_N=0
sleep 0.2
if ! kill -0 "$QA_APP_PID" 2>/dev/null; then
    infra "$ID.resume" "application backend failed to start: $(head -c 300 "$QA_APP_DIR/err")"
    exit 0
fi
if ! app_step "SELECT pg_backend_pid()" || [[ ${QA_STEP_ERR[1]} == true ]]; then
    app_close
    infra "$ID.resume" "pid: ${QA_INFRA_REASON:-${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}}"
    exit 0
fi
resume_pid=${QA_STEP_OUT[1]}
if ! app_step "BEGIN" || ! app_step "SAVEPOINT qa_r4"; then
    app_close
    infra "$ID.resume" "transaction open: $QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[2]} == true || ${QA_STEP_ERR[3]} == true ]]; then
    app_close
    infra "$ID.resume" "BEGIN/SAVEPOINT rejected: ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-} / ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
    exit 0
fi
# BEGIN and SAVEPOINT now check fingerprints too, so this transaction holds
# a read lock on the fingerprint relation. Revoke its SELECT privilege to
# make the catalog unusable without waiting for an exclusive relation lock.
qa_admin "$ON" "REVOKE SELECT ON TABLE public.sql_firewall_query_fingerprints FROM PUBLIC" ||
    { app_close; infra "$ID.resume" "$QA_INFRA_REASON"; exit 0; }
if ! app_step "SELECT 'qa_phase2d_resume_down'"; then
    app_close
    infra "$ID.resume" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[4]} != true || ${QA_STEP_STATE[4]} != 55000 || ${QA_STEP_MSG[4]:-} != "$UNAVAIL_FP" ]]; then
    app_close
    fail "$ID.resume.unavailable" "err=${QA_STEP_ERR[4]} state=${QA_STEP_STATE[4]} msg=${QA_STEP_MSG[4]:-}"
    exit 0
fi
ok "$ID.resume.unavailable" "pid $resume_pid rejected: ${QA_STEP_STATE[4]} ${QA_STEP_MSG[4]}"
if ! app_step "ROLLBACK TO SAVEPOINT qa_r4"; then
    app_close
    infra "$ID.resume" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[5]} == true ]]; then
    app_close
    fail "$ID.resume.recover" "ROLLBACK TO SAVEPOINT failed: ${QA_STEP_STATE[5]} ${QA_STEP_MSG[5]:-}"
else
    ok "$ID.resume.recover" "pid $resume_pid recovered the savepoint"
fi
qa_admin "$ON" "GRANT SELECT ON TABLE public.sql_firewall_query_fingerprints TO PUBLIC" ||
    { app_close; infra "$ID.resume" "$QA_INFRA_REASON"; exit 0; }
if ! app_step "INSERT INTO public.qa_act_t VALUES (4)"; then
    app_close
    infra "$ID.resume" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[6]} == true && ${QA_STEP_STATE[6]} == 42501 && ${QA_STEP_MSG[6]:-} == "sql_firewall: No rule found for command 'INSERT' for role '$ROLE'" ]]; then
    ok "$ID.resume.inspect" "pid $resume_pid inspection resumed: ${QA_STEP_STATE[6]} ${QA_STEP_MSG[6]}"
else
    fail "$ID.resume.inspect" "err=${QA_STEP_ERR[6]} state=${QA_STEP_STATE[6]} msg=${QA_STEP_MSG[6]:-}"
fi
if ! app_step "ROLLBACK" || ! app_step "SELECT pg_backend_pid()"; then
    app_close
    infra "$ID.resume" "$QA_INFRA_REASON"
    exit 0
fi
app_close
if [[ ${QA_STEP_ERR[8]} == false && ${QA_STEP_OUT[8]} == "$resume_pid" ]]; then
    ok "$ID.resume.same_backend" "application backend $resume_pid stayed up through repair"
else
    fail "$ID.resume.same_backend" "before=$resume_pid after=${QA_STEP_OUT[8]:-} err=${QA_STEP_ERR[8]:-} ${QA_STEP_MSG[8]:-}"
fi

# Bootstrap with superuser bypass off: CREATE EXTENSION must still commit.
qa_admin postgres \
    "CREATE DATABASE qa_act_boot" \
    "ALTER DATABASE qa_act_boot SET sql_firewall.mode = 'enforce'" \
    "ALTER DATABASE qa_act_boot SET sql_firewall.allow_superuser_auth_bypass = off" ||
    { infra "$ID.bootstrap" "$QA_INFRA_REASON"; exit 0; }
# Bypass is off for every new session in this database, so a follow-up
# SELECT cannot read pg_extension. CREATE succeeding and the next statement
# being rejected is the same-backend proof that the extension is installed.
if ! qa_sql_steps "$QA_SUPERUSER" qa_act_boot qa_admin \
    "SELECT pg_backend_pid()" \
    "SELECT 'qa_phase2d_boot_before'" \
    "CREATE EXTENSION sql_firewall" \
    "SELECT 'qa_phase2d_boot_after'"; then
    infra "$ID.bootstrap" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[2]} == false && ${QA_STEP_OUT[2]} == qa_phase2d_boot_before && ${QA_STEP_ERR[3]} == false && ${QA_STEP_ERR[4]} == true && ${QA_STEP_STATE[4]} == 42501 && ${QA_STEP_MSG[4]:-} == "sql_firewall: No rule found for command 'SELECT' for role '$QA_SUPERUSER'" ]]; then
    ok "$ID.bootstrap" "pid ${QA_STEP_OUT[1]} CREATE EXTENSION committed with bypass off; following select rejected ${QA_STEP_STATE[4]} ${QA_STEP_MSG[4]}"
else
    fail "$ID.bootstrap" "pid=${QA_STEP_OUT[1]} before=${QA_STEP_ERR[2]}/${QA_STEP_OUT[2]} create=${QA_STEP_ERR[3]} ${QA_STEP_MSG[3]:-} after=${QA_STEP_ERR[4]} ${QA_STEP_STATE[4]} ${QA_STEP_MSG[4]:-}"
fi

exit 0
