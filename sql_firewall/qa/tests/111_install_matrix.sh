#!/usr/bin/env bash
# Phase 9 (P9-01): installation states that need a server restart.
#
# The test restarts the disposable server with changed settings and restores
# shared_preload_libraries and sql_firewall.launcher_database at the end
# (also on an early exit), offline from a saved copy of postgresql.auto.conf.
#
# Contract (README 4):
#   no_preload.refused   without shared_preload_libraries, CREATE EXTENSION
#                        fails with 55000 and the restart instruction; no
#                        pg_extension row and no sql_firewall relation remain,
#                        and the database keeps working
#   no_preload.reload    with sql_firewall written into the setting and only a
#                        reload, it is still refused (the detail names the
#                        value waiting for a restart): only a library loaded
#                        at start counts
#   launcher_database    after the restart with preload and
#                        sql_firewall.launcher_database set, CREATE EXTENSION
#                        succeeds, the launcher runs in that database and the
#                        installed database's consumer processes events
#   preloaded            status reports the mode and an unapproved statement
#                        of an enforce-mode role is refused
#   removed_preload      after a restart without the library, the existing
#                        installation reports NOT ACTIVE and is not inspected
#                        (the documented limit: the library cannot act when it
#                        is not loaded)
#   restored             with the settings reset, the launcher is in postgres
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.install_matrix
EV=install_matrix
DB=qa_inst
LDB=qa_inst_launcher
APP=qa_inst_app
REFUSED="sql_firewall: the library is not loaded through shared_preload_libraries; add sql_firewall to shared_preload_libraries, restart PostgreSQL, and run the command again"
NOT_ACTIVE="sql_firewall NOT ACTIVE: not loaded through shared_preload_libraries; statements are not inspected"

ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }

qa_evidence "$EV" "# $ID" ""
qa_admin postgres "SHOW data_directory" "SHOW shared_preload_libraries" \
    "CREATE ROLE $APP LOGIN NOSUPERUSER" "CREATE DATABASE $DB" "CREATE DATABASE $LDB" \
    "GRANT CONNECT ON DATABASE $DB TO $APP, $QA_CANARY_ROLE" \
    "ALTER ROLE $APP IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $DB SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
DATA=${QA_STEP_OUT[1]} PRELOAD=${QA_STEP_OUT[2]}
[[ $PRELOAD == *sql_firewall* ]] || { infra "$ID" "the run's server does not preload sql_firewall: '$PRELOAD'"; exit 0; }
qa_admin "$DB" "CREATE TABLE public.qa_inst_t (id integer)" "GRANT SELECT ON public.qa_inst_t TO $APP" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

PG_CTL=$(dirname "$(readlink "/proc/$QA_PM_PID/exe")")/pg_ctl
AUTO_CONF=$DATA/postgresql.auto.conf
SAVED_AUTO_CONF=$QA_RUN_DIR/install_matrix.postgresql.auto.conf
cp "$AUTO_CONF" "$SAVED_AUTO_CONF" || { infra "$ID" "could not save the disposable server configuration"; exit 0; }
switch_settings() { # literal configuration lines to append to the saved auto.conf
    "$PG_CTL" -D "$DATA" -m fast -w -t 60 stop >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 || true
    cp "$SAVED_AUTO_CONF" "$AUTO_CONF" || return 1
    if (($#)); then printf '%s\n' "$@" >>"$AUTO_CONF" || return 1; fi
    "$PG_CTL" -D "$DATA" -l "$QA_SERVER_LOG" -w -t 60 start >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 || return 1
    QA_PM_PID=$(head -1 "$DATA/postmaster.pid")
}
restore() {
    switch_settings || infra "$ID.restore" "could not restart the disposable server with its original configuration"
}
trap restore EXIT
launcher_db() { # -> LAUNCHER ('' when none)
    qa_admin postgres "SELECT coalesce(string_agg(coalesce(datname, '?'), ','), '') FROM pg_catalog.pg_stat_activity WHERE backend_type = 'sql_firewall_launcher'" ||
        return 1
    LAUNCHER=${QA_STEP_OUT[1]}
}
select_as_app() { # -> APP_OUT (allow | SQLSTATE message)
    qa_sql_steps "$APP" "$DB" qa_inst "SELECT count(*) FROM public.qa_inst_t" || { APP_OUT="infra: $QA_INFRA_REASON"; return; }
    if [[ ${QA_STEP_ERR[1]} == false ]]; then APP_OUT=allow; else APP_OUT="${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"; fi
}
residue() { # -> RESIDUE "extension rows / sql_firewall relations / sql_firewall functions"
    qa_admin "$DB" "SELECT count(*) FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" \
        "SELECT count(*) FROM pg_catalog.pg_class WHERE relname LIKE 'sql\\_firewall%'" \
        "SELECT count(*) FROM pg_catalog.pg_proc WHERE proname LIKE 'sql\\_firewall%'" || return 1
    RESIDUE="${QA_STEP_OUT[1]}/${QA_STEP_OUT[2]}/${QA_STEP_OUT[3]}"
}
create_extension() { # -> CREATE_ERR, CREATE_STATE, CREATE_MSG, CREATE_OUT (psql stderr+stdout)
    qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin "CREATE EXTENSION sql_firewall" || return 1
    CREATE_ERR=${QA_STEP_ERR[1]} CREATE_STATE=${QA_STEP_STATE[1]} CREATE_MSG=${QA_STEP_MSG[1]:-}
}

# --- without shared_preload_libraries ----------------------------------------
switch_settings "shared_preload_libraries = ''" || { infra "$ID.no_preload" "restart failed: $(tail -3 "$QA_RUN_DIR/logs/pg_ctl.log" | tr '\n' ' ')"; exit 0; }
create_extension || { infra "$ID.no_preload.refused" "$QA_INFRA_REASON"; exit 0; }
residue || { infra "$ID.no_preload.refused" "$QA_INFRA_REASON"; exit 0; }
qa_evidence "$EV" "- CREATE EXTENSION without preload: err=$CREATE_ERR $CREATE_STATE $CREATE_MSG; residue (extension/relations/functions) $RESIDUE"
select_as_app
if [[ $CREATE_ERR == true && $CREATE_STATE == 55000 && $CREATE_MSG == "$REFUSED" && $RESIDUE == 0/0/0 && $APP_OUT == allow ]]; then
    ok "$ID.no_preload.refused" "CREATE EXTENSION was refused (55000 '$REFUSED'); no extension row, relation, or function remained; the database kept working"
else
    fail "$ID.no_preload.refused" "err=$CREATE_ERR $CREATE_STATE '$CREATE_MSG'; residue $RESIDUE; app statement: $APP_OUT"
fi

# The setting names the library, but the server was only reloaded. The value
# written differs from the run's postgresql.conf entry ('sql_firewall'), so the
# detail must name the entry ALTER SYSTEM wrote, which PostgreSQL marks "could
# not be applied" until the restart (a filter on that column once read the
# superseded entry instead, and nothing at all on a server whose
# postgresql.conf does not set the parameter; seen in the manual spot check
# on the PGDG 17 package). No restart follows with this value.
PENDING="pg_stat_statements, sql_firewall"
# A list, not one quoted string (that would name a single library).
qa_admin postgres "ALTER SYSTEM SET shared_preload_libraries = $PENDING" "SELECT pg_catalog.pg_reload_conf()" ||
    { infra "$ID.no_preload.reload" "$QA_INFRA_REASON"; exit 0; }
detail_out=$("$QA_PSQL" -X -A -t -v VERBOSITY=verbose -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" -c "CREATE EXTENSION sql_firewall" 2>&1)
residue || { infra "$ID.no_preload.reload" "$QA_INFRA_REASON"; exit 0; }
qa_evidence "$EV" "- after ALTER SYSTEM + reload only:" "$(sed 's/^/    /' <<<"$detail_out")"
if grep -qF "55000: $REFUSED" <<<"$detail_out" && grep -qF "the configuration sets '$PENDING', which takes effect only after a restart" <<<"$detail_out" && [[ $RESIDUE == 0/0/0 ]]; then
    ok "$ID.no_preload.reload" "with the setting written ('$PENDING') and reloaded but no restart, CREATE EXTENSION was still refused and the detail named that pending value; nothing remained"
else
    fail "$ID.no_preload.reload" "output: $(tr '\n' ' ' <<<"$detail_out"); residue $RESIDUE"
fi

# --- preloaded, launcher in another database ---------------------------------
switch_settings "sql_firewall.launcher_database = '$LDB'" ||
    { infra "$ID.launcher_database" "restart failed: $(tail -3 "$QA_RUN_DIR/logs/pg_ctl.log" | tr '\n' ' ')"; exit 0; }
create_extension || { infra "$ID.launcher_database" "$QA_INFRA_REASON"; exit 0; }
[[ $CREATE_ERR == false ]] || { fail "$ID.launcher_database" "CREATE EXTENSION with preload failed: $CREATE_STATE $CREATE_MSG"; exit 0; }
live=0
qa_wait_worker_live "$DB" 90 && live=1
launcher_db || { infra "$ID.launcher_database" "$QA_INFRA_REASON"; exit 0; }
if [[ $live == 1 && $LAUNCHER == "$LDB" ]]; then
    ok "$ID.launcher_database" "with preload CREATE EXTENSION succeeded; the launcher ran in $LDB and the consumer of $DB processed a canary"
else
    fail "$ID.launcher_database" "launcher in '$LAUNCHER'; consumer live: $live (${QA_INFRA_REASON:-})"
fi
qa_admin "$DB" "SELECT public.sql_firewall_status()" || { infra "$ID.preloaded" "$QA_INFRA_REASON"; exit 0; }
status=${QA_STEP_OUT[1]}
select_as_app
if [[ $status == "sql_firewall running in "* && $APP_OUT == "42501 sql_firewall: No rule found for command 'SELECT' for role '$APP'" ]]; then
    ok "$ID.preloaded" "status '$status'; the unapproved SELECT was refused: $APP_OUT"
else
    fail "$ID.preloaded" "status '$status'; SELECT: $APP_OUT"
fi

# --- preload removed after installation --------------------------------------
switch_settings "shared_preload_libraries = ''" ||
    { infra "$ID.removed_preload" "restart failed: $(tail -3 "$QA_RUN_DIR/logs/pg_ctl.log" | tr '\n' ' ')"; exit 0; }
status_out=$("$QA_PSQL" -X -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" -c "SELECT public.sql_firewall_status()" 2>&1)
qa_evidence "$EV" "- status after removing preload:" "$(sed 's/^/    /' <<<"$status_out")"
launcher_db || { infra "$ID.removed_preload" "$QA_INFRA_REASON"; exit 0; }
select_as_app
if grep -qxF "$NOT_ACTIVE" <<<"$status_out" && grep -q "WARNING:  sql_firewall: the library is not loaded through shared_preload_libraries" <<<"$status_out" &&
    [[ -z $LAUNCHER && $APP_OUT == allow ]]; then
    ok "$ID.removed_preload" "after removing the library from the setting and restarting, the existing installation reported '$NOT_ACTIVE' with a WARNING, no launcher ran, and the enforce-mode statement was not inspected (documented limit)"
else
    fail "$ID.removed_preload" "status: $(tr '\n' ' ' <<<"$status_out"); launcher '$LAUNCHER'; SELECT: $APP_OUT"
fi

# --- restore ------------------------------------------------------------------
restore
trap - EXIT
launcher_db || { infra "$ID.restored" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 30))
while [[ $LAUNCHER != postgres ]] && ((SECONDS < deadline)); do sleep 1; launcher_db || break; done
if [[ $LAUNCHER == postgres ]]; then
    ok "$ID.restored" "settings reset; the launcher runs in postgres again"
else
    fail "$ID.restored" "launcher in '$LAUNCHER' after the reset"
fi
exit 0
