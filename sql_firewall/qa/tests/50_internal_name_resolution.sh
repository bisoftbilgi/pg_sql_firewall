#!/usr/bin/env bash
# Foreground firewall SPI must not resolve functions, operators, or types
# through the application session's search_path.
#
# Contract:
#   A. Under search_path = qa_shadow, pg_catalog, public, a superuser (firewall
#      bypass still on) invoking the shadowed names hits the application
#      objects. If that fixture does not fire, a later empty marker table is
#      INFRA, not protection.
#   B. A non-superuser learn-mode statement that does not itself use those
#      names still runs regex, approval, and fingerprint lookups (cache miss).
#      Those lookups must not call the shadows. The statement stays allowed.
#   C. That role's own function, table, and current_setting() still resolve
#      in qa_shadow.
#   D. A regex rule still blocks a matching statement.
#   E. In enforce mode, a seeded approved command is still allowed, and an
#      unapproved statement is still rejected. With alert notifications on,
#      the rejection must not call a shadowed pg_notify.
#   F. A superuser with bypass off does not run retention inside its query or
#      call shadowed now(), make_interval(), or comparison operators. The
#      worker's asynchronous pruning is checked separately.
#
# A setup failure, a native SQL error, or an internal path that did not run is
# INFRA. A shadow marker on a firewall-internal execution is FAIL.
# Runs only inside the disposable cluster.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.internal_name_resolution
EV=internal_name_resolution
ROLE=qa_spi_app
APP=qa_spi_app
LEARN_DB=qa_names
ENF_DB=qa_names_enf
OK_DB=qa_names_ok
PATH_SQL="SET search_path = qa_shadow, pg_catalog, public"

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Application shadows in an earlier search_path schema must not run during foreground firewall SPI. The same session's own objects must still resolve there. Policy outcomes stay as they are." ""

read_hits() { # DB -> HITS
    HITS=
    qa_admin "$1" \
        "SELECT coalesce(string_agg(s.kind || '=' || s.n::pg_catalog.text, ',' ORDER BY s.kind), '') FROM (SELECT kind, count(*) AS n FROM qa_shadow.hit GROUP BY kind) s" ||
        return $?
    HITS=${QA_STEP_OUT[1]}
}

# Superuser, bypass still at default (on): the firewall does not run, so a hit
# is the application object and not firewall SPI.
prove_fixture() { # DB LABEL SQL EXPECTED_HITS
    local db=$1 label=$2 sql=$3 expect=$4
    qa_admin "$db" "DELETE FROM qa_shadow.hit" || { infra "$label" "clear markers: $QA_INFRA_REASON"; return 1; }
    if ! qa_sql_steps "$QA_SUPERUSER" "$db" qa_admin "$PATH_SQL" "$sql"; then
        infra "$label" "$QA_INFRA_REASON"
        return 1
    fi
    if [[ ${QA_STEP_ERR[1]} == true || ${QA_STEP_ERR[2]} == true ]]; then
        infra "$label" "fixture SQL failed: ${QA_STEP_STATE[2]:-${QA_STEP_STATE[1]}} ${QA_STEP_MSG[2]:-${QA_STEP_MSG[1]:-}}"
        return 1
    fi
    local fixture_out=${QA_STEP_OUT[2]}
    read_hits "$db" || { infra "$label" "read markers: $QA_INFRA_REASON"; return 1; }
    qa_evidence "$EV" "- fixture $label hits=$HITS output=$fixture_out"
    if [[ $HITS != "$expect" ]]; then
        infra "$label" "hostile search_path did not reach this shadow (hits='$HITS', expected '$expect')"
        return 1
    fi
    ok "$label" "fixture under hostile search_path hit $HITS"
    return 0
}

install_shadows() { # DB
    local db=$1
    qa_admin "$db" \
        "CREATE SCHEMA qa_shadow AUTHORIZATION $ROLE" \
        "CREATE TABLE qa_shadow.hit (kind text)" \
        "CREATE TABLE qa_shadow.app_t (v pg_catalog.int4)" \
        "INSERT INTO qa_shadow.app_t VALUES (7)" \
        "CREATE FUNCTION qa_shadow.app_add(n pg_catalog.int4) RETURNS pg_catalog.int4 LANGUAGE sql AS 'SELECT n + 1'" \
        "CREATE FUNCTION qa_shadow.current_setting(setting pg_catalog.text) RETURNS pg_catalog.text LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('current_setting'); RETURN pg_catalog.current_setting(setting); END \$\$" \
        "CREATE FUNCTION qa_shadow.regex_match(a pg_catalog.text, b pg_catalog.text) RETURNS pg_catalog.bool LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('regex_op'); RETURN a OPERATOR(pg_catalog.~*) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.~* (FUNCTION = qa_shadow.regex_match, LEFTARG = pg_catalog.text, RIGHTARG = pg_catalog.text)" \
        "CREATE FUNCTION qa_shadow.eq_name(a pg_catalog.name, b pg_catalog.name) RETURNS pg_catalog.bool LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('name_eq'); RETURN a OPERATOR(pg_catalog.=) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.= (FUNCTION = qa_shadow.eq_name, LEFTARG = pg_catalog.name, RIGHTARG = pg_catalog.name)" \
        "CREATE FUNCTION qa_shadow.eq_text(a pg_catalog.text, b pg_catalog.text) RETURNS pg_catalog.bool LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('text_eq'); RETURN a OPERATOR(pg_catalog.=) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.= (FUNCTION = qa_shadow.eq_text, LEFTARG = pg_catalog.text, RIGHTARG = pg_catalog.text)" \
        "CREATE FUNCTION qa_shadow.eq_bool(a pg_catalog.bool, b pg_catalog.bool) RETURNS pg_catalog.bool LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('bool_eq'); RETURN a OPERATOR(pg_catalog.=) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.= (FUNCTION = qa_shadow.eq_bool, LEFTARG = pg_catalog.bool, RIGHTARG = pg_catalog.bool)" \
        "CREATE FUNCTION qa_shadow.eq_int(a pg_catalog.int4, b pg_catalog.int4) RETURNS pg_catalog.bool LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('int_eq'); RETURN a OPERATOR(pg_catalog.=) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.= (FUNCTION = qa_shadow.eq_int, LEFTARG = pg_catalog.int4, RIGHTARG = pg_catalog.int4)" \
        "CREATE FUNCTION qa_shadow.now() RETURNS pg_catalog.timestamptz LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('now'); RETURN pg_catalog.now(); END \$\$" \
        "CREATE FUNCTION qa_shadow.make_interval(days pg_catalog.int4) RETURNS pg_catalog.interval LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('make_interval'); RETURN pg_catalog.make_interval(days => days); END \$\$" \
        "CREATE FUNCTION qa_shadow.lt_ts(a pg_catalog.timestamptz, b pg_catalog.timestamptz) RETURNS pg_catalog.bool LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('lt_ts'); RETURN a OPERATOR(pg_catalog.<) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.< (FUNCTION = qa_shadow.lt_ts, LEFTARG = pg_catalog.timestamptz, RIGHTARG = pg_catalog.timestamptz)" \
        "CREATE FUNCTION qa_shadow.minus_ts(a pg_catalog.timestamptz, b pg_catalog.interval) RETURNS pg_catalog.timestamptz LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('minus_ts'); RETURN a OPERATOR(pg_catalog.-) b; END \$\$" \
        "CREATE OPERATOR qa_shadow.- (FUNCTION = qa_shadow.minus_ts, LEFTARG = pg_catalog.timestamptz, RIGHTARG = pg_catalog.interval)" \
        "CREATE FUNCTION qa_shadow.pg_notify(channel pg_catalog.text, payload pg_catalog.text) RETURNS void LANGUAGE plpgsql AS \$\$ BEGIN INSERT INTO qa_shadow.hit(kind) VALUES ('pg_notify'); RAISE WARNING 'qa_shadow_marker:pg_notify'; PERFORM pg_catalog.pg_notify(channel, payload); END \$\$" \
        "ALTER TABLE qa_shadow.hit OWNER TO $ROLE" \
        "ALTER TABLE qa_shadow.app_t OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.app_add(pg_catalog.int4) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.current_setting(pg_catalog.text) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.regex_match(pg_catalog.text, pg_catalog.text) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.eq_name(pg_catalog.name, pg_catalog.name) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.eq_text(pg_catalog.text, pg_catalog.text) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.eq_bool(pg_catalog.bool, pg_catalog.bool) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.eq_int(pg_catalog.int4, pg_catalog.int4) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.now() OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.make_interval(pg_catalog.int4) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.lt_ts(pg_catalog.timestamptz, pg_catalog.timestamptz) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.minus_ts(pg_catalog.timestamptz, pg_catalog.interval) OWNER TO $ROLE" \
        "ALTER FUNCTION qa_shadow.pg_notify(pg_catalog.text, pg_catalog.text) OWNER TO $ROLE" \
        "GRANT CONNECT ON DATABASE $db TO $ROLE" ||
        return $?
}

log_has() { # OFFSET NEEDLE
    tail -c +"$(($1 + 1))" "$QA_SERVER_LOG" | grep -F -q -- "$2"
}

# The saved value must be a real search_path list. Quoting the whole list
# stores one schema name, and an empty marker table is then not protection.
require_saved_path() { # DB LABEL
    qa_admin postgres \
        "SELECT coalesce((SELECT c FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase JOIN pg_roles r ON r.oid = s.setrole, unnest(s.setconfig) c WHERE d.datname = '$1' AND r.rolname = '$ROLE' AND c LIKE 'search_path=%'), 'unset')" ||
        { infra "$2" "read search_path: $QA_INFRA_REASON"; return 1; }
    if [[ ${QA_STEP_OUT[1]} != "search_path=qa_shadow, pg_catalog, public" ]]; then
        infra "$2" "saved search_path is '${QA_STEP_OUT[1]}'"
        return 1
    fi
    return 0
}

qa_admin postgres "CREATE ROLE $ROLE LOGIN" || { infra "$ID" "create role: $QA_INFRA_REASON"; exit 0; }

qa_create_db "$LEARN_DB" sql_firewall.mode=learn sql_firewall.enable_regex_scan=on sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "learn db: $QA_INFRA_REASON"; exit 0; }
install_shadows "$LEARN_DB" || { infra "$ID" "learn shadows: $QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "ALTER ROLE $ROLE IN DATABASE $LEARN_DB SET search_path = qa_shadow, pg_catalog, public" \
    "ALTER ROLE $ROLE IN DATABASE $LEARN_DB SET log_min_messages = 'debug1'" ||
    { infra "$ID" "learn role settings: $QA_INFRA_REASON"; exit 0; }

# The installation default is deliberately inactive. Seed an active rule so
# the foreground regex lookup is exercised by this isolation test.
qa_admin "$LEARN_DB" \
    "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('qa_phase2b_fixture_never_matches', 'name-resolution lookup fixture')" ||
    { infra "$ID" "regex fixture: $QA_INFRA_REASON"; exit 0; }
qa_admin "$LEARN_DB" \
    "SELECT count(*) FROM public.sql_firewall_regex_rules WHERE is_active OPERATOR(pg_catalog.=) true" ||
    { infra "$ID" "rule count: $QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} == 0 ]]; then
    infra "$ID" "no active regex rule; the ~* path would not execute"
    exit 0
fi
qa_evidence "$EV" "- active regex rules: ${QA_STEP_OUT[1]}"

# --- A. Fixtures. Bypass is on, so only the statement itself can mark. ---
FIXTURE_LEARN=1
prove_fixture "$LEARN_DB" "$ID.fixture.current_setting" "SELECT current_setting('statement_timeout')" "current_setting=1" || FIXTURE_LEARN=0
prove_fixture "$LEARN_DB" "$ID.fixture.regex_op" "SELECT 'A' ~* 'a'" "regex_op=1" || FIXTURE_LEARN=0
prove_fixture "$LEARN_DB" "$ID.fixture.name_eq" "SELECT 'qa'::pg_catalog.name = 'qa'::pg_catalog.name" "name_eq=1" || FIXTURE_LEARN=0
prove_fixture "$LEARN_DB" "$ID.fixture.text_eq" "SELECT 'qa'::pg_catalog.text = 'qa'::pg_catalog.text" "text_eq=1" || FIXTURE_LEARN=0
prove_fixture "$LEARN_DB" "$ID.fixture.bool_eq" "SELECT true = true" "bool_eq=1" || FIXTURE_LEARN=0

# --- B. Learn-mode probe. The statement names none of the shadows. ---
# A non-matching row forces the approval and fingerprint comparisons to run.
# An empty table would not call those operators.
require_saved_path "$LEARN_DB" "$ID.learn_probe" || exit 0
qa_admin "$LEARN_DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('qa_other', 'SELECT', false)" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('0000000000000000', 'SELECT QA_OTHER', 'qa_other', 'SELECT', 'select qa_other', 1, false)" \
    "DELETE FROM qa_shadow.hit" \
    "SELECT public.sql_firewall_clear_approval_cache()" ||
    { infra "$ID.learn_probe" "reset: $QA_INFRA_REASON"; exit 0; }
LEARN_OFF=$(qa_server_log_offset)
if ! qa_sql_steps "$ROLE" "$LEARN_DB" "$APP" "SELECT 1"; then
    infra "$ID.learn_probe" "$QA_INFRA_REASON"
elif [[ ${QA_STEP_ERR[1]} == true && ${QA_STEP_MSG[1]} == sql_firewall:* ]]; then
    fail "$ID.learn_probe" "learn-mode statement rejected: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]}"
elif [[ ${QA_STEP_ERR[1]} == true ]]; then
    infra "$ID.learn_probe" "unexpected error ${QA_STEP_STATE[1]}: ${QA_STEP_MSG[1]}"
elif [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    infra "$ID.learn_probe" "statement returned '${QA_STEP_OUT[1]}' (expected 1)"
else
    read_hits "$LEARN_DB" || { infra "$ID.learn_probe" "read markers: $QA_INFRA_REASON"; exit 0; }
    qa_evidence "$EV" "- learn probe hits=$HITS"
    if [[ $FIXTURE_LEARN -ne 1 ]]; then
        infra "$ID.learn_probe" "fixture did not demonstrate the shadows (hits='$HITS')"
    elif [[ -n $HITS ]]; then
        fail "$ID.learn_probe" "foreground internal SQL invoked application shadows: $HITS"
    elif ! log_has "$LEARN_OFF" "auto-approved & queued for persistence"; then
        infra "$ID.learn_probe" "approval lookup path was not observed in the server log"
    elif ! log_has "$LEARN_OFF" "fingerprint hit queued"; then
        infra "$ID.learn_probe" "fingerprint lookup path was not observed in the server log"
    elif log_has "$LEARN_OFF" "approval lookup failed" || log_has "$LEARN_OFF" "fingerprint fetch failed" || log_has "$LEARN_OFF" "regex check failed"; then
        infra "$ID.learn_probe" "an internal query failed; empty markers are not protection"
    else
        ok "$ID.learn_probe" "learn-mode SELECT stayed allowed and called no application shadow"
    fi
fi

# --- C. Application objects in qa_shadow still resolve. ---
qa_admin "$LEARN_DB" "DELETE FROM qa_shadow.hit" || { infra "$ID.application_resolution" "clear: $QA_INFRA_REASON"; exit 0; }
if ! qa_sql_steps "$ROLE" "$LEARN_DB" "$APP" \
    "SELECT app_add(41)" \
    "SELECT v FROM app_t" \
    "SELECT current_setting('server_version')"; then
    infra "$ID.application_resolution" "$QA_INFRA_REASON"
elif [[ ${QA_STEP_ERR[1]} == true || ${QA_STEP_ERR[2]} == true || ${QA_STEP_ERR[3]} == true ]]; then
    infra "$ID.application_resolution" "application SQL failed: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-} | ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-} | ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
elif [[ ${QA_STEP_OUT[1]} != 42 || ${QA_STEP_OUT[2]} != 7 || -z ${QA_STEP_OUT[3]} ]]; then
    infra "$ID.application_resolution" "results app_add='${QA_STEP_OUT[1]}' app_t='${QA_STEP_OUT[2]}' version='${QA_STEP_OUT[3]}'"
else
    app_version=${QA_STEP_OUT[3]}
    read_hits "$LEARN_DB" || { infra "$ID.application_resolution" "read markers: $QA_INFRA_REASON"; exit 0; }
    qa_evidence "$EV" "- application resolution hits=$HITS version=$app_version"
    if [[ $FIXTURE_LEARN -ne 1 ]]; then
        infra "$ID.application_resolution" "current_setting fixture did not fire"
    elif [[ $HITS != "current_setting=1" ]]; then
        fail "$ID.application_resolution" "expected only the application current_setting call (current_setting=1); hits=$HITS"
    else
        ok "$ID.application_resolution" "app_add=42, app_t=7, and current_setting resolved once in qa_shadow"
    fi
fi

# --- D. Regex policy still blocks. ---
qa_admin "$LEARN_DB" \
    "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('qa_phase2b_block_token', 'phase 2b policy probe')" ||
    { infra "$ID.regex_policy" "seed rule: $QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$LEARN_DB" "$APP" "SELECT 'qa_phase2b_block_token'" \
    42501 "^sql_firewall: Query blocked by security regex pattern\\.$"
qa_evidence "$EV" "- regex policy: $QA_VERDICT ($QA_DETAIL)"
qa_record "$QA_VERDICT" "$ID.regex_policy" "$QA_DETAIL"

# --- E. Enforce: seeded approval still allows; unapproved notify path does not. ---
qa_create_db "$OK_DB" sql_firewall.mode=enforce sql_firewall.enable_regex_scan=on sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID.approval_match" "db: $QA_INFRA_REASON"; exit 0; }
install_shadows "$OK_DB" || { infra "$ID.approval_match" "shadows: $QA_INFRA_REASON"; exit 0; }
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $OK_DB SET search_path = qa_shadow, pg_catalog, public" ||
    { infra "$ID.approval_match" "role path: $QA_INFRA_REASON"; exit 0; }
require_saved_path "$OK_DB" "$ID.approval_match" || exit 0
qa_admin "$OK_DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true)" \
    "SELECT public.sql_firewall_clear_approval_cache()" \
    "DELETE FROM qa_shadow.hit" ||
    { infra "$ID.approval_match" "seed: $QA_INFRA_REASON"; exit 0; }
if ! qa_sql_steps "$ROLE" "$OK_DB" "$APP" "SELECT 1"; then
    infra "$ID.approval_match" "$QA_INFRA_REASON"
elif [[ ${QA_STEP_ERR[1]} == true && ${QA_STEP_MSG[1]} == sql_firewall:* ]]; then
    fail "$ID.approval_match" "approved SELECT was rejected: ${QA_STEP_MSG[1]}"
elif [[ ${QA_STEP_ERR[1]} == true ]]; then
    infra "$ID.approval_match" "unexpected error ${QA_STEP_STATE[1]}: ${QA_STEP_MSG[1]}"
elif [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    infra "$ID.approval_match" "returned '${QA_STEP_OUT[1]}'"
else
    read_hits "$OK_DB" || { infra "$ID.approval_match" "read markers: $QA_INFRA_REASON"; exit 0; }
    qa_evidence "$EV" "- approval match hits=$HITS"
    if [[ $FIXTURE_LEARN -ne 1 ]]; then
        infra "$ID.approval_match" "name/text equality fixtures did not fire in the learn database"
    elif [[ -n $HITS ]]; then
        fail "$ID.approval_match" "approved lookup invoked application shadows: $HITS"
    else
        ok "$ID.approval_match" "seeded SELECT approval was honored and called no application shadow"
    fi
fi

qa_create_db "$ENF_DB" sql_firewall.mode=enforce sql_firewall.enable_alert_notifications=on sql_firewall.enable_regex_scan=on ||
    { infra "$ID.notify" "db: $QA_INFRA_REASON"; exit 0; }
install_shadows "$ENF_DB" || { infra "$ID.notify" "shadows: $QA_INFRA_REASON"; exit 0; }
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $ENF_DB SET search_path = qa_shadow, pg_catalog, public" ||
    { infra "$ID.notify" "role path: $QA_INFRA_REASON"; exit 0; }
require_saved_path "$ENF_DB" "$ID.notify" || exit 0
qa_admin "$ENF_DB" "SELECT pg_catalog.current_setting('sql_firewall.enable_alert_notifications')" ||
    { infra "$ID.notify" "alert guc: $QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != on ]]; then
    infra "$ID.notify" "alert notifications are '${QA_STEP_OUT[1]}'; pg_notify would not run"
    exit 0
fi
NOTIFY_FIXTURE=0
NFIX_OFF=$(qa_server_log_offset)
if prove_fixture "$ENF_DB" "$ID.fixture.pg_notify" "SELECT pg_notify('qa_chan', 'fixture')" "pg_notify=1"; then
    if log_has "$NFIX_OFF" "qa_shadow_marker:pg_notify"; then
        NOTIFY_FIXTURE=1
    else
        infra "$ID.fixture.pg_notify_warning" "pg_notify marker row was not accompanied by qa_shadow_marker:pg_notify"
    fi
fi

qa_admin "$ENF_DB" "DELETE FROM qa_shadow.hit" || { infra "$ID.notify" "clear: $QA_INFRA_REASON"; exit 0; }
NOTIFY_OFF=$(qa_server_log_offset)
qa_check_rejection "$ROLE" "$ENF_DB" "$APP" "SELECT 1" \
    42501 "^sql_firewall: No rule found for command 'SELECT' for role '$ROLE'$"
qa_evidence "$EV" "- notify rejection: $QA_VERDICT ($QA_DETAIL)"
if [[ $QA_VERDICT != PASS ]]; then
    qa_record "$QA_VERDICT" "$ID.notify" "$QA_DETAIL"
elif [[ $NOTIFY_FIXTURE -ne 1 ]]; then
    infra "$ID.notify" "pg_notify fixture did not fire; absence of the warning is not protection"
elif log_has "$NOTIFY_OFF" "qa_shadow_marker:pg_notify"; then
    fail "$ID.notify" "blocked statement invoked application pg_notify"
elif log_has "$NOTIFY_OFF" "failed to emit alert notify"; then
    infra "$ID.notify" "alert notify failed; the shadow was not the observed outcome"
else
    ok "$ID.notify" "unapproved SELECT was rejected and did not call application pg_notify"
fi

# --- F. Prune path. search_path is set while bypass is still on. ---
PRUNE_FIXTURE=1
prove_fixture "$LEARN_DB" "$ID.fixture.now" "SELECT now()" "now=1" || PRUNE_FIXTURE=0
prove_fixture "$LEARN_DB" "$ID.fixture.make_interval" "SELECT make_interval(days => 1)" "make_interval=1" || PRUNE_FIXTURE=0
prove_fixture "$LEARN_DB" "$ID.fixture.lt_ts" "SELECT pg_catalog.now() < pg_catalog.now()" "lt_ts=1" || PRUNE_FIXTURE=0
prove_fixture "$LEARN_DB" "$ID.fixture.minus_ts" "SELECT pg_catalog.now() - pg_catalog.make_interval(days => 1)" "minus_ts=1" || PRUNE_FIXTURE=0
prove_fixture "$LEARN_DB" "$ID.fixture.int_eq" "SELECT 1 = 1" "int_eq=1" || PRUNE_FIXTURE=0

qa_admin "$LEARN_DB" \
    "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) VALUES (pg_catalog.now() - pg_catalog.make_interval(days => 400), 'qa_prune_seed', pg_catalog.current_database(), 'QA_PRUNE_OLD', 'SELECT', 'ALLOWED', 'seed')" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text = 'QA_PRUNE_OLD'" ||
    { infra "$ID.prune" "seed: $QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[2]} != 1 ]]; then
    infra "$ID.prune" "seeded row count is '${QA_STEP_OUT[2]}'"
    exit 0
fi
if ! qa_sql_steps "$QA_SUPERUSER" "$LEARN_DB" qa_admin \
    "DELETE FROM qa_shadow.hit" \
    "$PATH_SQL" \
    "SET sql_firewall.allow_superuser_auth_bypass = off" \
    "SELECT 1"; then
    infra "$ID.prune" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_ERR[1]} == true || ${QA_STEP_ERR[2]} == true || ${QA_STEP_ERR[3]} == true || ${QA_STEP_ERR[4]} == true ]]; then
    infra "$ID.prune" "probe failed at a step: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-} | ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-} | ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-} | ${QA_STEP_STATE[4]} ${QA_STEP_MSG[4]:-}"
    exit 0
fi
qa_admin "$LEARN_DB" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text = 'QA_PRUNE_OLD'" ||
    { infra "$ID.prune" "count after probe: $QA_INFRA_REASON"; exit 0; }
OLD_LEFT=${QA_STEP_OUT[1]}
read_hits "$LEARN_DB" || { infra "$ID.prune" "read markers: $QA_INFRA_REASON"; exit 0; }
qa_evidence "$EV" "- prune hits=$HITS old_rows_left=$OLD_LEFT"
if [[ $PRUNE_FIXTURE -ne 1 ]]; then
    infra "$ID.prune" "prune fixtures did not all fire (hits='$HITS', old_rows_left=$OLD_LEFT)"
elif [[ -n $HITS ]]; then
    fail "$ID.prune" "foreground query invoked application shadows: $HITS (old_rows_left=$OLD_LEFT)"
else
    ok "$ID.prune" "foreground query did not invoke application shadows; retention belongs to the worker"
fi
