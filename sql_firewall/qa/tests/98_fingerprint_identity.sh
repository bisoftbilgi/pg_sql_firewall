#!/usr/bin/env bash
# Phase 4B: fingerprint identities from the production path (release build).
#
# Ordinary roles send statements in learn mode. The production lookup writes a
# 'LEARNED (FINGERPRINT AUTO)' activity row, synchronously, only for an
# identity it has not seen for that role and command; a statement whose
# identity was already seen writes none. That row count is the equality oracle.
# Rows persisted by the worker show the identity, the version 2
# canonical text, and the role, command, and database association.
#
# Each group uses its own role, so identities of other groups never match.
# Every multi-statement case is one simple-query message; extended-protocol
# cases are Parse/Bind/Execute through libpq.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.fingerprint_identity
EV=fingerprint_identity
DB=qa_fpid
PREFIX=qa_fpid_

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Learn-mode ordinary roles; one role per group. 'learned' counts LEARNED (FINGERPRINT AUTO) rows, one per new identity." ""

qa_create_db "$DB" sql_firewall.mode=learn sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "CREATE TABLE public.qa_t (id integer, v text)" \
    "INSERT INTO public.qa_t VALUES (1, 'row')" \
    "CREATE TABLE public.t (a integer, b integer, account_a integer, account_b integer, \"Account\" integer, account integer)" \
    "CREATE TABLE public.table1 (value integer)" \
    "CREATE TABLE public.table2 (value integer)" \
    "CREATE TABLE public.qa_ins (v text)" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID.ready" "$QA_INFRA_REASON"; exit 0; }

# role NAME: an ordinary role with the privileges every group needs.
role() {
    qa_admin "$DB" \
        "CREATE ROLE $1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" \
        "GRANT CONNECT ON DATABASE $DB TO $1" \
        "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO $1" \
        "GRANT CREATE ON SCHEMA public TO $1" \
        "ALTER ROLE $1 IN DATABASE $DB SET log_statement = 'all'"
}

LIBPQ=$(dirname "$QA_PSQL")/../lib/libpq.so.5
[[ -f $LIBPQ ]] || { infra "$ID" "libpq not found at $LIBPQ"; exit 0; }
export QA_LIBPQ=$LIBPQ
export QA_CONNINFO="host=$QA_SOCK port=$QA_PORT dbname=$DB"

# send ROLE [DB]: stdin lines (see qa/pq_session.py) -> OUT[], one result
# line per protocol exchange.
send() {
    mapfile -t OUT < <(python3 "$(dirname "$0")/../pq_session.py" "$@") || {
        infra "$ID" "client failed for $1"
        exit 0
    }
}

log_has() { # OFFSET TEXT: TEXT occurs in the server log after OFFSET
    tail -c +"$(($1 + 1))" "$QA_SERVER_LOG" | grep -F -- "$2" >/dev/null
}

learned() { # ROLE FAMILY -> LEARNED, LEARNED_TEXTS
    qa_admin "$DB" \
        "SELECT count(*)::text || E'\\x1f' || coalesce(string_agg(query_text, ' ~ ' ORDER BY log_id), '') FROM public.sql_firewall_activity_log WHERE role_name OPERATOR(pg_catalog.=) '$1' AND command_type OPERATOR(pg_catalog.=) '$2' AND action OPERATOR(pg_catalog.=) 'LEARNED (FINGERPRINT AUTO)'" ||
        return $?
    LEARNED=${QA_STEP_OUT[1]%%$'\x1f'*}
    LEARNED_TEXTS=${QA_STEP_OUT[1]#*$'\x1f'}
}

# persisted ROLE FAMILY COUNT -> ROWS (fingerprint|normalized|sample per line,
# by fingerprint), once COUNT rows exist for ROLE and FAMILY.
persisted() {
    local where="role_name OPERATOR(pg_catalog.=) '$1' AND command_type OPERATOR(pg_catalog.=) '$2'"
    qa_poll "$DB" "SELECT count(*)::text FROM public.sql_firewall_query_fingerprints WHERE $where" "$3" 30 || return $?
    qa_admin "$DB" \
        "SELECT string_agg(fingerprint || '|' || normalized_query || '|' || sample_query, E'\\n' ORDER BY fingerprint) FROM public.sql_firewall_query_fingerprints WHERE $where" ||
        return $?
    ROWS=${QA_STEP_OUT[1]}
}

# expect_learned LABEL ROLE FAMILY N: N distinct identities were seen.
expect_learned() {
    learned "$2" "$3" || { infra "$ID.$1" "$QA_INFRA_REASON"; return 1; }
    qa_evidence "$EV" "- $1: $2/$3 learned=$LEARNED: $LEARNED_TEXTS"
    if [[ $LEARNED != "$4" ]]; then
        fail "$ID.$1" "$2/$3 learned $LEARNED new identities, expected $4: $LEARNED_TEXTS"
        return 1
    fi
}

all_ok() { # expected result lines are all OK
    local line
    for line in "${OUT[@]}"; do
        [[ $line == OK* ]] || { fail "$ID.$1" "a statement returned '$line'"; return 1; }
    done
}

# ---------------------------------------------------------------------------
# Structural differences: every statement is a new identity.
# ---------------------------------------------------------------------------
R=${PREFIX}struct
role $R || { infra "$ID.structure" "$QA_INFRA_REASON"; exit 0; }
DISTINCT=(
    'SELECT "account_a" FROM public.t'
    'SELECT "account_b" FROM public.t'
    'SELECT value FROM public.table1'
    'SELECT value FROM public.table2'
    'SELECT "Account" FROM public.t'
    'SELECT account FROM public.t'
    'SELECT a FROM public.t WHERE a < 1'
    'SELECT a FROM public.t WHERE a <= 1'
    'SELECT a::int FROM public.t'
    'SELECT a::bigint FROM public.t'
    'SELECT a FROM public.t WHERE a = -1'
    'SELECT a FROM public.t WHERE a = 1.0'
    'SELECT a FROM public.t WHERE a = 1 AND b = 2'
    'SELECT a FROM public.t WHERE b = 2 AND a = 1'
    'SELECT a FROM public.t WHERE a IN (1, 2)'
    'SELECT a FROM public.t WHERE a IN (1, 2, 3)'
    'SELECT a/**/b FROM public.t'
)
send $R < <(printf 'exec\t%s\n' "${DISTINCT[@]}")
if all_ok structure && expect_learned structure $R SELECT ${#DISTINCT[@]}; then
    ok "$ID.structure" "${#DISTINCT[@]} statements differing in identifier content or case, digits in a table name, operator, cast, sign, literal category, predicate order, IN-list length, or a comment between tokens were ${#DISTINCT[@]} identities"
fi

# Parameter relationships: extended protocol and SQL PREPARE.
R=${PREFIX}param
role $R || { infra "$ID.parameters" "$QA_INFRA_REASON"; exit 0; }
log_at=$(qa_server_log_offset)
send $R <<'EOF'
prepare	qa_same	SELECT a FROM public.t WHERE a = $1 AND b = $1
prepare	qa_diff	SELECT a FROM public.t WHERE a = $1 AND b = $2
run	qa_same	1
run	qa_same	2
run	qa_diff	1,1
run	qa_diff	3,4
exec	PREPARE qa_psame (int) AS SELECT a FROM public.t WHERE a = $1 AND b = $1
exec	EXECUTE qa_psame(1)
exec	EXECUTE qa_psame(2)
exec	PREPARE qa_pdiff (int, int) AS SELECT a FROM public.t WHERE a = $1 AND b = $2
exec	EXECUTE qa_pdiff(1, 1)
EOF
if all_ok parameters && expect_learned parameters $R SELECT 4 && expect_learned parameters.execute $R EXECUTE 2; then
    if ! log_has "$log_at" "execute qa_same: SELECT a FROM public.t WHERE a = \$1 AND b = \$1"; then
        infra "$ID.parameters" "no 'execute qa_same:' log line; extended protocol not shown"
    elif persisted $R SELECT 4; then
        expect=$(printf '%s\n' \
            'v3: PREPARE "qa_pdiff" ( INT , INT ) AS SELECT "a" FROM "public" . "t" WHERE "a" = $1 AND "b" = $2' \
            'v3: PREPARE "qa_psame" ( INT ) AS SELECT "a" FROM "public" . "t" WHERE "a" = $1 AND "b" = $1' \
            'v3: SELECT "a" FROM "public" . "t" WHERE "a" = $1 AND "b" = $1' \
            'v3: SELECT "a" FROM "public" . "t" WHERE "a" = $1 AND "b" = $2' | sort)
        got=$(cut -d'|' -f2 <<<"$ROWS" | sort)
        if [[ $got == "$expect" ]]; then
            ok "$ID.parameters" "Parse/Bind/Execute and SQL PREPARE/EXECUTE: \$1,\$1 and \$1,\$2 were different identities, and executions with different values shared one; persisted text keeps the parameter numbers"
        else
            fail "$ID.parameters" "persisted normalized texts: ${got//$'\n'/ ; }"
        fi
    else
        infra "$ID.parameters" "$QA_INFRA_REASON"
    fi
fi

# ---------------------------------------------------------------------------
# Literal values, formatting, and batching: one identity per group.
# ---------------------------------------------------------------------------
R=${PREFIX}values
role $R || { infra "$ID.values" "$QA_INFRA_REASON"; exit 0; }
send $R <<'EOF'
exec	SELECT v FROM public.qa_t WHERE id = 1
exec	select V from PUBLIC.QA_T where ID = 2
exec	SELECT v FROM public.qa_t /* c /* nested */ c */ WHERE id = 0x1F -- tail
exec	SELECT v{NL}{TAB}FROM public.qa_t{NL}WHERE id = 1_000;
exec	SELECT v FROM public.qa_t WHERE id = 8; SELECT v FROM public.qa_t WHERE id = 9;
exec	SHOW application_name; SELECT v FROM public.qa_t WHERE id = 10
EOF
if all_ok values && expect_learned values $R SELECT 1 && expect_learned values.show $R SHOW 1; then
    if persisted $R SELECT 1 && [[ $ROWS =~ ^[0-9a-f]{64}\|'v3: SELECT "v" FROM "public" . "qa_t" WHERE "id" = ?int|SELECT v FROM public.qa_t WHERE id = 1'$ ]]; then
        ok "$ID.values" "integer value changes, keyword and identifier case, comments (nested and line), whitespace, a terminal ';', and batching (after a SELECT or a SHOW in one message) kept one identity, persisted for $R/SELECT as '${ROWS#*|}'"
    else
        fail "$ID.values" "persisted rows: ${ROWS:-$QA_INFRA_REASON}"
    fi
fi

R=${PREFIX}strings
role $R || { infra "$ID.literals" "$QA_INFRA_REASON"; exit 0; }
send $R <<'EOF'
exec	SELECT v FROM public.qa_t WHERE v = 'a'
exec	SELECT v FROM public.qa_t WHERE v = 'it''s'
exec	SELECT v FROM public.qa_t WHERE v = E'b\n'
exec	SELECT v FROM public.qa_t WHERE v = $$c$$
exec	SELECT v FROM public.qa_t WHERE v = $tag$d;e$tag$
exec	SELECT v FROM public.qa_t WHERE v = 'ış€😀'
exec	SELECT v FROM public.qa_t WHERE id = 1.5
exec	SELECT v FROM public.qa_t WHERE id = 2e10
exec	SELECT v FROM public.qa_t WHERE id = 3000000000
exec	SELECT v FROM public.qa_t WHERE v = U&'\0041'
exec	SELECT v FROM public.qa_t WHERE v = U&'b'
EOF
if all_ok literals && expect_learned literals $R SELECT 3; then
    ok "$ID.literals" "standard, doubled-quote, escape, dollar-quoted, and UTF8 strings were one identity; decimal, exponent, and beyond-int4 numerics another; U& strings a third"
fi

# Standalone versus batched, and a SET of standard_conforming_strings earlier
# in the same message (the message is parsed before the SET runs).
R=${PREFIX}batch
role $R || { infra "$ID.batch" "$QA_INFRA_REASON"; exit 0; }
send $R <<'EOF'
exec	SELECT v FROM public.qa_t WHERE id = 1 /* qa_standalone */
exec	SELECT 'x'; SELECT v FROM public.qa_t WHERE id = 2
exec	SELECT 'q\' AS p
exec	SET standard_conforming_strings = off; SELECT 'r\' AS p
EOF
if all_ok batch && expect_learned batch $R SELECT 3; then
    ok "$ID.batch" "a statement later in a message had the identity of the same statement sent alone; after SET standard_conforming_strings = off in the same message, SELECT 'r\\' AS p kept the identity of SELECT 'q\\' AS p"
fi

# ---------------------------------------------------------------------------
# A plain string whose backslash changes the structure is refused.
# ---------------------------------------------------------------------------
# With standard_conforming_strings off the backslash escapes the quote and the
# whole text is one literal; with it on the literal ends there and a UNION
# reads public.review_secret. Both readings are valid, so the text does not
# show which structure PostgreSQL parsed. Before this revision both readings
# were joined into one identity, 0330c478ba8ebabe (reviewer run
# sqlfw-review-4b-9r7vocd3), shared by both structures. The native control
# runs in a database without the extension; every SET is its own message
# unless stated.
AMB="SELECT 'safe\\' UNION ALL SELECT v FROM public.review_secret --'"
AMB_INS="INSERT INTO public.review_log SELECT 'safe\\' UNION ALL SELECT v FROM public.review_secret --'"
AMB_ERR="ERR 0A000 sql_firewall: statement reads differently with standard_conforming_strings on and off; its fingerprint is ambiguous"
OLD_COMBINED=0330c478ba8ebabe
OLD_COMBINED_NORM='v2: ?scs_on SELECT ?str UNION ALL SELECT "v" FROM "public" . "review_secret" ?scs_off SELECT ?str'
NATIVE=${PREFIX}native
R=${PREFIX}ambig
REVIEW_SETUP=(
    "CREATE TABLE public.review_secret (v text)"
    "INSERT INTO public.review_secret VALUES ('review_secret_value')"
    "CREATE TABLE public.review_log (v text)"
)
if ! qa_admin "$DB" "${REVIEW_SETUP[@]}" || ! role $R || ! qa_admin postgres "CREATE DATABASE $NATIVE" ||
    ! qa_admin "$NATIVE" "${REVIEW_SETUP[@]}" "GRANT CONNECT ON DATABASE $NATIVE TO $R" \
        "GRANT SELECT ON public.review_secret TO $R" "GRANT INSERT ON public.review_log TO $R" ||
    ! qa_admin "$DB" \
        "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('$OLD_COMBINED', $(qa_sql_quote "$OLD_COMBINED_NORM"), '$R', 'SELECT', $(qa_sql_quote "$AMB"), 1, true)"; then
    infra "$ID.ambiguous" "$QA_INFRA_REASON"
    exit 0
fi
AMB_LINES=(
    "SET standard_conforming_strings = off"
    "$AMB"
    "$AMB_INS"
    "SET standard_conforming_strings = on"
    "$AMB"
    "$AMB_INS"
    "SET standard_conforming_strings = off; $AMB"
)
send $R $NATIVE < <(printf 'exec\t%s\n' "${AMB_LINES[@]}")
NATIVE_OUT=("${OUT[@]}")
send $R < <(printf 'exec\t%s\n' "${AMB_LINES[@]}")
FW_OUT=("${OUT[@]}")
qa_evidence "$EV" "- ambiguous, native ($NATIVE): ${NATIVE_OUT[*]}" "- ambiguous, sql_firewall ($DB): ${FW_OUT[*]}"
native_expect=("OK" "OK rows=1: safe' UNION ALL SELECT v FROM public.review_secret --" "OK" "OK" "OK rows=2: safe\\|review_secret_value" "OK" "OK rows=2: safe\\|review_secret_value")
fw_expect=("OK" "$AMB_ERR" "$AMB_ERR" "OK" "$AMB_ERR" "$AMB_ERR" "$AMB_ERR")
if [[ ${NATIVE_OUT[*]} != "${native_expect[*]}" ]]; then
    infra "$ID.ambiguous" "native control did not show both structures: ${NATIVE_OUT[*]}"
elif [[ ${FW_OUT[*]} != "${fw_expect[*]}" ]]; then
    fail "$ID.ambiguous" "sql_firewall results: ${FW_OUT[*]}"
elif ! qa_admin "$DB" "SELECT count(*) FROM public.review_log" || [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.ambiguous" "review_log in $DB holds '${QA_STEP_OUT[1]:-$QA_INFRA_REASON}' rows"
else
    ok "$ID.ambiguous" "natively the text returned one literal with the setting off and the secret row with it on (also when SET off preceded it in the same message, which was parsed with the setting on); under sql_firewall every execution, SELECT or INSERT, failed with 0A000 before running (review_log stayed empty), although an approved row for the old combined identity $OLD_COMBINED existed for $R"
fi
qa_admin "$DB" "SELECT hit_count || ',' || is_approved FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) '$R' AND fingerprint OPERATOR(pg_catalog.=) '$OLD_COMBINED'" &&
    qa_evidence "$EV" "- supplementary: seeded $OLD_COMBINED row for $R is (hit_count,is_approved) = ${QA_STEP_OUT[1]} after the refused executions"

# Across setting changes: SQL PREPARE/EXECUTE and Parse/Bind/Execute. A text
# with one valid reading keeps it after the setting changes; the ambiguous
# text is refused at Execute, and a SQL PREPARE of it is refused.
send $R <<'EOF'
exec	SET standard_conforming_strings = off
prepare	qa_amb_ext	SELECT 'safe\' UNION ALL SELECT v FROM public.review_secret --'
prepare	qa_one_ext	SELECT 'w\'' AS v
run	qa_amb_ext	
exec	SET standard_conforming_strings = on
run	qa_amb_ext	
run	qa_one_ext	
exec	PREPARE qa_one_sql AS SELECT 'q\' AS v
exec	SET standard_conforming_strings = off
exec	EXECUTE qa_one_sql
exec	SET standard_conforming_strings = on
exec	EXECUTE qa_one_sql
exec	SET standard_conforming_strings = off
exec	PREPARE qa_amb_sql AS SELECT 'safe\' UNION ALL SELECT v FROM public.review_secret --'
EOF
qa_evidence "$EV" "- ambiguous across settings: ${OUT[*]}"
across_expect=("OK" "OK" "OK" "$AMB_ERR" "OK" "$AMB_ERR" "OK rows=1: w'" "OK" "OK" "OK rows=1: q\\" "OK" "OK rows=1: q\\" "OK" "$AMB_ERR")
if [[ ${OUT[*]} != "${across_expect[*]}" ]]; then
    fail "$ID.ambiguous.settings" "results: ${OUT[*]}"
elif expect_learned ambiguous.settings $R SELECT 2; then
    ok "$ID.ambiguous.settings" "a Parse under off and a SQL PREPARE under on kept their one valid reading (values w' and q\\) after the setting changed, with one identity each across executions; the ambiguous text was refused at Execute under both settings and as a SQL PREPARE"
fi

# ---------------------------------------------------------------------------
# Executable bodies keep their identity; data strings do not.
# ---------------------------------------------------------------------------
# DO is not used here: its family is OTHER, and approval_requirement returns
# before any fingerprint lookup for OTHER in learn and permissive modes (and
# enforce skips fingerprints for an approved command). DO body identities are
# covered by probe/06 through the same normalizer.
R=${PREFIX}bodies
role $R || { infra "$ID.bodies" "$QA_INFRA_REASON"; exit 0; }
send $R <<'EOF'
exec	CREATE OR REPLACE FUNCTION public.qa_fpid_fn() RETURNS int LANGUAGE sql AS $$SELECT 1$$
exec	CREATE OR REPLACE FUNCTION public.qa_fpid_fn() RETURNS int LANGUAGE sql AS $$SELECT 2$$
exec	CREATE OR REPLACE FUNCTION public.qa_fpid_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'
exec	CREATE OR REPLACE PROCEDURE public.qa_fpid_proc() LANGUAGE sql AS $$INSERT INTO public.qa_ins VALUES ('p1')$$
exec	CREATE OR REPLACE PROCEDURE public.qa_fpid_proc() LANGUAGE sql AS $$INSERT INTO public.qa_ins VALUES ('p2')$$
exec	INSERT INTO public.qa_ins VALUES ('INSERT INTO public.qa_ins VALUES (1)')
exec	INSERT INTO public.qa_ins VALUES ('DELETE FROM public.qa_ins')
EOF
if all_ok bodies && expect_learned bodies.create $R CREATE 4 && expect_learned bodies.data $R INSERT 1; then
    expect=$(printf '%s\n' \
        "v3: CREATE OR REPLACE FUNCTION \"public\" . \"qa_fpid_fn\" ( ) RETURNS INT LANGUAGE SQL AS 'SELECT 1'" \
        "v3: CREATE OR REPLACE FUNCTION \"public\" . \"qa_fpid_fn\" ( ) RETURNS INT LANGUAGE SQL AS 'SELECT 2'" \
        "v3: CREATE OR REPLACE PROCEDURE \"public\" . \"qa_fpid_proc\" ( ) LANGUAGE SQL AS 'INSERT INTO public.qa_ins VALUES (''p1'')'" \
        "v3: CREATE OR REPLACE PROCEDURE \"public\" . \"qa_fpid_proc\" ( ) LANGUAGE SQL AS 'INSERT INTO public.qa_ins VALUES (''p2'')'" | sort)
    if ! persisted $R CREATE 4; then
        infra "$ID.bodies" "$QA_INFRA_REASON"
    elif [[ $(cut -d'|' -f2 <<<"$ROWS" | sort) == "$expect" ]]; then
        ok "$ID.bodies" "two function bodies and two procedure bodies were four identities, and one function body in \$\$ and '...' quoting was one; the persisted text keeps each body; SQL text inserted as data was one identity"
    else
        fail "$ID.bodies" "persisted CREATE rows: ${ROWS//$'\n'/ ; }"
    fi
fi

# ---------------------------------------------------------------------------
# The identity covers the whole statement; stored text is truncated display.
# ---------------------------------------------------------------------------
R=${PREFIX}long
role $R || { infra "$ID.long" "$QA_INFRA_REASON"; exit 0; }
cols=""
for ((i = 0; i < 90; i++)); do cols+="v AS c$(printf '%03d' "$i"), "; done
LONG1="SELECT ${cols}v AS qa_end_one FROM public.qa_t"
LONG2="SELECT ${cols}v AS qa_end_two FROM public.qa_t"
send $R < <(printf 'exec\t%s\n' "$LONG1" "$LONG2")
if all_ok long && expect_learned long $R SELECT 2; then
    if persisted $R SELECT 2 && qa_admin "$DB" \
        "SELECT count(DISTINCT fingerprint) || ',' || count(DISTINCT normalized_query) || ',' || count(DISTINCT sample_query) || ',' || max(octet_length(normalized_query)) || ',' || max(octet_length(sample_query)) FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) '$R'"; then
        IFS=, read -r nfp nnorm nsample lnorm lsample <<<"${QA_STEP_OUT[1]}"
        if [[ $nfp == 2 && $nnorm == 1 && $nsample == 1 && $lnorm -le 1023 && $lsample -le 511 ]]; then
            ok "$ID.long" "two ${#LONG1}-byte statements differing only in the last alias had different identities, while their stored normalized_query ($lnorm bytes) and sample_query ($lsample bytes) were identical truncations"
        else
            fail "$ID.long" "fingerprints=$nfp normalized=$nnorm samples=$nsample lengths=$lnorm/$lsample"
        fi
    else
        infra "$ID.long" "$QA_INFRA_REASON"
    fi
fi

# The identical unqualified text must not reuse an approval after PostgreSQL
# binds it to another relation, including a prepared replan and a new OID at
# the same qualified name.
R=${PREFIX}binding
role $R || { infra "$ID.binding" "$QA_INFRA_REASON"; exit 0; }
if ! qa_admin "$DB" \
    "CREATE SCHEMA qa_bind_a" "CREATE SCHEMA qa_bind_b" \
    "CREATE TABLE qa_bind_a.t (v text)" "CREATE TABLE qa_bind_b.t (v text)" \
    "INSERT INTO qa_bind_a.t VALUES ('x')" "INSERT INTO qa_bind_b.t VALUES ('x')" \
    "GRANT USAGE ON SCHEMA qa_bind_a, qa_bind_b TO $R" \
    "GRANT SELECT ON qa_bind_a.t, qa_bind_b.t TO $R"; then
    infra "$ID.binding" "$QA_INFRA_REASON"
    exit 0
fi
send $R <<'EOF'
exec	SET search_path = qa_bind_a, public
prepare	qa_binding	SELECT v FROM t WHERE v = 'x'
run	qa_binding
exec	SET search_path = qa_bind_b, public
run	qa_binding
EOF
if all_ok binding && expect_learned binding $R SELECT 2; then
    ok "$ID.binding.search_path" "a prepared statement replanned under a different search_path and learned a separate relation-bound identity"
fi
if ! qa_admin "$DB" \
    "DROP TABLE qa_bind_b.t" \
    "CREATE TABLE qa_bind_b.t (v text)" \
    "INSERT INTO qa_bind_b.t VALUES ('x')" \
    "GRANT SELECT ON qa_bind_b.t TO $R"; then
    infra "$ID.binding.recreate" "$QA_INFRA_REASON"
else
    send $R <<'EOF'
exec	SET search_path = qa_bind_b, public
exec	SELECT v FROM t WHERE v = 'x'
EOF
    if all_ok binding.recreate && expect_learned binding.recreate $R SELECT 3 &&
        persisted $R SELECT 3 && qa_admin "$DB" \
        "SELECT count(DISTINCT fingerprint) || ',' || count(DISTINCT normalized_query) FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) '$R' AND command_type OPERATOR(pg_catalog.=) 'SELECT'"; then
        if [[ ${QA_STEP_OUT[1]} == 3,1 ]]; then
            ok "$ID.binding.recreate" "same SQL and display text after DROP/CREATE had three distinct identities for three relation OIDs"
        else
            fail "$ID.binding.recreate" "bound identity/display counts: ${QA_STEP_OUT[1]}"
        fi
    fi
fi

# PostgreSQL also records dependencies on user-defined functions in the plan.
# Avoid SQL-function inlining so the function OID is the dependency examined.
R=${PREFIX}function
role $R || { infra "$ID.binding.function" "$QA_INFRA_REASON"; exit 0; }
if ! qa_admin "$DB" \
    "CREATE FUNCTION qa_bind_a.f() RETURNS text LANGUAGE plpgsql VOLATILE AS \$\$ BEGIN RETURN 'x'; END \$\$" \
    "CREATE FUNCTION qa_bind_b.f() RETURNS text LANGUAGE plpgsql VOLATILE AS \$\$ BEGIN RETURN 'x'; END \$\$" \
    "GRANT USAGE ON SCHEMA qa_bind_a, qa_bind_b TO $R" \
    "GRANT EXECUTE ON FUNCTION qa_bind_a.f(), qa_bind_b.f() TO $R"; then
    infra "$ID.binding.function" "$QA_INFRA_REASON"
else
    send $R <<'EOF'
exec	SET search_path = qa_bind_a, public
exec	SELECT f()
exec	SET search_path = qa_bind_b, public
exec	SELECT f()
EOF
    if all_ok binding.function && qa_admin "$DB" \
        "SELECT count(*)::text FROM public.sql_firewall_activity_log WHERE role_name OPERATOR(pg_catalog.=) '$R' AND query_text OPERATOR(pg_catalog.=) 'SELECT f()' AND action OPERATOR(pg_catalog.=) 'LEARNED (FINGERPRINT AUTO)'"; then
        if [[ ${QA_STEP_OUT[1]} == 2 ]]; then
            ok "$ID.binding.function" "same function call text resolved to distinct user-defined functions and learned separate identities"
        else
            fail "$ID.binding.function" "outer function call learned ${QA_STEP_OUT[1]} identities, expected 2"
        fi
    fi
    if ! qa_admin "$DB" \
        "DROP FUNCTION qa_bind_b.f()" \
        "CREATE FUNCTION qa_bind_b.f() RETURNS text LANGUAGE plpgsql VOLATILE AS \$\$ BEGIN RETURN 'x'; END \$\$" \
        "GRANT EXECUTE ON FUNCTION qa_bind_b.f() TO $R"; then
        infra "$ID.binding.function_recreate" "$QA_INFRA_REASON"
    else
        send $R <<'EOF'
exec	SET search_path = qa_bind_b, public
exec	SELECT f()
EOF
        if all_ok binding.function_recreate && qa_admin "$DB" \
            "SELECT count(*)::text FROM public.sql_firewall_activity_log WHERE role_name OPERATOR(pg_catalog.=) '$R' AND query_text OPERATOR(pg_catalog.=) 'SELECT f()' AND action OPERATOR(pg_catalog.=) 'LEARNED (FINGERPRINT AUTO)'"; then
            if [[ ${QA_STEP_OUT[1]} == 3 ]]; then
                ok "$ID.binding.function_recreate" "new function OID under the same name did not inherit the prior fingerprint"
            else
                fail "$ID.binding.function_recreate" "outer function call learned ${QA_STEP_OUT[1]} identities, expected 3"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Errors, then statements in the same backend.
# ---------------------------------------------------------------------------
R=${PREFIX}errors
role $R || { infra "$ID.errors" "$QA_INFRA_REASON"; exit 0; }
send $R <<'EOF'
exec	SELECT pg_backend_pid()
exec	SELECT 1 / (id - id) AS qa_div FROM public.qa_t
exec	SELECT v FROM public.qa_t WHERE id = 5 /* after error */
exec	BEGIN
exec	SAVEPOINT qa_s
exec	SELECT 1 / (id - id) AS qa_div_sp FROM public.qa_t
exec	ROLLBACK TO SAVEPOINT qa_s
exec	SELECT a FROM public.t WHERE a = 5 /* after savepoint */
exec	COMMIT
exec	SELECT pg_backend_pid()
EOF
if [[ ${OUT[1]:-} != "ERR 22012 division by zero" || ${OUT[5]:-} != "ERR 22012 division by zero" || ${OUT[0]} != "${OUT[9]:-}" ]]; then
    fail "$ID.errors" "session results: ${OUT[*]}"
elif learned $R SELECT && [[ $LEARNED_TEXTS == *"id = 5 /* after error */"* && $LEARNED_TEXTS == *"a = 5 /* after savepoint */"* ]]; then
    if qa_poll "$DB" "SELECT count(*)::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) '$R' AND command_type OPERATOR(pg_catalog.=) 'SELECT' AND normalized_query LIKE 'v3: %' AND (sample_query LIKE '%after error%' OR sample_query LIKE '%after savepoint%')" 2 30; then
        ok "$ID.errors" "after a failed statement and after ROLLBACK TO SAVEPOINT, the same backend (${OUT[0]##*: }) learned and persisted the following statements' identities"
    else
        infra "$ID.errors" "$QA_INFRA_REASON"
    fi
else
    fail "$ID.errors" "learned after errors: ${LEARNED_TEXTS:-$QA_INFRA_REASON}"
fi

# ---------------------------------------------------------------------------
# Version 1 rows are not matched; version 3 rows are.
# ---------------------------------------------------------------------------
# 96a05c1e0e986e50 is the version 1 identity of this statement (retained run
# sqlfw-qa.IPLWNH, tests/30). An approved legacy row must not stand in for it.
LEGACY=${PREFIX}legacy
CURRENT=${PREFIX}current
STMT="SELECT v FROM qa_t WHERE id = 1"
role $LEGACY && role $CURRENT || { infra "$ID.legacy" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('96a05c1e0e986e50', 'SELECT V FROM QA_T WHERE ID = ?', '$LEGACY', 'SELECT', '$STMT', 7, true)" ||
    { infra "$ID.legacy" "$QA_INFRA_REASON"; exit 0; }
send $LEGACY < <(printf 'exec\t%s\n' "$STMT")
if all_ok legacy && expect_learned legacy $LEGACY SELECT 1; then
    if ! persisted $LEGACY SELECT 2; then
        infra "$ID.legacy" "$QA_INFRA_REASON"
    else
        legacy_row=$(grep '^96a05c1e0e986e50|' <<<"$ROWS")
        new_row=$(grep -v '^96a05c1e0e986e50|' <<<"$ROWS")
        V3_FP=${new_row%%|*} V3_NORM=$(cut -d'|' -f2 <<<"$new_row")
        if ! qa_admin "$DB" "SELECT hit_count || ',' || is_approved FROM public.sql_firewall_query_fingerprints WHERE fingerprint OPERATOR(pg_catalog.=) '96a05c1e0e986e50'"; then
            infra "$ID.legacy" "$QA_INFRA_REASON"
        elif [[ $legacy_row != '96a05c1e0e986e50|SELECT V FROM QA_T WHERE ID = ?|'* || ${QA_STEP_OUT[1]} != 7,true || ! $V3_FP =~ ^[0-9a-f]{64}$ || $V3_NORM != 'v3: SELECT "v" FROM "qa_t" WHERE "id" = ?int' ]]; then
            fail "$ID.legacy" "legacy '$legacy_row' (${QA_STEP_OUT[1]}), new '$new_row'"
        elif ! qa_admin "$DB" \
            "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('$V3_FP', $(qa_sql_quote "$V3_NORM"), '$CURRENT', 'SELECT', '$STMT', 1, true)"; then
            infra "$ID.legacy" "$QA_INFRA_REASON"
        else
            # Positive control: an approved version 3 row, read from the
            # catalog (this role's cache is cold), is matched.
            send $CURRENT < <(printf 'exec\t%s\n' "$STMT")
            if all_ok legacy.current && expect_learned legacy.current $CURRENT SELECT 0; then
                ok "$ID.legacy" "an approved version 1 row (96a05c1e0e986e50, hit_count 7) was not matched: the statement was learned as $V3_FP and the legacy row stayed unchanged; an approved $V3_FP row for another role was matched from the catalog"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Database, role, and command association of persisted rows.
# ---------------------------------------------------------------------------
# The two explicitly seeded legacy rows are the only rows without v3 text or
# a 64-hex identity. Every newly learned row must have both.
if qa_admin "$DB" \
    "SELECT count(*) FILTER (WHERE role_name::text NOT LIKE '${PREFIX}%') || ',' || count(*) FILTER (WHERE fingerprint NOT IN ('96a05c1e0e986e50', '$OLD_COMBINED') AND normalized_query NOT LIKE 'v3: %') || ',' || count(*) FILTER (WHERE fingerprint NOT IN ('96a05c1e0e986e50', '$OLD_COMBINED') AND fingerprint !~ '^[0-9a-f]{64}\$') || ',' || count(*) FILTER (WHERE command_type OPERATOR(pg_catalog.=) 'CREATE' AND normalized_query NOT LIKE 'v3: CREATE %') || ',' || count(*) FROM public.sql_firewall_query_fingerprints"; then
    IFS=, read -r foreign unversioned badhex badcreate total <<<"${QA_STEP_OUT[1]}"
    if [[ $foreign == 0 && $unversioned == 0 && $badhex == 0 && $badcreate == 0 && $total -gt 20 ]]; then
        ok "$ID.association" "$total rows in $DB's catalog, each for the test role and command that produced it (checked per group above), with a 64-hex identity and version 3 text"
    else
        fail "$ID.association" "foreign=$foreign unversioned=$unversioned bad_hex=$badhex bad_create=$badcreate total=$total"
    fi
else
    infra "$ID.association" "$QA_INFRA_REASON"
fi

# ---------------------------------------------------------------------------
# The inspection helper is not in the release package.
# ---------------------------------------------------------------------------
# The staged installation's own layout: lib/postgresql for a source build,
# lib for the PGDG packages (a fixed path read missing files there,
# sqlfw-qa.Z2urDT).
STAGE_PGC=$(dirname "$QA_PSQL")/pg_config
SO=$("$STAGE_PGC" --pkglibdir)/sql_firewall.so
SQL=$("$STAGE_PGC" --sharedir)/extension/sql_firewall--0.0.0.sql
if [[ ! -f $SO || ! -f $SQL ]]; then
    infra "$ID.release" "staged files not found: $SO $SQL"
elif qa_admin "$DB" "SELECT count(*) FROM pg_catalog.pg_proc WHERE proname::text LIKE 'sql_firewall_%probe%'"; then
    in_so=$(grep -c "sql_firewall_fingerprint_probe" "$SO")
    in_sql=$(grep -c "sql_firewall_fingerprint_probe" "$SQL")
    if [[ ${QA_STEP_OUT[1]} == 0 && $in_so == 0 && $in_sql == 0 ]]; then
        ok "$ID.release" "no probe function in pg_proc, the staged library, or the install script"
    else
        fail "$ID.release" "pg_proc=${QA_STEP_OUT[1]} library=$in_so script=$in_sql"
    fi
else
    infra "$ID.release" "$QA_INFRA_REASON"
fi

exit 0
