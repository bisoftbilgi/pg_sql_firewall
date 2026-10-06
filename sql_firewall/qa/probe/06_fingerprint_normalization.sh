#!/usr/bin/env bash
# Fingerprint identity v3 (version 2 canonical tokens) through the production normalizer.
#
# Run with the fingerprint_probe build only:
#   QA_CARGO_FEATURES=fingerprint_probe QA_TEST_DIR=sql_firewall/qa/probe \
#       sql_firewall/qa/run.sh --only '06*'
# public.sql_firewall_fingerprint_probe(text) returns the FingerprintSummary
# that fingerprints::enforce builds (identity and normalized_query). It is
# superuser-only and absent from the release library (tests/98 checks that).
# Expected values below are written out by hand; nothing here re-implements
# the lexer or the normalizer.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.fingerprint_normalization
EV=fingerprint_normalization
DB=qa_fpnorm

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "This run is the fingerprint_probe build, not the release library. Each row is fingerprint | normalized_query from the production normalizer." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

# Dollar quoting passes every text unchanged whatever the session's
# standard_conforming_strings is.
dq() {
    [[ $1 != *'$qa_fp$'* ]] || { infra "$ID" "test text contains the quoting tag"; exit 0; }
    printf '$qa_fp$%s$qa_fp$' "$1"
}

# probe TEXT... -> FP[i] NORM[i] for i = 1..n (one superuser session)
probe() {
    local steps=() t
    for t in "$@"; do
        steps+=("SELECT fingerprint || E'\\x1f' || normalized_query FROM public.sql_firewall_fingerprint_probe($(dq "$t"))")
    done
    FP=() NORM=()
    qa_admin "$DB" "${steps[@]}" || return $?
    local i
    for ((i = 1; i <= $#; i++)); do
        FP[i]=${QA_STEP_OUT[i]%%$'\x1f'*}
        NORM[i]=${QA_STEP_OUT[i]#*$'\x1f'}
    done
}

# Independent digest oracle for the current identity domain and complete
# canonical text. Distinct and equal-shape cases below test the normalizer.
if ! probe 'SELECT 1'; then
    infra "$ID.digest" "$QA_INFRA_REASON"
else
    qa_admin "$DB" "SELECT (SELECT system_identifier FROM pg_catalog.pg_control_system())::text || '|' || (SELECT oid::text FROM pg_catalog.pg_database WHERE datname = current_database()) || '|' || (SELECT oid::text FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall')" || { infra "$ID.digest" "$QA_INFRA_REASON"; exit 0; }
    IFS='|' read -r SYSTEM_ID DB_OID EXT_OID <<<"${QA_STEP_OUT[1]}"
    EXPECTED=$(python3 - "$SYSTEM_ID" "$DB_OID" "$EXT_OID" <<'PY'
import hashlib, sys
h = hashlib.sha256()
h.update(b'sql_firewall fingerprint v3 sha256\x00')
h.update(b'\x00installation\x00')
h.update((int(sys.argv[1]) % (1 << 64)).to_bytes(8, 'big'))
h.update(int(sys.argv[2]).to_bytes(4, 'big'))
h.update(int(sys.argv[3]).to_bytes(4, 'big'))
h.update(b'SELECT ?int')
print(h.hexdigest())
PY
)
    if [[ ${NORM[1]} == 'v3: SELECT ?int' && ${FP[1]} == "$EXPECTED" ]]; then
        ok "$ID.digest" "full SHA-256 digest of domain, installation and canonical SELECT ?int matches an independent oracle"
    else
        fail "$ID.digest" "expected $EXPECTED / v3: SELECT ?int, got ${FP[1]} / ${NORM[1]}"
    fi
fi

LONG_A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# ---------------------------------------------------------------------------
# Pairs that must have different identities.
# ---------------------------------------------------------------------------
DISTINCT=(
    'quoted identifier content' 'SELECT "account_a" FROM public.t' 'SELECT "account_b" FROM public.t'
    'digits in a table name' 'SELECT value FROM public.table1' 'SELECT value FROM public.table2'
    'quoted identifier case' 'SELECT "Account" FROM public.t' 'SELECT "account" FROM public.t'
    'parameter repetition' 'SELECT * FROM t WHERE a = $1 AND b = $1' 'SELECT * FROM t WHERE a = $1 AND b = $2'
    'operator' 'SELECT a FROM t WHERE a < 1' 'SELECT a FROM t WHERE a <= 1'
    'operator family' 'SELECT a FROM t WHERE a = 1' 'SELECT a FROM t WHERE a <> 1'
    'cast target' 'SELECT a::int FROM t' 'SELECT a::bigint FROM t'
    'cast syntax' 'SELECT a::int FROM t' 'SELECT CAST(a AS int) FROM t'
    'sign' 'SELECT a FROM t WHERE a = 1' 'SELECT a FROM t WHERE a = -1'
    'integer vs numeric' 'SELECT a FROM t WHERE a = 1' 'SELECT a FROM t WHERE a = 1.0'
    'string vs integer' "SELECT a FROM t WHERE a = '1'" 'SELECT a FROM t WHERE a = 1'
    'bit vs hex string' "SELECT b'1'" "SELECT x'1'"
    'unicode vs plain string' "SELECT U&'a'" "SELECT 'a'"
    'identifier vs string' 'SELECT "x"' "SELECT 'x'"
    'comment does not join tokens' 'SELECT a/**/b FROM t' 'SELECT ab FROM t'
    'dollar sign in identifier' 'SELECT a$1 FROM t' 'SELECT a$2 FROM t'
    'digit in identifier' 'SELECT col1 FROM t' 'SELECT col2 FROM t'
    'UTF8 identifier case' 'SELECT "ğ" FROM t' 'SELECT "Ğ" FROM t'
    'keyword vs quoted identifier' 'SELECT value FROM t' 'SELECT "value" FROM t'
    'U& identifier vs plain' 'SELECT U&"ab" FROM t' 'SELECT "ab" FROM t'
    'UESCAPE character' "SELECT U&\"a!0062\" UESCAPE '!' FROM t" "SELECT U&\"a!0062\" UESCAPE '#' FROM t"
    'IN-list length' 'SELECT a FROM t WHERE a IN (1, 2)' 'SELECT a FROM t WHERE a IN (1, 2, 3)'
    'predicate order' 'SELECT a FROM t WHERE a = 1 AND b = 2' 'SELECT a FROM t WHERE b = 2 AND a = 1'
    'statement list' 'SELECT 1; SELECT 2' 'SELECT 1'
    'DO body' 'DO $$BEGIN PERFORM 1; END$$' 'DO $$BEGIN PERFORM 2; END$$'
    'function body' 'CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$SELECT 1$$' 'CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$SELECT 2$$'
    'procedure body' 'CREATE OR REPLACE PROCEDURE p() LANGUAGE sql AS $$DELETE FROM a$$' 'CREATE OR REPLACE PROCEDURE p() LANGUAGE sql AS $$DELETE FROM b$$'
    'C function symbol' "CREATE FUNCTION f() RETURNS int LANGUAGE c AS 'lib', 'sym_a'" "CREATE FUNCTION f() RETURNS int LANGUAGE c AS 'lib', 'sym_b'"
    'COPY PROGRAM command' "COPY t FROM PROGRAM 'cat /tmp/a'" "COPY t FROM PROGRAM 'rm -rf /tmp/b'"
    'LOAD library' "LOAD 'lib_a'" "LOAD 'lib_b'"
)
passed=1
for ((i = 0; i < ${#DISTINCT[@]}; i += 3)); do
    label=${DISTINCT[i]} a=${DISTINCT[i + 1]} b=${DISTINCT[i + 2]}
    if ! probe "$a" "$b"; then
        infra "$ID.distinct" "$label: $QA_INFRA_REASON"
        exit 0
    fi
    qa_evidence "$EV" "- distinct / $label: \`${FP[1]} ${NORM[1]}\` vs \`${FP[2]} ${NORM[2]}\`"
    if [[ ! ${FP[1]} =~ ^[0-9a-f]{64}$ || ! ${FP[2]} =~ ^[0-9a-f]{64}$ || ${FP[1]} == "${FP[2]}" || ${NORM[1]} == "${NORM[2]}" ]]; then
        fail "$ID.distinct" "$label: '${NORM[1]}' and '${NORM[2]}' share ${FP[1]} / ${FP[2]}"
        passed=0
    fi
done
((passed)) && ok "$ID.distinct" "$((${#DISTINCT[@]} / 3)) structurally different pairs (identifier content, case, digits and \$ in names, parameter repetition, operators, casts, signs, literal categories, comments between tokens, keyword vs identifier, UESCAPE, IN lists, predicate order, executable bodies, COPY PROGRAM, LOAD) have different identities"

# ---------------------------------------------------------------------------
# Groups whose members must share one identity.
# ---------------------------------------------------------------------------
check_group() { # LABEL TEXT...
    local label=$1 i
    shift
    if ! probe "$@"; then
        infra "$ID.equal" "$label: $QA_INFRA_REASON"
        exit 0
    fi
    qa_evidence "$EV" "- equal / $label: \`${FP[1]} ${NORM[1]}\`"
    for ((i = 2; i <= $#; i++)); do
        if [[ ${FP[i]} != "${FP[1]}" || ${NORM[i]} != "${NORM[1]}" ]]; then
            fail "$ID.equal" "$label: member $i '${NORM[i]}' (${FP[i]}) differs from '${NORM[1]}' (${FP[1]})"
            return 1
        fi
    done
}
passed=1
check_group 'integer values' 'SELECT a FROM t WHERE a = 1' 'SELECT a FROM t WHERE a = 2' 'SELECT a FROM t WHERE a = 0x1F' 'SELECT a FROM t WHERE a = 1_000' || passed=0
check_group 'numeric values' 'SELECT a FROM t WHERE a = 1.5' 'SELECT a FROM t WHERE a = 2e10' 'SELECT a FROM t WHERE a = .5' 'SELECT a FROM t WHERE a = 3000000000' || passed=0
check_group 'string values and forms' "SELECT a FROM t WHERE a = 'x'" "SELECT a FROM t WHERE a = 'it''s'" "SELECT a FROM t WHERE a = E'y\\n'" 'SELECT a FROM t WHERE a = $$z$$' 'SELECT a FROM t WHERE a = $tag$w;x$tag$' "SELECT a FROM t WHERE a = 'ış€😀'" || passed=0
check_group 'bit strings' "SELECT b'1'" "SELECT b'0101'" || passed=0
check_group 'hex strings' "SELECT x'1'" "SELECT x'ff'" || passed=0
check_group 'unicode strings' "SELECT U&'\\0041'" "SELECT U&'b'" || passed=0
check_group 'whitespace and comments' 'SELECT a FROM t' $'SELECT  a\n\tFROM t' $'SELECT /* c */ a -- d\nFROM t' 'SELECT /* a /* nested */ b */ a FROM t' || passed=0
check_group 'keyword and unquoted identifier case' 'select A from T' 'SELECT a FROM t' 'SELECT "a" FROM "t"' || passed=0
check_group '!= and <>' 'SELECT a FROM t WHERE a != 1' 'SELECT a FROM t WHERE a <> 1' || passed=0
check_group 'terminal semicolons' 'SELECT 1' 'SELECT 1;' 'SELECT 1 ;;' || passed=0
check_group 'DO body quoting' 'DO $$BEGIN PERFORM 1; END$$' "DO 'BEGIN PERFORM 1; END'" "DO E'BEGIN PERFORM 1; END'" || passed=0
check_group 'data strings in INSERT' "INSERT INTO t VALUES ('BEGIN PERFORM 1; END')" "INSERT INTO t VALUES ('BEGIN PERFORM 2; END')" || passed=0
check_group 'identifiers PostgreSQL truncates' "SELECT ${LONG_A}x FROM t" "SELECT ${LONG_A}y FROM t" || passed=0
((passed)) && ok "$ID.equal" "value changes within one literal category, the quoting form of a string, whitespace, line/block/nested comments, keyword and unquoted identifier case, != vs <>, terminal semicolons, and PostgreSQL's own identifier truncation leave the identity unchanged; the same DO body in three quoting forms is one identity; data strings in INSERT are placeholders"

# ---------------------------------------------------------------------------
# Exact canonical text.
# ---------------------------------------------------------------------------
# name is an unreserved keyword: the lexer returns it as a keyword even as a
# column name, so it is written NAME, unlike the identifiers around it.
EXACT=(
    'SELECT v FROM public.qa_t WHERE id = $1 AND name = '\''x'\'' -- c'
    'v3: SELECT "v" FROM "public" . "qa_t" WHERE "id" = $1 AND NAME = ?str'
    'SELECT 1, 1.5, 1e10, -2, +3, '\''s'\'', E'\''e'\'', $$d$$, U&'\''u'\'', b'\''1'\'', x'\''1F'\'', N'\''n'\'', DATE '\''2020-01-01'\'''
    'v3: SELECT ?int , ?num , ?num , - ?int , + ?int , ?str , ?str , ?str , ?ustr , ?bits , ?hex , NCHAR ?str , "date" ?str'
    'SELECT "we""ird", col$1, a::text, j ?| ARRAY['\''k'\''] FROM "T"'
    'v3: SELECT "we""ird" , "col$1" , "a" :: TEXT , "j" ?| ARRAY [ ?str ] FROM "T"'
    'DO $$BEGIN PERFORM 1; END$$'
    "v3: DO 'BEGIN PERFORM 1; END'"
    'create or replace function f() returns int language sql as $$select 1$$ cost 10'
    "v3: CREATE OR REPLACE FUNCTION \"f\" ( ) RETURNS INT LANGUAGE SQL AS 'select 1' COST 10"
    "SELECT E'a\\'b', 'c\\d' AS p"
    'v3: SELECT ?str , ?str AS "p"'
    'CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$SELECT '\''a\b'\''$$'
    "v3: CREATE FUNCTION \"f\" ( ) RETURNS TEXT LANGUAGE SQL AS 'SELECT ''a\\b'''"
    "SELECT 'a\\' AS p"
    'v3: SELECT ?str AS "p"'
    'SELECT 1; SELECT 2;'
    'v3: SELECT ?int ; SELECT ?int'
)
passed=1
for ((i = 0; i < ${#EXACT[@]}; i += 2)); do
    probe "${EXACT[i]}" || { infra "$ID.canonical" "$QA_INFRA_REASON"; exit 0; }
    qa_evidence "$EV" "- canonical: \`${EXACT[i]}\` -> \`${NORM[1]}\`"
    if [[ ${NORM[1]} != "${EXACT[i + 1]}" ]]; then
        fail "$ID.canonical" "'${EXACT[i]}' normalized to '${NORM[1]}', expected '${EXACT[i + 1]}'"
        passed=0
    fi
done
((passed)) && ok "$ID.canonical" "canonical text: keywords upper case, identifiers always quoted, placeholders per literal category, parameters numbered, bodies of DO/CREATE FUNCTION kept, a backslash text with one valid reading read that way"

# ---------------------------------------------------------------------------
# Legacy identities are not reproduced.
# ---------------------------------------------------------------------------
# 8aeaf212cd039fd1 and 96a05c1e0e986e50 are the version 1 identities of this
# statement with and without its ';' (retained runs sqlfw-qa.HEjhMK and
# sqlfw-qa.IPLWNH).
probe 'SELECT v FROM qa_t WHERE id = 1;' 'SELECT v FROM qa_t WHERE id = 1' || { infra "$ID.legacy" "$QA_INFRA_REASON"; exit 0; }
if [[ ${FP[1]} == "${FP[2]}" && ${FP[1]} != 8aeaf212cd039fd1 && ${FP[1]} != 96a05c1e0e986e50 && ${NORM[1]} == v3:\ * ]]; then
    ok "$ID.legacy" "version 3 identity ${FP[1]} ('${NORM[1]}') is neither version 1 identity (8aeaf212cd039fd1, 96a05c1e0e986e50)"
else
    fail "$ID.legacy" "identities ${FP[1]} / ${FP[2]} normalized '${NORM[1]}'"
fi

# ---------------------------------------------------------------------------
# Texts that read one way have one identity whatever the session's
# standard_conforming_strings is: one valid reading ('a\' AS p is valid only
# with it on, 'y\'' only with it off), two equal readings (data strings with
# \\), E'' and dollar-quoted strings, U& strings, and bodies in $$...$$.
# ---------------------------------------------------------------------------
SCS_TEXTS=(
    "SELECT 'a\\' AS p"
    "SELECT 'y\\'' AS p"
    "SELECT 'C:\\\\dir', 'x'"
    "SELECT E'a\\'b' AS p"
    "SELECT \$q\$x\\y'z\$q\$ AS p"
    "SELECT U&'u'"
    "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS \$\$SELECT 'a\\b'\$\$"
    "DO \$\$BEGIN RAISE NOTICE 'x\\y'; END\$\$"
)
steps=()
for setting in on off; do
    steps+=("SET standard_conforming_strings = $setting")
    for t in "${SCS_TEXTS[@]}"; do
        steps+=("SELECT fingerprint FROM public.sql_firewall_fingerprint_probe($(dq "$t"))")
    done
done
if ! qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin "${steps[@]}"; then
    infra "$ID.settings" "$QA_INFRA_REASON"
else
    n=${#SCS_TEXTS[@]} passed=1
    for ((i = 0; i < n; i++)); do
        on_step=$((i + 2)) off_step=$((i + n + 3))
        if [[ ${QA_STEP_ERR[on_step]} != false || ${QA_STEP_ERR[off_step]} != false || ${QA_STEP_OUT[on_step]} != "${QA_STEP_OUT[off_step]}" ]]; then
            fail "$ID.settings" "'${SCS_TEXTS[i]}': on=${QA_STEP_OUT[on_step]:-${QA_STEP_MSG[on_step]:-}} off=${QA_STEP_OUT[off_step]:-${QA_STEP_MSG[off_step]:-}}"
            passed=0
        fi
    done
    ((passed)) && ok "$ID.settings" "$n texts with backslashes in plain strings of one valid reading or equal readings, E'' and dollar-quoted strings, a U& string, and bodies in dollar quotes had the same identity with standard_conforming_strings on and off"
fi

# ---------------------------------------------------------------------------
# Two valid readings with different canonical text are refused.
# ---------------------------------------------------------------------------
# The first text is the reviewer's reproduction: one literal with the setting
# off, a UNION with it on. Before this revision its readings were joined into
# one identity, 0330c478ba8ebabe. The last two differ only in a kept value
# (a function body, a COPY path), which is also identity.
AMB="SELECT 'safe\\' UNION ALL SELECT v FROM public.review_secret --'"
AMB_MSG="sql_firewall: statement reads differently with standard_conforming_strings on and off; its fingerprint is ambiguous"
AMB_TEXTS=(
    "$AMB"
    "SELECT 'a\\' , (SELECT 1) --'"
    "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS 'SELECT ''a\\\\b'''"
    "COPY t FROM 'C:\\\\in.csv'"
)
steps=()
for setting in on off; do
    steps+=("SET standard_conforming_strings = $setting")
    for t in "${AMB_TEXTS[@]}"; do
        steps+=("SELECT fingerprint FROM public.sql_firewall_fingerprint_probe($(dq "$t"))")
    done
done
if ! qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin "${steps[@]}"; then
    infra "$ID.ambiguous" "$QA_INFRA_REASON"
else
    n=${#AMB_TEXTS[@]} passed=1
    for ((i = 0; i < n; i++)); do
        for step in $((i + 2)) $((i + n + 3)); do
            if [[ ${QA_STEP_ERR[step]} != true || ${QA_STEP_STATE[step]} != 0A000 || ${QA_STEP_MSG[step]:-} != "$AMB_MSG" ]]; then
                fail "$ID.ambiguous" "'${AMB_TEXTS[i]}' (step $step): ${QA_STEP_STATE[step]} ${QA_STEP_MSG[step]:-} ${QA_STEP_OUT[step]:-}"
                passed=0
            fi
        done
    done
    ((passed)) && ok "$ID.ambiguous" "$n texts with two valid, different readings (a UNION hidden in one literal, a subquery, a function body, a COPY path) were refused with 0A000 and no identity under both session settings"
fi

# The refusal leaves the backend usable: the same backend continues, a
# savepoint recovers, message levels are restored, no scan context remains,
# and a query cancel is still processed, after the refusal and after a text
# whose rejected reading the shim consumed ('a\' AS p read with the setting
# off). A held interrupt count would let pg_sleep run past statement_timeout.
if ! qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin \
    "SELECT pg_backend_pid()" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe($(dq "$AMB"))" \
    "SELECT pg_backend_pid()" \
    "BEGIN" \
    "SAVEPOINT qa_amb" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe($(dq "$AMB"))" \
    "ROLLBACK TO SAVEPOINT qa_amb" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe('SELECT 3')" \
    "COMMIT" \
    "SET statement_timeout = '300ms'" \
    "SELECT pg_sleep(5)" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe($(dq "SELECT 'a\\' AS p"))" \
    "SELECT pg_sleep(5)" \
    "RESET statement_timeout" \
    "SHOW client_min_messages" \
    "SELECT count(*) FROM pg_catalog.pg_backend_memory_contexts WHERE name OPERATOR(pg_catalog.=) 'sql_firewall fingerprint scan'"; then
    infra "$ID.ambiguous_recovery" "$QA_INFRA_REASON"
elif [[ ${QA_STEP_STATE[2]} != 0A000 || ${QA_STEP_OUT[3]} != "${QA_STEP_OUT[1]}" || ${QA_STEP_STATE[6]} != 0A000 || ${QA_STEP_ERR[7]} != false || ! ${QA_STEP_OUT[8]} =~ ^[0-9a-f]{64}$ || ${QA_STEP_ERR[9]} != false ]]; then
    fail "$ID.ambiguous_recovery" "refusals ${QA_STEP_STATE[2]}/${QA_STEP_STATE[6]}, pid ${QA_STEP_OUT[1]} -> ${QA_STEP_OUT[3]}, rollback ${QA_STEP_ERR[7]}, '${QA_STEP_OUT[8]}', commit ${QA_STEP_ERR[9]}"
elif [[ ${QA_STEP_STATE[11]} != 57014 || ! ${QA_STEP_OUT[12]} =~ ^[0-9a-f]{64}$ || ${QA_STEP_STATE[13]} != 57014 ]]; then
    fail "$ID.ambiguous_recovery" "cancel after refusal ${QA_STEP_STATE[11]}, one-reading text '${QA_STEP_OUT[12]}', cancel after it ${QA_STEP_STATE[13]}"
elif [[ ${QA_STEP_OUT[15]} != notice || ${QA_STEP_OUT[16]} != 0 ]]; then
    fail "$ID.ambiguous_recovery" "client_min_messages '${QA_STEP_OUT[15]}', scan contexts ${QA_STEP_OUT[16]}"
else
    ok "$ID.ambiguous_recovery" "after 0A000 refusals the same backend (pid ${QA_STEP_OUT[1]}) recovered a savepoint and fingerprinted again; statement_timeout cancelled pg_sleep (57014) after a refusal and after a consumed lexer rejection; client_min_messages=notice; no scan context left"
fi

# An old combined 64-bit identity approved in the catalog is not reused:
# its width no longer fits the shared cache and the ambiguous text is refused
# before any lookup. The current-format control identity is seeded into the
# shared cache to show that cache hits still work: its seeded statement is not
# learned again, an unseeded one is.
LIBPQ=$(dirname "$QA_PSQL")/../lib/libpq.so.5
[[ -f $LIBPQ ]] || { infra "$ID.ambiguous_cache" "libpq not found at $LIBPQ"; exit 0; }
export QA_LIBPQ=$LIBPQ QA_CONNINFO="host=$QA_SOCK port=$QA_PORT dbname=$DB"
OLD_COMBINED=0330c478ba8ebabe
OLD_COMBINED_NORM='v2: ?scs_on SELECT ?str UNION ALL SELECT "v" FROM "public" . "review_secret" ?scs_off SELECT ?str'
CTL_STMT="SELECT 1"
CTL_UNSEEDED="SELECT 1 WHERE 1 IS NOT NULL"
setup=("CREATE TABLE public.review_secret (v text)" "INSERT INTO public.review_secret VALUES ('review_secret_value')")
for r in qa_fpnorm_amb qa_fpnorm_ctl; do
    setup+=("CREATE ROLE $r LOGIN NOSUPERUSER" "GRANT CONNECT ON DATABASE $DB TO $r" "GRANT SELECT ON public.review_secret TO $r"
        "ALTER ROLE $r IN DATABASE $DB SET sql_firewall.mode = 'learn'")
done
if ! qa_admin "$DB" "${setup[@]}" || ! probe "$CTL_STMT"; then
    infra "$ID.ambiguous_cache" "$QA_INFRA_REASON"
    exit 0
fi
CTL_FP=${FP[1]}
if ! qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('$OLD_COMBINED', $(qa_sql_quote "$OLD_COMBINED_NORM"), 'qa_fpnorm_amb', 'SELECT', $(qa_sql_quote "$AMB"), 1, true)" \
    "SELECT public.sql_firewall_fingerprint_probe_cache('qa_fpnorm_ctl', '$CTL_FP', 'SELECT')"; then
    infra "$ID.ambiguous_cache" "$QA_INFRA_REASON"
    exit 0
fi
mapfile -t AMB_OUT < <(printf 'exec\t%s\n' "SET standard_conforming_strings = off" "$AMB" "SET standard_conforming_strings = on" "$AMB" |
    python3 "$(dirname "$0")/../pq_session.py" qa_fpnorm_amb)
mapfile -t CTL_OUT < <(printf 'exec\t%s\n' "$CTL_STMT" "$CTL_UNSEEDED" | python3 "$(dirname "$0")/../pq_session.py" qa_fpnorm_ctl)
qa_evidence "$EV" "- current-format cache seed: ${QA_STEP_OUT[2]}" "- qa_fpnorm_amb: ${AMB_OUT[*]}" "- qa_fpnorm_ctl: ${CTL_OUT[*]}"
if ! qa_admin "$DB" "SELECT coalesce(string_agg(query_text, ' ~ ' ORDER BY log_id), '') FROM public.sql_firewall_activity_log WHERE role_name OPERATOR(pg_catalog.=) 'qa_fpnorm_ctl' AND action OPERATOR(pg_catalog.=) 'LEARNED (FINGERPRINT AUTO)'"; then
    infra "$ID.ambiguous_cache" "$QA_INFRA_REASON"
elif [[ ${CTL_OUT[0]:-} != "OK rows=1: 1" || ${CTL_OUT[1]:-} != "OK rows=1: 1" || ${QA_STEP_OUT[1]} != "$CTL_UNSEEDED" ]]; then
    infra "$ID.ambiguous_cache" "positive control did not show a seeded cache entry being honored: ${CTL_OUT[*]}; learned '${QA_STEP_OUT[1]}'"
elif [[ ${AMB_OUT[0]:-} != OK || ${AMB_OUT[1]:-} != "ERR 0A000 $AMB_MSG" || ${AMB_OUT[2]:-} != OK || ${AMB_OUT[3]:-} != "ERR 0A000 $AMB_MSG" ]]; then
    fail "$ID.ambiguous_cache" "with legacy $OLD_COMBINED approved in the catalog: ${AMB_OUT[*]}"
else
    ok "$ID.ambiguous_cache" "with legacy $OLD_COMBINED approved in the catalog, the text was refused with 0A000 under both settings; the control role's current-format cache entry was honored (not learned again) while its unseeded statement was learned"
fi

# ---------------------------------------------------------------------------
# A text the lexer rejects is an explicit error, and the backend recovers.
# ---------------------------------------------------------------------------
if ! qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin \
    "SELECT pg_backend_pid()" \
    "SELECT * FROM public.sql_firewall_fingerprint_probe('SELECT ''unterminated')" \
    "SELECT * FROM public.sql_firewall_fingerprint_probe('SELECT \"unterminated')" \
    "SELECT pg_backend_pid()" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe('SELECT 1')" \
    "BEGIN" \
    "SAVEPOINT qa_s" \
    "SELECT * FROM public.sql_firewall_fingerprint_probe('SELECT ''x')" \
    "ROLLBACK TO SAVEPOINT qa_s" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe('SELECT 2')" \
    "COMMIT" \
    "SHOW client_min_messages" \
    "SELECT count(*) FROM pg_catalog.pg_backend_memory_contexts WHERE name OPERATOR(pg_catalog.=) 'sql_firewall fingerprint scan'"; then
    infra "$ID.error" "$QA_INFRA_REASON"
else
    expect="^sql_firewall: statement could not be tokenized for fingerprinting: unterminated quoted (string|identifier) at or near"
    if [[ ${QA_STEP_ERR[2]} != true || ${QA_STEP_STATE[2]} != XX000 || ! ${QA_STEP_MSG[2]:-} =~ $expect ]]; then
        fail "$ID.error" "unterminated string: ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-} (${QA_STEP_OUT[2]:-})"
    elif [[ ${QA_STEP_ERR[3]} != true || ${QA_STEP_STATE[3]} != XX000 || ! ${QA_STEP_MSG[3]:-} =~ $expect ]]; then
        fail "$ID.error" "unterminated identifier: ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
    elif [[ ${QA_STEP_OUT[4]} != "${QA_STEP_OUT[1]}" || ! ${QA_STEP_OUT[5]} =~ ^[0-9a-f]{64}$ ]]; then
        fail "$ID.error" "after the errors: pid ${QA_STEP_OUT[1]} -> ${QA_STEP_OUT[4]}, identity '${QA_STEP_OUT[5]}'"
    elif [[ ${QA_STEP_ERR[8]} != true || ${QA_STEP_STATE[8]} != XX000 || ${QA_STEP_ERR[9]} != false || ! ${QA_STEP_OUT[10]} =~ ^[0-9a-f]{64}$ || ${QA_STEP_ERR[11]} != false ]]; then
        fail "$ID.error" "savepoint recovery: ${QA_STEP_STATE[8]} / rollback ${QA_STEP_ERR[9]} / '${QA_STEP_OUT[10]}' / commit ${QA_STEP_ERR[11]}"
    elif [[ ${QA_STEP_OUT[12]} != notice || ${QA_STEP_OUT[13]} != 0 ]]; then
        fail "$ID.error" "client_min_messages '${QA_STEP_OUT[12]}', scan contexts left ${QA_STEP_OUT[13]}"
    else
        ok "$ID.error" "an unterminated string or identifier raised XX000 '${QA_STEP_MSG[2]}' with no identity; the same backend (pid ${QA_STEP_OUT[1]}) then fingerprinted statements, recovered a savepoint, kept client_min_messages=notice, and held no scan memory context"
    fi
fi

# 2000 rejected texts caught in PL/pgSQL, and 20000 accepted ones, leave no
# scan context behind.
if ! qa_admin "$DB" \
    "DO \$\$ DECLARE n int := 0; BEGIN FOR i IN 1..2000 LOOP BEGIN PERFORM public.sql_firewall_fingerprint_probe('SELECT ''open' || i); EXCEPTION WHEN internal_error THEN n := n + 1; END; END LOOP; IF n <> 2000 THEN RAISE EXCEPTION 'caught %', n; END IF; END \$\$" \
    "SELECT count(*) FROM (SELECT public.sql_firewall_fingerprint_probe('SELECT ' || g || ', ''s' || g || ''' FROM t' || g) FROM generate_series(1, 20000) g) s" \
    "SELECT count(*) FROM pg_catalog.pg_backend_memory_contexts WHERE name OPERATOR(pg_catalog.=) 'sql_firewall fingerprint scan'"; then
    infra "$ID.memory" "$QA_INFRA_REASON"
elif [[ ${QA_STEP_OUT[2]} == 20000 && ${QA_STEP_OUT[3]} == 0 ]]; then
    ok "$ID.memory" "2000 caught normalization errors and 20000 normalizations left no scan memory context"
else
    fail "$ID.memory" "normalizations ${QA_STEP_OUT[2]}, contexts left ${QA_STEP_OUT[3]}"
fi

# ---------------------------------------------------------------------------
# PostgreSQL already reported identifier truncation; the re-scan does not.
# ---------------------------------------------------------------------------
LONG_ID="${LONG_A}zz"
log_at=$(qa_server_log_offset)
if ! qa_admin "$DB" \
    "SET log_min_messages = notice" \
    "SELECT 1 AS $LONG_ID" \
    "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe('SELECT ' || repeat('q', 70) || ' FROM t')"; then
    infra "$ID.notice" "$QA_INFRA_REASON"
else
    notices=$(tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -c "will be truncated to")
    if [[ $notices == 1 && ${QA_STEP_OUT[3]} =~ ^[0-9a-f]{64}$ ]]; then
        ok "$ID.notice" "the parser's own truncation NOTICE was logged once; normalizing a 70-character identifier added none"
    else
        fail "$ID.notice" "truncation notices in window: $notices (expected 1, from the parser)"
    fi
fi

# ---------------------------------------------------------------------------
# The probe is not callable by an ordinary role.
# ---------------------------------------------------------------------------
# Learn mode lets the call through the firewall, so the function's own gate
# (or a native EXECUTE denial) is what is observed.
qa_admin "$DB" "CREATE ROLE qa_fpnorm_app LOGIN NOSUPERUSER" "GRANT CONNECT ON DATABASE $DB TO qa_fpnorm_app" \
    "ALTER ROLE qa_fpnorm_app IN DATABASE $DB SET sql_firewall.mode = 'learn'" ||
    { infra "$ID.superuser" "$QA_INFRA_REASON"; exit 0; }
if qa_sql_steps qa_fpnorm_app "$DB" qa_fpnorm_app "SELECT fingerprint FROM public.sql_firewall_fingerprint_probe('SELECT 1')"; then
    if [[ ${QA_STEP_ERR[1]} == true && (${QA_STEP_MSG[1]:-} == "sql_firewall: fingerprint probe requires a superuser" || ${QA_STEP_MSG[1]:-} == "permission denied for function"*) ]]; then
        ok "$ID.superuser" "ordinary role refused: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"
    else
        fail "$ID.superuser" "ordinary role got '${QA_STEP_OUT[1]:-}' ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"
    fi
else
    infra "$ID.superuser" "$QA_INFRA_REASON"
fi

exit 0
