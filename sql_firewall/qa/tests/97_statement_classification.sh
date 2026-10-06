#!/usr/bin/env bash
# Phase 4A: command families come from PostgreSQL's parsed statement, and each
# hook invocation sees only that statement's source span.
#
# Recorded text is PostgreSQL's span for the statement (stmt_location and
# stmt_len, byte offsets into the source that belongs to the plan) with the
# lexer's whitespace trimmed from both edges. Comments inside the span stay.
# PostgreSQL 18 starts the span at the statement's first token (16 and 17
# start it at the beginning of the message or after the previous ';'), so a
# comment before the first token is part of the recorded text up to 17 only;
# the expected texts below are chosen by server_version_num (lead()).
# Inner plans that PostgreSQL plans without offsets of their own (EXPLAIN,
# CREATE TABLE AS, SELECT INTO, DECLARE CURSOR) are recorded with the span of
# the utility that runs them. Checks compare exact family|text rows.
#
# Every multi-statement case is one PQexec call: one simple-query message.
# The role logs its statements (log_statement = all) so the server log shows
# each such message as one "statement:" line, and extended-protocol
# executions as "execute <name>:" lines.
#
# Rejected statements roll back their activity row with the transaction, so
# their text is read from sql_firewall_blocked_queries (asynchronous; polled).
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.statement_classification
EV=statement_classification
DB=qa_stmt
ROLE=qa_stmt_app

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Ordinary-role traffic. Multi-statement cases are one simple-query message. Extended protocol is PQprepare/PQexecPrepared, not SQL PREPARE." ""

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=off || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO $ROLE" \
    "ALTER ROLE $ROLE IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE $ROLE IN DATABASE $DB SET log_statement = 'all'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "CREATE TABLE public.qa_stmt_target (id integer)" \
    "INSERT INTO public.qa_stmt_target VALUES (1)" \
    "CREATE TABLE public.qa_stmt_cte (id integer)" \
    "GRANT SELECT, INSERT, UPDATE, TRUNCATE ON public.qa_stmt_target, public.qa_stmt_cte TO $ROLE" \
    "GRANT CREATE ON SCHEMA public TO $ROLE" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SHOW', true), ('$ROLE', 'SELECT', true)" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 60; then
    infra "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi

qa_admin postgres "SHOW server_version_num" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
PG_NUM=${QA_STEP_OUT[1]}
# lead UPTO17 FROM18: the expected recorded text for this server.
lead() { if ((PG_NUM >= 180000)); then printf '%s' "$2"; else printf '%s' "$1"; fi; }

LIBPQ=$(dirname "$QA_PSQL")/../lib/libpq.so.5
[[ -f $LIBPQ ]] || { infra "$ID" "libpq not found at $LIBPQ"; exit 0; }

cat >"$QA_RUN_DIR/stmt_client.py" <<'PY'
import ctypes, os, sys

lib = ctypes.CDLL(os.environ["QA_LIBPQ"])
lib.PQconnectdb.restype = ctypes.c_void_p
lib.PQconnectdb.argtypes = [ctypes.c_char_p]
lib.PQstatus.argtypes = [ctypes.c_void_p]
lib.PQerrorMessage.restype = ctypes.c_char_p
lib.PQerrorMessage.argtypes = [ctypes.c_void_p]
lib.PQexec.restype = ctypes.c_void_p
lib.PQexec.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.PQresultStatus.argtypes = [ctypes.c_void_p]
lib.PQresultErrorField.restype = ctypes.c_char_p
lib.PQresultErrorField.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.PQresultErrorMessage.restype = ctypes.c_char_p
lib.PQresultErrorMessage.argtypes = [ctypes.c_void_p]
lib.PQclear.argtypes = [ctypes.c_void_p]
lib.PQprepare.restype = ctypes.c_void_p
lib.PQprepare.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
lib.PQexecPrepared.restype = ctypes.c_void_p
lib.PQexecPrepared.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
lib.PQgetCopyData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
lib.PQfreemem.argtypes = [ctypes.c_void_p]
lib.PQgetResult.restype = ctypes.c_void_p
lib.PQgetResult.argtypes = [ctypes.c_void_p]
lib.PQfinish.argtypes = [ctypes.c_void_p]

PGRES_COMMAND_OK = 1
PGRES_TUPLES_OK = 2
PGRES_COPY_OUT = 3
PGRES_FATAL_ERROR = 7

def finish_result(res):
    status = lib.PQresultStatus(res)
    if status in (PGRES_COMMAND_OK, PGRES_TUPLES_OK):
        lib.PQclear(res)
        return "OK"
    if status == PGRES_COPY_OUT:
        lib.PQclear(res)
        return "COPY"
    state = lib.PQresultErrorField(res, ord("C"))
    msg = lib.PQresultErrorField(res, ord("M"))
    lib.PQclear(res)
    s = state.decode() if state else "?"
    m = msg.decode(errors="replace") if msg else ""
    return f"ERR {s} {m}"

def main():
    conninfo = os.environ["QA_CONNINFO"].encode()
    conn = lib.PQconnectdb(conninfo)
    if lib.PQstatus(conn) != 0:
        err = lib.PQerrorMessage(conn)
        sys.stderr.write((err or b"connect failed").decode(errors="replace"))
        return 2
    op = sys.argv[1]
    if op == "exec":
        # One PQexec is one simple-query message, however many statements.
        sql = sys.argv[2].encode()
        res = lib.PQexec(conn, sql)
        status = lib.PQresultStatus(res)
        if status == PGRES_COPY_OUT:
            lib.PQclear(res)
            buf = ctypes.c_char_p()
            while True:
                n = lib.PQgetCopyData(conn, ctypes.byref(buf), 0)
                if n == -1:
                    break
                if n < 0:
                    print("ERR ? copy data failed")
                    lib.PQfinish(conn)
                    return 0
                if buf:
                    lib.PQfreemem(buf)
            res2 = lib.PQgetResult(conn)
            print(finish_result(res2) if res2 else "OK")
        else:
            print(finish_result(res))
    elif op == "session":
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            kind, _, rest = line.partition("\t")
            if kind == "exec":
                res = lib.PQexec(conn, rest.encode())
                print(finish_result(res))
            elif kind == "prepare":
                # Parse message.
                name, _, sql = rest.partition("\t")
                res = lib.PQprepare(conn, name.encode(), sql.encode(), 0, None)
                print(finish_result(res))
            elif kind == "exec_prepared":
                # Bind and Execute messages.
                res = lib.PQexecPrepared(conn, rest.encode(), 0, None, None, None, 0)
                print(finish_result(res))
            else:
                sys.stderr.write(f"unknown session op {kind}\n")
                return 2
    else:
        sys.stderr.write("unknown op\n")
        return 2
    lib.PQfinish(conn)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
PY

export QA_LIBPQ=$LIBPQ
export QA_CONNINFO="host=$QA_SOCK port=$QA_PORT user=$ROLE dbname=$DB"

REJECT_PREFIX="ERR 42501 sql_firewall: No rule found for command"

simple() { # SQL -> QA_SIMPLE
    QA_SIMPLE=$(python3 "$QA_RUN_DIR/stmt_client.py" exec "$1") || {
        infra "$ID" "simple-query client failed"
        exit 0
    }
}

rejected_as() { # FAMILY: QA_SIMPLE is the firewall's no-rule rejection for FAMILY
    [[ $QA_SIMPLE == "$REJECT_PREFIX '$1' for role '$ROLE'" ]]
}

count_rows() {
    qa_admin "$DB" "SELECT count(*)::text FROM public.qa_stmt_target" || return $?
    QA_ROWS=${QA_STEP_OUT[1]}
}

activity_rows() { # MARKER -> QA_ACTIVITY: family|text per row, in log order
    qa_admin "$DB" \
        "SELECT coalesce(string_agg(command_type || '|' || query_text, E'\n' ORDER BY log_id), '') FROM public.sql_firewall_activity_log WHERE role_name OPERATOR(pg_catalog.=) '$ROLE' AND strpos(query_text, $(qa_sql_quote "$1")) > 0" ||
        return $?
    QA_ACTIVITY=${QA_STEP_OUT[1]}
}

blocked_rows() { # MARKER COUNT -> QA_BLOCKED once COUNT rows carry MARKER
    if ! qa_poll "$DB" \
        "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, $(qa_sql_quote "$1")) > 0" \
        "$2" 20; then
        QA_BLOCKED="(not delivered: $QA_INFRA_REASON)"
        return 1
    fi
    qa_admin "$DB" \
        "SELECT coalesce(string_agg(command_type || '|' || query_text, E'\n' ORDER BY block_id), '') FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, $(qa_sql_quote "$1")) > 0" ||
        return $?
    QA_BLOCKED=${QA_STEP_OUT[1]}
}

# check_activity LABEL MARKER EXPECTED: activity rows for MARKER are exactly EXPECTED.
check_activity() {
    if ! activity_rows "$2"; then
        infra "$ID.$1" "$QA_INFRA_REASON"
        return 1
    fi
    if [[ $QA_ACTIVITY != "$3" ]]; then
        fail "$ID.$1" "activity for $2 was '${QA_ACTIVITY//$'\n'/ ; }', expected '${3//$'\n'/ ; }'"
        return 1
    fi
}

# check_blocked LABEL MARKER COUNT EXPECTED: COUNT blocked rows carry MARKER
# and, joined by newlines, they are exactly EXPECTED. A statement's own text
# can contain a newline, so COUNT is explicit.
check_blocked() {
    if ! blocked_rows "$2" "$3"; then
        infra "$ID.$1" "blocked rows for $2: $QA_BLOCKED"
        return 1
    fi
    if [[ $QA_BLOCKED != "$4" ]]; then
        fail "$ID.$1" "blocked rows for $2 were '${QA_BLOCKED//$'\n'/ ; }', expected '${4//$'\n'/ ; }'"
        return 1
    fi
}

# check_unchanged LABEL: qa_stmt_target still holds its single row.
check_unchanged() {
    count_rows || { infra "$ID.$1" "$QA_INFRA_REASON"; return 1; }
    [[ $QA_ROWS == 1 ]] || { fail "$ID.$1" "qa_stmt_target changed (count $QA_ROWS)"; return 1; }
}

# expect_reject LABEL FAMILY SQL MARKER EXPECTED_TEXT: SQL (one message) is
# rejected as FAMILY, qa_stmt_target is unchanged, and the one blocked row for
# MARKER is FAMILY|EXPECTED_TEXT.
expect_reject() {
    simple "$3"
    if ! rejected_as "$2"; then
        fail "$ID.$1" "expected $2 rejection, got '$QA_SIMPLE'"
        return 1
    fi
    check_unchanged "$1" || return 1
    check_blocked "$1" "$4" 1 "$2|$5"
}

log_has() { # OFFSET TEXT: TEXT occurs in the server log after OFFSET
    tail -c +"$(($1 + 1))" "$QA_SERVER_LOG" | grep -F -- "$2" >/dev/null
}

# ---------------------------------------------------------------------------
# Comments, whitespace, and case do not change the family.
# ---------------------------------------------------------------------------
passed=1
expect_reject comment.block TRUNCATE $'/* lead */\nTRUNCATE public.qa_stmt_target /* qa_c_block */' \
    qa_c_block "$(lead $'/* lead */\nTRUNCATE public.qa_stmt_target /* qa_c_block */' 'TRUNCATE public.qa_stmt_target /* qa_c_block */')" || passed=0
expect_reject comment.nested TRUNCATE '/* outer /* inner */ still */ TRUNCATE public.qa_stmt_target /* qa_c_nested */' \
    qa_c_nested "$(lead '/* outer /* inner */ still */ TRUNCATE public.qa_stmt_target /* qa_c_nested */' 'TRUNCATE public.qa_stmt_target /* qa_c_nested */')" || passed=0
expect_reject comment.line TRUNCATE $'-- leading\nTRUNCATE public.qa_stmt_target /* qa_c_line */' \
    qa_c_line "$(lead $'-- leading\nTRUNCATE public.qa_stmt_target /* qa_c_line */' 'TRUNCATE public.qa_stmt_target /* qa_c_line */')" || passed=0
expect_reject comment.case TRUNCATE $' \n\t tRuNcAtE public.qa_stmt_target /* qa_c_case */ \n' \
    qa_c_case 'tRuNcAtE public.qa_stmt_target /* qa_c_case */' || passed=0
((passed)) && ok "$ID.comments" "leading block, nested block, and line comments, whitespace, and mixed case: each rejected as TRUNCATE, table unchanged, recorded as PostgreSQL's statement span with edge whitespace trimmed (leading comments kept up to PostgreSQL 17, not part of the span from 18; server_version_num $PG_NUM)"

# ---------------------------------------------------------------------------
# One simple-query message: SHOW is approved; TRUNCATE is the second statement.
# ---------------------------------------------------------------------------
BATCH='SHOW application_name; TRUNCATE public.qa_stmt_target /* qa_batch_trunc */'
log_at=$(qa_server_log_offset)
if expect_reject batch TRUNCATE "$BATCH" qa_batch_trunc 'TRUNCATE public.qa_stmt_target /* qa_batch_trunc */'; then
    if log_has "$log_at" "statement: $BATCH"; then
        ok "$ID.batch" "'$BATCH' arrived as one simple-query message (one log_statement line), was rejected as TRUNCATE before the table changed, and recorded only the TRUNCATE statement"
    else
        infra "$ID.batch" "server log has no single 'statement: $BATCH' line; one-message delivery not shown"
    fi
fi

# Approving OTHER does not authorize a commented TRUNCATE.
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'OTHER', true)" ||
    { infra "$ID.other" "$QA_INFRA_REASON"; exit 0; }
expect_reject other TRUNCATE $'/* not other */ TRUNCATE public.qa_stmt_target -- qa_other_trunc' \
    qa_other_trunc "$(lead '/* not other */ TRUNCATE public.qa_stmt_target -- qa_other_trunc' 'TRUNCATE public.qa_stmt_target -- qa_other_trunc')" &&
    ok "$ID.other" "an OTHER approval left the commented TRUNCATE rejected as TRUNCATE"

# Positive control: the TRUNCATE approval is what permits TRUNCATE.
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'TRUNCATE', true)" ||
    { infra "$ID.allow" "$QA_INFRA_REASON"; exit 0; }
simple '/* qa_allow_lead */ TRUNCATE public.qa_stmt_target /* qa_allow_body */'
count_rows || { infra "$ID.allow" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_SIMPLE != OK || $QA_ROWS != 0 ]]; then
    fail "$ID.allow" "approved commented TRUNCATE returned '$QA_SIMPLE', count $QA_ROWS"
elif check_activity allow qa_allow_body "TRUNCATE|$(lead '/* qa_allow_lead */ TRUNCATE public.qa_stmt_target /* qa_allow_body */' 'TRUNCATE public.qa_stmt_target /* qa_allow_body */')"; then
    ok "$ID.allow" "approving TRUNCATE let the same role truncate the table with a leading comment; logged as TRUNCATE"
fi
qa_admin "$DB" "INSERT INTO public.qa_stmt_target VALUES (1)" \
    "DELETE FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) '$ROLE' AND command_type OPERATOR(pg_catalog.=) 'TRUNCATE'" \
    "SELECT public.sql_firewall_clear_approval_cache()" ||
    { infra "$ID.allow" "$QA_INFRA_REASON"; exit 0; }

# ---------------------------------------------------------------------------
# Semicolons that are not statement boundaries.
# ---------------------------------------------------------------------------
passed=1
expect_reject semi.literal TRUNCATE $'SELECT \'qa_semi;inside\'; TRUNCATE public.qa_stmt_target /* qa_semi_tail */;' \
    qa_semi_tail 'TRUNCATE public.qa_stmt_target /* qa_semi_tail */' || passed=0
expect_reject semi.comment TRUNCATE $'SELECT \'qa_comment_semi\' /* semi; in comment */; TRUNCATE public.qa_stmt_target /* qa_comment_tail */' \
    qa_comment_tail 'TRUNCATE public.qa_stmt_target /* qa_comment_tail */' || passed=0
expect_reject semi.dollar TRUNCATE $'SELECT $qa$qa_dollar; body$qa$; TRUNCATE public.qa_stmt_target /* qa_dollar_tail */' \
    qa_dollar_tail 'TRUNCATE public.qa_stmt_target /* qa_dollar_tail */' || passed=0
expect_reject semi.ident TRUNCATE $'SELECT 1 AS "qa;ident"; TRUNCATE public.qa_stmt_target /* qa_ident_tail */' \
    qa_ident_tail 'TRUNCATE public.qa_stmt_target /* qa_ident_tail */' || passed=0
simple $'SELECT \'qa_semi_ok;x\' /* c; */; SELECT $q$qa_semi_ok2;$q$ -- tail; comment\n'
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.semi.allowed" "allowed batch returned '$QA_SIMPLE'"
    passed=0
else
    check_activity semi.allowed qa_semi_ok $'SELECT|SELECT \'qa_semi_ok;x\' /* c; */\nSELECT|SELECT $q$qa_semi_ok2;$q$ -- tail; comment' || passed=0
fi
((passed)) && ok "$ID.semi" "semicolons in a literal, a comment, a dollar quote, and a quoted identifier were not boundaries: the following TRUNCATE was rejected and recorded alone, and an allowed batch kept each statement's own text"

# ---------------------------------------------------------------------------
# Several executor statements; multibyte text before a later statement.
# ---------------------------------------------------------------------------
passed=1
simple $'SELECT \'qa_exec_é\'; SELECT \'qa_exec_second\''
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.exec" "two SELECT statements returned '$QA_SIMPLE'"
    passed=0
else
    check_activity exec.first qa_exec_é $'SELECT|SELECT \'qa_exec_é\'' || passed=0
    check_activity exec.second qa_exec_second $'SELECT|SELECT \'qa_exec_second\'' || passed=0
fi
simple $'SELECT \'qa_mb_ış€😀\';\tSELECT \'qa_mb_next_ğ\' ; SELECT \'qa_mb_last\''
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.exec.multibyte" "multibyte batch returned '$QA_SIMPLE'"
    passed=0
else
    check_activity exec.multibyte qa_mb_ $'SELECT|SELECT \'qa_mb_ış€😀\'\nSELECT|SELECT \'qa_mb_next_ğ\'\nSELECT|SELECT \'qa_mb_last\'' || passed=0
fi
expect_reject exec.multibyte_reject TRUNCATE $'SELECT \'qa_mbr_😀ış\'; TRUNCATE public.qa_stmt_target /* qa_mbr_trunc_ş */' \
    qa_mbr_trunc 'TRUNCATE public.qa_stmt_target /* qa_mbr_trunc_ş */' || passed=0
((passed)) && ok "$ID.exec" "executor statements in one message were recorded separately with exact text; 2-, 3- and 4-byte UTF8 before a later statement kept byte offsets on character boundaries"

# ---------------------------------------------------------------------------
# Mixed utility and executor statements in one message.
# ---------------------------------------------------------------------------
passed=1
simple 'SHOW application_name /* qa_mix_show */; SELECT '\''qa_mix_exec'\'''
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.mixed.allowed" "SHOW; SELECT returned '$QA_SIMPLE'"
    passed=0
else
    check_activity mixed.utility qa_mix_show 'SHOW|SHOW application_name /* qa_mix_show */' || passed=0
    check_activity mixed.executor qa_mix_exec $'SELECT|SELECT \'qa_mix_exec\'' || passed=0
fi
expect_reject mixed.exec_then_utility TRUNCATE $'SELECT \'qa_mix_first\'; TRUNCATE public.qa_stmt_target /* qa_mix_trunc */' \
    qa_mix_trunc 'TRUNCATE public.qa_stmt_target /* qa_mix_trunc */' || passed=0
expect_reject mixed.utility_then_exec INSERT 'SHOW application_name; INSERT INTO public.qa_stmt_target VALUES (5) /* qa_mix_ins */' \
    qa_mix_ins 'INSERT INTO public.qa_stmt_target VALUES (5) /* qa_mix_ins */' || passed=0
expect_reject mixed.exec_then_exec UPDATE $'SELECT \'qa_ee_first\'; UPDATE public.qa_stmt_target SET id = id /* qa_ee_upd */' \
    qa_ee_upd 'UPDATE public.qa_stmt_target SET id = id /* qa_ee_upd */' || passed=0
((passed)) && ok "$ID.mixed" "utility-then-executor and executor-then-utility messages: each statement kept its own family and text; the rejected later statement (TRUNCATE, INSERT, UPDATE) did not modify the table"

# ---------------------------------------------------------------------------
# A statement sent alone and the same statement later in a message.
# ---------------------------------------------------------------------------
passed=1
simple 'TRUNCATE public.qa_stmt_target /* qa_eq_trunc */'
rejected_as TRUNCATE || { fail "$ID.standalone" "standalone TRUNCATE returned '$QA_SIMPLE'"; passed=0; }
simple 'SHOW application_name; TRUNCATE public.qa_stmt_target /* qa_eq_trunc */'
rejected_as TRUNCATE || { fail "$ID.standalone" "batched TRUNCATE returned '$QA_SIMPLE'"; passed=0; }
check_unchanged standalone || passed=0
check_blocked standalone.trunc qa_eq_trunc 2 $'TRUNCATE|TRUNCATE public.qa_stmt_target /* qa_eq_trunc */\nTRUNCATE|TRUNCATE public.qa_stmt_target /* qa_eq_trunc */' || passed=0
simple $'SELECT \'qa_eq_sel\''
[[ $QA_SIMPLE == OK ]] || { fail "$ID.standalone" "standalone SELECT returned '$QA_SIMPLE'"; passed=0; }
simple $'SHOW application_name;\n  SELECT \'qa_eq_sel\'  '
[[ $QA_SIMPLE == OK ]] || { fail "$ID.standalone" "batched SELECT returned '$QA_SIMPLE'"; passed=0; }
check_activity standalone.select qa_eq_sel $'SELECT|SELECT \'qa_eq_sel\'\nSELECT|SELECT \'qa_eq_sel\'' || passed=0
((passed)) && ok "$ID.standalone" "TRUNCATE and SELECT sent alone and later in a message got the same family and identical recorded text"

# ---------------------------------------------------------------------------
# SQL PREPARE/EXECUTE (not the extended protocol) and the extended protocol.
# A plan executed by EXECUTE uses its saved source and offsets.
# ---------------------------------------------------------------------------
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'PREPARE', true), ('$ROLE', 'EXECUTE', true)" ||
    { infra "$ID.prepare" "$QA_INFRA_REASON"; exit 0; }
log_at=$(qa_server_log_offset)
mapfile -t session_out < <(python3 "$QA_RUN_DIR/stmt_client.py" session <<'EOF'
exec	PREPARE qa_stmt_p AS SELECT 'qa_sql_prepare_marker'
exec	EXECUTE qa_stmt_p
exec	SELECT 'qa_prep_pad_0123456789abcdefghij'; PREPARE qa_stmt_p2 AS SELECT 'qa_prep2_marker'
exec	EXECUTE qa_stmt_p2
exec	SELECT 'qa_exec_pad_abcdefghijklmnopqrstuvwxyz_0123456789'; EXECUTE qa_stmt_p2
exec	PREPARE qa_stmt_p3 AS SELECT 'qa_prep3_marker'; EXECUTE qa_stmt_p3
prepare	qa_ext	SELECT 'qa_ext_proto_marker'
exec_prepared	qa_ext
prepare	qa_ext2	/* qa_ext2_lead */ SELECT 'qa_ext2_marker';
exec_prepared	qa_ext2
prepare	qa_ext_trunc	/* qa_ext_lead */ TRUNCATE public.qa_stmt_target /* qa_ext_body */
exec_prepared	qa_ext_trunc
EOF
) || { infra "$ID.prepare" "session client failed"; exit 0; }
passed=1
for i in 0 1 2 3 4 5; do
    [[ ${session_out[i]:-} == OK ]] || { fail "$ID.prepare" "SQL PREPARE/EXECUTE step $i returned '${session_out[i]:-}'"; passed=0; }
done
check_activity prepare.plan qa_sql_prepare_marker $'PREPARE|PREPARE qa_stmt_p AS SELECT \'qa_sql_prepare_marker\'\nSELECT|PREPARE qa_stmt_p AS SELECT \'qa_sql_prepare_marker\'' || passed=0
check_activity prepare.offset qa_prep2_marker $'PREPARE|PREPARE qa_stmt_p2 AS SELECT \'qa_prep2_marker\'\nSELECT|PREPARE qa_stmt_p2 AS SELECT \'qa_prep2_marker\'\nSELECT|PREPARE qa_stmt_p2 AS SELECT \'qa_prep2_marker\'' || passed=0
check_activity prepare.same_message qa_prep3_marker $'PREPARE|PREPARE qa_stmt_p3 AS SELECT \'qa_prep3_marker\'\nSELECT|PREPARE qa_stmt_p3 AS SELECT \'qa_prep3_marker\'' || passed=0
if qa_admin "$DB" "SELECT coalesce(string_agg(command_type || '|' || query_text, E'\n' ORDER BY log_id), '') FROM public.sql_firewall_activity_log WHERE role_name OPERATOR(pg_catalog.=) '$ROLE' AND command_type OPERATOR(pg_catalog.=) 'EXECUTE'"; then
    if [[ ${QA_STEP_OUT[1]} != $'EXECUTE|EXECUTE qa_stmt_p\nEXECUTE|EXECUTE qa_stmt_p2\nEXECUTE|EXECUTE qa_stmt_p2\nEXECUTE|EXECUTE qa_stmt_p3' ]]; then
        fail "$ID.prepare.execute" "EXECUTE rows were '${QA_STEP_OUT[1]//$'\n'/ ; }'"
        passed=0
    fi
else
    infra "$ID.prepare.execute" "$QA_INFRA_REASON"
    passed=0
fi
((passed)) && ok "$ID.prepare" "SQL PREPARE/EXECUTE: the executed SELECT carried its saved PREPARE text, including when PREPARE was the second statement of its message and EXECUTE came later in a shorter or different message; the EXECUTE wrapper carried its own text"

passed=1
if [[ ${session_out[6]:-} != OK || ${session_out[7]:-} != OK || ${session_out[8]:-} != OK || ${session_out[9]:-} != OK ]]; then
    fail "$ID.extended" "prepare/execute returned '${session_out[6]:-}' '${session_out[7]:-}' '${session_out[8]:-}' '${session_out[9]:-}'"
    passed=0
fi
check_activity extended.plain qa_ext_proto_marker $'SELECT|SELECT \'qa_ext_proto_marker\'' || passed=0
check_activity extended.comment qa_ext2_marker "SELECT|$(lead "/* qa_ext2_lead */ SELECT 'qa_ext2_marker'" "SELECT 'qa_ext2_marker'")" || passed=0
if [[ ${session_out[10]:-} != OK || ${session_out[11]:-} != "$REJECT_PREFIX 'TRUNCATE' for role '$ROLE'" ]]; then
    fail "$ID.extended.reject" "Parse '${session_out[10]:-}', Execute '${session_out[11]:-}'"
    passed=0
else
    check_unchanged extended.reject || passed=0
    check_blocked extended.reject qa_ext_body 1 "TRUNCATE|$(lead '/* qa_ext_lead */ TRUNCATE public.qa_stmt_target /* qa_ext_body */' 'TRUNCATE public.qa_stmt_target /* qa_ext_body */')" || passed=0
fi
if ! log_has "$log_at" "execute qa_ext_trunc: /* qa_ext_lead */ TRUNCATE public.qa_stmt_target /* qa_ext_body */"; then
    infra "$ID.extended" "server log has no 'execute qa_ext_trunc:' line; extended-protocol execution not shown"
    passed=0
fi
((passed)) && ok "$ID.extended" "Parse/Bind/Execute (logged as 'execute <name>:'): prepared SELECTs were recorded with their text, the terminating ';' excluded; a commented TRUNCATE was rejected as TRUNCATE at Execute"

# ---------------------------------------------------------------------------
# EXPLAIN: the wrapper and the inner plan are separate inspections.
# ---------------------------------------------------------------------------
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'EXPLAIN', true)" ||
    { infra "$ID.explain" "$QA_INFRA_REASON"; exit 0; }
passed=1
simple "EXPLAIN SELECT 'qa_explain_plain'"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.explain.plain" "EXPLAIN returned '$QA_SIMPLE'"
    passed=0
else
    check_activity explain.plain qa_explain_plain $'EXPLAIN|EXPLAIN SELECT \'qa_explain_plain\'\nSELECT|EXPLAIN SELECT \'qa_explain_plain\'' || passed=0
fi
simple "EXPLAIN ANALYZE SELECT 'qa_explain_analyze'"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.explain.analyze" "EXPLAIN ANALYZE returned '$QA_SIMPLE'"
    passed=0
else
    check_activity explain.analyze qa_explain_analyze $'EXPLAIN|EXPLAIN ANALYZE SELECT \'qa_explain_analyze\'\nSELECT|EXPLAIN ANALYZE SELECT \'qa_explain_analyze\'' || passed=0
fi
simple $'SELECT \'qa_exb_first\'; EXPLAIN ANALYZE SELECT \'qa_exb_inner\''
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.explain.batch" "batched EXPLAIN ANALYZE returned '$QA_SIMPLE'"
    passed=0
else
    check_activity explain.batch qa_exb_ $'SELECT|SELECT \'qa_exb_first\'\nEXPLAIN|EXPLAIN ANALYZE SELECT \'qa_exb_inner\'\nSELECT|EXPLAIN ANALYZE SELECT \'qa_exb_inner\'' || passed=0
fi
expect_reject explain.inner_reject INSERT $'SELECT \'qa_exi_first\'; EXPLAIN ANALYZE INSERT INTO public.qa_stmt_target VALUES (9) /* qa_exi_ins */' \
    qa_exi_ins 'EXPLAIN ANALYZE INSERT INTO public.qa_stmt_target VALUES (9) /* qa_exi_ins */' || passed=0
((passed)) && ok "$ID.explain" "EXPLAIN is inspected as EXPLAIN and its plan as SELECT; in a message the inner plan carries the EXPLAIN statement's text, not the whole message; an EXPLAIN approval did not authorize EXPLAIN ANALYZE INSERT, which was rejected as INSERT before the row was written"

# ---------------------------------------------------------------------------
# CREATE TABLE AS, SELECT INTO, COPY, DECLARE CURSOR, MERGE.
# ---------------------------------------------------------------------------
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'CREATE', true), ('$ROLE', 'COPY', true)" ||
    { infra "$ID.compound" "$QA_INFRA_REASON"; exit 0; }
passed=1
simple "CREATE TABLE public.qa_stmt_ctas AS SELECT 'qa_ctas_marker'"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.ctas" "CREATE TABLE AS returned '$QA_SIMPLE'"
    passed=0
else
    check_activity ctas qa_ctas_marker $'CREATE|CREATE TABLE public.qa_stmt_ctas AS SELECT \'qa_ctas_marker\'\nSELECT|CREATE TABLE public.qa_stmt_ctas AS SELECT \'qa_ctas_marker\'' || passed=0
fi
simple $'SELECT \'qa_ctasb_first\'; CREATE TABLE public.qa_stmt_ctas2 AS SELECT \'qa_ctasb_inner\''
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.ctas.batch" "batched CREATE TABLE AS returned '$QA_SIMPLE'"
    passed=0
else
    check_activity ctas.batch qa_ctasb_ $'SELECT|SELECT \'qa_ctasb_first\'\nCREATE|CREATE TABLE public.qa_stmt_ctas2 AS SELECT \'qa_ctasb_inner\'\nSELECT|CREATE TABLE public.qa_stmt_ctas2 AS SELECT \'qa_ctasb_inner\'' || passed=0
fi
simple "SELECT 'qa_select_into_marker' INTO public.qa_stmt_into"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.into" "SELECT INTO returned '$QA_SIMPLE'"
    passed=0
else
    check_activity into qa_select_into_marker $'CREATE|SELECT \'qa_select_into_marker\' INTO public.qa_stmt_into\nSELECT|SELECT \'qa_select_into_marker\' INTO public.qa_stmt_into' || passed=0
fi
simple "COPY (SELECT 'qa_copy_marker') TO STDOUT"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.copy" "COPY returned '$QA_SIMPLE'"
    passed=0
else
    check_activity copy qa_copy_marker $'COPY|COPY (SELECT \'qa_copy_marker\') TO STDOUT\nSELECT|COPY (SELECT \'qa_copy_marker\') TO STDOUT' || passed=0
fi
simple $'SELECT \'qa_copyb_first\'; COPY (SELECT \'qa_copyb_inner\') TO STDOUT'
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.copy.batch" "batched COPY returned '$QA_SIMPLE'"
    passed=0
else
    check_activity copy.batch qa_copyb_ $'SELECT|SELECT \'qa_copyb_first\'\nCOPY|COPY (SELECT \'qa_copyb_inner\') TO STDOUT\nSELECT|COPY (SELECT \'qa_copyb_inner\') TO STDOUT' || passed=0
fi
# DECLARE CURSOR plans on a copy of the message text. The OTHER approval above
# covers DECLARE CURSOR, which has no family of its own.
simple $'SELECT \'qa_cur_first\'; DECLARE qa_stmt_cur CURSOR FOR SELECT \'qa_cur_inner\''
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.cursor.batch" "batched DECLARE CURSOR returned '$QA_SIMPLE'"
    passed=0
else
    check_activity cursor.batch qa_cur_ $'SELECT|SELECT \'qa_cur_first\'\nOTHER|DECLARE qa_stmt_cur CURSOR FOR SELECT \'qa_cur_inner\'\nSELECT|DECLARE qa_stmt_cur CURSOR FOR SELECT \'qa_cur_inner\'' || passed=0
fi
# A materialized view's stored query is read back from the catalog without a
# location (-1). REFRESH plans it against the whole message text.
simple "CREATE MATERIALIZED VIEW public.qa_stmt_mv AS SELECT 'qa_mv_inner' AS v"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.matview" "CREATE MATERIALIZED VIEW returned '$QA_SIMPLE'"
    passed=0
else
    check_activity matview qa_mv_inner $'CREATE|CREATE MATERIALIZED VIEW public.qa_stmt_mv AS SELECT \'qa_mv_inner\' AS v\nSELECT|CREATE MATERIALIZED VIEW public.qa_stmt_mv AS SELECT \'qa_mv_inner\' AS v' || passed=0
fi
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'REFRESH', true)" ||
    { infra "$ID.refresh" "$QA_INFRA_REASON"; exit 0; }
simple $'SELECT \'qa_ref_first\'; REFRESH MATERIALIZED VIEW public.qa_stmt_mv /* qa_ref_mark */'
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.refresh.batch" "batched REFRESH returned '$QA_SIMPLE'"
    passed=0
else
    check_activity refresh.batch qa_ref_ $'SELECT|SELECT \'qa_ref_first\'\nREFRESH|REFRESH MATERIALIZED VIEW public.qa_stmt_mv /* qa_ref_mark */\nSELECT|REFRESH MATERIALIZED VIEW public.qa_stmt_mv /* qa_ref_mark */' || passed=0
fi
MERGE_SQL='MERGE INTO public.qa_stmt_target AS t USING (SELECT 1 AS id) AS s ON t.id = s.id WHEN MATCHED THEN UPDATE SET id = t.id /* qa_merge_rej */'
expect_reject merge MERGE "$MERGE_SQL" qa_merge_rej "$MERGE_SQL" || passed=0
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'MERGE', true)" ||
    { infra "$ID.merge" "$QA_INFRA_REASON"; exit 0; }
MERGE_BODY='MERGE INTO public.qa_stmt_target AS t USING (SELECT 1 AS id) AS s ON t.id = s.id WHEN MATCHED THEN UPDATE SET id = 2 /* qa_merge_body */'
MERGE_OK="/* qa_merge_ok */ $MERGE_BODY"
simple "$MERGE_OK"
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.merge.allow" "approved MERGE returned '$QA_SIMPLE'"
    passed=0
else
    qa_admin "$DB" "SELECT id::text FROM public.qa_stmt_target" || { infra "$ID.merge" "$QA_INFRA_REASON"; exit 0; }
    [[ ${QA_STEP_OUT[1]} == 2 ]] || { fail "$ID.merge.row" "id is '${QA_STEP_OUT[1]}'"; passed=0; }
    check_activity merge.allow qa_merge_body "MERGE|$(lead "$MERGE_OK" "$MERGE_BODY")" || passed=0
    qa_admin "$DB" "UPDATE public.qa_stmt_target SET id = 1" || { infra "$ID.merge" "$QA_INFRA_REASON"; exit 0; }
fi
((passed)) && ok "$ID.compound" "CREATE TABLE AS, SELECT INTO, and CREATE MATERIALIZED VIEW were CREATE and COPY was COPY, each with its inner plan inspected as SELECT under the wrapper's text, also when batched after another statement; the plans of DECLARE CURSOR and of a batched REFRESH carried their statement's text; MERGE was rejected as MERGE until a MERGE approval, then honored"

# ---------------------------------------------------------------------------
# Errors while a wrapper runs: a subtransaction abort inside PL/pgSQL, and a
# message aborted inside EXPLAIN ANALYZE. The same connection continues, and
# later wrappers still give their inner plans their own text. (The failed
# statements' activity rows roll back with their subtransaction or message.)
# ---------------------------------------------------------------------------
passed=1
mapfile -t recover_out < <(python3 "$QA_RUN_DIR/stmt_client.py" session <<'EOF'
exec	DO $$ BEGIN BEGIN EXECUTE 'CREATE TABLE public.qa_stmt_err AS SELECT 1/0 AS qa_rec_div'; EXCEPTION WHEN division_by_zero THEN NULL; END; END $$; EXPLAIN ANALYZE SELECT 'qa_rec_sub_after'
exec	SELECT 'qa_rec_abort_first'; EXPLAIN ANALYZE SELECT 1/0 AS qa_rec_abort
exec	SELECT 'qa_rec_top_first'; EXPLAIN ANALYZE SELECT 'qa_rec_top_after'
EOF
) || { infra "$ID.recovery" "session client failed"; exit 0; }
if [[ ${recover_out[0]:-} != OK || ${recover_out[1]:-} != "ERR 22012 division by zero" || ${recover_out[2]:-} != OK ]]; then
    fail "$ID.recovery" "session returned '${recover_out[0]:-}' '${recover_out[1]:-}' '${recover_out[2]:-}'"
    passed=0
fi
check_activity recovery.subxact qa_rec_sub_after $'EXPLAIN|EXPLAIN ANALYZE SELECT \'qa_rec_sub_after\'\nSELECT|EXPLAIN ANALYZE SELECT \'qa_rec_sub_after\'' || passed=0
check_activity recovery.xact qa_rec_top_ $'SELECT|SELECT \'qa_rec_top_first\'\nEXPLAIN|EXPLAIN ANALYZE SELECT \'qa_rec_top_after\'\nSELECT|EXPLAIN ANALYZE SELECT \'qa_rec_top_after\'' || passed=0
((passed)) && ok "$ID.recovery" "after a CREATE TABLE AS failed inside a PL/pgSQL exception block, and after a message aborted inside EXPLAIN ANALYZE, the same connection kept attributing inner plans to their own statements"

# ---------------------------------------------------------------------------
# Sub-commands PostgreSQL runs for a statement keep that statement's family.
# ---------------------------------------------------------------------------
# CREATE TABLE with a serial column also runs CREATE SEQUENCE and ALTER
# SEQUENCE ... OWNED BY through ProcessUtility. ALTER is not approved.
simple 'CREATE TABLE public.qa_stmt_serial (id serial) /* qa_sub_marker */'
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.subcommand" "CREATE TABLE with a serial column under a CREATE approval returned '$QA_SIMPLE'"
elif check_activity subcommand qa_sub_marker $'CREATE|CREATE TABLE public.qa_stmt_serial (id serial) /* qa_sub_marker */\nCREATE|CREATE TABLE public.qa_stmt_serial (id serial) /* qa_sub_marker */\nCREATE|CREATE TABLE public.qa_stmt_serial (id serial) /* qa_sub_marker */'; then
    ok "$ID.subcommand" "the table, its sequence, and the sequence's OWNED BY sub-command were all checked as CREATE with the statement's text; no ALTER approval was needed"
fi

# ---------------------------------------------------------------------------
# A data-modifying CTE needs the outer SELECT and its planned write family.
# ---------------------------------------------------------------------------
CTE="WITH x AS (INSERT INTO public.qa_stmt_cte VALUES (7) RETURNING id) SELECT 'qa_cte_marker' FROM x"
simple "$CTE"
if ! rejected_as INSERT; then
    fail "$ID.cte" "SELECT approval without INSERT approval returned '$QA_SIMPLE'"
elif ! qa_admin "$DB" "SELECT count(*)::text FROM public.qa_stmt_cte"; then
    infra "$ID.cte" "$QA_INFRA_REASON"
elif [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.cte" "rejected INSERT still wrote ${QA_STEP_OUT[1]} rows"
elif check_blocked cte.reject qa_cte_marker 1 "INSERT|$CTE"; then
    ok "$ID.cte.reject" "SELECT approval alone did not authorize the planned INSERT"
fi
if ! qa_admin "$DB" "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'INSERT', true)"; then
    infra "$ID.cte.approved" "$QA_INFRA_REASON"
else
    simple "$CTE"
    if [[ $QA_SIMPLE != OK ]]; then
        fail "$ID.cte.approved" "SELECT and INSERT approved, but CTE returned '$QA_SIMPLE'"
    elif ! qa_admin "$DB" "SELECT count(*)::text FROM public.qa_stmt_cte"; then
        infra "$ID.cte.approved" "$QA_INFRA_REASON"
    elif [[ ${QA_STEP_OUT[1]} != 1 ]]; then
        fail "$ID.cte.approved" "approved CTE wrote ${QA_STEP_OUT[1]} rows, expected 1"
    # The first, rejected attempt's outer SELECT was allowed before its
    # INSERT was rejected; that decision stays in the log (README 6.7).
    elif check_activity cte.approved qa_cte_marker "SELECT|$CTE"$'\n'"SELECT|$CTE"$'\n'"INSERT|$CTE"; then
        ok "$ID.cte.approved" "both planned families were inspected before the CTE wrote one row; the rejected attempt's allowed outer SELECT is also recorded"
    fi
fi

# SQL-standard function bodies store a parsed body and can supply no source
# text to ExecutorStart. An approved outer SELECT must not hide that write.
if ! qa_admin "$DB" \
    "CREATE FUNCTION public.qa_stmt_atomic() RETURNS void LANGUAGE SQL BEGIN ATOMIC INSERT INTO public.qa_stmt_cte VALUES (8); END"; then
    infra "$ID.atomic" "$QA_INFRA_REASON"
else
    simple 'SELECT public.qa_stmt_atomic() /* qa_atomic_call */'
    if [[ $QA_SIMPLE != 'ERR 0A000 sql_firewall: executable plan has no SQL source text for policy inspection' ]]; then
        fail "$ID.atomic" "source-free SQL function write returned '$QA_SIMPLE'"
    elif ! qa_admin "$DB" "SELECT count(*)::text FROM public.qa_stmt_cte"; then
        infra "$ID.atomic" "$QA_INFRA_REASON"
    elif [[ ${QA_STEP_OUT[1]} != 1 ]]; then
        fail "$ID.atomic" "source-free function changed the table to ${QA_STEP_OUT[1]} rows"
    else
        ok "$ID.atomic" "an approved outer SELECT could not execute a write whose SQL-standard body provided no inspectable source"
    fi
fi
if ! qa_admin "$DB" \
    "CREATE FUNCTION public.qa_stmt_atomic_read() RETURNS integer LANGUAGE SQL BEGIN ATOMIC SELECT 1; SELECT 2; END"; then
    infra "$ID.atomic_read" "$QA_INFRA_REASON"
else
    simple 'SELECT public.qa_stmt_atomic_read()'
    if [[ $QA_SIMPLE == 'ERR 0A000 sql_firewall: executable plan has no SQL source text for policy inspection' ]]; then
        ok "$ID.atomic_read" "a SQL-standard read body without source text was refused instead of silently skipping its policy checks"
    else
        fail "$ID.atomic_read" "source-free SQL-standard read returned '$QA_SIMPLE'"
    fi
fi

# A rewrite-rule action is another executable plan. Its query text must stay
# on the INSERT statement even when an earlier statement shares the message.
RULE_SQL='INSERT INTO public.qa_stmt_rule_src VALUES (9) /* qa_rule_batch */'
if ! qa_admin "$DB" \
    "CREATE TABLE public.qa_stmt_rule_src (id integer)" \
    "GRANT INSERT ON public.qa_stmt_rule_src TO $ROLE" \
    "CREATE RULE qa_stmt_rule AS ON INSERT TO public.qa_stmt_rule_src DO ALSO INSERT INTO public.qa_stmt_cte (id) VALUES (NEW.id)"; then
    infra "$ID.rule" "$QA_INFRA_REASON"
else
    simple "SHOW application_name; $RULE_SQL"
    if [[ $QA_SIMPLE != OK ]]; then
        fail "$ID.rule" "batched INSERT with a DO ALSO rule returned '$QA_SIMPLE'"
    elif ! activity_rows qa_rule_batch; then
        infra "$ID.rule" "$QA_INFRA_REASON"
    elif [[ $QA_ACTIVITY != "INSERT|$RULE_SQL"$'\n'"INSERT|$RULE_SQL" ]]; then
        fail "$ID.rule" "rule activity used wrong statement text: '${QA_ACTIVITY//$'\n'/ ; }'"
    elif ! qa_admin "$DB" "SELECT count(*)::text FROM public.qa_stmt_cte"; then
        infra "$ID.rule" "$QA_INFRA_REASON"
    elif [[ ${QA_STEP_OUT[1]} != 2 ]]; then
        fail "$ID.rule" "rewrite-rule action left ${QA_STEP_OUT[1]} target rows, expected 2"
    else
        ok "$ID.rule" "original INSERT and DO ALSO action each used the INSERT span of a batched message"
    fi
    simple "INSERT INTO public.qa_stmt_rule_src VALUES (10) /* qa_rule_ambiguous */; INSERT INTO public.qa_stmt_target VALUES (10)"
    if [[ $QA_SIMPLE != 'ERR 0A000 sql_firewall: executable plan has no unambiguous source statement' ]]; then
        fail "$ID.rule.ambiguous" "two possible DML parents returned '$QA_SIMPLE'"
    elif ! qa_admin "$DB" \
        "SELECT (SELECT count(*) FROM public.qa_stmt_rule_src) || ',' || (SELECT count(*) FROM public.qa_stmt_cte)"; then
        infra "$ID.rule.ambiguous" "$QA_INFRA_REASON"
    elif [[ ${QA_STEP_OUT[1]} != 1,2 ]]; then
        fail "$ID.rule.ambiguous" "rejected ambiguous rule changed row counts to ${QA_STEP_OUT[1]}"
    else
        ok "$ID.rule.ambiguous" "two possible DML parents were refused before a rule action could use the wrong identity"
    fi
fi

# ---------------------------------------------------------------------------
# A SQL function body is still inspected; it is not firewall recursion.
# ---------------------------------------------------------------------------
qa_admin "$DB" \
    "CREATE FUNCTION public.qa_stmt_wrap() RETURNS text LANGUAGE sql AS \$fn\$ SELECT 'qa_wrap_setup'; SELECT 'qa_wrap_marker' \$fn\$" ||
    { infra "$ID.wrap" "$QA_INFRA_REASON"; exit 0; }
simple 'SELECT public.qa_stmt_wrap() /* qa_wrap_call */'
if [[ $QA_SIMPLE != OK ]]; then
    fail "$ID.wrap" "wrapper call returned '$QA_SIMPLE'"
elif check_activity wrap qa_wrap_ $'SELECT|SELECT public.qa_stmt_wrap() /* qa_wrap_call */\nSELECT|SELECT \'qa_wrap_setup\'\nSELECT|SELECT \'qa_wrap_marker\''; then
    ok "$ID.wrap" "the call and both statements of the non-inlined SQL function body were inspected, each with its own text from the function source"
fi

exit 0
