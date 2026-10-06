#!/usr/bin/env python3
"""Phase 5B transaction-start behavior using separate libpq connections."""

import ctypes
import os
import time

from policy_cache import SU, Conn, Check, Infra, admin, lib, must, note, run, sync_activity, value

DB = "qa_txstart"
GOOD = "qa_tx_good"
DENIED = "qa_tx_denied"
REGEX = "qa_tx_regex"
# Snapshot-free utilities inside a transaction block. The reference is the same
# sequence in a database of this cluster where sql_firewall is not installed:
# there the preloaded hooks inspect nothing, as without the extension.
NATIVE = os.environ["QA_TX_NATIVE_DB"]
SERVER_LOG = os.environ.get("QA_SERVER_LOG")
SEQ = "qa_tx_seq"
NOSHOW = "qa_tx_noshow"
UNRELATED = "qa_tx_unrelated"
REPEATABLE = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
IN_SUBXACT = "ERR 25001 SET TRANSACTION ISOLATION LEVEL must not be called in a subtransaction"
AFTER_QUERY = "ERR 25001 SET TRANSACTION ISOLATION LEVEL must be called before any query"
REGEX_BLOCK = "ERR 42501 sql_firewall: Query blocked by security regex pattern."
# name, role settings, mode, whether the SHOW approval is cached before the
# measured SHOW. Each isolates one foreground operation that can take the
# transaction's first snapshot; "none" has none of them.
CAUSES = (
    ("none", "off", "off", "enforce", True),
    ("activity_write", "on", "off", "enforce", True),
    ("regex_read", "off", "on", "enforce", True),
    ("approval_read", "off", "off", "enforce", False),
    ("fingerprint_read", "off", "off", "learn", True),
)
# Deferred-record capacity (spi_checks.rs): rows and owned bytes.
# Activity records are carried up to this many bytes of statement text (README 6.7).
ACTIVITY_TEXT_BYTES = 2047
# Activity records go to the activity queue at the decision (README 6.7).
# Earlier builds held them in the backend until the transaction's first
# snapshot or commit, refused a statement with 54000 beyond 1024 records or
# 1 MiB, and discarded them with the transaction; these scenarios now check
# the queue contract instead.
MANY_RECORDS = 1100
# Line-comment endings. PostgreSQL's lexer ends a -- comment at CR or LF
# (scan.l: newline [\n\r]). These are the bytes 0x0d and 0x0a in the message.
CR, LF = chr(13), chr(10)
LEARN_COMMIT = "qa_tx_learn_commit"
LEARN_ROLLBACK = "qa_tx_learn_rollback"
LEARN_CAPACITY = "qa_tx_learn_capacity"


def lit(text):
    return "'" + text.replace("'", "''") + "'"


def setup():
    a = admin(DB, "setup")
    must(a, "CREATE TABLE public.tx_rows(id integer)")
    must(a, "INSERT INTO public.tx_rows VALUES (1)")
    for role in (GOOD, DENIED, REGEX):
        must(a, f"CREATE ROLE {role} LOGIN")
        must(a, f"ALTER ROLE {role} SET sql_firewall.mode = 'enforce'")
        must(a, f"ALTER ROLE {role} SET sql_firewall.enable_fingerprint_learning = 'off'")
        must(a, f"GRANT SELECT ON public.tx_rows TO {role}")
    for command in ("BEGIN", "SET", "SELECT", "SHOW", "ROLLBACK"):
        must(a, f"SELECT sql_firewall_approve_command('{GOOD}', '{command}')")
    for command in ("BEGIN", "SELECT", "ROLLBACK"):
        must(a, f"SELECT sql_firewall_approve_command('{DENIED}', '{command}')")
    for command in ("BEGIN", "SELECT"):
        must(a, f"SELECT sql_firewall_approve_command('{REGEX}', '{command}')")
    roles = {
        SEQ: ("BEGIN", "SET", "RESET", "SELECT", "SHOW", "SAVEPOINT", "RELEASE", "ROLLBACK", "LOCK", "COMMIT",
              "PREPARE", "OTHER"),
        NOSHOW: ("BEGIN", "SET", "SELECT", "SAVEPOINT", "RELEASE", "ROLLBACK"),
    }
    for name, activity, regex_scan, mode, _ in CAUSES:
        roles[f"qa_tx_cause_{name}"] = ("BEGIN", "SET", "SELECT", "SHOW", "ROLLBACK")
    for role, commands in roles.items():
        must(a, f"CREATE ROLE {role} LOGIN")
        must(a, f"ALTER ROLE {role} SET sql_firewall.mode = 'enforce'")
        must(a, f"ALTER ROLE {role} SET sql_firewall.enable_fingerprint_learning = 'off'")
        must(a, f"GRANT SELECT ON public.tx_rows TO {role}")
        for command in commands:
            must(a, f"SELECT sql_firewall_approve_command('{role}', '{command}')")
    for name, activity, regex_scan, mode, _ in CAUSES:
        role = f"qa_tx_cause_{name}"
        must(a, f"ALTER ROLE {role} SET sql_firewall.mode = '{mode}'")
        if name == "fingerprint_read":
            must(a, f"ALTER ROLE {role} SET sql_firewall.enable_fingerprint_learning = 'on'")
        must(a, f"ALTER ROLE {role} SET sql_firewall.enable_activity_logging = '{activity}'")
        must(a, f"ALTER ROLE {role} SET sql_firewall.enable_regex_scan = '{regex_scan}'")
    for role in (LEARN_COMMIT, LEARN_ROLLBACK, LEARN_CAPACITY):
        must(a, f"CREATE ROLE {role} LOGIN")
        must(a, f"ALTER ROLE {role} SET sql_firewall.mode = 'learn'")
        must(a, f"GRANT SELECT ON public.tx_rows TO {role}")
    must(a, f"CREATE ROLE {UNRELATED} LOGIN")
    a.close()
    n = admin(NATIVE, "native-setup")
    if value(n, "SELECT count(*) FROM pg_extension WHERE extname = 'sql_firewall'") != "0":
        raise Infra(f"{NATIVE} has sql_firewall installed; it is not a native reference")
    must(n, "CREATE TABLE public.tx_rows(id integer)")
    must(n, "INSERT INTO public.tx_rows VALUES (1)")
    must(n, f"GRANT SELECT ON public.tx_rows TO {SEQ}")
    n.close()


def begin_options(c: Check, statement: str, isolation: str, readonly: str, marker: int):
    a = admin(DB, "writer")
    u = Conn("ordinary", GOOD, DB)
    c.equal("BEGIN/START", u.q(statement), "OK")
    must(a, f"INSERT INTO public.tx_rows VALUES ({marker})")
    count = value(a, "SELECT count(*) FROM public.tx_rows")
    c.equal("first data snapshot", u.q("SELECT count(*) FROM public.tx_rows"), f"OK rows=1: {count}")
    c.equal("isolation", u.q("SHOW transaction_isolation"), f"OK rows=1: {isolation}")
    c.equal("read-only", u.q("SHOW transaction_read_only"), f"OK rows=1: {readonly}")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    return f"{statement}: options applied; first data snapshot included committed row {marker}"


def set_options(c: Check, isolation: str, marker: int):
    a = admin(DB, "writer")
    u = Conn("ordinary", GOOD, DB)
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("SET TRANSACTION", u.q(f"SET TRANSACTION ISOLATION LEVEL {isolation}"), "OK")
    must(a, f"INSERT INTO public.tx_rows VALUES ({marker})")
    count = value(a, "SELECT count(*) FROM public.tx_rows")
    c.equal("first data snapshot", u.q("SELECT count(*) FROM public.tx_rows"), f"OK rows=1: {count}")
    c.equal("isolation", u.q("SHOW transaction_isolation"), f"OK rows=1: {isolation.lower()}")
    c.equal("regex timeout restored", u.q("SHOW statement_timeout"), "OK rows=1: 0")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    return f"BEGIN then SET TRANSACTION {isolation}: no 25001; first data snapshot included row {marker}"


def denied(c: Check):
    u = Conn("unapproved-BEGIN", DENIED, DB)
    # Remove BEGIN approval through a separate committed policy write.
    a = admin(DB, "policy")
    must(a, f"DELETE FROM public.sql_firewall_command_approvals WHERE role_name = '{DENIED}' AND command_type = 'BEGIN'")
    c.expect("unapproved BEGIN", u.q("BEGIN ISOLATION LEVEL REPEATABLE READ"), "norule", DENIED, "BEGIN")
    c.expect("session usable after denial", u.q("SELECT count(*) FROM public.tx_rows"), "allow", DENIED, "SELECT")
    must(a, f"SELECT sql_firewall_approve_command('{DENIED}', 'BEGIN')")
    c.equal("approved BEGIN", u.q("BEGIN"), "OK")
    c.expect("unapproved SET", u.q("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"), "norule", DENIED, "SET")
    c.equal("transaction aborted by denial", u.q("SELECT count(*) FROM public.tx_rows"),
            "ERR 25P02 current transaction is aborted, commands ignored until end of transaction block")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    c.expect("session usable after rollback", u.q("SELECT count(*) FROM public.tx_rows"), "allow", DENIED, "SELECT")
    return "unapproved BEGIN and SET remain blocked with 42501; explicit ROLLBACK recovers the session"


def regex(c: Check):
    a = admin(DB, "regex-policy")
    must(a, "INSERT INTO public.sql_firewall_regex_rules(pattern, description, allowed_roles) "
            "VALUES ('BEGIN READ WRITE', 'qa_txstart', ARRAY['other_role'])")
    u = Conn("regex-BEGIN", REGEX, DB)
    c.equal("regex block", u.q("BEGIN READ WRITE"),
            "ERR 42501 sql_firewall: Query blocked by security regex pattern.")
    c.expect("session usable after regex block", u.q("SELECT count(*) FROM public.tx_rows"), "allow", REGEX, "SELECT")
    must(a, "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa_txstart'")
    return "transaction-control regex rule still blocks before any data statement"


# ---------------------------------------------------------------------------
# Snapshot-free utilities before the first snapshot
# ---------------------------------------------------------------------------

def transcript(db, role, steps):
    """Runs steps on one application connection of role in db and returns one
    line per step: the result and the transaction status afterwards. '@marker'
    commits a row from a second connection; '@first' is the first data SELECT
    and reports only whether that row is visible, so transcripts from two
    databases compare."""
    a = admin(db, f"writer-{db}")
    u = Conn(f"app-{db}", role, db)
    lines, expected = [], None
    for step in steps:
        if step == "@marker":
            must(a, "INSERT INTO public.tx_rows VALUES (900)")
            expected = value(a, "SELECT count(*) FROM public.tx_rows")
            lines.append("@marker committed by another session")
        elif step == "@first":
            got = u.q("SELECT count(*) FROM public.tx_rows")
            if got.startswith("OK rows=1: ") and expected is not None:
                seen = "visible" if got.split(": ", 1)[1] == expected else "NOT visible"
                lines.append(f"@first data SELECT: marker {seen} [{u.txn()}]")
            else:
                lines.append(f"@first data SELECT: {got} [{u.txn()}]")
        else:
            shown = step.replace(CR, "<CR>").replace(LF, "<LF>")
            lines.append(f"{shown} => {u.q(step)} [{u.txn()}]")
    u.close()
    a.close()
    return lines


def against_native(c, steps, native_expect):
    """The firewall database, with an ordinary role holding every needed
    approval, must reproduce the native transcript exactly. native_expect
    pins what the native run must show, so the sequence tests what it names."""
    native = transcript(NATIVE, SEQ, steps)
    note("    native transcript:\n        " + "\n        ".join(native))
    for index, want in native_expect:
        if want not in native[index]:
            raise Infra(f"native step {index} is {native[index]!r}, expected {want!r}")
    firewall = transcript(DB, SEQ, steps)
    note("    firewall transcript:\n        " + "\n        ".join(firewall))
    for index, (n, f) in enumerate(zip(native, firewall)):
        c.equal(f"step {index} as native", f, n)
    return " / ".join(native)


SEQUENCES = {
    "show_then_set": (
        ["BEGIN", "SHOW transaction_isolation", "@marker", REPEATABLE, "@first",
         "SHOW transaction_isolation", "SHOW statement_timeout", "ROLLBACK"],
        [(3, "=> OK [in-transaction]"), (4, "marker visible"), (5, "repeatable read"), (6, ": 0 ")]),
    "set_then_set": (
        ["BEGIN", "SET application_name = 'qa_tx_seq_set'", "RESET work_mem", "@marker",
         "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "@first", "SHOW transaction_isolation",
         "SHOW application_name", "ROLLBACK"],
        [(4, "=> OK [in-transaction]"), (5, "marker visible"), (6, "serializable"), (7, "qa_tx_seq_set")]),
    "set_local_then_set": (
        ["BEGIN", "SET LOCAL statement_timeout = '7s'", "SET LOCAL lock_timeout = '4s'", "@marker",
         REPEATABLE, "@first", "SHOW statement_timeout", "SHOW lock_timeout", "ROLLBACK",
         "SHOW statement_timeout"],
        [(4, "=> OK [in-transaction]"), (5, "marker visible"), (6, ": 7s "), (7, ": 4s "), (9, ": 0 ")]),
    "savepoint_release_then_set": (
        ["BEGIN", "SAVEPOINT qa_s1", "RELEASE SAVEPOINT qa_s1", "@marker", REPEATABLE, "@first", "ROLLBACK"],
        [(4, "=> OK [in-transaction]"), (5, "marker visible")]),
    "savepoint_rejects_then_recovers": (
        ["BEGIN", "SAVEPOINT qa_s2", REPEATABLE, "ROLLBACK TO SAVEPOINT qa_s2", "RELEASE SAVEPOINT qa_s2",
         "@marker", REPEATABLE, "@first", "SHOW transaction_isolation", "ROLLBACK"],
        [(2, IN_SUBXACT), (3, "=> OK [in-transaction]"), (6, "=> OK [in-transaction]"),
         (7, "marker visible"), (8, "repeatable read")]),
    "rollback_to_stays_in_subtransaction": (
        ["BEGIN", "SAVEPOINT qa_s3", "ROLLBACK TO SAVEPOINT qa_s3", REPEATABLE, "ROLLBACK"],
        [(3, IN_SUBXACT)]),
    "data_query_then_set": (
        ["BEGIN", "SELECT 1", REPEATABLE, "ROLLBACK"],
        [(2, AFTER_QUERY)]),
    "lock_then_set": (
        ["BEGIN", "LOCK TABLE public.tx_rows IN ACCESS SHARE MODE", "@marker", REPEATABLE, "@first", "ROLLBACK"],
        [(3, "=> OK [in-transaction]"), (4, "marker visible")]),
    "repeatable_read_first_snapshot": (
        ["BEGIN ISOLATION LEVEL REPEATABLE READ", "SHOW search_path", "SET LOCAL work_mem = '9MB'",
         "SAVEPOINT qa_s4", "RELEASE SAVEPOINT qa_s4", "LOCK TABLE public.tx_rows IN ACCESS SHARE MODE",
         "@marker", "@first", "COMMIT"],
        [(7, "marker visible")]),
    "show_then_read_only": (
        ["BEGIN", "SHOW work_mem", "SET TRANSACTION READ ONLY", "@marker", "@first",
         "SHOW transaction_read_only", "COMMIT"],
        [(2, "=> OK [in-transaction]"), (4, "marker visible"), (5, ": on ")]),
    # The chained block is an explicit block: a utility in it is not the end
    # of an implicit transaction.
    "commit_and_chain_then_set": (
        ["BEGIN", "SHOW work_mem", "COMMIT AND CHAIN", "SHOW work_mem", "@marker", REPEATABLE, "@first",
         "SHOW transaction_isolation", "COMMIT"],
        [(2, "=> OK [in-transaction]"), (5, "=> OK [in-transaction]"), (6, "marker visible"),
         (7, "repeatable read")]),
    "rollback_and_chain_then_set": (
        ["BEGIN", "SHOW work_mem", "ROLLBACK AND CHAIN", "SHOW work_mem", "@marker", REPEATABLE, "@first",
         "COMMIT"],
        [(2, "=> OK [in-transaction]"), (5, "=> OK [in-transaction]"), (6, "marker visible")]),
    "failed_block_chain_then_set": (
        ["BEGIN", "SELECT 1/0", "ROLLBACK AND CHAIN", "SHOW work_mem", "@marker", REPEATABLE, "@first",
         "COMMIT"],
        [(1, "22012"), (2, "=> OK [in-transaction]"), (5, "=> OK [in-transaction]"), (6, "marker visible")]),
    # BEGIN at the end of a message turns its implicit block into an explicit
    # one; a message may also end inside an explicit block.
    "utility_then_begin_message": (
        ["SHOW work_mem; BEGIN", "@marker", REPEATABLE, "@first", "COMMIT"],
        [(0, "=> OK [in-transaction]"), (2, "=> OK [in-transaction]"), (3, "marker visible")]),
    "begin_then_utility_message": (
        ["BEGIN; SHOW work_mem", "@marker", REPEATABLE, "@first", "COMMIT"],
        [(0, "[in-transaction]"), (2, "=> OK [in-transaction]"), (3, "marker visible")]),
    # One simple-query message each; the comment ends at CR, LF, or CRLF.
    "comment_cr_then_set": (
        [f"SHOW application_name; -- comment{CR}{REPEATABLE};"], [(0, "=> OK [idle]")]),
    "comment_lf_then_set": (
        [f"SHOW application_name; -- comment{LF}{REPEATABLE};"], [(0, "=> OK [idle]")]),
    "comment_crlf_then_set": (
        [f"SHOW application_name; -- comment{CR}{LF}{REPEATABLE};"], [(0, "=> OK [idle]")]),
    "nested_comment_then_set": (
        [f"SHOW application_name; /* outer /* nested */ still outer */ {REPEATABLE};"], [(0, "=> OK [idle]")]),
    "comment_cr_then_begin": (
        [f"SHOW application_name; -- comment{CR}BEGIN", "@marker", REPEATABLE, "@first", "COMMIT"],
        [(0, "=> OK [in-transaction]"), (2, "=> OK [in-transaction]"), (3, "marker visible")]),
    "trailing_comment_after_begin": (
        ["SHOW application_name; BEGIN; -- trailing comment", "@marker", REPEATABLE, "@first", "COMMIT"],
        [(0, "=> OK [in-transaction]"), (2, "=> OK [in-transaction]"), (3, "marker visible")]),
}


# ---------------------------------------------------------------------------
# Extended-protocol pipelines
# ---------------------------------------------------------------------------

for _name, _restype, _argtypes in (
    ("PQenterPipelineMode", ctypes.c_int, [ctypes.c_void_p]),
    ("PQexitPipelineMode", ctypes.c_int, [ctypes.c_void_p]),
    ("PQpipelineSync", ctypes.c_int, [ctypes.c_void_p]),
    ("PQsendFlushRequest", ctypes.c_int, [ctypes.c_void_p]),
    ("PQflush", ctypes.c_int, [ctypes.c_void_p]),
    ("PQgetResult", ctypes.c_void_p, [ctypes.c_void_p]),
    ("PQsendQueryParams", ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]),
    ("PQexecParams", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]),
):
    getattr(lib, _name).restype = _restype
    getattr(lib, _name).argtypes = _argtypes
PIPELINE_SYNC, PIPELINE_ABORTED = 10, 11


def describe(res):
    status = lib.PQresultStatus(res)
    if status == 1:
        return "OK"
    if status == 2:
        return f"OK rows={lib.PQntuples(res)}: " + "|".join(
            lib.PQgetvalue(res, i, 0).decode(errors="replace") for i in range(lib.PQntuples(res)))
    if status == PIPELINE_SYNC:
        return "SYNC"
    if status == PIPELINE_ABORTED:
        return "ABORTED"
    code, message = lib.PQresultErrorField(res, ord("C")), lib.PQresultErrorField(res, ord("M"))
    return f"ERR {code.decode() if code else '?'} {message.decode(errors='replace') if message else ''} (status {status})"


def pipeline(u, statements, pause=None):
    """Sends each statement with PQsendQueryParams (Parse, Bind, Describe,
    Execute; no Sync) in pipeline mode, then one PQpipelineSync, and returns
    one line per statement and one for the Sync. pause=(k, fn) sends the first
    k statements with a Flush request, reads their results (so the server has
    run them), calls fn, and only then sends the rest and the Sync."""
    conn = u.conn
    if lib.PQenterPipelineMode(conn) != 1:
        raise Infra(f"{u.label}: PQenterPipelineMode failed")

    def send(sql):
        if lib.PQsendQueryParams(conn, sql.encode(), 0, None, None, None, None, 0) != 1:
            raise Infra(f"{u.label}: PQsendQueryParams failed for {sql!r}")

    def read(sql):
        res = lib.PQgetResult(conn)
        if not res:
            raise Infra(f"{u.label}: no pipeline result for {sql!r}")
        out = describe(res)
        lib.PQclear(res)
        if lib.PQgetResult(conn):
            raise Infra(f"{u.label}: more than one result for {sql!r}")
        return out

    lines = []
    first, rest = (statements[:pause[0]], statements[pause[0]:]) if pause else (statements, [])
    for sql in first:
        send(sql)
    if pause:
        if lib.PQsendFlushRequest(conn) != 1 or lib.PQflush(conn) != 0:
            raise Infra(f"{u.label}: flush request failed")
        for sql in first:
            lines.append(f"{sql} => {read(sql)}")
        lines.append(pause[1]())
        first = []
    for sql in rest:
        send(sql)
    if lib.PQpipelineSync(conn) != 1:
        raise Infra(f"{u.label}: PQpipelineSync failed")
    for sql in first + rest:
        lines.append(f"{sql} => {read(sql)}")
    # The Sync commits a transaction that is not in a block; an error there
    # arrives before the Sync's own result.
    sync = []
    for _ in range(4):
        res = lib.PQgetResult(conn)
        if not res:
            continue
        sync.append(describe(res))
        done = lib.PQresultStatus(res) == PIPELINE_SYNC
        lib.PQclear(res)
        if done:
            break
    else:
        raise Infra(f"{u.label}: no PIPELINE_SYNC result")
    if lib.PQexitPipelineMode(conn) != 1:
        raise Infra(f"{u.label}: PQexitPipelineMode failed")
    lines.append(f"Sync => {' + '.join(sync)} [{u.txn()}]")
    for line in lines:
        note(f"    [{u.label}] pipeline {line}")
    return lines


def exec_params(u, sql):
    """One statement through the extended protocol, with its own Sync."""
    res = lib.PQexecParams(u.conn, sql.encode(), 0, None, None, None, None, 0)
    out = describe(res)
    lib.PQclear(res)
    note(f"    [{u.label}] PQexecParams {sql}\n        => {out}")
    return out


def pipeline_transcript(db, role, statements, marker_after=None, setup=()):
    a = admin(db, f"writer-{db}")
    # The label is the application_name; SHOW application_name must match.
    u = Conn("pipeline", role, db)
    for sql in setup:
        must(u, sql)
    pause = None
    if marker_after is not None:
        def commit_marker():
            must(a, "INSERT INTO public.tx_rows VALUES (902)")
            return "@marker committed by another session"
        pause = (marker_after, commit_marker)
    lines = pipeline(u, statements, pause)
    count = value(a, "SELECT count(*) FROM public.tx_rows")
    u.close()
    a.close()
    # Row counts differ between databases; report whether the first data
    # SELECT saw the marker instead.
    return [line.replace(f"OK rows=1: {count}", "OK rows=1: <all rows, marker included>") for line in lines]


def pipeline_against_native(c, statements, native_expect, marker_after=None, setup=()):
    native = pipeline_transcript(NATIVE, SEQ, statements, marker_after, setup)
    note("    native pipeline:\n        " + "\n        ".join(native))
    for index, want in native_expect:
        if want not in native[index]:
            raise Infra(f"native pipeline step {index} is {native[index]!r}, expected {want!r}")
    firewall = pipeline_transcript(DB, SEQ, statements, marker_after, setup)
    note("    firewall pipeline:\n        " + "\n        ".join(firewall))
    c.equal("same number of results", len(firewall), len(native))
    for index, (n, f) in enumerate(zip(native, firewall)):
        c.equal(f"pipeline result {index} as native", f, n)
    return " / ".join(native)


PIPELINES = {
    "show_begin_set_commit": (
        ["SHOW application_name", "BEGIN", "SHOW application_name", REPEATABLE, "COMMIT"], {},
        [(3, f"{REPEATABLE} => OK"), (4, "COMMIT => OK"), (5, "SYNC [idle]")]),
    "begin_show_set_commit": (
        ["BEGIN", "SHOW application_name", REPEATABLE, "COMMIT"], {},
        [(2, f"{REPEATABLE} => OK"), (4, "SYNC [idle]")]),
    "show_set": (
        ["SHOW application_name", REPEATABLE], {},
        [(1, f"{REPEATABLE} => OK"), (2, "SYNC [idle]")]),
    "show_begin_isolation": (
        ["SHOW application_name", "BEGIN ISOLATION LEVEL REPEATABLE READ", "SHOW transaction_isolation", "COMMIT"], {},
        [(1, "=> OK"), (2, "repeatable read"), (4, "SYNC [idle]")]),
    # Default REPEATABLE READ: the first data SELECT takes the transaction's
    # snapshot. A second session commits after the SHOW has run in the same
    # server transaction and before the SELECT is sent.
    "first_snapshot_after_show": (
        ["SHOW application_name", "SELECT count(*) FROM public.tx_rows", "SHOW transaction_isolation"],
        {"marker_after": 1, "setup": ("SET default_transaction_isolation = 'repeatable read'",)},
        [(2, "marker included"), (3, "repeatable read"), (4, "SYNC [idle]")]),
    "begin_show_first_snapshot": (
        ["BEGIN ISOLATION LEVEL REPEATABLE READ", "SHOW application_name", "SELECT count(*) FROM public.tx_rows",
         "COMMIT"],
        {"marker_after": 2},
        [(3, "marker included"), (5, "SYNC [idle]")]),
}


def pipeline_records(c):
    a = admin(DB, "pipeline-records")
    u = Conn("pipeline-records", SEQ, DB)
    got = pipeline(u, [show("qa_pipe_single")])
    c.equal("SHOW then Sync", got[-1], "Sync => SYNC [idle]")
    c.equal("row committed at Sync, once", rows_for(a, "qa_pipe_single"), "SHOW:ALLOWED")
    got = pipeline(u, [show("qa_pipe_before_error"), "SELECT 1/0", show("qa_pipe_after_error")])
    c.equal("failing statement", got[1].split(" => ")[1][:9], "ERR 22012")
    c.equal("queued statement after the error", got[2].split(" => ")[1], "ABORTED")
    c.equal("Sync after the error", got[-1], "Sync => SYNC [idle]")
    c.equal("decision recorded for the statement before the error, none for the aborted one",
            rows_for(a, "qa_pipe_before_error") + "|" + rows_for(a, "qa_pipe_after_error"), "SHOW:ALLOWED|")
    got = pipeline(u, [show("qa_pipe_recovered"), "SELECT 1"])
    c.equal("next pipeline", [line.split(" => ")[1] for line in got], ["OK rows=1: 4MB", "OK rows=1: 1", "SYNC [idle]"])
    c.equal("recovered row once", rows_for(a, "qa_pipe_recovered"), "SHOW:ALLOWED")
    got = pipeline(u, [show("qa_pipe_top"), "BEGIN", show("qa_pipe_block"), "SAVEPOINT qa_pipe_s",
                       show("qa_pipe_rolled"), "ROLLBACK TO SAVEPOINT qa_pipe_s", "COMMIT"])
    c.equal("pipeline with BEGIN and a savepoint", [line.split(" => ")[1] for line in got][-2:], ["OK", "SYNC [idle]"])
    for marker, want in (("qa_pipe_top", "SHOW:ALLOWED"), ("qa_pipe_block", "SHOW:ALLOWED"), ("qa_pipe_rolled", "SHOW:ALLOWED")):
        c.equal(f"rows for {marker}", rows_for(a, marker), want)
    c.equal("PQexecParams SHOW", exec_params(u, show("qa_pipe_exec_params")), "OK rows=1: 4MB")
    c.equal("PQexecParams row once", rows_for(a, "qa_pipe_exec_params"), "SHOW:ALLOWED")
    n = Conn("pipeline-unapproved", NOSHOW, DB)
    got = pipeline(n, ["SET application_name = 'qa_pipe_denied'", "SHOW work_mem", "SET application_name = 'qa_pipe_after'"])
    c.expect("unapproved SHOW in a pipeline", got[1].split(" => ")[1].rsplit(" (status", 1)[0], "norule", NOSHOW, "SHOW")
    c.equal("queued statement after the rejection", got[2].split(" => ")[1], "ABORTED")
    c.equal("Sync after the rejection", got[-1], "Sync => SYNC [idle]")
    c.expect("session usable", n.q("SELECT count(*) FROM public.tx_rows"), "allow", NOSHOW, "SELECT")
    c.equal("application_name unchanged by the aborted pipeline", n.q("SELECT current_setting('application_name')"),
            "OK rows=1: qa_pc_pipeline-unapproved")
    return "a pipelined SHOW was recorded once; after an error the executed statement's decision stayed recorded and the aborted one never ran; the session recovered; BEGIN, savepoint rollback (the rolled-back SHOW's decision kept), PQexecParams, and a rejected SHOW behaved as documented"


def comment_records(c):
    a = admin(DB, "comment-records")
    u = Conn("comment-records", SEQ, DB)
    messages = {
        "qa_cmt_cr": f"{show('qa_cmt_cr')}; -- comment{CR}{REPEATABLE};",
        "qa_cmt_lf": f"{show('qa_cmt_lf')}; -- comment{LF}{REPEATABLE};",
        "qa_cmt_crlf": f"{show('qa_cmt_crlf')}; -- comment{CR}{LF}{REPEATABLE};",
        "qa_cmt_nested": f"{show('qa_cmt_nested')}; /* a /* b */ c */ {REPEATABLE};",
        "qa_cmt_trailing": f"{show('qa_cmt_trailing')}; SHOW work_mem; -- trailing",
    }
    raw = messages["qa_cmt_cr"].encode()
    c.equal("CR message carries byte 0x0d and no backslash", (b"\x0d" in raw, b"\\" in raw), (True, False))
    for marker, message in messages.items():
        want = "OK rows=1: 4MB" if marker == "qa_cmt_trailing" else "OK"
        c.equal(f"message {marker}", u.q(message), want)
        c.equal(f"rows for {marker}", rows_for(a, marker), "SHOW:ALLOWED")
    return "each message (comment ended by CR, LF, CRLF, a nested comment, or a trailing comment) ran as natively and recorded its SHOW once"


def commit_point_portal(c):
    """No hidden portal: CLOSE ALL inside a savepoint and a client cursor
    named like the portal earlier builds registered behave as natively, and
    every statement's decision is recorded once."""
    a = admin(DB, "commit-point")
    u = Conn("commit-point", SEQ, DB)
    steps = ["BEGIN", show("qa_cp_top"), "SAVEPOINT qa_cp_s", "CLOSE ALL", "ROLLBACK TO SAVEPOINT qa_cp_s",
             "RELEASE SAVEPOINT qa_cp_s", "COMMIT"]
    for step in steps:
        c.equal(step[:40], u.q(step).split(":")[0], "OK rows=1" if step.startswith("SHOW") else "OK")
    c.equal("SHOW row", rows_for(a, "qa_cp_top"), "SHOW:ALLOWED")
    c.equal("SAVEPOINT row", activity(a, "SAVEPOINT qa_cp_s"), "ALLOWED/SAVEPOINT")
    c.equal("CLOSE ALL row kept after its savepoint rolled back", activity(a, "CLOSE ALL"), "ALLOWED/OTHER")
    held = '"sql_firewall deferred activity 0"'
    c.equal("client cursor WITH HOLD using the old portal name", u.q(f"DECLARE {held} CURSOR WITH HOLD FOR SELECT 1"), "OK")
    for step in ("BEGIN", show("qa_cp_named")):
        u.q(step)
    c.equal("only the client cursor is listed", u.q("SELECT string_agg(name, ',') FROM pg_cursors"),
            "OK rows=1: sql_firewall deferred activity 0")
    c.equal("COMMIT", u.q("COMMIT"), "OK")
    c.equal("row recorded", rows_for(a, "qa_cp_named"), "SHOW:ALLOWED")
    c.equal("client cursor still open", u.q(f"FETCH 1 FROM {held}"), "OK rows=1: 1")
    c.equal("CLOSE", u.q(f"CLOSE {held}"), "OK")
    return "CLOSE ALL inside a rolled-back savepoint and a client WITH HOLD cursor with the old portal name behaved natively; pg_cursors listed only the client's cursor; each decision was recorded once"


def session_authorization_attribution(c):
    """A record names the role whose policy decided the statement: the
    current role when it was inspected (README 6.1a)."""
    a = admin(DB, "attribution-reader")
    s = admin(DB, "attribution")
    for sql in ("SET sql_firewall.mode = 'learn'", "SET sql_firewall.allow_superuser_auth_bypass = off"):
        must(s, sql)
    switch, back = f"SET SESSION AUTHORIZATION {SEQ}", "RESET SESSION AUTHORIZATION"
    c.equal(switch, s.q(switch), "OK")
    c.equal(back, s.q(back), "OK")
    s.close()

    def roles(statement):
        sync_activity(a)
        return value(a, "SELECT coalesce(string_agg(DISTINCT role_name, ','), '') FROM public.sql_firewall_activity_log "
                        f"WHERE query_text = {lit(statement)}")
    c.equal("SET SESSION AUTHORIZATION: attributed to the superuser that ran it", roles(switch), SU)
    c.equal("RESET SESSION AUTHORIZATION: attributed to the role that ran it", roles(back), SEQ)
    return f"with superuser bypass off, {switch} was recorded as {SU}, who ran it, and {back} as {SEQ}"


def denied_utilities(c):
    u = Conn("unapproved-utilities", DENIED, DB)
    for statement, command in (("SHOW work_mem", "SHOW"), ("SET work_mem = '5MB'", "SET"),
                               ("SAVEPOINT qa_denied", "SAVEPOINT")):
        c.equal("BEGIN", u.q("BEGIN"), "OK")
        c.expect(f"unapproved {command} in a transaction block", u.q(statement), "norule", DENIED, command)
        c.equal(f"ROLLBACK after {command}", u.q("ROLLBACK"), "OK")
    c.expect("session usable", u.q("SELECT count(*) FROM public.tx_rows"), "allow", DENIED, "SELECT")
    return "unapproved SHOW, SET, and SAVEPOINT in a transaction block are rejected with 42501; ROLLBACK recovers"


def denied_in_savepoint(c):
    a = admin(DB, "writer")
    u = Conn("no-SHOW", NOSHOW, DB)
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("SAVEPOINT", u.q("SAVEPOINT qa_s5"), "OK")
    c.expect("unapproved SHOW inside a savepoint", u.q("SHOW work_mem"), "norule", NOSHOW, "SHOW")
    c.equal("ROLLBACK TO SAVEPOINT", u.q("ROLLBACK TO SAVEPOINT qa_s5"), "OK")
    c.equal("RELEASE SAVEPOINT", u.q("RELEASE SAVEPOINT qa_s5"), "OK")
    must(a, "INSERT INTO public.tx_rows VALUES (901)")
    count = value(a, "SELECT count(*) FROM public.tx_rows")
    c.equal("SET TRANSACTION after the rejected SHOW was rolled back", u.q(REPEATABLE), "OK")
    c.equal("first data snapshot", u.q("SELECT count(*) FROM public.tx_rows"), f"OK rows=1: {count}")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    return "a SHOW rejected inside a savepoint left no snapshot: after ROLLBACK TO and RELEASE, SET TRANSACTION succeeded and the first SELECT saw a row committed after the rejection"


def regex_utility(c):
    a = admin(DB, "regex-policy")
    must(a, "INSERT INTO public.sql_firewall_regex_rules(pattern, description, allowed_roles) "
            "VALUES ('qa_tx_regex_set', 'qa_txstart_utility', ARRAY['other_role'])")
    u = Conn("regex-SET", SEQ, DB)
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("regex block of SET", u.q("SET application_name = 'qa_tx_regex_set'"), REGEX_BLOCK)
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("SAVEPOINT", u.q("SAVEPOINT qa_s6"), "OK")
    c.equal("regex block of SET inside a savepoint", u.q("SET application_name = 'qa_tx_regex_set'"), REGEX_BLOCK)
    c.equal("ROLLBACK TO SAVEPOINT", u.q("ROLLBACK TO SAVEPOINT qa_s6"), "OK")
    c.equal("RELEASE SAVEPOINT", u.q("RELEASE SAVEPOINT qa_s6"), "OK")
    c.equal("SET TRANSACTION after the regex rejection", u.q(REPEATABLE), "OK")
    c.equal("regex timeout restored", u.q("SHOW statement_timeout"), "OK rows=1: 0")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    c.equal("application_name unchanged", u.q("SHOW application_name"), "OK rows=1: qa_pc_regex-SET")
    must(a, "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa_txstart_utility'")
    return "a regex rule still rejects SET in a transaction block and inside a savepoint; after recovery SET TRANSACTION succeeds and statement_timeout is the session's"


def causes(c):
    a = admin(DB, "cause-policy")
    rows = []
    for name, activity, regex_scan, mode, warm in CAUSES:
        role = f"qa_tx_cause_{name}"
        u = Conn(f"cause-{name}", role, DB)
        if warm:
            # Caches the SHOW approval; this SHOW has another fingerprint.
            for statement in ("BEGIN", "SHOW work_mem", "ROLLBACK"):
                if u.q(statement) != ("OK rows=1: 4MB" if statement.startswith("SHOW") else "OK"):
                    raise Infra(f"{name}: warm-up {statement} failed")
        else:
            # A committed approval write makes this database's cached approvals unusable.
            must(a, f"SELECT sql_firewall_approve_command('{UNRELATED}', 'SELECT')")
        got = (u.q("BEGIN"), u.q("SHOW transaction_isolation"), u.q(REPEATABLE), u.q("ROLLBACK"))
        rows.append(f"{name} (activity={activity}, regex={regex_scan}, mode={mode}, cached={warm}): {got[2]}")
        c.equal(f"{name}: BEGIN, SHOW, SET TRANSACTION, ROLLBACK", got,
                ("OK", "OK rows=1: read committed", "OK", "OK"))
        u.close()
    return "; ".join(rows)


def activity(conn, statement):
    sync_activity(conn)
    return value(conn, "SELECT coalesce(string_agg(action || '/' || command_type, ',' ORDER BY log_id), '') "
                       f"FROM public.sql_firewall_activity_log WHERE query_text = {lit(statement)}")


def activity_commit(c):
    a = admin(DB, "activity")
    u = Conn("activity-commit", SEQ, DB)
    show, sp, rel = "SHOW /* qa_act_commit */ work_mem", "SAVEPOINT qa_act_sp", "RELEASE SAVEPOINT qa_act_sp"
    select = "SELECT count(*) /* qa_act_commit */ FROM public.tx_rows"
    for statement in ("BEGIN", show, sp, rel, REPEATABLE):
        c.equal(statement, u.q(statement).split(":")[0], "OK rows=1" if statement == show else "OK")
    before = activity(a, show)
    c.equal("SHOW decision recorded before COMMIT (the worker writes it)", before, "ALLOWED/SHOW")
    c.equal(select, u.q(select).split(":")[0], "OK rows=1")
    c.equal("COMMIT", u.q("COMMIT"), "OK")
    for statement, want in ((show, "ALLOWED/SHOW"), (sp, "ALLOWED/SAVEPOINT"), (rel, "ALLOWED/RELEASE"),
                            (select, "ALLOWED/SELECT")):
        c.equal(f"activity rows for {statement!r}", activity(a, statement), want)
    c.equal("SET TRANSACTION recorded for this role",
            value(a, f"SELECT count(*) > 0 FROM public.sql_firewall_activity_log WHERE role_name = {lit(SEQ)} AND query_text = {lit(REPEATABLE)}"), "t")
    return "one ALLOWED row each for SHOW (already before COMMIT), SAVEPOINT, RELEASE, SET TRANSACTION, and the SELECT; the transaction's isolation applied as natively"


def activity_rollbacks(c):
    a = admin(DB, "activity")
    u = Conn("activity-rollback", SEQ, DB)
    rolled = "SHOW /* qa_act_rollback */ work_mem"
    for statement in ("BEGIN", rolled, REPEATABLE, "SELECT 1", "ROLLBACK"):
        u.q(statement)
    c.equal("ROLLBACK: the decision stays recorded", activity(a, rolled), "ALLOWED/SHOW")
    inner, kept = "SHOW /* qa_act_sp_rolled */ work_mem", "SHOW /* qa_act_sp_kept */ work_mem"
    for statement in ("BEGIN", "SAVEPOINT qa_act_s", inner, "ROLLBACK TO SAVEPOINT qa_act_s",
                      "RELEASE SAVEPOINT qa_act_s", kept):
        if not u.q(statement).startswith("OK"):
            raise Infra(f"{statement} failed")
    c.equal("COMMIT with no data statement", u.q("COMMIT"), "OK")
    c.equal("rolled-back savepoint: the decision stays recorded", activity(a, inner), "ALLOWED/SHOW")
    c.equal("kept statement: one row", activity(a, kept), "ALLOWED/SHOW")
    failed = "SHOW /* qa_act_error */ work_mem"
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal(failed, u.q(failed).split(":")[0], "OK rows=1")
    c.equal("failing statement", u.q("SELECT 1/0").split(" ")[1], "22012")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    c.equal("transaction ended by an error: the decision stays recorded", activity(a, failed), "ALLOWED/SHOW")
    c.expect("session usable", u.q("SELECT count(*) FROM public.tx_rows"), "allow", SEQ, "SELECT")
    return "each allowed statement's decision was recorded once, also after ROLLBACK, ROLLBACK TO SAVEPOINT, or an error ended its transaction (README 6.7)"


def activity_commit_inside_savepoint(c):
    """A SAVEPOINT recorded before the first snapshot, followed only by
    statements inside that savepoint, is recorded once."""
    a = admin(DB, "activity")
    u = Conn("activity-commit-in-savepoint", SEQ, DB)
    sp = "SAVEPOINT qa_act_open"
    select = "SELECT count(*) /* qa_act_in_savepoint */ FROM public.tx_rows"
    for statement in ("BEGIN", sp, select, "COMMIT"):
        c.equal(statement, u.q(statement).split(":")[0], "OK rows=1" if statement == select else "OK")
    c.equal("SAVEPOINT row", activity(a, sp), "ALLOWED/SAVEPOINT")
    c.equal("SELECT row", activity(a, select), "ALLOWED/SELECT")
    return "a SAVEPOINT recorded at the top level before the first snapshot, followed only by statements inside that savepoint, was recorded once"


def show(marker, pad=0):
    """A SHOW whose text carries marker and, optionally, pad bytes of comment."""
    return f"SHOW /* {marker}{' ' + 'x' * pad if pad else ''} */ work_mem"


def rows_for(conn, marker):
    sync_activity(conn)
    return value(conn, "SELECT coalesce(string_agg(command_type || ':' || action, ',' ORDER BY log_id), '') "
                       f"FROM public.sql_firewall_activity_log WHERE strpos(query_text, {lit(marker)}) > 0")


def prepared(conn, gid):
    return value(conn, f"SELECT count(*) FROM pg_prepared_xacts WHERE gid = {lit(gid)}")


def rejected_records(a):
    return int(value(a, "SELECT activity_records_rejected FROM public.sql_firewall_queue_statistics()"))


def deferred_constraint(c):
    """A deferred constraint trigger on the activity table runs in the
    worker's transaction, not the client's (README 6.7): the client's COMMIT,
    PREPARE TRANSACTION, implicit block, single statement, and Sync succeed
    as natively, and the worker skips and counts each record the constraint
    rejects."""
    a = admin(DB, "constraint")
    must(a, "CREATE FUNCTION public.qa_tx_activity_check() RETURNS trigger LANGUAGE plpgsql AS $f$ "
            "BEGIN IF strpos(NEW.query_text, 'qa_deferred_failure') > 0 THEN "
            "RAISE EXCEPTION 'qa_deferred_failure rejected' USING ERRCODE = '23514'; END IF; RETURN NULL; END $f$")
    must(a, "CREATE CONSTRAINT TRIGGER qa_tx_activity_check AFTER INSERT ON public.sql_firewall_activity_log "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.qa_tx_activity_check()")
    try:
        u = Conn("deferred-constraint", SEQ, DB)
        before = rejected_records(a)
        cases = (
            ("data statement before COMMIT", "qa_deferred_failure_control", ["BEGIN", "@show", "SELECT 1", "COMMIT"], "OK"),
            ("COMMIT inside a savepoint", "qa_deferred_failure_commit", ["BEGIN", "@show", "SAVEPOINT qa_inner", "COMMIT"], "OK"),
            ("COMMIT with no other statement", "qa_deferred_failure_commit_only", ["BEGIN", "@show", "COMMIT"], "OK"),
            ("COMMIT AND CHAIN", "qa_deferred_failure_chain", ["BEGIN", "@show", "COMMIT AND CHAIN", "COMMIT"], "OK"),
        )
        for label, marker, steps, want in cases:
            outcome = [u.q(show(marker) if step == "@show" else step) for step in steps]
            c.equal(f"{label}: final statement", outcome[-1], want)
            c.equal(f"{label}: transaction ended", u.txn(), "idle")
        for step in ("BEGIN", show("qa_deferred_failure_prepare"), "SAVEPOINT qa_inner", "PREPARE TRANSACTION 'qa_tx_prepare_fail'"):
            u.q(step)
        c.equal("PREPARE TRANSACTION inside a savepoint: prepared", prepared(a, "qa_tx_prepare_fail"), "1")
        must(a, "COMMIT PREPARED 'qa_tx_prepare_fail'")
        c.equal("implicit block", u.q(f"{show('qa_deferred_failure_implicit')}; SHOW work_mem"), "OK rows=1: 4MB")
        c.equal("single statement", u.q(show("qa_deferred_failure_single")), "OK rows=1: 4MB")
        got = pipeline(u, [show("qa_deferred_failure_pipeline"), "SHOW work_mem"])
        c.equal("pipeline Sync", got[-1], "Sync => SYNC [idle]")
        c.equal("implicit block without a rejected row", u.q(f"{show('qa_deferred_accepted')}; SHOW work_mem"), "OK rows=1: 4MB")
        c.equal("accepted row recorded", rows_for(a, "qa_deferred_accepted"), "SHOW:ALLOWED")
        c.equal("rejected records: none written", rows_for(a, "qa_deferred_failure"), "")
        c.equal("rejected records: skipped and counted by the worker", rejected_records(a) - before, 8)
    finally:
        if prepared(a, "qa_tx_prepare_fail") != "0":
            must(a, "ROLLBACK PREPARED 'qa_tx_prepare_fail'")
        must(a, "DROP TRIGGER qa_tx_activity_check ON public.sql_firewall_activity_log")
        must(a, "DROP FUNCTION public.qa_tx_activity_check()")
    return "with a deferred constraint rejecting some activity rows, the clients' COMMIT (also inside a savepoint and AND CHAIN), PREPARE TRANSACTION, implicit block, single statement, and Sync succeeded as natively; the worker skipped the 8 rejected records, counted them in activity_records_rejected, and wrote the accepted one"


def prepared_outcomes(c):
    a = admin(DB, "prepared")
    u = Conn("prepared", SEQ, DB)
    try:
        for step in ("BEGIN", show("qa_prep_commit"), "SAVEPOINT qa_prep_sp", "PREPARE TRANSACTION 'qa_tx_prep_commit'"):
            c.equal(step, u.q(step).split(":")[0], "OK rows=1" if step.startswith("SHOW") else "OK")
        c.equal("decision recorded while prepared", rows_for(a, "qa_prep_commit"), "SHOW:ALLOWED")
        c.equal("prepared", prepared(a, "qa_tx_prep_commit"), "1")
        c.equal("COMMIT PREPARED", u.q("COMMIT PREPARED 'qa_tx_prep_commit'"), "OK")
        c.equal("once after COMMIT PREPARED", rows_for(a, "qa_prep_commit"), "SHOW:ALLOWED")
        c.equal("SAVEPOINT row", activity(a, "SAVEPOINT qa_prep_sp"), "ALLOWED/SAVEPOINT")
        for step in ("BEGIN", show("qa_prep_rollback"), "PREPARE TRANSACTION 'qa_tx_prep_rollback'"):
            c.equal(step, u.q(step).split(":")[0], "OK rows=1" if step.startswith("SHOW") else "OK")
        c.equal("ROLLBACK PREPARED", u.q("ROLLBACK PREPARED 'qa_tx_prep_rollback'"), "OK")
        c.equal("kept after ROLLBACK PREPARED", rows_for(a, "qa_prep_rollback"), "SHOW:ALLOWED")
    finally:
        for gid in ("qa_tx_prep_commit", "qa_tx_prep_rollback"):
            if prepared(a, gid) != "0":
                must(a, f"ROLLBACK PREPARED '{gid}'")
    return "decisions made before PREPARE TRANSACTION were recorded once, whether the prepared transaction was committed or rolled back"


def ownership(c):
    """Decisions inside nested savepoints are recorded once each, whatever
    happens to the savepoints."""
    a = admin(DB, "ownership")
    u = Conn("ownership", SEQ, DB)
    steps = ["BEGIN", show("qa_own_parent"), "SAVEPOINT qa_own_a", show("qa_own_child_kept"),
             "SAVEPOINT qa_own_b", show("qa_own_child_rolled"), "ROLLBACK TO SAVEPOINT qa_own_b",
             "RELEASE SAVEPOINT qa_own_b", "RELEASE SAVEPOINT qa_own_a", "COMMIT"]
    for step in steps:
        c.equal(step[:40], u.q(step).split(":")[0], "OK rows=1" if step.startswith("SHOW") else "OK")
    for marker, want in (("qa_own_parent", "SHOW:ALLOWED"), ("qa_own_child_kept", "SHOW:ALLOWED"),
                         ("qa_own_child_rolled", "SHOW:ALLOWED")):
        c.equal(f"rows for {marker}", rows_for(a, marker), want)
    for statement, want in (("SAVEPOINT qa_own_a", "ALLOWED/SAVEPOINT"), ("SAVEPOINT qa_own_b", "ALLOWED/SAVEPOINT"),
                            ("ROLLBACK TO SAVEPOINT qa_own_b", ""), ("RELEASE SAVEPOINT qa_own_b", "ALLOWED/RELEASE"),
                            ("RELEASE SAVEPOINT qa_own_a", "ALLOWED/RELEASE")):
        c.equal(f"rows for {statement!r}", activity(a, statement), want)
    return "the parent's, the released child's, and the rolled-back child's decisions once each; ROLLBACK TO SAVEPOINT, which is not inspected, has none"


def failed_flush(c):
    """A trigger that rejects some activity rows fails nothing in the client:
    the worker skips and counts those records and writes the others."""
    a = admin(DB, "failed-flush")
    must(a, "CREATE FUNCTION public.qa_tx_activity_fail() RETURNS trigger LANGUAGE plpgsql AS $f$ "
            "BEGIN IF strpos(NEW.query_text, 'qa_flush_fail') > 0 THEN "
            "RAISE EXCEPTION 'qa_flush_fail rejected' USING ERRCODE = 'QAF01'; END IF; RETURN NEW; END $f$")
    must(a, "CREATE TRIGGER qa_tx_activity_fail BEFORE INSERT ON public.sql_firewall_activity_log "
            "FOR EACH ROW EXECUTE FUNCTION public.qa_tx_activity_fail()")
    try:
        u = Conn("failed-flush", SEQ, DB)
        before = rejected_records(a)
        steps = ["BEGIN", "SAVEPOINT qa_ff_s", show("qa_flush_fail_inner"), "SELECT 1",
                 "ROLLBACK TO SAVEPOINT qa_ff_s", show("qa_ff_after"), "SELECT 2", "COMMIT"]
        got = [u.q(step) for step in steps]
        c.equal("data statement after the rejected record", got[3], "OK rows=1: 1")
        c.equal("COMMIT", got[7], "OK")
        got = [u.q(step) for step in ("BEGIN", show("qa_flush_fail_commit"), "SAVEPOINT qa_ff_c", "COMMIT")]
        c.equal("COMMIT with a rejected record", got[3], "OK")
        c.equal("single statement with a rejected record", u.q(show("qa_flush_fail_single")), "OK rows=1: 4MB")
        c.equal("rejected rows absent", rows_for(a, "qa_flush_fail"), "")
        c.equal("later row once", rows_for(a, "qa_ff_after"), "SHOW:ALLOWED")
        c.equal("savepoint row once", activity(a, "SAVEPOINT qa_ff_s"), "ALLOWED/SAVEPOINT")
        c.equal("rejected records skipped and counted", rejected_records(a) - before, 3)
        for step in ("BEGIN", show("qa_ff_recovered"), REPEATABLE, "SELECT 3", "COMMIT"):
            c.equal(f"afterwards: {step[:30]}", u.q(step).split(":")[0], "OK rows=1" if step.startswith(("SHOW", "SELECT")) else "OK")
        c.equal("later transaction recorded once", rows_for(a, "qa_ff_recovered"), "SHOW:ALLOWED")
    finally:
        must(a, "DROP TRIGGER qa_tx_activity_fail ON public.sql_firewall_activity_log")
        must(a, "DROP FUNCTION public.qa_tx_activity_fail()")
    return "a trigger rejecting activity rows failed no client statement or COMMIT; the worker skipped the 3 rejected records, counted them, and wrote every other record once"


def chained_records(c):
    a = admin(DB, "chain")
    u = Conn("chain", SEQ, DB)
    for step in ("BEGIN", show("qa_chain_a"), "COMMIT AND CHAIN", show("qa_chain_b"), REPEATABLE, "COMMIT",
                 "BEGIN", show("qa_chain_c"), "ROLLBACK AND CHAIN", show("qa_chain_d"), REPEATABLE, "COMMIT"):
        c.equal(step[:40], u.q(step).split(":")[0], "OK rows=1" if step.startswith("SHOW") else "OK")
    for marker, want in (("qa_chain_a", "SHOW:ALLOWED"), ("qa_chain_b", "SHOW:ALLOWED"), ("qa_chain_c", "SHOW:ALLOWED"),
                         ("qa_chain_d", "SHOW:ALLOWED")):
        c.equal(f"rows for {marker}", rows_for(a, marker), want)
    return "COMMIT AND CHAIN and ROLLBACK AND CHAIN kept every decision of both blocks once"


def vmrss(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unavailable"


def capacity_bytes(c):
    """No per-transaction limit: large statements are allowed and recorded
    with their text cut at the queue's field size on a character boundary."""
    a = admin(DB, "capacity")
    u = Conn("capacity-bytes", SEQ, DB)
    pid = u.q("SELECT pg_backend_pid()").split(": ", 1)[1]
    note(f"    backend {pid} VmRSS before: {vmrss(pid)}")
    for step in ("BEGIN", show("qa_cap_first", 700 * 1024), show("qa_cap_second", 400 * 1024), "COMMIT"):
        c.equal(step[:30], u.q(step).split(":")[0], "OK rows=1" if step.startswith("SHOW") else "OK")
    note(f"    backend {pid} VmRSS after: {vmrss(pid)}")
    c.equal("single statement of 1.1 MB", u.q(show("qa_cap_single", 1100 * 1024)).split(":")[0], "OK rows=1")
    sync_activity(a)
    for marker in ("qa_cap_first", "qa_cap_second", "qa_cap_single"):
        c.equal(f"{marker}: recorded once, truncated to {ACTIVITY_TEXT_BYTES} bytes",
                value(a, f"SELECT count(*) || ':' || bool_and(query_truncated) || ':' || max(octet_length(query_text)) "
                         f"FROM public.sql_firewall_activity_log WHERE strpos(query_text, {lit(marker)}) > 0"),
                f"1:true:{ACTIVITY_TEXT_BYTES}")
    return "statements of 700 kB, 400 kB, and 1.1 MB were allowed as natively (no 54000) and recorded once each with the text cut to 2047 bytes and query_truncated set"


def capacity_rows(c):
    """No per-transaction record limit."""
    a = admin(DB, "capacity")
    u = Conn("capacity-rows", SEQ, DB)
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    failures = [i for i in range(MANY_RECORDS) if not u.q(show(f"qa_cap_row_{i}_")).startswith("OK")]
    c.equal(f"{MANY_RECORDS} SHOW statements in one transaction", failures, [])
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    sync_activity(a)
    c.equal("every decision recorded once",
            value(a, "SELECT count(*) FROM public.sql_firewall_activity_log WHERE strpos(query_text, 'qa_cap_row_') > 0"),
            str(MANY_RECORDS))
    return f"{MANY_RECORDS} statements before the first snapshot of one transaction were allowed (no 54000) and each decision recorded once, although the transaction rolled back"


def capacity_savepoints(c):
    u = Conn("capacity-savepoints", SEQ, DB)
    steps = [("BEGIN", "OK"), ("SAVEPOINT qa_cap_s", "OK"), (show("qa_cap_sp_a", 700 * 1024), "OK rows=1"),
             ("ROLLBACK TO SAVEPOINT qa_cap_s", "OK"), (show("qa_cap_sp_b", 700 * 1024), "OK rows=1"),
             ("RELEASE SAVEPOINT qa_cap_s", "OK"), (show("qa_cap_sp_c", 400 * 1024), "OK rows=1"), ("ROLLBACK", "OK")]
    for step, want in steps:
        c.equal(step[:40], u.q(step).split(":")[0], want)
    return "large statements around ROLLBACK TO and RELEASE ran as natively; nothing is held in the backend"


def capacity_enforcement(c):
    u = Conn("capacity-enforcement", NOSHOW, DB)
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    failures = [i for i in range(MANY_RECORDS) if u.q(f"SET LOCAL application_name = 'qa_cap_{i}'") != "OK"]
    c.equal(f"{MANY_RECORDS} approved SET statements", failures, [])
    c.expect("unapproved SHOW after them", u.q("SHOW work_mem"), "norule", NOSHOW, "SHOW")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    c.expect("session usable", u.q("SELECT count(*) FROM public.tx_rows"), "allow", NOSHOW, "SELECT")
    return f"after {MANY_RECORDS} approved SET statements in one transaction an unapproved SHOW was still the firewall's 42501 rejection"


def capacity_learning(c):
    """A large learn-mode statement in a rolled-back transaction is allowed
    and not learned; a later committed statement is (README 6.1b)."""
    a = admin(DB, "capacity-learning")
    u = Conn("capacity-learning", LEARN_CAPACITY, DB)
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("learn-mode SHOW of 1.1 MB", u.q(show("qa_cap_learn", 1100 * 1024)).split(":")[0], "OK rows=1")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    later = "SELECT count(*) /* qa_cap_learn_later */ FROM public.tx_rows"
    c.equal("later learned statement", u.q(later).split(":")[0], "OK rows=1")
    where = f"role_name = {lit(LEARN_CAPACITY)}"
    deadline = time.time() + 30
    while time.time() < deadline:
        if value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE {where} AND command_type = 'SELECT'") == "1" \
                and value(a, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE {where} AND command_type = 'SELECT'") == "1":
            break
        time.sleep(0.2)
    else:
        raise Infra(f"learning events for {LEARN_CAPACITY} not delivered within 30s")
    c.equal("no SHOW approval learned", value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE {where} AND command_type = 'SHOW'"), "0")
    c.equal("no SHOW fingerprint learned", value(a, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE {where} AND command_type = 'SHOW'"), "0")
    return "a 1.1 MB learn-mode SHOW in a rolled-back transaction was allowed and left no approval or fingerprint; a later committed statement was learned"


def implicit_block_records(c):
    a = admin(DB, "implicit")
    u = Conn("implicit", SEQ, DB)
    c.equal("utilities only", u.q(f"{show('qa_impl_a')}; {show('qa_impl_b')}").split(":")[0], "OK rows=1")
    c.equal("utility then SET TRANSACTION", u.q(f"{show('qa_impl_c')}; {REPEATABLE}"), "OK")
    c.equal("utility, SET TRANSACTION, data", u.q(f"{show('qa_impl_d')}; {REPEATABLE}; SHOW transaction_isolation"), "OK rows=1: repeatable read")
    c.equal("utility then BEGIN", u.q(f"{show('qa_impl_e')}; BEGIN"), "OK")
    c.equal("SET TRANSACTION in the block that BEGIN opened", u.q(REPEATABLE), "OK")
    c.equal("COMMIT", u.q("COMMIT"), "OK")
    c.equal("BEGIN then utility", u.q(f"BEGIN; {show('qa_impl_f')}").split(":")[0], "OK rows=1")
    c.equal("recorded while the block is still open", rows_for(a, "qa_impl_f"), "SHOW:ALLOWED")
    c.equal("SET TRANSACTION in the next message", u.q(REPEATABLE), "OK")
    c.equal("COMMIT", u.q("COMMIT"), "OK")
    for marker in ("qa_impl_a", "qa_impl_b", "qa_impl_c", "qa_impl_d", "qa_impl_e", "qa_impl_f"):
        c.equal(f"rows for {marker}", rows_for(a, marker), "SHOW:ALLOWED")
    return "multi-statement messages ending in a utility or SET TRANSACTION recorded every utility once; SET TRANSACTION after a utility in one message still applied, also in the block a message's BEGIN opened"


def server_log_has(text, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        with open(SERVER_LOG, encoding="utf-8", errors="replace") as log:
            if text in log.read():
                return True
        time.sleep(0.2)
    return False


def activity_read_only(c):
    """Read-only transactions record their decisions in the activity table:
    the worker writes them, not the read-only transaction."""
    a = admin(DB, "activity")
    u = Conn("activity-read-only", SEQ, DB)
    show = "SHOW /* qa_act_read_only */ work_mem"
    for statement in ("BEGIN", show, "SET TRANSACTION READ ONLY"):
        c.equal(statement, u.q(statement).split(":")[0], "OK rows=1" if statement == show else "OK")
    c.equal("first data SELECT in the read-only transaction", u.q("SELECT count(*) FROM public.tx_rows").split(":")[0], "OK rows=1")
    c.equal("COMMIT", u.q("COMMIT"), "OK")
    c.equal("activity row of the read-only transaction", activity(a, show), "ALLOWED/SHOW")
    ro = "SHOW /* qa_act_begin_read_only */ work_mem"
    for statement in ("BEGIN READ ONLY", ro, "COMMIT"):
        u.q(statement)
    c.equal("BEGIN READ ONLY: activity row", activity(a, ro), "ALLOWED/SHOW")
    return "SHOW decisions in a transaction made read-only by SET TRANSACTION READ ONLY and in BEGIN READ ONLY were recorded in the activity table"


def queue_counts(a):
    """(approval_events, fingerprint_events) published cluster-wide so far."""
    out = value(a, "SELECT approval_events || ',' || fingerprint_events FROM public.sql_firewall_queue_statistics()")
    return tuple(int(x) for x in out.split(","))


def sync_worker(a, timeout=30):
    """Wait until DB's worker has passed a canary published now."""
    token = f"qa_tx_canary_{time.time_ns()}"
    c = Conn("canary", "qa_canary", DB)
    try:
        out = c.q(f"SELECT '{token}' AS marker")
    finally:
        c.close()
    if not out.startswith("ERR 42501 sql_firewall: No rule found"):
        raise Infra(f"canary not rejected as expected: {out}")
    deadline = time.time() + timeout
    while value(a, f"SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '{token}') > 0") != "1":
        if time.time() > deadline:
            raise Infra(f"worker did not deliver canary {token} within {timeout}s")
        time.sleep(0.2)


def learning(c, role, end):
    """Learn observations are published when the transaction commits
    (README 6.1b). A rolled-back transaction publishes none: the publication
    counters do not move (this driver is the cluster's only client; the
    canary is a blocked-query event), and after a later canary the catalog
    has no row. The COMMIT case is the positive control."""
    a = admin(DB, "learning")
    u = Conn(f"learn-{end.lower()}", role, DB)
    show = f"SHOW /* {role} */ search_path"
    before = queue_counts(a)
    for statement in ("BEGIN", show, REPEATABLE, "SELECT count(*) FROM public.tx_rows", end):
        c.equal(statement, u.q(statement).split(":")[0], "OK rows=1" if statement.startswith(("SHOW", "SELECT")) else "OK")
    after = queue_counts(a)
    rows = activity(a, show)
    # Decisions are recorded when made, also in a transaction that rolls back.
    c.equal("activity rows", rows, "LEARNED (FINGERPRINT AUTO)/SHOW,ALLOWED (LEARN MODE - AUTO)/SHOW")
    where = f"role_name = {lit(role)} AND command_type = 'SHOW'"
    if end == "ROLLBACK":
        c.equal("no learn event published (approval, fingerprint deltas)", (after[0] - before[0], after[1] - before[1]), (0, 0))
        sync_worker(a)
        c.equal("no SHOW fingerprint", value(a, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE {where}"), "0")
        c.equal("no SHOW approval", value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE {where}"), "0")
        return f"ROLLBACK: the transaction's learn observations were discarded (no publication, no catalog row); its decisions stayed in the activity log: {rows}"
    c.equal("learn events published at COMMIT", after[0] > before[0] and after[1] > before[1], True)
    deadline, fp = time.time() + 30, ""
    while time.time() < deadline:
        fp = value(a, f"SELECT coalesce(string_agg(hit_count || ':' || sample_query, ','), '') FROM public.sql_firewall_query_fingerprints WHERE {where}")
        ap = value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE {where}")
        if fp and ap == "1":
            break
        time.sleep(0.2)
    else:
        raise Infra(f"learning events for {role} not delivered within 30s (fingerprint {fp!r})")
    c.equal("fingerprint row, delivered once", fp, f"1:{show}")
    return f"{end}: the SHOW before SET TRANSACTION was learned once at commit (fingerprint hit_count 1, approval row); activity rows: {rows or 'none'}"



if __name__ == "__main__":
    try:
        setup()
    except Infra as exc:
        print(f"INFRA\tsetup\t{exc}", flush=True)
        raise SystemExit(2)
    run("begin_repeatable_read", "BEGIN with REPEATABLE READ", lambda c: begin_options(c, "BEGIN ISOLATION LEVEL REPEATABLE READ", "repeatable read", "off", 101))
    run("start_serializable_read_only", "START with SERIALIZABLE READ ONLY DEFERRABLE", lambda c: begin_options(c, "START TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY, DEFERRABLE", "serializable", "on", 102))
    run("set_repeatable_read", "BEGIN then SET TRANSACTION REPEATABLE READ", lambda c: set_options(c, "REPEATABLE READ", 103))
    run("set_serializable", "BEGIN then SET TRANSACTION SERIALIZABLE", lambda c: set_options(c, "SERIALIZABLE", 104))
    run("unapproved", "command approval still applies", denied)
    run("regex", "regex policy still applies", regex)
    for name, (steps, expect) in SEQUENCES.items():
        run(f"native.{name}", f"as native PostgreSQL: {name}",
            lambda c, steps=steps, expect=expect: against_native(c, steps, expect))
    for name, (statements, options, expect) in PIPELINES.items():
        run(f"pipeline.{name}", f"extended-protocol pipeline as native PostgreSQL: {name}",
            lambda c, statements=statements, options=options, expect=expect:
            pipeline_against_native(c, statements, expect, **options))
    run("pipeline_records", "activity rows and recovery in extended-protocol pipelines", pipeline_records)
    run("comment_records", "comment endings in simple-query messages", comment_records)
    run("commit_point_portal", "CLOSE ALL and a client portal name", commit_point_portal)
    run("session_authorization", "attribution of a deferred SET SESSION AUTHORIZATION", session_authorization_attribution)
    run("unapproved_utilities", "SHOW, SET, and SAVEPOINT still need approval", denied_utilities)
    run("unapproved_in_savepoint", "a rejected utility inside a savepoint leaves no snapshot", denied_in_savepoint)
    run("regex_utility", "regex policy on SET in a transaction block", regex_utility)
    run("snapshot_causes", "each foreground operation that could take the first snapshot", causes)
    run("activity_commit", "activity rows of deferred utilities at COMMIT", activity_commit)
    run("activity_rollbacks", "activity rows after ROLLBACK, savepoint rollback, and errors", activity_rollbacks)
    run("activity_commit_in_savepoint", "a deferred row still pending at COMMIT", activity_commit_inside_savepoint)
    run("deferred_constraint", "deferred constraint triggers see deferred rows", deferred_constraint)
    run("prepared_outcomes", "COMMIT PREPARED and ROLLBACK PREPARED", prepared_outcomes)
    run("activity_ownership", "nested savepoint ownership", ownership)
    run("failed_flush", "a failed write of deferred rows and recovery", failed_flush)
    run("implicit_block_records", "multi-statement messages", implicit_block_records)
    run("chained_records", "COMMIT AND CHAIN and ROLLBACK AND CHAIN", chained_records)
    run("capacity_bytes", "deferred-record byte limit", capacity_bytes)
    run("capacity_rows", "deferred-record row limit", capacity_rows)
    run("capacity_savepoints", "capacity accounting across savepoints", capacity_savepoints)
    run("capacity_enforcement", "enforcement at capacity", capacity_enforcement)
    run("capacity_learning", "no learning event from a refused statement", capacity_learning)
    run("activity_read_only", "read-only transactions keep the server-log record", activity_read_only)
    run("learning_commit", "learn mode, committed", lambda c: learning(c, LEARN_COMMIT, "COMMIT"))
    run("learning_rollback", "learn mode, rolled back", lambda c: learning(c, LEARN_ROLLBACK, "ROLLBACK"))
