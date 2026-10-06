#!/usr/bin/env python3
"""Phase 8 session policies (qa/tests/108_session_policies.sh; README 6.3,
6.4, 6.6, 6.1c).

Reuses the libpq driver of qa/policy_cache.py. Each scenario has its own
roles, and settings are made per role in the database (ALTER ROLE ... IN
DATABASE), so a new connection of the role runs under exactly them.
"""
import os, threading, time

import policy_cache as pc
from policy_cache import Infra, Conn, admin, must, value, once, run, setup_role, approve, sync_worker

DB, DB2 = os.environ["QA_PC_DB"], os.environ["QA_PC_DB2"]
REGEX_DEADLINE = "ERR 42501 sql_firewall: regex rules could not be evaluated within {ms} ms; the statement is refused."


def role_in(a, role, settings, db=DB, grants=("SELECT",)):
    setup_role(a, role, [db], [f"GRANT SELECT ON public.sp_t TO {role}"] +
               [f"ALTER ROLE {role} IN DATABASE {db} SET {k} = '{v}'" for k, v in settings.items()])
    if grants:
        x = admin(db, label=f"approve-{db}") if db != DB else a
        approve(x, role, *grants)
        if x is not a:
            x.close()


def blocked_rows(a, role, marker):
    sync_worker(a)
    return value(a, f"SELECT count(*) || ':' || coalesce(string_agg(DISTINCT reason, '|'), '') FROM public.sql_firewall_blocked_queries "
                    f"WHERE role_name = '{role}' AND strpos(query_text, '{marker}') > 0")


def timed(conn, sql):
    start = time.monotonic()
    out = conn.q(sql)
    return out, time.monotonic() - start


# ---------------------------------------------------------------------------
# P8-01: regex deadline
# ---------------------------------------------------------------------------
def regex_deadline(c):
    a = admin()
    role, waiter = "qa_sp_rx", "qa_sp_rxwait"
    base = {"sql_firewall.enable_regex_scan": "on", "sql_firewall.mode": "enforce"}
    role_in(a, role, base, grants=("SELECT", "SET", "SHOW", "RESET"))
    role_in(a, waiter, {**base, "sql_firewall.regex_timeout_ms": "5000"}, grants=("SELECT", "SET", "SHOW"))
    u = Conn("regex-app", role, DB)
    c.equal("SET statement_timeout", u.q("SET statement_timeout = '7s'"), "OK")
    c.expect("ordinary statement", u.q("SELECT count(*) FROM public.sp_t"), "allow", role, "SELECT")
    c.equal("the session's statement_timeout is unchanged", u.q("SHOW statement_timeout"), "OK rows=1: 7s")

    # Deadline during a lock wait on the rules: deterministic. The lock is held
    # only around the measured statement: while it is held every statement of
    # a role with regex scan on waits for it and is refused at the deadline.
    locker = admin(label="rules-locker")
    w = Conn("regex-waiter", waiter, DB)
    pid = w.q("SELECT pg_backend_pid()").split(": ", 1)[1]

    def locked(fn):
        must(locker, "BEGIN")
        must(locker, "LOCK TABLE public.sql_firewall_regex_rules IN ACCESS EXCLUSIVE MODE")
        try:
            return fn()
        finally:
            must(locker, "ROLLBACK")

    out, took = locked(lambda: timed(u, "SELECT count(*) /* qa_sp_rx_lock */ FROM public.sp_t"))
    c.equal("lock wait longer than the deadline: refused", out, REGEX_DEADLINE.format(ms=100))
    c.equal(f"refused at the deadline, not at the 7 s statement_timeout ({took:.3f} s)", 0.09 <= took < 2.0, True)
    c.equal("statement_timeout still 7s after the refusal", u.q("SHOW statement_timeout"), "OK rows=1: 7s")
    # The session's own, earlier statement_timeout still fires first.
    c.equal("SET statement_timeout 40ms", u.q("SET statement_timeout = '40ms'"), "OK")
    out, _ = locked(lambda: timed(u, "SELECT count(*) /* qa_sp_rx_own */ FROM public.sp_t"))
    c.equal("an earlier statement_timeout is PostgreSQL's own error", out, "ERR 57014 canceling statement due to statement timeout")
    c.equal("RESET statement_timeout", u.q("RESET statement_timeout"), "OK")

    # A client cancel during the (5 s) regex deadline is the client's cancel.
    def cancel():
        result = {}
        t = threading.Thread(target=lambda: result.setdefault("out", w.q("SELECT count(*) /* qa_sp_rx_cancel */ FROM public.sp_t")))
        t.start()
        deadline = time.time() + 5
        while value(a, f"SELECT count(*) FROM pg_locks WHERE pid = {pid} AND NOT granted") == "0" and time.time() < deadline:
            time.sleep(0.05)
        must(a, f"SELECT pg_cancel_backend({pid})")
        t.join(10)
        return result.get("out")

    c.equal("client cancel during the rules wait", locked(cancel), "ERR 57014 canceling statement due to user request")
    c.expect("after the lock is gone the same statement is allowed", u.q("SELECT count(*) /* qa_sp_rx_lock */ FROM public.sp_t"), "allow", role, "SELECT")
    c.equal("refusal recorded as a blocked query", blocked_rows(a, role, "qa_sp_rx_lock"),
            "1:" + REGEX_DEADLINE.format(ms=100)[10:])

    # A genuinely expensive evaluation: a back-reference rule on a 40 MB
    # statement. The outcome proves the deadline path; end-to-end timing also
    # includes sending and parsing 40 MB and cannot isolate regex time. The
    # regex engine notices a cancel only when its automaton grows, so the
    # evaluation can run past the deadline and finish (no match); it must be
    # refused all the same, every time (before the fix the second statement
    # of a PostgreSQL 17 run was allowed, sqlfw-qa.oVn7NF). The limit is 5 ms,
    # far below any build's time for 40 MB: with 100 ms, an optimized build
    # (PGDG 17) finished the second, warm evaluation in time and rightly
    # allowed it (sqlfw-qa.Z2urDT), so 100 ms did not prove the overrun.
    must(a, "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES "
            "('(a|e|i)[b-z]{3,8}(x|y)\\1', 'qa expensive back-reference rule')")
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.regex_timeout_ms = '5'")
    t = Conn("regex-tight", role, DB)
    big = "SELECT length('" + "abcdefghij" * 4_000_000 + "') /* qa_sp_rx_big */"
    runs = [timed(t, big) for _ in range(2)]
    c.equal("expensive evaluation refused at the deadline", [o for o, _ in runs], [REGEX_DEADLINE.format(ms=5)] * 2)
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.regex_timeout_ms = '60000'")
    v = Conn("regex-generous", role, DB)
    full = [timed(v, big) for _ in range(2)]
    c.equal("with a 60 s limit the same statement completes", [o.split(":")[0] for o, _ in full], ["OK rows=1"] * 2)
    must(a, "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa expensive back-reference rule'")

    # An invalid stored pattern is refused, not skipped.
    must(a, "ALTER TABLE public.sql_firewall_regex_rules DISABLE TRIGGER validate_regex_trigger")
    must(a, "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('(unclosed', 'qa invalid rule')")
    must(a, "ALTER TABLE public.sql_firewall_regex_rules ENABLE TRIGGER validate_regex_trigger")
    out = u.q("SELECT 1 /* qa_sp_rx_invalid */")
    c.equal("invalid rule: statement refused", out.startswith("ERR 42501 sql_firewall: a regex rule could not be evaluated (invalid regular expression"), True)
    must(a, "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa invalid rule'")
    c.expect("after removing it", u.q("SELECT count(*) FROM public.sp_t"), "allow", role, "SELECT")
    for x in (u, w, t, v, locker):
        x.close()
    return (f"a rules lock wait was refused at the 100 ms deadline ({took:.2f} s end to end); "
            f"a 40 MB back-reference evaluation was refused at a 5 ms deadline twice ({runs[0][1]:.2f} s, {runs[1][1]:.2f} s end to end) "
            f"and completed twice with a 60 s limit ({full[0][1]:.2f} s, {full[1][1]:.2f} s); the session's statement_timeout was unchanged, "
            "an earlier one and a client cancel kept PostgreSQL's own 57014 errors; an invalid stored rule refused the statement")


# ---------------------------------------------------------------------------
# Phase 9 (P9-06): the "no active rule" memo (README 6.6). A backend that
# found no active rule skips the evaluation; a commit that changes the rules
# makes it evaluate again at its next statement, also inside an open
# REPEATABLE READ transaction, and with the rules' invalidation triggers
# disabled the memo is not used at all.
# ---------------------------------------------------------------------------
REGEX_MATCH = "ERR 42501 sql_firewall: Query blocked by security regex pattern."


def regex_memo(c):
    a = admin()
    role = "qa_sp_memo"
    role_in(a, role, {"sql_firewall.enable_regex_scan": "on", "sql_firewall.mode": "enforce"}, grants=("SELECT", "BEGIN"))
    active = value(a, "SELECT count(*) FROM public.sql_firewall_regex_rules WHERE is_active")
    if active != "0":
        raise Infra(f"{active} active regex rules exist before the memo scenario")
    rule = "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('qa_memo_marker_[0-9]+', 'qa memo rule')"
    drop = "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa memo rule'"
    u = Conn("memo-app", role, DB)
    c.expect("no active rule: allowed (memo taken)", u.q("SELECT count(*) /* qa_memo_0 */ FROM public.sp_t"), "allow", role, "SELECT")
    c.expect("still allowed with the memo", u.q("SELECT 'qa_memo_marker_0'"), "allow", role, "SELECT")
    must(a, rule)
    c.equal("a rule committed by another session refuses at the next statement", u.q("SELECT 'qa_memo_marker_1'"), REGEX_MATCH)
    must(a, drop)
    c.expect("the rule's removal allows again", u.q("SELECT 'qa_memo_marker_2'"), "allow", role, "SELECT")

    c.equal("BEGIN ISOLATION LEVEL REPEATABLE READ", u.q("BEGIN ISOLATION LEVEL REPEATABLE READ"), "OK")
    c.expect("open transaction, memo in use", u.q("SELECT count(*) FROM public.sp_t"), "allow", role, "SELECT")
    must(a, rule)
    c.equal("inside the open transaction the committed rule refuses", u.q("SELECT 'qa_memo_marker_3'"), REGEX_MATCH)
    u.q("ROLLBACK")
    must(a, drop)

    must(a, "ALTER TABLE public.sql_firewall_regex_rules DISABLE TRIGGER sql_firewall_policy_changing")
    must(a, "ALTER TABLE public.sql_firewall_regex_rules DISABLE TRIGGER sql_firewall_policy_changed")
    try:
        c.expect("triggers disabled, no rule: allowed", u.q("SELECT 'qa_memo_marker_4'"), "allow", role, "SELECT")
        must(a, rule)
        c.equal("a rule inserted while the triggers are disabled still refuses (memo not used)", u.q("SELECT 'qa_memo_marker_5'"), REGEX_MATCH)
        must(a, drop)
    finally:
        must(a, "ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_policy_changing")
        must(a, "ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_policy_changed")
    c.expect("triggers restored, no rule: allowed", u.q("SELECT 'qa_memo_marker_6'"), "allow", role, "SELECT")
    u.close()
    return ("with no active rule the session was allowed; a rule committed by another session refused its next statement, "
            "also inside an open REPEATABLE READ transaction; with the rules' invalidation triggers disabled a newly inserted rule still refused")


# ---------------------------------------------------------------------------
# P8-02: keyword and built-in checks on SQL tokens; regex on raw text.
# User decision (2026-09-30): the built-in check counts only OR tautologies
# and has its own setting; the installation default regex rule is inactive.
# ---------------------------------------------------------------------------
KEYWORD = "ERR 42000 sql_firewall: Blocked due to blacklisted keyword '{k}'."
TAUTOLOGY = "ERR 42501 sql_firewall: Query matched default injection pattern."


def tokens(c):
    a = admin()
    role, rx, off = "qa_sp_tok", "qa_sp_tokrx", "qa_sp_tokoff"
    # Regex rules off here, so only the token checks decide; the regex role
    # below shows raw-text matching.
    role_in(a, role, {"sql_firewall.mode": "enforce", "sql_firewall.enable_keyword_scan": "on",
                      "sql_firewall.blacklisted_keywords": "pg_sleep, union select, drop",
                      "sql_firewall.enable_regex_scan": "off"}, grants=("SELECT",))
    role_in(a, rx, {"sql_firewall.mode": "enforce", "sql_firewall.enable_regex_scan": "on"}, grants=("SELECT",))
    role_in(a, off, {"sql_firewall.mode": "enforce", "sql_firewall.enable_regex_scan": "off",
                     "sql_firewall.enable_builtin_injection_check": "off"}, grants=("SELECT",))
    must(a, "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('qa_sp_raw_marker', 'qa raw text rule')")
    u = Conn("tokens", role, DB)
    allowed = [
        "SELECT 'call pg_sleep(1) here'",
        "SELECT 1 -- pg_sleep(1)",
        "SELECT 1 /* outer /* nested pg_sleep */ still comment */",
        "SELECT $$union select$$",
        "SELECT $tag$ drop table $tag$",
        "SELECT E'it''s drop\\'s'",
        "SELECT 'ığdır pg_sleep ölçü'",
        "SELECT 'x or 1=1'",
        "SELECT 1 -- or 1=1",
        "SELECT count(*) FROM public.sp_t WHERE id = 1 OR 1 = 2",
        "SELECT count(*) FROM public.sp_t WHERE 1=1",
        "SELECT count(*) FROM public.sp_t WHERE 1 = 1 AND id = 7",
        "SELECT count(*) FROM public.sp_t WHERE id = 7 AND 'a'='a'",
    ]
    for sql in allowed:
        c.expect(f"allowed: {sql}", u.q(sql), "allow", role, "SELECT")
    refused = [
        ("SELECT pg_sleep(0)", KEYWORD.format(k="pg_sleep")),
        ('SELECT "pg_sleep"(0)', KEYWORD.format(k="pg_sleep")),
        ("SELECT 1 UNION SELECT 2", KEYWORD.format(k="union select")),
        ("SELECT 1 union /* gap */ select 2", KEYWORD.format(k="union select")),
        ("SELECT count(*) FROM public.sp_t WHERE id = 7 OR 1 = 1", TAUTOLOGY),
        ("SELECT count(*) FROM public.sp_t WHERE 1 = 1 OR 1=1", TAUTOLOGY),
        ("SELECT count(*) FROM public.sp_t WHERE id = 7 OR 'a'='a'", TAUTOLOGY),
    ]
    for sql, want in refused:
        c.equal(f"refused: {sql}", u.q(sql), want)
    c.equal("regex rule on raw text: a marker in a comment", once(rx, "SELECT 1 -- qa_sp_raw_marker"),
            "ERR 42501 sql_firewall: Query blocked by security regex pattern.")
    default = "installation_default = 'simple_sql_injection'"
    c.equal("installation default regex rule is installed inactive",
            value(a, f"SELECT is_active FROM public.sql_firewall_regex_rules WHERE {default}"), "f")
    c.expect("inactive installation default: an OR predicate is allowed",
             once(rx, "SELECT count(*) FROM public.sp_t WHERE id = 1 OR id = 2"), "allow", rx, "SELECT")
    must(a, f"UPDATE public.sql_firewall_regex_rules SET is_active = true WHERE {default}")
    try:
        c.equal("activated installation default on raw text: a tautology inside a literal", once(rx, "SELECT 'x or 1=1'"),
                "ERR 42501 sql_firewall: Query blocked by security regex pattern.")
    finally:
        must(a, f"UPDATE public.sql_firewall_regex_rules SET is_active = false WHERE {default}")
    c.expect("enable_builtin_injection_check = off: an OR tautology is allowed",
             once(off, "SELECT count(*) FROM public.sp_t WHERE id = 7 OR 1 = 1"), "allow", off, "SELECT")
    must(a, "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa raw text rule'")
    u.close()
    return ("keywords and the built-in OR-tautology check matched only SQL tokens (not string, dollar-quoted, escaped, or UTF-8 "
            "literals, line or nested comments), including a quoted identifier and a keyword pair across a comment; WHERE/AND "
            "1=1 were allowed; enable_builtin_injection_check = off turned the check off; the installation default regex rule "
            "is inactive and, once activated, matched the raw text including a literal")


# ---------------------------------------------------------------------------
# P8-03: quiet hours in the policy time zone
# ---------------------------------------------------------------------------
QUIET = "ERR 42501 sql_firewall: Blocked during quiet hours ({s} - {e})."
QUIET_INCOMPLETE = ("ERR 42501 sql_firewall: Quiet hours are enabled but quiet_hours_start and quiet_hours_end "
                    "are not both set; the statement is refused.")


def hhmm(minutes):
    minutes %= 1440
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def utc_minute(a):
    return int(value(a, "SELECT (extract(hour FROM now() AT TIME ZONE 'UTC') * 60 + extract(minute FROM now() AT TIME ZONE 'UTC'))::int"))


def quiet_hours(c):
    a = admin()
    role = "qa_sp_quiet"
    role_in(a, role, {"sql_firewall.mode": "enforce"}, grants=("SELECT", "SET"))

    def configure(start, end, zone):
        for k, v in (("enable_quiet_hours", "on"), ("quiet_hours_start", start), ("quiet_hours_end", end),
                     ("quiet_hours_timezone", zone)):
            must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.{k} = '{v}'")

    def attempt(timezone):
        conn = Conn("quiet", role, DB)
        try:
            if timezone:
                conn.q(f"SET TimeZone = '{timezone}'")
            return conn.q("SELECT count(*) FROM public.sp_t")
        finally:
            conn.close()

    for _ in range(3):  # stay clear of a minute boundary
        now = utc_minute(a)
        start, end = hhmm(now - 1), hhmm(now + 3)
        configure(start, end, "UTC")
        got = [attempt(None), attempt("Pacific/Kiritimati"), attempt("America/Adak")]
        if utc_minute(a) == now:
            break
    c.equal(f"window {start}-{end} UTC, session TimeZone default / UTC+14 / UTC-10",
            got, [QUIET.format(s=start, e=end)] * 3)
    start, end = hhmm(now + 5), hhmm(now + 7)
    configure(start, end, "UTC")
    c.expect(f"window {start}-{end} UTC is not now, whatever the session TimeZone", attempt("Asia/Kathmandu"), "allow", role, "SELECT")
    # A window across midnight: pick a fixed offset that makes it 23:59 now.
    for _ in range(3):
        now = utc_minute(a)
        offset = (now - (23 * 60 + 59)) % 1440  # local = UTC - offset (POSIX sign)
        zone = f"QAT+{offset // 60:02d}:{offset % 60:02d}"
        configure("23:58", "00:02", zone)
        across = attempt("UTC")
        configure("00:03", "00:05", zone)
        after = attempt("UTC")
        if utc_minute(a) == now:
            break
    c.equal(f"23:58-00:02 in {zone} (local 23:59) refuses", across, QUIET.format(s="23:58", e="00:02"))
    c.expect(f"00:03-00:05 in {zone} allows", after, "allow", role, "SELECT")
    # Enabled but incomplete: refused, not silently without a window.
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} RESET sql_firewall.quiet_hours_end")
    c.equal("enabled with quiet_hours_end unset", attempt(None), QUIET_INCOMPLETE)
    c.equal("an empty quiet_hours_end is rejected at assignment",
            a.q(f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.quiet_hours_end = ''").split(":")[0],
            'ERR 22023 invalid value for parameter "sql_firewall.quiet_hours_end"')
    c.equal("an unknown quiet_hours_timezone is rejected", a.q("SET sql_firewall.quiet_hours_timezone = 'Nowhere/Qa'").split(":")[0],
            'ERR 22023 invalid value for parameter "sql_firewall.quiet_hours_timezone"')
    c.equal("a malformed quiet_hours_start is rejected", a.q("SET sql_firewall.quiet_hours_start = '25:00'").split(":")[0],
            'ERR 22023 invalid value for parameter "sql_firewall.quiet_hours_start"')
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.enable_quiet_hours = 'off'")
    return (f"quiet hours followed sql_firewall.quiet_hours_timezone, not the session TimeZone (UTC+14, UTC-10, UTC+5:45 sessions); "
            f"a window across midnight refused at local 23:59 in {zone}; an enabled window with an unset bound refused "
            f"the statement; an empty bound, unknown zone and malformed time were rejected at assignment")


# ---------------------------------------------------------------------------
# P8-06/07: rate limits per database, window, concurrency, role recreation
# ---------------------------------------------------------------------------
RATE = "ERR 53400 sql_firewall: Rate limit for command 'SELECT' exceeded for role '{r}'"


def rate_limits(c):
    a = admin()
    role = "qa_sp_rate"
    limits = {"sql_firewall.select_limit_count": "2", "sql_firewall.command_limit_seconds": "3"}
    role_in(a, role, {"sql_firewall.mode": "enforce", **limits}, grants=("SELECT",))
    for db in (DB2,):
        x = admin(db, label="db2")
        must(x, "CREATE TABLE IF NOT EXISTS public.sp_t (id integer)")
        must(x, f"GRANT CONNECT ON DATABASE {db} TO {role}")
        must(x, f"GRANT SELECT ON public.sp_t TO {role}")
        for k, v in {"sql_firewall.mode": "enforce", **limits}.items():
            must(x, f"ALTER ROLE {role} IN DATABASE {db} SET {k} = '{v}'")
        approve(x, role, "SELECT")
        x.close()
    q = "SELECT count(*) FROM public.sp_t"
    first = [once(role, q) for _ in range(3)]
    c.equal("database 1: two allowed, the third refused", [o.split(":")[0] for o in first[:2]] + [first[2]],
            ["OK rows=1", "OK rows=1", RATE.format(r=role)])
    other = [once(role, q, db=DB2) for _ in range(2)]
    c.equal("database 2 has its own allowance", [o.split(":")[0] for o in other], ["OK rows=1", "OK rows=1"])
    time.sleep(3.2)
    c.equal("after the 3 s window the role is allowed again", once(role, q).split(":")[0], "OK rows=1")
    # Concurrency: 12 sessions, 3 statements each, limit 5 in one window.
    busy = "qa_sp_rate2"
    role_in(a, busy, {"sql_firewall.mode": "enforce", "sql_firewall.select_limit_count": "5",
                      "sql_firewall.command_limit_seconds": "60"}, grants=("SELECT",))
    conns = [Conn(f"rate-{i}", busy, DB) for i in range(12)]
    outs = []
    lock = threading.Lock()

    def work(conn):
        for _ in range(3):
            o = conn.q(q)
            with lock:
                outs.append(o)

    threads = [threading.Thread(target=work, args=(x,)) for x in conns]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    allowed = sum(1 for o in outs if o.startswith("OK"))
    refused = sum(1 for o in outs if o == RATE.format(r=busy))
    c.equal("36 concurrent attempts, limit 5: allowed/refused", (allowed, refused), (5, 31))
    for x in conns:
        x.close()
    # A dropped and recreated role (new OID) starts with its own counter.
    again = "qa_sp_rate3"
    role_in(a, again, {"sql_firewall.mode": "enforce", **limits}, grants=("SELECT",))
    tries = [once(again, q) for _ in range(3)]
    c.equal("role at its limit", [t.split(":")[0] for t in tries[:2]] + [tries[2]], ["OK rows=1", "OK rows=1", RATE.format(r=again)])
    must(a, f"DROP OWNED BY {again}")
    must(a, f"DROP ROLE {again}")
    role_in(a, again, {"sql_firewall.mode": "enforce", **limits}, grants=("SELECT",))
    c.equal("recreated role (new OID) within the old window: allowed", once(again, q).split(":")[0], "OK rows=1")
    return ("limits were counted per database (the second database kept its allowance), a 3 s window ended on time, "
            "36 concurrent attempts against a limit of 5 allowed exactly 5, and a recreated role started fresh")


# ---------------------------------------------------------------------------
# P8-05: application name and parallel workers
# ---------------------------------------------------------------------------
def application_name(c):
    a = admin()
    role = "qa_sp_app"
    role_in(a, role, {"sql_firewall.mode": "enforce", "sql_firewall.enable_application_blocking": "on",
                      "sql_firewall.blocked_applications": "qa_pc_sp_bad"}, grants=("SELECT", "SET"))
    good = Conn("good-app", role, DB)  # startup application_name qa_pc_good-app
    c.equal("SET application_name to the blocked name", good.q("SET application_name = 'qa_pc_sp_bad'"), "OK")
    c.expect("policy keeps the startup application_name", good.q("SELECT count(*) FROM public.sp_t"), "allow", role, "SELECT")
    good.close()
    bad = Conn("sp_bad", role, DB)  # startup application_name qa_pc_sp_bad
    c.equal("startup application_name blocked", bad.q("SELECT count(*) FROM public.sp_t"),
            "ERR 42501 sql_firewall: Connections from application 'qa_pc_sp_bad' are not allowed.")
    c.equal("SET application_name away from it", bad.q("SET application_name = 'qa_other'"),
            "ERR 42501 sql_firewall: Connections from application 'qa_pc_sp_bad' are not allowed.")
    bad.close()
    return ("application blocking used the application_name the client sent at connection; a later SET application_name "
            "neither triggered nor evaded it (README 6.1c: not an authenticated identity)")


def parallel_query(c):
    a = admin()
    role = "qa_sp_par"
    role_in(a, role, {"sql_firewall.mode": "enforce", "sql_firewall.enable_activity_logging": "on",
                      "debug_parallel_query": "on", "parallel_setup_cost": "0", "parallel_tuple_cost": "0",
                      "min_parallel_table_scan_size": "0", "max_parallel_workers_per_gather": "2"},
            grants=("SELECT", "EXPLAIN"))
    u = Conn("parallel", role, DB)
    plan = u.q("EXPLAIN (COSTS OFF) SELECT count(*) /* qa_sp_par */ FROM public.sp_t")
    c.equal("the plan uses parallel workers", "Gather" in plan, True)
    c.expect("parallel query allowed", u.q("SELECT count(*) /* qa_sp_par */ FROM public.sp_t"), "allow", role, "SELECT")
    pc.sync_activity(a)
    c.equal("one decision recorded for the statement (the leader's), none from the workers",
            value(a, f"SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '{role}' AND query_text LIKE 'SELECT count(*) /* qa_sp_par */%'"), "1")
    u.close()
    return "a parallel query was inspected once, in the leader; its parallel workers were exempt"


def main():
    for db in (DB,):
        x = admin(db, label="setup")
        must(x, "CREATE TABLE public.sp_t (id integer)")
        must(x, "INSERT INTO public.sp_t SELECT g FROM generate_series(1, 1000) g")
        x.close()
    run("regex_deadline", "regex rules under a real deadline", regex_deadline)
    run("tokens", "keyword and built-in checks on SQL tokens", tokens)
    run("quiet_hours", "quiet hours in the policy time zone", quiet_hours)
    run("rate_limits", "rate limit scope, window, concurrency", rate_limits)
    run("application_name", "application name used by policy", application_name)
    run("parallel_query", "parallel workers", parallel_query)
    run("regex_memo", "the no-active-rule memo and its invalidation", regex_memo)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
