#!/usr/bin/env python3
"""Policy cache visibility scenarios (qa/tests/99_policy_cache.sh).

Every scenario uses separate libpq connections driven from this one process,
so the order of statements across sessions is explicit: nothing depends on
sleeps. Each step records the connection, its transaction status before and
after, the statement, and the result with SQLSTATE; catalog state is read on
an independent superuser connection. Output: one JSON object per check on
stdout, as STATUS<TAB>ID<TAB>DETAIL; the transcript goes to QA_PC_EVIDENCE.

Expected outcomes are classified strictly:
  allow   the statement succeeded
  pending 42501 "sql_firewall: BLOCKED - Approval for command 'C' is pending for role 'R'"
  norule  42501 "sql_firewall: No rule found for command 'C' for role 'R'"
Any other error (a native permission error, an aborted transaction, a
missing object) is INFRA: the decision under test was not observed.
"""
import ctypes, os, time

ENV = os.environ
SU = ENV["QA_PC_SUPERUSER"]
BASE = f"host={ENV['QA_PC_SOCK']} port={ENV['QA_PC_PORT']}"
DB, DB2, DBL = ENV["QA_PC_DB"], ENV["QA_PC_DB2"], ENV["QA_PC_DBL"]
EVIDENCE = open(ENV["QA_PC_EVIDENCE"], "a", encoding="utf-8")

lib = ctypes.CDLL(ENV["QA_LIBPQ"])
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
lib.PQgetvalue.restype = ctypes.c_char_p
lib.PQgetvalue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
lib.PQntuples.argtypes = [ctypes.c_void_p]
lib.PQclear.argtypes = [ctypes.c_void_p]
lib.PQfinish.argtypes = [ctypes.c_void_p]
lib.PQtransactionStatus.argtypes = [ctypes.c_void_p]
TXN = {0: "idle", 1: "active", 2: "in-transaction", 3: "in-failed-transaction", 4: "unknown"}


class Infra(Exception):
    pass


def note(line):
    EVIDENCE.write(line + "\n")
    EVIDENCE.flush()


OPEN = []


class Conn:
    def __init__(self, label, user, db, options=""):
        self.label = label
        extra = f" options='{options}'" if options else ""
        # application_name must survive the connection string: labels are free text.
        tag = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in label)
        self.conn = lib.PQconnectdb(f"{BASE} dbname={db} user={user} application_name=qa_pc_{tag}{extra}".encode())
        if lib.PQstatus(self.conn) != 0:
            message = lib.PQerrorMessage(self.conn).decode(errors="replace").strip()
            lib.PQfinish(self.conn)
            raise Infra(f"{label}: connect failed: {message}")
        OPEN.append(self)
        note(f"    [{label}] connected as {user} to {db}{' with ' + options if options else ''}")

    def txn(self):
        return TXN.get(lib.PQtransactionStatus(self.conn), "?")

    def q(self, sql):
        before = self.txn()
        res = lib.PQexec(self.conn, sql.encode())
        status = lib.PQresultStatus(res)
        if status == 1:
            out = "OK"
        elif status == 2:
            n = lib.PQntuples(res)
            out = f"OK rows={n}: " + "|".join(lib.PQgetvalue(res, i, 0).decode(errors="replace") for i in range(n))
        else:
            c = lib.PQresultErrorField(res, ord("C"))
            m = lib.PQresultErrorField(res, ord("M"))
            out = f"ERR {c.decode() if c else '?'} {m.decode(errors='replace') if m else ''}"
        lib.PQclear(res)
        shown = (sql if len(sql) <= 512 else f"{sql[:200]} ... [{len(sql)} bytes]").replace(chr(13), "<CR>")
        note(f"    [{self.label}] ({before} -> {self.txn()}) {shown}\n        => {out}")
        return out

    def close(self):
        if self in OPEN:
            OPEN.remove(self)
            lib.PQfinish(self.conn)


def admin(db=DB, label="admin"):
    return Conn(label, SU, db)


def must(conn, sql):
    out = conn.q(sql)
    if out.startswith("ERR"):
        raise Infra(f"setup step failed on {conn.label}: {sql}: {out}")
    return out


def value(conn, sql):
    out = must(conn, sql)
    return out.split(": ", 1)[1] if ": " in out else ""


def once(role, sql, db=DB, label=None, options=""):
    c = Conn(label or f"new-{role}", role, db, options)
    try:
        return c.q(sql)
    finally:
        c.close()


class Check:
    """Collects step verdicts for one check id."""

    def __init__(self, cid, title):
        self.cid, self.failures, self.infra, self.passes = cid, [], [], 0
        note(f"\n## {cid}: {title}")

    def expect(self, what, out, kind, role, command):
        want = {
            "allow": None,
            "pending": f"ERR 42501 sql_firewall: BLOCKED - Approval for command '{command}' is pending for role '{role}'",
            "norule": f"ERR 42501 sql_firewall: No rule found for command '{command}' for role '{role}'",
        }[kind]
        if kind == "allow":
            good = out.startswith("OK")
        else:
            good = out == want
        firewall = out.startswith("ERR 42501 sql_firewall:")
        if good:
            self.passes += 1
            note(f"        ok: {what}: expected {kind}")
        elif out.startswith("OK") or firewall:
            self.failures.append(f"{what}: expected {kind}, got '{out}'")
            note(f"        FAIL: {what}: expected {kind}")
        else:
            self.infra.append(f"{what}: '{out}' is not a firewall decision")
            note(f"        INFRA: {what}")

    def equal(self, what, got, want):
        if got == want:
            self.passes += 1
            note(f"        ok: {what} = {got!r}")
        else:
            self.failures.append(f"{what}: got {got!r}, expected {want!r}")
            note(f"        FAIL: {what}: got {got!r}, expected {want!r}")

    def result(self, summary):
        if self.failures:
            return ("FAIL", "; ".join(self.failures + [f"(also not observed: {x})" for x in self.infra]))
        if self.infra:
            return ("INFRA", "; ".join(self.infra))
        return ("PASS", summary)


RESULTS = []


def run(cid, title, fn):
    check = Check(cid, title)
    summary = ""
    try:
        summary = fn(check)
    except Infra as exc:
        check.infra.append(str(exc))
    except Exception as exc:  # a driver defect is not a verdict
        check.infra.append(f"driver error: {exc!r}")
    finally:
        # A check that stopped early must not leave a transaction open.
        for conn in list(OPEN):
            conn.close()
        if PAUSED:
            try:
                resume_worker(admin(label="resume"))
            except Infra as exc:
                check.infra.append(f"cleanup: {exc}")
            for conn in list(OPEN):
                conn.close()
    status, detail = check.result(summary)
    note(f"**{cid}: {status}** - {detail}")
    emit(status, cid, detail)


def emit(status, cid, detail):
    detail = " ".join(detail.split())
    print(f"{status}\t{cid}\t{detail}", flush=True)


PAUSED = []


def pause_worker(a):
    """Pause DB's approval worker; the reply means a live consumer acknowledged it."""
    reply = value(a, "SELECT public.sql_firewall_pause_approval_worker()")
    if not reply.startswith("approval worker paused epoch="):
        raise Infra(f"pause returned {reply!r}")
    PAUSED.append(True)


def resume_worker(a):
    reply = value(a, "SELECT public.sql_firewall_resume_approval_worker()")
    if not reply.startswith("approval worker running epoch="):
        raise Infra(f"resume returned {reply!r}")
    PAUSED.clear()


def approvals(a, role):
    return value(a, f"SELECT coalesce(string_agg(command_type || '=' || is_approved, ',' ORDER BY command_type), '') "
                    f"FROM public.sql_firewall_command_approvals WHERE role_name = '{role}'")


def select_state(a, role):
    """The committed SELECT approval row as another session sees it."""
    return value(a, f"SELECT coalesce((SELECT is_approved::text FROM public.sql_firewall_command_approvals "
                    f"WHERE role_name = '{role}' AND command_type = 'SELECT'), 'absent')")


# A writer that switches to the application role with SET LOCAL ROLE ends its
# transaction or savepoint as that role, and the firewall checks those
# statements too; the application roles have them approved.
TXN_CONTROL = ("COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE")


def setup_role(a, role, db_list, extra=()):
    must(a, f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
    for db in db_list:
        must(a, f"GRANT CONNECT ON DATABASE {db} TO {role}")
        # Command-cache scenarios isolate command approval from fingerprint
        # approval. Fingerprint scenarios turn this back on explicitly.
        must(a, f"ALTER ROLE {role} IN DATABASE {db} SET sql_firewall.enable_fingerprint_learning = 'off'")
    for sql in extra:
        must(a, sql)


def approve(a, role, *commands):
    for command in commands:
        must(a, f"SELECT public.sql_firewall_approve_command('{role}', '{command}')")


# ---------------------------------------------------------------------------
def committed_revoke(c):
    """F1: a warm allow, then a committed revoke, for an existing and a new session."""
    a = admin()
    role = "qa_pc_rev"
    setup_role(a, role, [DB], [f"GRANT SELECT, INSERT ON public.pc_orders TO {role}"])
    approve(a, role, "SELECT", "INSERT")
    e = Conn("existing", role, DB)
    c.expect("existing session warm SELECT", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    c.expect("existing session warm INSERT", e.q("INSERT INTO public.pc_orders VALUES (100)"), "allow", role, "INSERT")
    c.expect("new session warm SELECT", once(role, "SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    rows_before = value(a, "SELECT count(*) FROM public.pc_orders")
    must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
    must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'INSERT')")
    c.equal("catalog after revoke", approvals(a, role), "INSERT=false,SELECT=false")
    c.expect("existing session SELECT after revoke", e.q("SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    c.expect("existing session INSERT after revoke", e.q("INSERT INTO public.pc_orders VALUES (101)"), "pending", role, "INSERT")
    c.expect("new session SELECT after revoke", once(role, "SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    c.equal("pc_orders rows (denied INSERT wrote nothing)", value(a, "SELECT count(*) FROM public.pc_orders"), rows_before)
    e.close()
    return "a cached allow was not used after a committed revoke: the existing and a new session got the firewall rejection and the denied INSERT wrote nothing"


def committed_approve(c):
    """F1 reverse: a warm explicit denial, then a committed approval."""
    a = admin()
    role = "qa_pc_grant"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}",
                               f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', false)"])
    e = Conn("existing", role, DB)
    c.expect("existing session warm denial", e.q("SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    c.expect("new session warm denial", once(role, "SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    approve(a, role, "SELECT")
    c.equal("catalog after approve", approvals(a, role), "SELECT=true")
    c.expect("existing session after approve", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    c.expect("new session after approve", once(role, "SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    e.close()
    return "a cached denial was not used after a committed approval: the existing and a new session were allowed"


def uncommitted_and_rollback(c):
    """F2: an administrator's uncommitted approval, read by its writer, then ROLLBACK."""
    a = admin()
    other = admin(label="catalog")
    role = "qa_pc_txn"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    approve(a, role, *TXN_CONTROL)
    e = Conn("existing", role, DB)
    c.expect("existing session before", e.q("SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    w = admin(label="writer")
    must(w, "SET sql_firewall.mode = enforce")
    must(w, "BEGIN")
    must(w, f"SELECT public.sql_firewall_approve_command('{role}', 'SELECT')")
    must(w, f"SET LOCAL ROLE {role}")
    c.expect("writer reads its own uncommitted approval", w.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    c.equal("writer transaction status", w.txn(), "in-transaction")
    c.equal("SELECT approval seen by another session", select_state(other, role), "absent")
    c.expect("concurrent new session", once(role, "SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    c.expect("concurrent existing session", e.q("SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.equal("SELECT approval after rollback", select_state(other, role), "absent")
    c.expect("new session after rollback", once(role, "SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    c.expect("existing session after rollback", e.q("SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    # Read-your-own-writes against a warm cached allow: the writer's own
    # uncommitted revoke wins in its transaction, and nothing leaks.
    approve(a, role, "SELECT")
    c.expect("warm allow", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    must(w, "BEGIN")
    must(w, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
    must(w, f"SET LOCAL ROLE {role}")
    c.expect("writer reads its own uncommitted revoke", w.q("SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    c.expect("concurrent session keeps committed allow", once(role, "SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.expect("after rollback the committed allow stands", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    for x in (w, e, other):
        x.close()
    return "an uncommitted approval authorized only its writer (SET LOCAL ROLE); concurrent sessions stayed denied, and after a successful ROLLBACK there was no row and no leaked allow; an uncommitted revoke applied to its writer only"


def savepoints(c):
    """F2: savepoint rollback, release plus commit, and concurrent readers."""
    a = admin()
    other = admin(label="catalog")
    role = "qa_pc_sp"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    approve(a, role, *TXN_CONTROL)
    q = "SELECT count(*) FROM public.pc_orders"
    w = admin(label="writer")
    must(w, "BEGIN")
    must(w, "INSERT INTO public.pc_orders VALUES (301)")
    must(w, "SAVEPOINT qa_s1")
    must(w, f"SELECT public.sql_firewall_approve_command('{role}', 'SELECT')")
    must(w, "ROLLBACK TO SAVEPOINT qa_s1")
    # The writer's own view, inside a savepoint so that the denial does not
    # abort the transaction that is committed below.
    must(w, "SAVEPOINT qa_probe")
    must(w, f"SET LOCAL ROLE {role}")
    c.expect("writer after ROLLBACK TO SAVEPOINT", w.q(q), "norule", role, "SELECT")
    must(w, "ROLLBACK TO SAVEPOINT qa_probe")
    c.expect("concurrent session", once(role, q), "norule", role, "SELECT")
    c.equal("writer transaction status before COMMIT", w.txn(), "in-transaction")
    c.equal("COMMIT", w.q("COMMIT"), "OK")
    c.equal("marker row committed by the same transaction", value(other, "SELECT count(*) FROM public.pc_orders WHERE id = 301"), "1")
    c.equal("SELECT approval after commit", select_state(other, role), "absent")
    c.expect("new session after commit", once(role, q), "norule", role, "SELECT")
    must(w, "BEGIN")
    must(w, "SAVEPOINT qa_s2")
    must(w, f"SELECT public.sql_firewall_approve_command('{role}', 'SELECT')")
    must(w, "RELEASE SAVEPOINT qa_s2")
    must(w, "SAVEPOINT qa_probe")
    must(w, f"SET LOCAL ROLE {role}")
    c.expect("writer after RELEASE SAVEPOINT", w.q(q), "allow", role, "SELECT")
    must(w, "ROLLBACK TO SAVEPOINT qa_probe")
    c.expect("concurrent session before COMMIT", once(role, q), "norule", role, "SELECT")
    c.equal("COMMIT", w.q("COMMIT"), "OK")
    c.equal("SELECT approval after commit", select_state(other, role), "true")
    c.expect("new session after COMMIT", once(role, q), "allow", role, "SELECT")
    return "an approval rolled back to a savepoint authorized nobody, the writer included, and stayed absent after the enclosing transaction really committed (its marker row is visible); a released savepoint's approval applied to the writer, was invisible to a concurrent session until COMMIT, and applied right after it"


def old_snapshot(c, level, role):
    """F3: an open REPEATABLE READ or SERIALIZABLE transaction and a committed revoke."""
    a = admin()
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET default_transaction_isolation = '{level}'"])
    approve(a, role, "BEGIN", "SHOW", "SELECT", "ROLLBACK")
    o = Conn("old", role, DB)
    c.equal("old BEGIN", o.q("BEGIN"), "OK")
    c.equal("old SHOW transaction_isolation", o.q("SHOW transaction_isolation"), f"OK rows=1: {level}")
    first = o.q("SELECT count(*) FROM public.pc_orders")
    c.expect("old SELECT before revoke", first, "allow", role, "SELECT")
    must(a, "INSERT INTO public.pc_orders VALUES (200)")
    c.equal("old snapshot still sees the old row count", o.q("SELECT count(*) FROM public.pc_orders"), first)
    must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
    must(a, "SELECT public.sql_firewall_clear_approval_cache()")
    c.equal("catalog after revoke", value(a, f"SELECT is_approved FROM public.sql_firewall_command_approvals WHERE role_name = '{role}' AND command_type = 'SELECT'"), "f")
    c.expect("old transaction's next SELECT (latest committed policy)", o.q("SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    c.expect("new session after old reader activity", once(role, "SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    c.equal("old ROLLBACK", o.q("ROLLBACK"), "OK")
    c.expect("new session after old transaction ended", once(role, "SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    o.close()
    return f"a {level} transaction whose data snapshot predated the revoke (row count unchanged) was denied at its next statement, and did not repopulate an allow: new sessions were denied during and after it"


def reinstall(c):
    """F4: DROP/CREATE EXTENSION in the same database."""
    a = admin(DBL)
    role = "qa_pc_life"
    setup_role(a, role, [DBL], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    approve(a, role, "SELECT")
    e = Conn("existing", role, DBL)
    c.expect("existing session warm", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    c.expect("new session warm", once(role, "SELECT count(*) FROM public.pc_orders", DBL), "allow", role, "SELECT")
    old_ext = value(a, "SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'")
    must(a, "DROP EXTENSION sql_firewall")
    must(a, "CREATE EXTENSION sql_firewall")
    new_ext = value(a, "SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'")
    note(f"        installation {old_ext} -> {new_ext}")
    c.equal("approvals in the new installation", value(a, "SELECT count(*) FROM public.sql_firewall_command_approvals"), "0")
    c.expect("existing session after reinstall", e.q("SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    c.expect("new session after reinstall", once(role, "SELECT count(*) FROM public.pc_orders", DBL), "norule", role, "SELECT")
    approve(a, role, "SELECT")
    c.expect("new installation's own approval", once(role, "SELECT count(*) FROM public.pc_orders", DBL), "allow", role, "SELECT")
    e.close()
    return f"after DROP/CREATE EXTENSION (installation {old_ext} -> {new_ext}) the old installation's cached approval was not used; the new installation's approval was"


def installation_rollback(c):
    """F4: rolled-back DROP and DROP/CREATE, whole and to a savepoint."""
    a = admin(DBL)
    role = "qa_pc_life"
    approve(a, role, *TXN_CONTROL)
    e = Conn("existing", role, DBL)
    c.expect("warm allow", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    ext = value(a, "SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'")
    must(a, "SET sql_firewall.mode = enforce")
    must(a, "BEGIN")
    must(a, "DROP EXTENSION sql_firewall")
    c.equal("ROLLBACK of DROP", a.q("ROLLBACK"), "OK")
    c.expect("existing session after rolled-back DROP", e.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    must(a, "BEGIN")
    must(a, "DROP EXTENSION sql_firewall")
    must(a, "CREATE EXTENSION sql_firewall")
    must(a, f"SET LOCAL ROLE {role}")
    c.expect("inside the transaction the new installation has no approval", a.q("SELECT count(*) FROM public.pc_orders"), "norule", role, "SELECT")
    c.equal("ROLLBACK of DROP/CREATE", a.q("ROLLBACK"), "OK")
    c.expect("new session after rolled-back DROP/CREATE", once(role, "SELECT count(*) FROM public.pc_orders", DBL), "allow", role, "SELECT")
    must(a, "BEGIN")
    must(a, "SAVEPOINT qa_ext")
    must(a, "DROP EXTENSION sql_firewall")
    must(a, "CREATE EXTENSION sql_firewall")
    must(a, "ROLLBACK TO SAVEPOINT qa_ext")
    must(a, f"SET LOCAL ROLE {role}")
    c.expect("after ROLLBACK TO SAVEPOINT, same transaction", a.q("SELECT count(*) FROM public.pc_orders"), "allow", role, "SELECT")
    c.equal("COMMIT", a.q("COMMIT"), "OK")
    c.equal("installation kept", value(a, "SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'"), ext)
    c.expect("new session after commit", once(role, "SELECT count(*) FROM public.pc_orders", DBL), "allow", role, "SELECT")
    must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
    c.expect("original installation's policy still applies (revoke)", e.q("SELECT count(*) FROM public.pc_orders"), "pending", role, "SELECT")
    e.close()
    return "rolled-back DROP, DROP/CREATE, and DROP/CREATE to a savepoint left the original installation in force with its approvals; a later revoke in it still applied"


def direct_dml(c):
    """Supported direct superuser DML and TRUNCATE on the approvals table."""
    a = admin()
    role = "qa_pc_dml"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    approve(a, role, "SELECT")
    e = Conn("existing", role, DB)
    q = "SELECT count(*) FROM public.pc_orders"
    c.expect("warm allow", e.q(q), "allow", role, "SELECT")
    must(a, f"UPDATE public.sql_firewall_command_approvals SET is_approved = false WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("after UPDATE false (existing)", e.q(q), "pending", role, "SELECT")
    c.expect("after UPDATE false (new)", once(role, q), "pending", role, "SELECT")
    must(a, f"UPDATE public.sql_firewall_command_approvals SET is_approved = true WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("after UPDATE true", e.q(q), "allow", role, "SELECT")
    must(a, f"DELETE FROM public.sql_firewall_command_approvals WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("after DELETE", e.q(q), "norule", role, "SELECT")
    must(a, f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', true)")
    c.expect("after INSERT true", e.q(q), "allow", role, "SELECT")
    must(a, "SET session_replication_role = replica")
    must(a, f"UPDATE public.sql_firewall_command_approvals SET is_approved = false WHERE role_name = '{role}' AND command_type = 'SELECT'")
    must(a, "RESET session_replication_role")
    c.expect("after UPDATE with session_replication_role = replica", e.q(q), "pending", role, "SELECT")
    must(a, f"UPDATE public.sql_firewall_command_approvals SET is_approved = true WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("allow again", e.q(q), "allow", role, "SELECT")
    # TRUNCATE removes every role's approvals; restore what other checks use.
    saved = value(a, "SELECT count(*) FROM public.sql_firewall_command_approvals")
    must(a, "CREATE TEMP TABLE pc_saved AS SELECT * FROM public.sql_firewall_command_approvals")
    must(a, "TRUNCATE public.sql_firewall_command_approvals")
    c.expect("after TRUNCATE (existing)", e.q(q), "norule", role, "SELECT")
    c.expect("after TRUNCATE (new)", once(role, q), "norule", role, "SELECT")
    must(a, "INSERT INTO public.sql_firewall_command_approvals SELECT * FROM pc_saved")
    c.equal("approvals restored", value(a, "SELECT count(*) FROM public.sql_firewall_command_approvals"), saved)
    c.expect("after restoring the rows", e.q(q), "allow", role, "SELECT")
    e.close()
    return "superuser UPDATE, DELETE, INSERT, TRUNCATE (and UPDATE under session_replication_role = replica) on the approvals table took effect for an existing session with a warm cache, without clearing it"


def trigger_ddl(c):
    """Policy writes while the invalidation trigger is disabled."""
    a = admin()
    role = "qa_pc_trg"
    t = "public.sql_firewall_command_approvals"
    q = "SELECT count(*) FROM public.pc_orders"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    approve(a, role, "SELECT")
    e = Conn("existing", role, DB)
    c.expect("warm allow", e.q(q), "allow", role, "SELECT")
    c.expect("warm allow again (cached)", e.q(q), "allow", role, "SELECT")
    must(a, "BEGIN")
    must(a, f"ALTER TABLE {t} DISABLE TRIGGER sql_firewall_policy_changed")
    must(a, f"UPDATE {t} SET is_approved = false WHERE role_name = '{role}' AND command_type = 'SELECT'")
    must(a, f"ALTER TABLE {t} ENABLE ALWAYS TRIGGER sql_firewall_policy_changed")
    c.equal("COMMIT (disable, update, re-enable)", a.q("COMMIT"), "OK")
    c.equal("SELECT approval", select_state(a, role), "false")
    c.expect("existing session after the hidden update", e.q(q), "pending", role, "SELECT")
    c.expect("new session after the hidden update", once(role, q), "pending", role, "SELECT")
    must(a, f"ALTER TABLE {t} DISABLE TRIGGER sql_firewall_policy_changed")
    must(a, f"UPDATE {t} SET is_approved = true WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("trigger disabled: update to true", e.q(q), "allow", role, "SELECT")
    must(a, f"UPDATE {t} SET is_approved = false WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("trigger disabled: update to false", e.q(q), "pending", role, "SELECT")
    c.expect("trigger disabled: new session", once(role, q), "pending", role, "SELECT")
    must(a, f"ALTER TABLE {t} ENABLE ALWAYS TRIGGER sql_firewall_policy_changed")
    c.expect("trigger re-enabled", e.q(q), "pending", role, "SELECT")
    must(a, f"UPDATE {t} SET is_approved = true WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.expect("trigger re-enabled: update to true", e.q(q), "allow", role, "SELECT")
    c.equal("trigger state restored", value(a, f"SELECT tgenabled FROM pg_catalog.pg_trigger WHERE tgrelid = '{t}'::regclass AND tgname = 'sql_firewall_policy_changed'"), "A")
    return "a policy update made while the invalidation trigger was disabled, in the same transaction that re-enabled it, took effect at once for an existing session with a cached allow; while the trigger stayed disabled, sessions read the catalog on every statement"


def sync_activity(a, timeout=30):
    """Wait until the connection's database has written every activity record
    published so far (README 6.7; qa/lib.sh qa_activity_sync)."""
    target, generation = value(a, "SELECT activity_write_position || ' ' || activity_generation "
                                  "FROM public.sql_firewall_queue_statistics()").split(" ")
    deadline = time.time() + timeout
    while value(a, f"SELECT coalesce((SELECT next_position >= {target} AND ring_generation = {generation} AND extension_oid = "
                   f"(SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall') "
                   f"FROM public.sql_firewall_activity_checkpoint), false)") != "t":
        if time.time() > deadline:
            raise Infra(f"activity records up to position {target} not written within {timeout}s (worker paused, stalled, or absent)")
        time.sleep(0.1)


def sync_worker(a, timeout=30):
    """Wait until DB's worker has passed a canary published now. Events are
    applied in ring order, so every earlier event was applied or discarded."""
    token = f"qa_pc_canary_{time.time_ns()}"
    out = once("qa_canary", f"SELECT '{token}' AS marker", label="canary")
    if out != "ERR 42501 sql_firewall: No rule found for command 'SELECT' for role 'qa_canary'":
        raise Infra(f"canary not rejected as expected: {out}")
    deadline = time.time() + timeout
    while value(a, f"SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '{token}') > 0") != "1":
        if time.time() > deadline:
            raise Infra(f"worker did not deliver canary {token} within {timeout}s")
        time.sleep(0.2)


def worker_command(c):
    """A queued learn-mode approval does not replace a later cached denial.

    "No rule" is not cached, so the queued learn-mode approval meets a cached
    decision: the administrator commits an explicit denial while the approval
    waits, and an enforce-mode session caches that denial. The worker only
    creates a command decision where there is none, and discards an
    observation made before a later administrator change to its key
    (tests/103), so the cached denial stays correct.
    """
    a = admin()
    role = "qa_pc_worker"
    q = "SELECT count(*) FROM public.pc_orders"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'learn'"])
    enf = admin(label="enforce-reader")
    must(enf, "SET sql_firewall.mode = enforce")
    must(enf, f"SET ROLE {role}")
    pause_worker(a)
    c.expect("learn-mode execution (queues an approval)", once(role, q), "allow", role, "SELECT")
    c.equal("catalog while the worker is paused", select_state(a, role), "absent")
    c.expect("enforce reader while the approval is only queued", enf.q(q), "norule", role, "SELECT")
    must(a, f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', false)")
    c.expect("enforce reader: committed denial", enf.q(q), "pending", role, "SELECT")
    c.expect("enforce reader: same denial again (cached)", enf.q(q), "pending", role, "SELECT")
    resume_worker(a)
    sync_worker(a)
    c.equal("catalog after the worker passed the queued approval", select_state(a, role), "false")
    c.expect("enforce reader with the cached denial", enf.q(q), "pending", role, "SELECT")
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'")
    c.expect("new session of the role, now in enforce mode", once(role, q), "pending", role, "SELECT")
    return "a queued learn-mode approval authorized nothing while the worker was paused; a denial committed meanwhile was read and cached; after the worker passed the queued approval the catalog and the cached denial still refused the command"


FP_STATEMENT = "SELECT count(*) FROM public.pc_orders WHERE id = 1"
IDENTITY = {}


def fingerprint_identity(db=DB):
    """Derive the identity from this database's actual plan. Relation OIDs
    differ across databases even when the SQL text and table names match."""
    if db in IDENTITY:
        return IDENTITY[db]
    a = admin(db, label="identity")
    helper = "qa_pc_fp_helper" if db == DB else "qa_pc_fp_helper_l"
    setup_role(a, helper, [db], [f"GRANT SELECT ON public.pc_orders TO {helper}",
                                 f"ALTER ROLE {helper} IN DATABASE {db} SET sql_firewall.mode = 'learn'",
                                 f"ALTER ROLE {helper} IN DATABASE {db} SET sql_firewall.enable_fingerprint_learning = 'on'"])
    out = once(helper, FP_STATEMENT, db)
    if not out.startswith("OK"):
        raise Infra(f"learn-mode helper statement failed: {out}")
    deadline = time.time() + 30
    while True:
        out = a.q(f"SELECT fingerprint || '~' || normalized_query FROM public.sql_firewall_query_fingerprints "
                  f"WHERE role_name = '{helper}' AND command_type = 'SELECT'")
        if out.startswith("OK rows=1"):
            IDENTITY[db] = out.split(": ", 1)[1].split("~", 1)
            a.close()
            return IDENTITY[db]
        if time.time() > deadline:
            raise Infra(f"no fingerprint row for {helper} within 30s: {out}")
        time.sleep(0.2)


def fp_role(a, role, db):
    setup_role(a, role, [db], [f"GRANT SELECT ON public.pc_orders TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {db} SET sql_firewall.mode = 'permissive'",
                               f"ALTER ROLE {role} IN DATABASE {db} SET sql_firewall.enable_fingerprint_learning = 'on'",
                               # A false SELECT approval keeps the command unapproved
                               # while permissive observes fingerprint policy.
                               f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', false)"])
    approve(a, role, "BEGIN", "SHOW", "COMMIT")


def pending_rows(a, role):
    sync_activity(a)
    return int(value(a, f"SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '{role}' "
                        f"AND command_type = 'SELECT' AND action = 'ALLOWED (PERMISSIVE - FINGERPRINT)'"))


def fingerprint_paths(c):
    """Fingerprint approval, block, direct DML, TRUNCATE, uncommitted approval, old snapshot."""
    a = admin()
    role = "qa_pc_fp"
    fp, norm = fingerprint_identity()
    fp_role(a, role, DB)
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET default_transaction_isolation = 'repeatable read'")
    must(a, f"INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) "
            f"VALUES ('{fp}', $n${norm}$n$, '{role}', 'SELECT', 'seeded', 1, true)")
    e = Conn("existing", role, DB)

    def step(what, conn, approved):
        before = pending_rows(a, role)
        out = conn.q(FP_STATEMENT)
        if not out.startswith("OK"):
            raise Infra(f"{what}: {out}")
        c.equal(f"{what}: fingerprint treated as {'approved' if approved else 'not approved'}",
                pending_rows(a, role) - before, 0 if approved else 1)

    step("warm, approved", e, True)
    step("warm again", e, True)
    must(a, f"SELECT public.sql_firewall_block_fingerprint('{fp}', '{role}', 'SELECT')")
    step("existing session after block", e, False)
    second = Conn("second", role, DB)
    step("new session after block", second, False)
    must(a, f"SELECT public.sql_firewall_approve_fingerprint('{fp}', '{role}', 'SELECT')")
    step("after approve", e, True)
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = false WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    step("after direct UPDATE false", e, False)
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = true WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    step("after direct UPDATE true", e, True)
    must(a, f"DELETE FROM public.sql_firewall_query_fingerprints WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    step("after direct DELETE", e, False)
    must(a, f"INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) "
            f"VALUES ('{fp}', $n${norm}$n$, '{role}', 'SELECT', 'seeded', 1, true)")
    step("after direct INSERT approved", e, True)
    must(a, "CREATE TEMP TABLE pc_fp_saved AS SELECT * FROM public.sql_firewall_query_fingerprints")
    must(a, "TRUNCATE public.sql_firewall_query_fingerprints")
    step("after TRUNCATE", e, False)
    must(a, "INSERT INTO public.sql_firewall_query_fingerprints SELECT * FROM pc_fp_saved")
    step("after restoring rows", e, True)
    # Uncommitted approval and rollback.
    must(a, f"SELECT public.sql_firewall_block_fingerprint('{fp}', '{role}', 'SELECT')")
    w = admin(label="writer")
    must(w, "BEGIN")
    must(w, f"SELECT public.sql_firewall_approve_fingerprint('{fp}', '{role}', 'SELECT')")
    step("concurrent session during uncommitted approval", second, False)
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    step("after rollback", second, False)
    # Old snapshot: an open REPEATABLE READ transaction, then a committed block.
    must(a, f"SELECT public.sql_firewall_approve_fingerprint('{fp}', '{role}', 'SELECT')")
    o = Conn("old", role, DB)
    c.equal("old BEGIN", o.q("BEGIN"), "OK")
    c.equal("old isolation", o.q("SHOW transaction_isolation"), "OK rows=1: repeatable read")
    before = pending_rows(a, role)
    c.expect("old statement while approved", o.q(FP_STATEMENT), "allow", role, "SELECT")
    must(a, f"SELECT public.sql_firewall_block_fingerprint('{fp}', '{role}', 'SELECT')")
    c.expect("old statement after the block", o.q(FP_STATEMENT), "allow", role, "SELECT")
    c.equal("old COMMIT", o.q("COMMIT"), "OK")
    c.equal("old transaction: approved first, not approved after the block", pending_rows(a, role) - before, 1)
    step("new session after old transaction", Conn("third", role, DB), False)
    c.equal("command approvals (oracle precondition)", approvals(a, role), "BEGIN=true,COMMIT=true,SELECT=false,SHOW=true")
    for x in (e, second, w, o):
        x.close()
    return f"fingerprint {fp}: management approve/block, direct UPDATE/DELETE/INSERT, and TRUNCATE took effect at once for existing and new sessions; an uncommitted approval and its rollback authorized nobody else; an open REPEATABLE READ transaction saw the committed block at its next statement"


def fingerprint_worker_and_memo(c):
    """A learn-mode memo is not policy; the worker's committed fingerprint approval is."""
    a = admin()
    role = "qa_pc_fpw"
    statement = "SELECT count(*) FROM public.pc_orders WHERE id = 2"
    fp_role(a, role, DB)
    learner = admin(label="learn-session")
    must(learner, "SET sql_firewall.mode = learn")
    must(learner, "SET sql_firewall.enable_fingerprint_learning = on")
    must(learner, "SET sql_firewall.fingerprint_learn_threshold = 1")
    must(learner, f"SET ROLE {role}")
    reader = Conn("permissive", role, DB)
    before = pending_rows(a, role)
    pause_worker(a)
    c.expect("learn-mode execution (memo + queued approval)", learner.q(statement), "allow", role, "SELECT")
    c.equal("fingerprint rows while paused", value(a, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}'"), "0")
    c.expect("permissive reader while only queued", reader.q(statement), "allow", role, "SELECT")
    resume_worker(a)
    # The activity record is written after the resume, with the decision the
    # reader got while the approval was only queued (README 6.7).
    c.equal("permissive reader ignored the learn memo (logged not approved)", pending_rows(a, role) - before, 1)
    deadline = time.time() + 30
    while value(a, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}' AND is_approved") != "1":
        if time.time() > deadline:
            raise Infra("the worker did not persist the fingerprint within 30s")
        time.sleep(0.2)
    before = pending_rows(a, role)
    c.expect("permissive reader after the worker committed", reader.q(statement), "allow", role, "SELECT")
    c.equal("worker-committed approval applies", pending_rows(a, role) - before, 0)
    c.equal("command approvals (oracle precondition)", approvals(a, role), "BEGIN=true,COMMIT=true,SELECT=false,SHOW=true")
    for x in (learner, reader):
        x.close()
    return "a learn-mode fingerprint memo was not used by a permissive session while the approval was only queued; the worker's committed approval was used right after it committed"


def fingerprint_reinstall(c):
    """F4 for fingerprints: DROP/CREATE EXTENSION."""
    a = admin(DBL)
    role = "qa_pc_fpl"
    fp, norm = fingerprint_identity(DBL)
    fp_role(a, role, DBL)
    must(a, f"INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) "
            f"VALUES ('{fp}', $n${norm}$n$, '{role}', 'SELECT', 'seeded', 1, true)")
    e = Conn("existing", role, DBL)
    before = pending_rows(a, role)
    c.expect("warm", e.q(FP_STATEMENT), "allow", role, "SELECT")
    c.equal("approved before reinstall", pending_rows(a, role) - before, 0)
    must(a, "DROP EXTENSION sql_firewall")
    must(a, "CREATE EXTENSION sql_firewall")
    must(a, f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', false)")
    c.expect("after reinstall", e.q(FP_STATEMENT), "allow", role, "SELECT")
    c.equal("new installation's empty catalog applies (logged not approved)", pending_rows(a, role), 1)
    c.equal("command approvals (oracle precondition)", approvals(a, role), "SELECT=false")
    e.close()
    return "after DROP/CREATE EXTENSION the old installation's cached fingerprint approval was not used"


# ---------------------------------------------------------------------------
# Intra-statement publication of uncommitted policy (Phase 5A revision).
#
# A RETURNING expression, and any user AFTER-row trigger sorting before the
# extension's, run after the policy row is inserted. A policy lookup nested
# there must not publish the writing transaction's own uncommitted decision:
# another session could use it, and a rollback cannot withdraw it. The
# observation that matters is what an independent connection decides, so
# every check below asks one, and never clears the cache.
# ---------------------------------------------------------------------------
APP_Q = "SELECT count(*) FROM public.pc_orders"


def probe_function(a, role, name, statement=APP_Q):
    """A SECURITY DEFINER function owned by `role`, so its body is inspected
    as that role. It reports the nested decision instead of raising, which
    keeps the enclosing statement and transaction usable."""
    must(a, f"""CREATE FUNCTION public.{name}() RETURNS text LANGUAGE plpgsql SECURITY DEFINER
                SET search_path = pg_catalog, public AS $probe$
                BEGIN
                    PERFORM {statement.replace("SELECT ", "", 1)};
                    RETURN 'allowed';
                EXCEPTION WHEN insufficient_privilege THEN
                    RETURN 'denied: ' || SQLERRM;
                END $probe$""")
    must(a, f"ALTER FUNCTION public.{name}() OWNER TO {role}")


def nested(out):
    """The single RETURNING value of a probe call."""
    return out.split(": ", 1)[1] if out.startswith("OK rows=1: ") else out


def returning_insert(c):
    """An approval inserted with a policy-reading RETURNING function."""
    a = admin()
    role = "qa_pc_ret"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    probe_function(a, role, "qa_pc_ret_probe")
    c.expect("baseline: new session", once(role, APP_Q), "norule", role, "SELECT")
    w = admin(label="writer")
    must(w, "SET sql_firewall.mode = enforce")
    must(w, "BEGIN")
    out = must(w, f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) "
                  f"VALUES ('{role}', 'SELECT', true) RETURNING public.qa_pc_ret_probe()")
    c.equal("nested read in RETURNING sees the writer's own approval", nested(out), "allowed")
    c.equal("SELECT approval seen by another session", select_state(a, role), "absent")
    c.expect("concurrent session while uncommitted", once(role, APP_Q), "norule", role, "SELECT")
    c.expect("second concurrent session while uncommitted", once(role, APP_Q), "norule", role, "SELECT")
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.equal("SELECT approval after rollback", select_state(a, role), "absent")
    c.expect("new session after rollback", once(role, APP_Q), "norule", role, "SELECT")
    c.expect("another new session after rollback (no cache clear)", once(role, APP_Q), "norule", role, "SELECT")
    return ("a nested policy read inside RETURNING saw the writer's own uncommitted approval and did not publish it: "
            "concurrent sessions stayed denied while the transaction was open and after ROLLBACK, with no cache clear")


def returning_savepoint(c):
    """The same insert inside a savepoint that is rolled back, then committed."""
    a = admin()
    role = "qa_pc_retsp"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    probe_function(a, role, "qa_pc_retsp_probe")
    w = admin(label="writer")
    must(w, "SET sql_firewall.mode = enforce")
    must(w, "BEGIN")
    must(w, "SAVEPOINT qa_ret")
    out = must(w, f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) "
                  f"VALUES ('{role}', 'SELECT', true) RETURNING public.qa_pc_retsp_probe()")
    c.equal("nested read inside the savepoint", nested(out), "allowed")
    c.expect("concurrent session while uncommitted", once(role, APP_Q), "norule", role, "SELECT")
    must(w, "ROLLBACK TO SAVEPOINT qa_ret")
    c.expect("concurrent session after ROLLBACK TO SAVEPOINT", once(role, APP_Q), "norule", role, "SELECT")
    must(w, "INSERT INTO public.pc_orders VALUES (401)")
    c.equal("COMMIT", w.q("COMMIT"), "OK")
    c.equal("marker row committed by the same transaction", value(a, "SELECT count(*) FROM public.pc_orders WHERE id = 401"), "1")
    c.equal("SELECT approval after commit", select_state(a, role), "absent")
    c.expect("new session after commit", once(role, APP_Q), "norule", role, "SELECT")
    return ("an approval inserted with a policy-reading RETURNING function and rolled back to a savepoint authorized "
            "nobody, during the transaction or after the enclosing transaction really committed (marker row visible)")


def returning_user_trigger(c):
    """A user AFTER-row trigger that sorts before the extension's."""
    a = admin()
    role = "qa_pc_rettrg"
    t = "public.sql_firewall_command_approvals"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    must(a, f"""CREATE FUNCTION public.qa_pc_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
                SET search_path = pg_catalog, public AS $audit$
                BEGIN
                    PERFORM count(*) FROM public.pc_orders;
                    RETURN NEW;
                EXCEPTION WHEN insufficient_privilege THEN
                    RETURN NEW;
                END $audit$""")
    must(a, f"ALTER FUNCTION public.qa_pc_audit() OWNER TO {role}")
    must(a, f"CREATE TRIGGER aaa_qa_pc_audit AFTER INSERT ON {t} FOR EACH ROW "
            f"WHEN (NEW.role_name = '{role}') EXECUTE FUNCTION public.qa_pc_audit()")
    try:
        # AFTER row triggers (row bit set, BEFORE bit clear), in firing
        # order. The extension's BEFORE row guard is not among them.
        c.equal("user trigger sorts before the extension's",
                value(a, f"SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_catalog.pg_trigger "
                         f"WHERE tgrelid = '{t}'::regclass AND NOT tgisinternal AND tgtype & 3 = 1"),
                "aaa_qa_pc_audit,sql_firewall_policy_changed")
        c.expect("baseline: new session", once(role, APP_Q), "norule", role, "SELECT")
        w = admin(label="writer")
        must(w, "SET sql_firewall.mode = enforce")
        must(w, "BEGIN")
        must(w, f"INSERT INTO {t} (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', true)")
        c.equal("SELECT approval seen by another session", select_state(a, role), "absent")
        c.expect("concurrent session while uncommitted", once(role, APP_Q), "norule", role, "SELECT")
        c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
        c.equal("SELECT approval after rollback", select_state(a, role), "absent")
        c.expect("new session after rollback", once(role, APP_Q), "norule", role, "SELECT")
    finally:
        must(a, f"DROP TRIGGER IF EXISTS aaa_qa_pc_audit ON {t}")
    return ("a user AFTER-row trigger running before the extension's, reading policy as the application role, did not "
            "publish the writing transaction's uncommitted approval; the trigger was removed afterwards")


def returning_cached_opposite(c):
    """UPDATE and DELETE with RETURNING, against an already-cached opposite decision."""
    a = admin()
    role = "qa_pc_retdml"
    t = "public.sql_firewall_command_approvals"
    where = f"WHERE role_name = '{role}' AND command_type = 'SELECT'"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}",
                               f"INSERT INTO {t} (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', false)"])
    probe_function(a, role, "qa_pc_retdml_probe")
    w = admin(label="writer")
    must(w, "SET sql_firewall.mode = enforce")
    c.expect("warm the cache with the committed denial", once(role, APP_Q), "pending", role, "SELECT")
    # UPDATE to true against a cached false.
    must(w, "BEGIN")
    out = must(w, f"UPDATE {t} SET is_approved = true {where} RETURNING public.qa_pc_retdml_probe()")
    c.equal("nested read beats the cached denial (own write)", nested(out), "allowed")
    c.expect("concurrent session keeps the committed denial", once(role, APP_Q), "pending", role, "SELECT")
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.equal("committed approval after rollback", select_state(a, role), "false")
    c.expect("new session after rollback", once(role, APP_Q), "pending", role, "SELECT")
    # The same UPDATE, committed.
    must(w, "BEGIN")
    out = must(w, f"UPDATE {t} SET is_approved = true {where} RETURNING public.qa_pc_retdml_probe()")
    c.equal("nested read before COMMIT", nested(out), "allowed")
    c.equal("COMMIT", w.q("COMMIT"), "OK")
    c.equal("committed approval", select_state(a, role), "true")
    c.expect("new session after COMMIT", once(role, APP_Q), "allow", role, "SELECT")
    # UPDATE to false against a cached true.
    must(w, "BEGIN")
    out = must(w, f"UPDATE {t} SET is_approved = false {where} RETURNING public.qa_pc_retdml_probe()")
    c.equal("nested read beats the cached allow (own write)", nested(out).split(":")[0], "denied")
    c.expect("concurrent session keeps the committed allow", once(role, APP_Q), "allow", role, "SELECT")
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.expect("new session after rollback", once(role, APP_Q), "allow", role, "SELECT")
    # DELETE against a cached true.
    must(w, "BEGIN")
    out = must(w, f"DELETE FROM {t} {where} RETURNING public.qa_pc_retdml_probe()")
    c.equal("nested read after its own DELETE", nested(out).split(":")[0], "denied")
    c.expect("concurrent session keeps the committed allow", once(role, APP_Q), "allow", role, "SELECT")
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.equal("row restored by rollback", select_state(a, role), "true")
    c.expect("new session after rollback", once(role, APP_Q), "allow", role, "SELECT")
    # The same DELETE, committed: also shows the row really is removed.
    must(w, f"DELETE FROM {t} {where}")
    c.equal("committed DELETE removed the row", select_state(a, role), "absent")
    c.expect("new session after the committed DELETE", once(role, APP_Q), "norule", role, "SELECT")
    return ("with the opposite decision already cached, an uncommitted UPDATE or DELETE applied to its own transaction "
            "only: concurrent sessions kept the committed decision, rollback restored the row, and each committed "
            "change (UPDATE to true, DELETE) took effect at once for new sessions")


def returning_fingerprint(c):
    """The fingerprint path: an approved fingerprint inserted with RETURNING."""
    a = admin()
    role = "qa_pc_retfp"
    fp, norm = fingerprint_identity()
    fp_role(a, role, DB)
    probe_function(a, role, "qa_pc_retfp_probe", FP_STATEMENT)
    t = "public.sql_firewall_query_fingerprints"
    row = (f"INSERT INTO {t} (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) "
           f"VALUES ('{fp}', $n${norm}$n$, '{role}', 'SELECT', 'seeded', 1, true)")

    def concurrent(what, approved):
        before = pending_rows(a, role)
        out = once(role, FP_STATEMENT, label=f"fp-{what}")
        if not out.startswith("OK"):
            raise Infra(f"{what}: the statement did not run: {out}")
        c.equal(f"{what}: fingerprint treated as {'approved' if approved else 'not approved'}",
                pending_rows(a, role) - before, 0 if approved else 1)

    concurrent("before any policy write", False)
    w = admin(label="writer")
    must(w, "SET sql_firewall.mode = permissive")
    must(w, "SET sql_firewall.enable_fingerprint_learning = on")
    must(w, "BEGIN")
    out = must(w, f"{row} RETURNING public.qa_pc_retfp_probe()")
    c.equal("nested run inside RETURNING", nested(out), "allowed")
    c.equal("fingerprint rows seen by another session",
            value(a, f"SELECT count(*) FROM {t} WHERE role_name = '{role}'"), "0")
    concurrent("concurrent session while uncommitted", False)
    c.equal("writer ROLLBACK", w.q("ROLLBACK"), "OK")
    c.equal("fingerprint rows after rollback",
            value(a, f"SELECT count(*) FROM {t} WHERE role_name = '{role}'"), "0")
    concurrent("new session after rollback", False)
    # Positive control: the same oracle reports an approved fingerprint as approved.
    must(a, row)
    concurrent("after the identical row is committed (positive control)", True)
    c.equal("command approvals (oracle precondition)", approvals(a, role), "BEGIN=true,COMMIT=true,SELECT=false,SHOW=true")
    return (f"fingerprint {fp}: an approved fingerprint inserted with a RETURNING function that runs the fingerprinted "
            f"statement was not published; concurrent sessions logged it as not approved while uncommitted and after "
            f"rollback, and as approved once the identical row committed (positive control)")


def isolation(c):
    """Database and role isolation, including a role rename."""
    a = admin()
    a2 = admin(DB2, "admin-other-db")
    role, other_role = "qa_pc_iso", "qa_pc_iso_other"
    setup_role(a, role, [DB, DB2], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    setup_role(a, other_role, [DB], [f"GRANT SELECT ON public.pc_orders TO {other_role}"])
    must(a2, f"GRANT SELECT ON public.pc_orders TO {role}")
    approve(a, role, "SELECT")
    q = "SELECT count(*) FROM public.pc_orders"
    c.expect("approved role, this database", once(role, q), "allow", role, "SELECT")
    c.expect("same role, other installed database", once(role, q, DB2), "norule", role, "SELECT")
    c.expect("other role, this database", once(other_role, q), "norule", other_role, "SELECT")
    must(a, f"ALTER ROLE {role} RENAME TO {role}_renamed")
    c.expect("renamed role (approval names the old name)", once(f"{role}_renamed", q), "norule", f"{role}_renamed", "SELECT")
    must(a, f"ALTER ROLE {role}_renamed RENAME TO {role}")
    c.expect("renamed back", once(role, q), "allow", role, "SELECT")
    a2.close()
    return "a warm approval did not authorize the same role in another installed database, another role, or the role after a rename"


def management_privileges(c):
    """Ordinary roles cannot change policy or the caches."""
    a = admin()
    role = "qa_pc_priv"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    approve(a, role, "SELECT", "INSERT", "UPDATE", "TRUNCATE")
    denied = {
        f"SELECT public.sql_firewall_approve_command('{role}', 'DELETE')": "permission denied for function sql_firewall_approve_command",
        "SELECT public.sql_firewall_clear_approval_cache()": "permission denied for function sql_firewall_clear_approval_cache",
        f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'DELETE', true)": "permission denied for table sql_firewall_command_approvals",
        f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = true": "permission denied for table sql_firewall_query_fingerprints",
        "TRUNCATE public.sql_firewall_command_approvals": "permission denied for table sql_firewall_command_approvals",
        "TRUNCATE public.sql_firewall_query_fingerprints": "permission denied for table sql_firewall_query_fingerprints",
        "SELECT public.sql_firewall_policy_changed()": "permission denied for function sql_firewall_policy_changed",
    }
    for sql, message in denied.items():
        c.equal(f"ordinary role: {sql}", once(role, sql), f"ERR 42501 {message}")
    return "an ordinary role with the relevant firewall command approvals was refused by native privileges for the management functions, cache clearing, and policy DML/TRUNCATE"


def main():
    for db in (DB, DBL, DB2):
        x = admin(db, f"setup-{db}")
        must(x, "CREATE TABLE public.pc_orders (id integer)")
        must(x, "INSERT INTO public.pc_orders VALUES (1), (2)")
        x.close()
    run("committed_revoke", "warm allow, committed revoke", committed_revoke)
    run("committed_approve", "warm denial, committed approve", committed_approve)
    run("uncommitted_rollback", "uncommitted approval, writer rollback", uncommitted_and_rollback)
    run("savepoints", "savepoint rollback, release and commit", savepoints)
    run("old_snapshot_rr", "REPEATABLE READ snapshot, committed revoke", lambda c: old_snapshot(c, "repeatable read", "qa_pc_rr"))
    run("old_snapshot_serializable", "SERIALIZABLE snapshot, committed revoke", lambda c: old_snapshot(c, "serializable", "qa_pc_ser"))
    run("reinstall", "DROP/CREATE EXTENSION", reinstall)
    run("installation_rollback", "rolled-back installation changes", installation_rollback)
    run("direct_dml", "direct superuser DML and TRUNCATE", direct_dml)
    run("trigger_ddl", "invalidation trigger disabled and re-enabled", trigger_ddl)
    run("worker_command", "worker-persisted approval", worker_command)
    run("fingerprint", "fingerprint approval, block, DML, old snapshot", fingerprint_paths)
    run("fingerprint_worker", "learn memo and worker-persisted fingerprint", fingerprint_worker_and_memo)
    run("fingerprint_reinstall", "fingerprint cache across reinstall", fingerprint_reinstall)
    run("returning_insert", "uncommitted approval read by RETURNING", returning_insert)
    run("returning_savepoint", "RETURNING inside a rolled-back savepoint", returning_savepoint)
    run("returning_user_trigger", "earlier user trigger reading policy", returning_user_trigger)
    run("returning_cached_opposite", "RETURNING UPDATE/DELETE against a cached opposite decision", returning_cached_opposite)
    run("returning_fingerprint", "uncommitted fingerprint approval read by RETURNING", returning_fingerprint)
    run("isolation", "database and role isolation", isolation)
    run("privileges", "management privileges", management_privileges)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        emit("INFRA", "setup", str(exc))
