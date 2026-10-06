#!/usr/bin/env python3
"""A reader racing a policy commit (qa/probe/07_policy_publish_race.sh).

policy_probe build only. A reader session with
sql_firewall_probe.hold_publish set stops after its policy catalog read and
before it publishes the result to the shared cache, waiting for a shared
advisory lock that a holder session keeps exclusively. The test waits until
pg_locks shows the reader waiting there, commits a policy change, releases the
reader, and then inspects the cache entry and new sessions' decisions.

Output and evidence as in qa/policy_cache.py, whose connection and check
helpers are reused.
"""
import ctypes, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import policy_cache as pc  # noqa: E402

lib = pc.lib
lib.PQsendQuery.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.PQgetResult.restype = ctypes.c_void_p
lib.PQgetResult.argtypes = [ctypes.c_void_p]
lib.PQbackendPID.argtypes = [ctypes.c_void_p]

DB = pc.DB
HOLD_KEY = 20260928
Q = "SELECT count(*) FROM public.pc_orders"


class Reader(pc.Conn):
    """A session whose next statement is sent without waiting for its result."""

    def __init__(self, role, cache):
        super().__init__("reader", role, DB, options=f"-c sql_firewall_probe.hold_publish={cache}")
        self.pid = lib.PQbackendPID(self.conn)

    def send(self, sql):
        self.sent = sql
        pc.note(f"    [reader pid={self.pid}] sent without waiting: {sql}")
        if lib.PQsendQuery(self.conn, sql.encode()) != 1:
            raise pc.Infra(f"PQsendQuery failed: {lib.PQerrorMessage(self.conn).decode(errors='replace')}")

    def finish(self):
        out = None
        while True:
            res = lib.PQgetResult(self.conn)
            if not res:
                break
            if out is None:
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
        pc.note(f"    [reader pid={self.pid}] result of {self.sent}\n        => {out}")
        return out or "ERR ? no result"


def wait_held(a, reader):
    """Positive evidence that the reader is waiting at the hold point."""
    deadline = time.time() + 30
    sql = (f"SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND objid = {HOLD_KEY} "
           f"AND objsubid = 1 AND mode = 'ShareLock' AND NOT granted AND pid = {reader.pid}")
    while pc.value(a, sql) != "1":
        if time.time() > deadline:
            raise pc.Infra(f"reader pid {reader.pid} did not reach the hold point within 30s")
        time.sleep(0.1)


def hold(label="holder"):
    h = pc.admin(label=label)
    pc.must(h, "BEGIN")
    pc.must(h, f"SELECT pg_catalog.pg_advisory_xact_lock({HOLD_KEY})")
    return h


def approval_state(a, role):
    return pc.value(a, f"SELECT public.sql_firewall_policy_probe_approval('{role}', 'SELECT')").split(" entry_")[0].split(" generation=")[0]


def race_revoke(c):
    """A cached allow must not be published after a revoke commits during the read."""
    a = pc.admin()
    role = "qa_pr_revoke"
    pc.setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}"])
    pc.approve(a, role, "SELECT")
    c.equal("cache before", approval_state(a, role), "absent")
    h = hold()
    r = Reader(role, "approvals")
    r.send(Q)
    wait_held(a, r)
    c.equal("cache while the reader is held after its read", approval_state(a, role), "absent")
    pc.must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
    c.equal("revoke committed", pc.select_state(a, role), "false")
    c.equal("holder COMMIT (releases the reader)", h.q("COMMIT"), "OK")
    c.expect("held reader's statement (read before the revoke committed)", r.finish(), "allow", role, "SELECT")
    c.equal("cache after the racing reader", approval_state(a, role), "absent")
    c.expect("new session", pc.once(role, Q), "pending", role, "SELECT")
    c.equal("cache after an unraced read (positive control)", approval_state(a, role), "current approved=false")
    c.expect("existing session", r.q(Q), "pending", role, "SELECT")
    return "a reader held between its catalog read (allow) and publication while a revoke committed did not publish its allow; the next sessions were denied and an unraced read published the committed denial"


def race_approve(c):
    """A cached denial must not be published after an approval commits during the read."""
    a = pc.admin()
    role = "qa_pr_approve"
    pc.setup_role(a, role, [DB], [f"GRANT SELECT ON public.pc_orders TO {role}",
                                  f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('{role}', 'SELECT', false)"])
    c.equal("cache before", approval_state(a, role), "absent")
    h = hold()
    r = Reader(role, "approvals")
    r.send(Q)
    wait_held(a, r)
    pc.approve(a, role, "SELECT")
    c.equal("approval committed", pc.select_state(a, role), "true")
    c.equal("holder COMMIT (releases the reader)", h.q("COMMIT"), "OK")
    c.expect("held reader's statement (read before the approval committed)", r.finish(), "pending", role, "SELECT")
    c.equal("cache after the racing reader", approval_state(a, role), "absent")
    c.expect("new session", pc.once(role, Q), "allow", role, "SELECT")
    c.equal("cache after an unraced read (positive control)", approval_state(a, role), "current approved=true")
    c.expect("existing session", r.q(Q), "allow", role, "SELECT")
    return "a reader held between its catalog read (denial) and publication while an approval committed did not publish its denial; the next sessions were allowed"


def race_fingerprint(c):
    """A cached fingerprint approval must not be published after a block commits during the read."""
    a = pc.admin()
    role = "qa_pr_fp"
    fp, norm = pc.fingerprint_identity()
    pc.fp_role(a, role, DB)
    pc.must(a, f"INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) "
               f"VALUES ('{fp}', $n${norm}$n$, '{role}', 'SELECT', 'seeded', 1, true)")

    def state():
        out = pc.value(a, f"SELECT public.sql_firewall_policy_probe_fingerprint('{role}', '{fp}', 'SELECT')")
        return out.split(" entry_")[0].split(" generation=")[0]

    c.equal("cache before", state(), "absent")
    h = hold()
    r = Reader(role, "fingerprints")
    before = pc.pending_rows(a, role)
    r.send(pc.FP_STATEMENT)
    wait_held(a, r)
    pc.must(a, f"SELECT public.sql_firewall_block_fingerprint('{fp}', '{role}', 'SELECT')")
    c.equal("holder COMMIT (releases the reader)", h.q("COMMIT"), "OK")
    out = r.finish()
    if not out.startswith("OK"):
        raise pc.Infra(f"held reader: {out}")
    c.equal("held reader treated the fingerprint as approved (read before the block)", pc.pending_rows(a, role) - before, 0)
    c.equal("cache after the racing reader", state(), "absent")
    before = pc.pending_rows(a, role)
    out = pc.once(role, pc.FP_STATEMENT)
    if not out.startswith("OK"):
        raise pc.Infra(f"new session: {out}")
    c.equal("new session treated the fingerprint as not approved", pc.pending_rows(a, role) - before, 1)
    c.equal("cache after an unraced read (positive control)", state(), "current state=Pending")
    c.equal("command approvals (oracle precondition)", pc.approvals(a, role), "BEGIN=true,COMMIT=true,SELECT=false,SHOW=true")
    return f"fingerprint {fp}: a reader held between its catalog read (approved) and publication while a block committed did not publish the approval; the next session logged it as not approved"


def probe_build(c):
    """The probe build is the one under test: its functions exist here."""
    a = pc.admin()
    c.equal("probe functions in this build", pc.value(a, "SELECT count(*) FROM pg_catalog.pg_proc WHERE proname::text LIKE 'sql_firewall_policy_probe_%'"), "2")
    return "the policy_probe functions are present in this (probe) build; tests/99 checks they are absent from the release build"


def main():
    x = pc.admin(label="setup")
    pc.must(x, "CREATE TABLE public.pc_orders (id integer)")
    pc.must(x, "INSERT INTO public.pc_orders VALUES (1), (2)")
    x.close()
    pc.run("probe_build", "probe functions present", probe_build)
    pc.run("race_revoke", "reader racing a committed revoke", race_revoke)
    pc.run("race_approve", "reader racing a committed approval", race_approve)
    pc.run("race_fingerprint", "reader racing a committed fingerprint block", race_fingerprint)


if __name__ == "__main__":
    try:
        main()
    except pc.Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
