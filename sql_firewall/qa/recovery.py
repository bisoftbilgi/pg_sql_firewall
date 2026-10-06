#!/usr/bin/env python3
"""Recovery paths (qa/tests/106_recovery.sh; README 6.1d).

  - ROLLBACK, ABORT, ROLLBACK AND CHAIN, and ROLLBACK TO SAVEPOINT need no
    approval and are not refused by any policy, in a healthy or a failed
    transaction; statements after them in the same message are still
    inspected.
  - With enforce, an empty policy, and sql_firewall.allow_superuser_auth_bypass
    off, a superuser is locked out like any role, and recovers through a
    connection that sets sql_firewall.enabled = off (a startup option: no
    statement has to pass the firewall first).
  - An ordinary role cannot use that path, or ALTER ROLE / ALTER DATABASE, to
    turn the firewall off or change its mode, even as the database owner.
"""
import os

import policy_cache as pc
from policy_cache import Infra, Conn, admin, must, value, once, run, setup_role, approve, lib, BASE, SU

DB = os.environ["QA_PC_DB"]


def try_connect(user, options):
    """The connection error message, or 'connected'."""
    conn = lib.PQconnectdb(f"{BASE} dbname={DB} user={user} application_name=qa_rec options='{options}'".encode())
    try:
        if lib.PQstatus(conn) == 0:
            return "connected"
        return lib.PQerrorMessage(conn).decode(errors="replace").strip()
    finally:
        lib.PQfinish(conn)


def rollbacks(c):
    a = admin()
    role = "qa_rec_app"
    setup_role(a, role, [DB], [f"GRANT SELECT, DELETE ON public.rec_t TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'"])
    approve(a, role, "BEGIN", "SELECT", "SAVEPOINT")
    u = Conn("app", role, DB)
    c.expect("an unapproved command is rejected (precondition)", u.q("DELETE FROM public.rec_t WHERE id = 0"), "norule", role, "DELETE")
    c.equal("healthy transaction: BEGIN", u.q("BEGIN"), "OK")
    c.expect("SELECT", u.q("SELECT count(*) FROM public.rec_t"), "allow", role, "SELECT")
    c.equal("ROLLBACK without an approval", u.q("ROLLBACK"), "OK")
    c.equal("transaction ended", u.txn(), "idle")
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("SAVEPOINT", u.q("SAVEPOINT s"), "OK")
    c.expect("SELECT inside the savepoint", u.q("SELECT count(*) FROM public.rec_t"), "allow", role, "SELECT")
    c.equal("ROLLBACK TO SAVEPOINT without an approval", u.q("ROLLBACK TO SAVEPOINT s"), "OK")
    c.equal("still in the transaction", u.txn(), "in-transaction")
    c.equal("ROLLBACK AND CHAIN", u.q("ROLLBACK AND CHAIN"), "OK")
    c.equal("chained transaction open", u.txn(), "in-transaction")
    c.equal("ABORT", u.q("ABORT"), "OK")
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.expect("rejected statement aborts the transaction", u.q("DELETE FROM public.rec_t WHERE id = 0"), "norule", role, "DELETE")
    c.equal("failed transaction", u.txn(), "in-failed-transaction")
    c.equal("ROLLBACK of the failed transaction", u.q("ROLLBACK"), "OK")
    c.equal("BEGIN", u.q("BEGIN"), "OK")
    c.equal("SAVEPOINT", u.q("SAVEPOINT s2"), "OK")
    c.equal("runtime error inside the savepoint", u.q("SELECT 1 / (count(*) - count(*)) FROM public.rec_t")[:9], "ERR 22012")
    c.equal("ROLLBACK TO SAVEPOINT of the failed savepoint", u.q("ROLLBACK TO SAVEPOINT s2"), "OK")
    c.expect("work continues after the savepoint", u.q("SELECT count(*) FROM public.rec_t"), "allow", role, "SELECT")
    c.equal("ROLLBACK", u.q("ROLLBACK"), "OK")
    c.expect("a statement after ROLLBACK in the same message is still inspected",
             u.q("ROLLBACK; DELETE FROM public.rec_t WHERE id = 0"), "norule", role, "DELETE")
    c.equal("rows untouched", value(a, "SELECT count(*) FROM public.rec_t"), "2")
    c.equal("no approval was created for the rollback statements",
            value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '{role}' AND command_type = 'ROLLBACK'"), "0")
    u.close()
    return ("in enforce with no ROLLBACK approval, ROLLBACK, ROLLBACK TO SAVEPOINT, ROLLBACK AND CHAIN, and ABORT ended the "
            "transaction or savepoint, healthy or failed; a DELETE after ROLLBACK in the same message was still rejected")


def superuser_lockout(c):
    a = admin(label="setup")
    must(a, f"ALTER DATABASE {DB} SET sql_firewall.allow_superuser_auth_bypass = off")
    a.close()
    try:
        s = Conn("superuser-locked", SU, DB)
        out = s.q("SELECT 1")
        c.equal("superuser without bypass under an empty enforce policy is rejected",
                out, f"ERR 42501 sql_firewall: No rule found for command 'SELECT' for role '{SU}'")
        out = s.q("SET sql_firewall.enabled = off")
        c.equal("its SET of the kill switch is itself a statement and is rejected",
                out, f"ERR 42501 sql_firewall: No rule found for command 'SET' for role '{SU}'")
        s.close()
        r = Conn("superuser-recovery", SU, DB, options="-c sql_firewall.enabled=off")
        c.equal("recovery connection: statements run", r.q("SELECT 1"), "OK rows=1: 1")
        c.equal("recovery connection: repair the setting", r.q(f"ALTER DATABASE {DB} RESET sql_firewall.allow_superuser_auth_bypass"), "OK")
        r.close()
        b = Conn("superuser-bypass-option", SU, DB, options="-c sql_firewall.allow_superuser_auth_bypass=on")
        c.equal("a bypass startup option also works", b.q("SELECT 1"), "OK rows=1: 1")
        b.close()
    finally:
        x = admin(label="cleanup", db="postgres")
        must(x, f"ALTER DATABASE {DB} RESET sql_firewall.allow_superuser_auth_bypass")
        x.close()
    n = Conn("superuser-after", SU, DB)
    c.equal("after repair a normal superuser connection works", n.q("SELECT 1"), "OK rows=1: 1")
    n.close()
    return ("with bypass off and an empty enforce policy a superuser's SELECT and its SET of the kill switch were rejected; a "
            "connection with the startup option sql_firewall.enabled=off (or allow_superuser_auth_bypass=on) ran and repaired it")


def ordinary_cannot_bypass(c):
    a = admin()
    role = "qa_rec_owner"
    setup_role(a, role, [DB], [f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'"])
    approve(a, role, "ALTER", "SET")  # command families (README 6.6a)
    must(a, f"ALTER DATABASE {DB} OWNER TO {role}")
    try:
        for option in ("-c sql_firewall.enabled=off", "-c sql_firewall.mode=learn", "-c sql_firewall.allow_superuser_auth_bypass=on"):
            got = try_connect(role, option)
            name = option.split("=")[0][3:]
            c.equal(f"connection with {option}", f'permission denied to set parameter "{name}"' in got, True)
            pc.note(f"        {option}: {got}")
        c.equal("ALTER ROLE self SET the kill switch",
                once(role, f"ALTER ROLE {role} SET sql_firewall.enabled = off"),
                'ERR 42501 permission denied to set parameter "sql_firewall.enabled"')
        c.equal("database owner: ALTER DATABASE SET the mode",
                once(role, f"ALTER DATABASE {DB} SET sql_firewall.mode = 'learn'"),
                'ERR 42501 permission denied to set parameter "sql_firewall.mode"')
        c.equal("SET the mode", once(role, "SET sql_firewall.mode = learn"),
                'ERR 42501 permission denied to set parameter "sql_firewall.mode"')
    finally:
        must(a, f"ALTER DATABASE {DB} OWNER TO {SU}")
    return ("an ordinary role, also as the database owner and with firewall approvals for the ALTER and SET families, "
            "could not turn the firewall off, change its mode, or enable superuser bypass through startup options, ALTER ROLE, "
            "ALTER DATABASE, or SET")


def main():
    x = admin(label="setup")
    must(x, "CREATE TABLE public.rec_t (id integer)")
    must(x, "INSERT INTO public.rec_t VALUES (1), (2)")
    x.close()
    run("rollbacks", "rollback statements need no approval", rollbacks)
    run("superuser_lockout", "locked-out superuser and its recovery path", superuser_lockout)
    run("ordinary_cannot_bypass", "an ordinary role cannot use the recovery path", ordinary_cannot_bypass)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
