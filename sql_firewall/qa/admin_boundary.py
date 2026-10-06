#!/usr/bin/env python3
"""Administration boundary scenarios (qa/tests/114_admin_boundary.sh;
README 6.1b "Who can change policy", 6.1a).

Reuses the libpq driver of qa/policy_cache.py. Separate connections in one
process make the order across sessions explicit.

  table_writes      a role holding explicit INSERT, UPDATE, DELETE, and
                    TRUNCATE grants on every table of the extension changes
                    none of them: each statement is refused by
                    sql_firewall_guard (42501), the tables are unchanged, and
                    it cannot approve itself or another role
  predefined_roles  pg_write_all_data membership and BYPASSRLS with an
                    explicit grant do not delegate it either; a superuser
                    session still writes directly and through the functions
  row_visibility    a role with write grants sees only its own approval and
                    fingerprint rows; a pg_read_all_data member sees all
  membership        ALTER EXTENSION ... DROP TABLE of a required policy
                    relation makes an existing session's next statement
                    unavailable (55000), ADD TABLE repairs both that session
                    and one that saw the error, and a rolled-back DROP
                    changes nothing (regression review 2026-10-05, R2)
"""
import os

import policy_cache as pc
from policy_cache import Infra, Conn, admin, must, value, once, run, setup_role, approve

DB = os.environ["QA_PC_DB"]
TABLES = {
    "sql_firewall_activity_log": "log_id",
    "sql_firewall_blocked_queries": "block_id",
    "sql_firewall_command_approvals": "is_approved",
    "sql_firewall_query_fingerprints": "is_approved",
    "sql_firewall_regex_rules": "is_active",
    "sql_firewall_regex_default_removals": "removed_at",
    "sql_firewall_policy_epoch": "epoch",
    "sql_firewall_policy_history": "change_id",
    "sql_firewall_fingerprint_hits": "fingerprint",
    "sql_firewall_consumer_checkpoint": "singleton",
    "sql_firewall_activity_checkpoint": "singleton",
    "sql_firewall_retention_status": "runs",
}


def guard(table):
    return (f"ERR 42501 sql_firewall: only a superuser session can change {table}; "
            "table privileges granted to other roles do not delegate firewall administration")


def digest(a):
    """Every table's content except the audit logs the canaries add to."""
    parts = " UNION ALL ".join(
        f"SELECT '{t}' || row_to_json(x)::text AS r FROM public.{t} x" for t in TABLES
        if t not in ("sql_firewall_activity_log", "sql_firewall_blocked_queries",
                     "sql_firewall_consumer_checkpoint", "sql_firewall_activity_checkpoint",
                     "sql_firewall_retention_status"))
    return value(a, f"SELECT md5(string_agg(r, E'\\n' ORDER BY r)) FROM ({parts}) s")


def writer_role(a, role, extra=()):
    """An enforce-mode role whose write statements the firewall allows, so
    that what refuses them is the table guard."""
    setup_role(a, role, [DB], [f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.enable_regex_scan = 'off'",
                               *extra])
    approve(a, role, "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")


def attempts(role, table, column):
    return [
        ("INSERT", once(role, f"INSERT INTO public.{table} DEFAULT VALUES")),
        ("UPDATE", once(role, f"UPDATE public.{table} SET {column} = {column}")),
        ("DELETE", once(role, f"DELETE FROM public.{table}")),
        ("TRUNCATE", once(role, f"TRUNCATE public.{table}")),
    ]


def table_writes(c):
    a = admin()
    role, victim = "qa_ab_writer", "qa_ab_victim"
    writer_role(a, role, [f"GRANT ALL ON TABLE public.{t} TO {role}" for t in TABLES])
    setup_role(a, victim, [DB])
    must(a, f"SELECT public.sql_firewall_revoke_command('{victim}', 'DELETE')")
    before = digest(a)
    for table, column in TABLES.items():
        for op, out in attempts(role, table, column):
            c.equal(f"{op} {table}", out, guard(table))
    c.equal("self-approval", once(role, "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) "
                                        f"VALUES ('{role}', 'CREATE', true)"), guard("sql_firewall_command_approvals"))
    c.equal("approving another role", once(role, f"UPDATE public.sql_firewall_command_approvals SET is_approved = true "
                                                 f"WHERE role_name = '{victim}' AND command_type = 'DELETE'"),
            guard("sql_firewall_command_approvals"))
    c.equal("tables unchanged", digest(a), before)
    c.equal("victim's denial unchanged", pc.approvals(a, victim), "DELETE=false")
    return (f"a role granted ALL on all {len(TABLES)} tables was refused (42501, sql_firewall_guard) for INSERT, UPDATE, "
            "DELETE, and TRUNCATE on each, could not approve itself or another role, and changed nothing")


def predefined_roles(c):
    a = admin()
    pwad, bypass = "qa_ab_pwad", "qa_ab_bypass"
    writer_role(a, pwad, [f"GRANT pg_write_all_data TO {pwad}"])
    writer_role(a, bypass, [f"ALTER ROLE {bypass} BYPASSRLS",
                            f"GRANT SELECT, UPDATE ON public.sql_firewall_command_approvals TO {bypass}"])
    before = digest(a)
    table = "sql_firewall_command_approvals"
    for role in (pwad, bypass):
        c.equal(f"{role}: UPDATE approvals", once(role, f"UPDATE public.{table} SET is_approved = true"), guard(table))
    c.equal(f"{pwad}: DELETE regex rules", once(pwad, "DELETE FROM public.sql_firewall_regex_rules"),
            guard("sql_firewall_regex_rules"))
    c.equal(f"{pwad}: DELETE history", once(pwad, "DELETE FROM public.sql_firewall_policy_history"),
            guard("sql_firewall_policy_history"))
    c.equal("tables unchanged", digest(a), before)
    # Positive control: a superuser session writes directly and through the functions.
    history = (f"SELECT count(*) FROM public.sql_firewall_policy_history WHERE new_role_name = '{pwad}' "
               "AND new_command_type = 'TRUNCATE' AND source = 'administrator'")
    recorded = int(value(a, history))
    must(a, f"UPDATE public.{table} SET is_approved = false WHERE role_name = '{pwad}' AND command_type = 'TRUNCATE'")
    c.equal("superuser direct DML", value(a, f"SELECT is_approved FROM public.{table} WHERE role_name = '{pwad}' AND command_type = 'TRUNCATE'"), "f")
    must(a, f"SELECT public.sql_firewall_approve_command('{pwad}', 'TRUNCATE')")
    c.equal("superuser management function", value(a, f"SELECT is_approved FROM public.{table} WHERE role_name = '{pwad}' AND command_type = 'TRUNCATE'"), "t")
    c.equal("both superuser changes recorded", int(value(a, history)) - recorded, 2)
    return ("pg_write_all_data membership and BYPASSRLS with an UPDATE grant were refused by the guard; "
            "a superuser session still changed policy directly and through the management function, both recorded")


def row_visibility(c):
    a = admin()
    writer, auditor = "qa_ab_reader_w", "qa_ab_auditor"
    writer_role(a, writer, [f"GRANT ALL ON TABLE public.sql_firewall_command_approvals, public.sql_firewall_query_fingerprints TO {writer}"])
    setup_role(a, auditor, [DB], [f"GRANT pg_read_all_data TO {auditor}"])
    approve(a, auditor, "SELECT")
    # Another role's fingerprint with a sample query the writer must not read.
    must(a, "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, "
            "sample_query, hit_count, is_approved) VALUES (repeat('ab', 32), 'v3: qa', 'qa_ab_other', 'SELECT', "
            "'SELECT secret_of_another_role', 1, false)")
    total = value(a, "SELECT count(*) FROM public.sql_firewall_command_approvals")
    own = value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '{writer}'")
    c.equal("writer sees only its own approvals",
            once(writer, "SELECT count(*) FROM public.sql_firewall_command_approvals"), f"OK rows=1: {own}")
    c.equal("writer sees no other role's fingerprint",
            once(writer, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name <> '{writer}'"),
            "OK rows=1: 0")
    c.equal("pg_read_all_data member sees every approval",
            once(auditor, "SELECT count(*) FROM public.sql_firewall_command_approvals"), f"OK rows=1: {total}")
    c.equal("pg_read_all_data member sees the other role's fingerprint",
            once(auditor, "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = 'qa_ab_other'"), "OK rows=1: 1")
    return (f"a role with write grants saw its own {own} approval rows of {total} and no other role's fingerprints; "
            "a pg_read_all_data member saw all")


UNAVAILABLE = "ERR 55000 sql_firewall: required policy catalog is unavailable: sql_firewall_policy_epoch"


def membership(c):
    a = admin()
    role = "qa_ab_member"
    setup_role(a, role, [DB], [f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.enable_regex_scan = 'off'"])
    approve(a, role, "SELECT", "BEGIN")
    existing = Conn("existing", role, DB)
    failing = Conn("saw-error", role, DB)
    c.expect("warm 1", existing.q("SELECT 1"), "allow", role, "SELECT")
    c.expect("warm 2", existing.q("SELECT 2"), "allow", role, "SELECT")
    c.expect("second session warm", failing.q("SELECT 2"), "allow", role, "SELECT")
    epoch = "public.sql_firewall_policy_epoch"
    try:
        must(a, f"ALTER EXTENSION sql_firewall DROP TABLE {epoch}")
        c.equal("existing session after DROP TABLE", existing.q("SELECT 3"), UNAVAILABLE)
        c.equal("second session after DROP TABLE", failing.q("SELECT 3"), UNAVAILABLE)
        c.equal("new session after DROP TABLE", once(role, "SELECT 3"), UNAVAILABLE)
    finally:
        must(a, f"ALTER EXTENSION sql_firewall ADD TABLE {epoch}")
    c.expect("existing session after ADD TABLE", existing.q("SELECT 4"), "allow", role, "SELECT")
    c.expect("session that saw the error after ADD TABLE", failing.q("SELECT 4"), "allow", role, "SELECT")
    c.equal("BEGIN in the existing session", existing.q("BEGIN"), "OK")
    c.expect("open transaction, before the administrator's DROP", existing.q("SELECT 5"), "allow", role, "SELECT")
    must(a, "BEGIN")
    must(a, f"ALTER EXTENSION sql_firewall DROP TABLE {epoch}")
    c.expect("uncommitted DROP: the open transaction is not affected", existing.q("SELECT 6"), "allow", role, "SELECT")
    must(a, "ROLLBACK")
    c.expect("after the rolled-back DROP", existing.q("SELECT 7"), "allow", role, "SELECT")
    existing.q("COMMIT")
    c.expect("new session after the rolled-back DROP", once(role, "SELECT 8"), "allow", role, "SELECT")
    c.equal("membership restored", value(a, "SELECT count(*) FROM pg_catalog.pg_depend WHERE classid = 'pg_class'::regclass "
                                            f"AND objid = '{epoch}'::regclass AND deptype = 'e'"), "1")
    existing.close()
    failing.close()
    return ("after ALTER EXTENSION DROP TABLE of the policy epoch an existing session's next statement and a new session got 55000; "
            "ADD TABLE repaired both, including the one that had seen the error; an uncommitted and then rolled-back DROP changed nothing")


def main():
    run("table_writes", "explicit table grants do not delegate administration", table_writes)
    run("predefined_roles", "pg_write_all_data and BYPASSRLS", predefined_roles)
    run("row_visibility", "row security for roles with write grants", row_visibility)
    run("membership", "extension membership changes reach cached sessions", membership)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
