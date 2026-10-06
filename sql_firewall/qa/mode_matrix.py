#!/usr/bin/env python3
"""Mode behaviour matrix (qa/tests/105_mode_matrix.sh; README 6.1c).

Every cell uses its own role, so its policy state is exactly the one the cell
names. A cell checks the statement's outcome (success, or the exact SQLSTATE
and firewall message), the activity rows the statement wrote, and, after a
canary shows the worker has applied everything published before it, the
policy row the cell's learning may have changed. Command cells run with
fingerprint checking off; fingerprint cells with it on and the command
approved.
"""
import os, time

import policy_cache as pc
from policy_cache import Infra, Conn, admin, must, value, once, run, setup_role, approve, sync_worker

DB = os.environ["QA_PC_DB"]
Q = "SELECT count(*) FROM public.mm_t WHERE id = 5"
THRESHOLD = 2
IDENT = {}


def activity(a, role):
    pc.sync_activity(a)
    return value(a, f"SELECT coalesce(string_agg(action, ',' ORDER BY log_id), '') FROM public.sql_firewall_activity_log "
                    f"WHERE role_name = '{role}' AND command_type = 'SELECT'")


def blocked(a, role):
    return value(a, f"SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE role_name = '{role}'")


def command_row(a, role):
    return value(a, f"SELECT coalesce((SELECT is_approved::text FROM public.sql_firewall_command_approvals "
                    f"WHERE role_name = '{role}' AND command_type = 'SELECT'), 'absent')")


def fp_row(a, role):
    fp = IDENT["fp"]
    return value(a, f"SELECT coalesce((SELECT hit_count || '/' || is_approved || '/' || auto_approval_disabled "
                    f"FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}' AND fingerprint = '{fp}'), 'absent')")


def identity():
    """This database's identity of Q, from a learn-mode helper."""
    if IDENT:
        return
    a = admin(label="identity")
    helper = "qa_mm_helper"
    setup_role(a, helper, [DB], [f"GRANT SELECT ON public.mm_t TO {helper}",
                                 f"ALTER ROLE {helper} IN DATABASE {DB} SET sql_firewall.mode = 'learn'",
                                 f"ALTER ROLE {helper} IN DATABASE {DB} SET sql_firewall.enable_fingerprint_learning = 'on'"])
    if not once(helper, Q).startswith("OK"):
        raise Infra("helper statement failed")
    sync_worker(a)
    out = must(a, f"SELECT fingerprint || '~' || normalized_query FROM public.sql_firewall_query_fingerprints WHERE role_name = '{helper}'")
    if not out.startswith("OK rows=1: "):
        raise Infra(f"helper identity: {out}")
    IDENT["fp"], IDENT["norm"] = out.split(": ", 1)[1].split("~", 1)
    a.close()


def cell_role(a, name, mode, fingerprints):
    role = f"qa_mm_{name}"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.mm_t TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = '{mode}'",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.enable_fingerprint_learning = '{fingerprints}'",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.fingerprint_learn_threshold = {THRESHOLD}"])
    return role


NORULE = "ERR 42501 sql_firewall: No rule found for command 'SELECT' for role '{r}'"
PENDING = "ERR 42501 sql_firewall: BLOCKED - Approval for command 'SELECT' is pending for role '{r}'"
FP_PENDING = "ERR 42501 sql_firewall: Fingerprint '{fp}' for role '{r}' is pending approval."

# (mode, command state) -> (outcome, activity actions, command row after, blocked rows)
COMMAND_CELLS = [
    ("learn", "unknown", "OK", "ALLOWED (LEARN MODE - AUTO)", "true", "0"),
    ("learn", "denied", "OK", "ALLOWED (LEARN MODE - PENDING)", "false", "0"),
    ("learn", "approved", "OK", "ALLOWED", "true", "0"),
    ("permissive", "unknown", "OK", "ALLOWED (PERMISSIVE - UNAPPROVED)", "absent", "0"),
    ("permissive", "denied", "OK", "ALLOWED (PERMISSIVE - PENDING)", "false", "0"),
    ("permissive", "approved", "OK", "ALLOWED", "true", "0"),
    ("enforce", "unknown", NORULE, "", "absent", "1"),
    ("enforce", "denied", PENDING, "", "false", "1"),
    ("enforce", "approved", "OK", "ALLOWED", "true", "0"),
]

# (mode, fingerprint state) -> (outcome, activity actions, fingerprint row after, blocked rows)
# Seeded rows: pending 1/false/false, denied 1/false/true, approved 1/true/false. Threshold 2.
FINGERPRINT_CELLS = [
    ("learn", "unknown", "OK", "LEARNED (FINGERPRINT AUTO),ALLOWED", "1/false/false", "0"),
    ("learn", "pending", "OK", "ALLOWED", "2/true/false", "0"),
    ("learn", "denied", "OK", "ALLOWED", "2/false/true", "0"),
    ("learn", "approved", "OK", "ALLOWED", "1/true/false", "0"),
    ("permissive", "unknown", "OK", "ALLOWED (PERMISSIVE - FINGERPRINT),ALLOWED", "absent", "0"),
    ("permissive", "pending", "OK", "ALLOWED (PERMISSIVE - FINGERPRINT),ALLOWED", "1/false/false", "0"),
    ("permissive", "denied", "OK", "ALLOWED (PERMISSIVE - FINGERPRINT),ALLOWED", "1/false/true", "0"),
    ("permissive", "approved", "OK", "ALLOWED", "1/true/false", "0"),
    ("enforce", "unknown", FP_PENDING, "", "1/false/false", "1"),
    ("enforce", "pending", FP_PENDING, "", "2/false/false", "1"),
    ("enforce", "denied", FP_PENDING, "", "2/false/true", "1"),
    ("enforce", "approved", "OK", "ALLOWED", "1/true/false", "0"),
]


def judge(c, what, out, want):
    if want == "OK":
        c.equal(f"{what}: outcome", out.split(":")[0] if out.startswith("OK") else out, "OK rows=1")
    else:
        # The fingerprint message continues with the administrator's hint.
        c.equal(f"{what}: outcome", out[:len(want)], want)


def command_matrix(c):
    a = admin()
    roles = []
    for mode, state, *_ in COMMAND_CELLS:
        role = cell_role(a, f"c_{mode[:4]}_{state[:4]}", mode, "off")
        if state == "denied":
            must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
        elif state == "approved":
            approve(a, role, "SELECT")
        roles.append(role)
    outs = [once(role, Q) for role in roles]
    sync_worker(a)
    for (mode, state, outcome, actions, row, nblocked), role, out in zip(COMMAND_CELLS, roles, outs):
        what = f"{mode}/{state}"
        judge(c, what, out, outcome.format(r=role))
        c.equal(f"{what}: activity", activity(a, role), actions)
        c.equal(f"{what}: command row after the worker", command_row(a, role), row)
        c.equal(f"{what}: blocked-query rows", blocked(a, role), nblocked)
    return "9 cells (learn, permissive, enforce x unknown, denied, approved command) matched README 6.1c: outcome, activity rows, learned approval, blocked-query rows"


def fingerprint_matrix(c):
    identity()
    fp, norm = IDENT["fp"], IDENT["norm"]
    a = admin()
    roles = []
    seeds = {"pending": ("false", "false"), "denied": ("false", "true"), "approved": ("true", "false")}
    for mode, state, *_ in FINGERPRINT_CELLS:
        role = cell_role(a, f"f_{mode[:4]}_{state[:4]}", mode, "on")
        approve(a, role, "SELECT")
        if state in seeds:
            approved, disabled = seeds[state]
            must(a, f"INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, "
                    f"sample_query, hit_count, is_approved, auto_approval_disabled) VALUES ('{fp}', $n${norm}$n$, '{role}', 'SELECT', "
                    f"'seeded', 1, {approved}, {disabled})")
        roles.append(role)
    outs = [once(role, Q) for role in roles]
    sync_worker(a)
    for (mode, state, outcome, actions, row, nblocked), role, out in zip(FINGERPRINT_CELLS, roles, outs):
        what = f"{mode}/{state}"
        judge(c, what, out, outcome.format(r=role, fp=fp))
        c.equal(f"{what}: activity", activity(a, role), actions)
        c.equal(f"{what}: fingerprint row after the worker", fp_row(a, role), row)
        c.equal(f"{what}: blocked-query rows", blocked(a, role), nblocked)
    return (f"12 cells (learn, permissive, enforce x unknown, pending, denied, approved fingerprint; command approved; "
            f"threshold {THRESHOLD}) matched README 6.1c; an approved command did not bypass fingerprint enforcement")


def sessions_and_switches(c):
    a = admin()
    role = "qa_mm_sessions"
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.mm_t TO {role}"])
    learner, enforcer = admin(label="learn-session"), admin(label="enforce-session")
    for conn, mode in ((learner, "learn"), (enforcer, "enforce")):
        must(conn, f"SET sql_firewall.mode = {mode}")
        must(conn, f"SET ROLE {role}")
    c.expect("enforce session of the role while a learn session is open", enforcer.q(Q), "norule", role, "SELECT")
    c.expect("learn session of the same role", learner.q(Q), "allow", role, "SELECT")
    sync_worker(a)
    c.expect("enforce session after the learn session's commit was applied", enforcer.q(Q), "allow", role, "SELECT")
    # A mode change inside a transaction applies from the next statement;
    # an observation made in learn mode counts when the transaction commits.
    other = "qa_mm_switch"
    setup_role(a, other, [DB], [f"GRANT SELECT ON public.mm_t TO {other}"])
    approve(a, other, "RESET")
    s = admin(label="switching-session")
    must(s, "BEGIN")
    must(s, "SET LOCAL sql_firewall.mode = learn")
    must(s, f"SET LOCAL ROLE {other}")
    c.expect("learn statement inside the transaction", s.q(Q), "allow", other, "SELECT")
    c.equal("RESET ROLE", s.q("RESET ROLE"), "OK")
    must(s, "SET LOCAL sql_firewall.mode = enforce")
    must(s, f"SET LOCAL ROLE {other}")
    c.expect("same statement after switching to enforce, before commit", s.q(Q), "norule", other, "SELECT")
    c.equal("COMMIT (fails: the rejection aborted the transaction)", s.q("COMMIT"), "OK")
    sync_worker(a)
    c.equal("aborted transaction: the learn-mode observation is not counted", command_row(a, other), "absent")
    must(s, "BEGIN")
    must(s, "SET LOCAL sql_firewall.mode = learn")
    must(s, f"SET LOCAL ROLE {other}")
    c.expect("learn statement, second transaction", s.q(Q), "allow", other, "SELECT")
    c.equal("RESET ROLE", s.q("RESET ROLE"), "OK")
    must(s, "SET LOCAL sql_firewall.mode = enforce")
    c.equal("COMMIT", s.q("COMMIT"), "OK")
    sync_worker(a)
    c.equal("committed transaction: the learn-mode observation counts although the mode changed before COMMIT",
            command_row(a, other), "true")
    for conn in (learner, enforcer, s):
        conn.close()
    return ("sessions of one role in different modes decided independently; a mode change applied from the next statement; a "
            "learn-mode observation counted only when its transaction committed, whatever the mode at COMMIT")


def limits(c):
    a = admin()
    c.equal("threshold 0 is refused", a.q("SET sql_firewall.fingerprint_learn_threshold = 0"),
            'ERR 22023 0 is outside the valid range for parameter "sql_firewall.fingerprint_learn_threshold" (1 .. 1000)')
    c.equal("threshold -1 is refused", a.q("SET sql_firewall.fingerprint_learn_threshold = -1"),
            'ERR 22023 -1 is outside the valid range for parameter "sql_firewall.fingerprint_learn_threshold" (1 .. 1000)')
    role = "qa_mm_ordinary"
    setup_role(a, role, [DB], [f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'learn'"])
    for setting in ("sql_firewall.mode = enforce", "sql_firewall.enabled = off", "sql_firewall.allow_superuser_auth_bypass = on",
                    "sql_firewall.fingerprint_learn_threshold = 5", "sql_firewall.enable_fingerprint_learning = off"):
        name = setting.split(" ")[0]
        c.equal(f"ordinary role cannot SET {name}", once(role, f"SET {setting}"),
                f'ERR 42501 permission denied to set parameter "{name}"')
    return "threshold 0 and -1 are refused (22023; range 1..1000); an ordinary role cannot change the mode, the kill switch, superuser bypass, the threshold, or fingerprint checking for its own session"


def permissive_rules(c):
    """README 6.1c and the operator's decision: permissive relaxes only the
    approval checks; every other rule still refuses and records."""
    a = admin()
    must(a, "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('qa_mm_perm_regex', 'qa permissive regex')")
    base = {"mode": "permissive", "enable_fingerprint_learning": "off", "enable_activity_logging": "on"}
    cases = [
        ("keyword", {"enable_keyword_scan": "on", "blacklisted_keywords": "qa_mm_kw"}, "SELECT 1 AS qa_mm_kw",
         "ERR 42000 sql_firewall: Blocked due to blacklisted keyword 'qa_mm_kw'."),
        ("regex", {"enable_regex_scan": "on"}, "SELECT 'qa_mm_perm_regex'",
         "ERR 42501 sql_firewall: Query blocked by security regex pattern."),
        ("builtin", {}, "SELECT count(*) FROM public.mm_t WHERE 1 = 2 OR 1 = 1",
         "ERR 42501 sql_firewall: Query matched default injection pattern."),
        ("quiet", {"enable_quiet_hours": "on", "quiet_hours_start": "00:00", "quiet_hours_end": "00:00"},
         "SELECT count(*) FROM public.mm_t", "ERR 42501 sql_firewall: Blocked during quiet hours (00:00 - 00:00)."),
        ("app", {"enable_application_blocking": "on", "blocked_applications": "qa_pc_new-qa_mm_p_app"},
         "SELECT count(*) FROM public.mm_t", "ERR 42501 sql_firewall: Connections from application 'qa_pc_new-qa_mm_p_app' are not allowed."),
    ]
    got, want, rows = [], [], []
    for name, extra, sql, expected in cases:
        role = f"qa_mm_p_{name}"
        setup_role(a, role, [DB], [f"GRANT SELECT ON public.mm_t TO {role}"] +
                   [f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.{k} = '{v}'" for k, v in {**base, **extra}.items()])
        got.append(once(role, sql))
        want.append(expected)
        rows.append(role)
    rate = "qa_mm_p_rate"
    setup_role(a, rate, [DB], [f"GRANT SELECT ON public.mm_t TO {rate}"] +
               [f"ALTER ROLE {rate} IN DATABASE {DB} SET sql_firewall.{k} = '{v}'" for k, v in
                {**base, "select_limit_count": "1", "command_limit_seconds": "60"}.items()])
    first, second = once(rate, "SELECT count(*) FROM public.mm_t"), once(rate, "SELECT count(*) FROM public.mm_t")
    c.equal("rate: first allowed (no approval: would_block), second refused",
            (first.split(":")[0], second), ("OK rows=1", f"ERR 53400 sql_firewall: Rate limit for command 'SELECT' exceeded for role '{rate}'"))
    for (name, *_), g, w in zip(cases, got, want):
        c.equal(f"permissive {name}: refused", g, w)
    sync_worker(a)
    counts = ",".join(blocked(a, r) for r in rows + [rate])
    c.equal("each refusal recorded once as a blocked query", counts, ",".join(["1"] * (len(rows) + 1)))
    pc.sync_activity(a)
    c.equal("the allowed approval violation is logged as would_block",
            value(a, f"SELECT string_agg(action || '/' || decision, ',') FROM public.sql_firewall_activity_log WHERE role_name = '{rate}'"),
            "ALLOWED (PERMISSIVE - UNAPPROVED)/would_block")
    c.equal("permissive made no approval", value(a, f"SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name LIKE 'qa_mm_p_%'"), "0")
    must(a, "DELETE FROM public.sql_firewall_regex_rules WHERE description = 'qa permissive regex'")
    return ("in permissive mode keyword, regex, built-in, quiet-hours, application, and rate rules still refused and recorded; "
            "only the missing approval was allowed, logged as would_block, and created no approval")


def main():
    x = admin(label="setup")
    must(x, "CREATE TABLE public.mm_t (id integer)")
    must(x, "INSERT INTO public.mm_t VALUES (5)")
    x.close()
    run("command_matrix", "mode x command state", command_matrix)
    run("fingerprint_matrix", "mode x fingerprint state", fingerprint_matrix)
    run("sessions_and_switches", "per-session modes and mode changes", sessions_and_switches)
    run("limits", "threshold range and ordinary-role settings", limits)
    run("permissive_rules", "permissive relaxes only approval checks", permissive_rules)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
