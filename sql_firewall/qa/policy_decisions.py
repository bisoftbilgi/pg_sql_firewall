#!/usr/bin/env python3
"""Policy decision order, state model, history, and role lifecycle
(qa/tests/103_policy_decisions.sh).

Reuses the libpq driver of qa/policy_cache.py. A queued learn event is made to
wait with sql_firewall_pause_approval_worker, an administrator decision is
committed meanwhile, and the worker is resumed. "The worker has reached this
point" is established by a canary emitted after the resume: events are applied
in ring order, so a delivered canary means every earlier event of this
database was either applied or discarded. A discarded event is not inferred
from an absent effect alone: the worker's LOG line that names the event's role,
command, and reason is required as well (server log after the step's offset).
"""
import os, time

import policy_cache as pc
from policy_cache import (Infra, Conn, admin, must, value, once, run, pause_worker, resume_worker, setup_role,
                          approve, sync_worker)

ENV = os.environ
DB = ENV["QA_PC_DB"]
SERVER_LOG = ENV["QA_PD_SERVER_LOG"]
SU = ENV["QA_PC_SUPERUSER"]
Q = "SELECT count(*) FROM public.pd_orders"


def log_offset():
    return os.path.getsize(SERVER_LOG)


def log_since(offset):
    with open(SERVER_LOG, "rb") as f:
        f.seek(offset)
        return f.read().decode(errors="replace")


def discarded(c, what, offset, role, command, reason):
    """The worker logged that it discarded the event for ROLE/COMMAND."""
    wanted = {
        "admin": "an administrator changed this decision after the observation",
        "role": "the name now belongs to role oid",
    }[reason]
    lines = [l for l in log_since(offset).splitlines()
             if f'discarded learn event for role "{role}" command {command}' in l and wanted in l]
    c.equal(f"{what}: worker logged the discard ({reason})", len(lines) >= 1, True)
    pc.note(f"        log: {lines[0].strip() if lines else '(none)'}")


def command_state(a, role, command):
    return value(a, f"SELECT coalesce((SELECT is_approved::text FROM public.sql_firewall_command_approvals "
                    f"WHERE role_name = '{role}' AND command_type = '{command}'), 'absent')")


def learn_role(a, role, extra=()):
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.pd_orders TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'learn'", *extra])


def fp_learn_role(a, role, threshold):
    learn_role(a, role, [f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.enable_fingerprint_learning = 'on'",
                         f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.fingerprint_learn_threshold = {threshold}"])


def fp_row(a, role, statement):
    """(fingerprint, hit_count, is_approved, auto_approval_disabled) of the row whose sample is STATEMENT, or None."""
    out = must(a, f"SELECT fingerprint || '|' || hit_count || '|' || is_approved || '|' || auto_approval_disabled "
                  f"FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}' AND sample_query = $s${statement}$s$")
    if out == "OK rows=0: ":
        return None
    if not out.startswith("OK rows=1: "):
        raise Infra(f"fingerprint row for {role} not unique: {out}")
    fp, hits, approved, disabled = out.split(": ", 1)[1].split("|")
    return fp, int(hits), approved, disabled


def fp_state(a, role, fp):
    return value(a, f"SELECT coalesce((SELECT hit_count || '/' || is_approved || '/' || auto_approval_disabled "
                    f"FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}' AND fingerprint = '{fp}'), 'absent')")


def wait_fp(a, role, statement, hits, timeout=30):
    deadline = time.time() + timeout
    while True:
        row = fp_row(a, role, statement)
        if row and row[1] >= hits:
            return row
        if time.time() > deadline:
            raise Infra(f"fingerprint for {role} did not reach {hits} hits within {timeout}s: {row}")
        time.sleep(0.2)


def ok(what, out):
    if not out.startswith("OK"):
        raise Infra(f"{what}: {out}")


# ---------------------------------------------------------------------------
# P5-01: a queued learn event does not override a later administrator decision
# ---------------------------------------------------------------------------
def command_denial(c):
    a = admin()
    role = "qa_pd_deny"
    learn_role(a, role)
    enf = admin(label="enforce-reader")
    must(enf, "SET sql_firewall.mode = enforce")
    must(enf, "SET sql_firewall.enable_fingerprint_learning = off")
    must(enf, f"SET ROLE {role}")
    pause_worker(a)
    c.expect("learn-mode execution (queues an approval)", once(role, Q), "allow", role, "SELECT")
    c.equal("catalog while the worker is paused", command_state(a, role, "SELECT"), "absent")
    must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'SELECT')")
    c.equal("revoke of a command without a row records an explicit denial", command_state(a, role, "SELECT"), "false")
    c.expect("enforce reader: committed denial", enf.q(Q), "pending", role, "SELECT")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "queued approval", offset, role, "SELECT", "admin")
    c.equal("catalog after the worker passed the queued approval", command_state(a, role, "SELECT"), "false")
    c.expect("enforce reader after the worker passed it", enf.q(Q), "pending", role, "SELECT")
    c.expect("new learn-mode execution: a denied command is allowed in learn mode", once(role, Q), "allow", role, "SELECT")
    sync_worker(a)
    c.equal("learn does not reopen the denial", command_state(a, role, "SELECT"), "false")
    must(a, f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'")
    c.expect("new enforce session of the role", once(role, Q), "pending", role, "SELECT")
    enf.close()
    return ("a learn-mode approval queued before an administrator's denial was discarded by the worker (logged), the denial "
            "stayed false for existing and new enforce sessions, and later learn observations did not reopen it")


def command_delete(c):
    a = admin()
    role = "qa_pd_del"
    learn_role(a, role)
    pause_worker(a)
    c.expect("learn-mode execution (queues an approval)", once(role, Q), "allow", role, "SELECT")
    approve(a, role, "SELECT")
    must(a, f"DELETE FROM public.sql_firewall_command_approvals WHERE role_name = '{role}' AND command_type = 'SELECT'")
    c.equal("catalog after the administrator's approve and delete", command_state(a, role, "SELECT"), "absent")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "queued approval", offset, role, "SELECT", "admin")
    c.equal("deleted decision not revived by the queued approval", command_state(a, role, "SELECT"), "absent")
    c.expect("new learn-mode execution after the delete", once(role, Q), "allow", role, "SELECT")
    sync_worker(a)
    c.equal("an observation made after the delete is learned", command_state(a, role, "SELECT"), "true")
    return ("a learn-mode approval queued before an administrator deleted the row did not bring it back; an observation made "
            "after the delete was learned normally")


def command_other_key(c):
    a = admin()
    role, other = "qa_pd_key", "qa_pd_key2"
    learn_role(a, role)
    setup_role(a, other, [DB])
    pause_worker(a)
    c.expect("learn-mode execution (queues an approval)", once(role, Q), "allow", role, "SELECT")
    approve(a, role, "INSERT")
    must(a, f"SELECT public.sql_firewall_revoke_command('{other}', 'SELECT')")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    c.equal("queued approval of another key applied", command_state(a, role, "SELECT"), "true")
    c.equal("no discard logged for it", f'discarded learn event for role "{role}"' in log_since(offset), False)
    c.equal("administrator decisions kept", command_state(a, role, "INSERT") + "," + command_state(a, other, "SELECT"), "true,false")
    return ("administrator changes to other keys (same role, other command; other role, same command) did not discard a "
            "queued learn approval")


def command_same_transaction(c):
    a = admin()
    role = "qa_pd_sametx"
    learn_role(a, role)
    pause_worker(a)
    must(a, "BEGIN")
    must(a, "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) "
            "VALUES ('qa_pd_unrelated', 'UPDATE', false)")
    must(a, "SET LOCAL sql_firewall.mode = 'learn'")
    must(a, f"SET LOCAL ROLE {role}")
    c.expect("learn observation after an unrelated policy write in this transaction", a.q(Q), "allow", role, "SELECT")
    must(a, "RESET ROLE")
    must(a, f"INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) "
            f"VALUES ('{role}', 'SELECT', false)")
    must(a, f"DELETE FROM public.sql_firewall_command_approvals WHERE role_name = '{role}' AND command_type = 'SELECT'")
    must(a, "COMMIT")
    c.equal("administrator left the command without a row", command_state(a, role, "SELECT"), "absent")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "same-transaction later administrator change", offset, role, "SELECT", "admin")
    c.equal("the earlier learn observation did not revive the deleted row", command_state(a, role, "SELECT"), "absent")
    return "a later same-key administrator write in the observation's own transaction had a newer epoch and discarded it"


def fingerprint_delete(c):
    a = admin()
    role = "qa_pd_fpdel"
    st = "SELECT count(*) FROM public.pd_orders WHERE id = 11"
    fp_learn_role(a, role, 3)
    approve(a, role, "SELECT")  # command approved; fingerprint policy is under test
    learner = Conn("learner", role, DB)
    ok("first hit", learner.q(st))
    fp, hits, approved, _ = wait_fp(a, role, st, 1)
    c.equal("after one observation (threshold 3)", f"{hits}/{approved}", "1/false")
    pause_worker(a)
    ok("second hit", learner.q(st))
    ok("third hit", learner.q(st))
    must(a, f"DELETE FROM public.sql_firewall_query_fingerprints WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "queued hits", offset, role, "SELECT", "admin")
    c.equal("deleted fingerprint not recreated or approved by hits queued before the delete", fp_state(a, role, fp), "absent")
    ok("hit after the delete", learner.q(st))
    sync_worker(a)
    c.equal("an observation after the delete starts learning again", fp_state(a, role, fp), "1/false/false")
    learner.close()
    return (f"fingerprint {fp}: two queued hits that would have reached threshold 3 were discarded after the administrator "
            "deleted the row; the next observation restarted the count at 1")


def fingerprint_block(c):
    a = admin()
    role = "qa_pd_fpblk"
    s1 = "SELECT count(*) FROM public.pd_orders WHERE id = 21"
    s2 = "SELECT max(id) FROM public.pd_orders WHERE id = 22"
    fp_learn_role(a, role, 3)
    approve(a, role, "SELECT")
    learner = Conn("learner", role, DB)
    ok("first hit s1", learner.q(s1))
    ok("first hit s2", learner.q(s2))
    f1 = wait_fp(a, role, s1, 1)[0]
    f2 = wait_fp(a, role, s2, 1)[0]
    pause_worker(a)
    ok("queued hit s1", learner.q(s1))
    ok("queued hit s2", learner.q(s2))
    must(a, f"SELECT public.sql_firewall_block_fingerprint('{f2}', '{role}', 'SELECT')")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "queued hit of the blocked fingerprint", offset, role, "SELECT", "admin")
    c.equal("blocked fingerprint: queued hit not counted", fp_state(a, role, f2), "1/false/true")
    c.equal("other fingerprint of the same role: queued hit counted", fp_state(a, role, f1), "2/false/false")
    learner.close()
    return ("a hit queued before the administrator blocked fingerprint B was not counted for B; the queued hit of fingerprint "
            "A of the same role and command was")


def fingerprint_truncate(c):
    a = admin()
    role = "qa_pd_fptrunc"
    st = "SELECT count(*) FROM public.pd_orders WHERE id = 31"
    fp_learn_role(a, role, 1)
    approve(a, role, "SELECT")
    pause_worker(a)
    ok("hit queued before TRUNCATE", once(role, st))
    must(a, "CREATE TEMP TABLE pd_fp_saved AS SELECT * FROM public.sql_firewall_query_fingerprints")
    must(a, "TRUNCATE public.sql_firewall_query_fingerprints")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "queued hit", offset, role, "SELECT", "admin")
    c.equal("no row for the role after TRUNCATE", value(a, f"SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}'"), "0")
    must(a, "INSERT INTO public.sql_firewall_query_fingerprints SELECT * FROM pd_fp_saved")
    return "a threshold-1 hit queued before TRUNCATE of the fingerprint table did not recreate or approve its row"


# ---------------------------------------------------------------------------
# P5-02: a manual denial is final for learning
# ---------------------------------------------------------------------------
def manual_fingerprint_denial(c):
    a = admin()
    role = "qa_pd_fpman"
    st = "SELECT count(*) FROM public.pd_orders WHERE id = 41"
    fp_learn_role(a, role, 1)
    approve(a, role, "SELECT")
    learner = Conn("learner", role, DB)
    ok("learn hit", learner.q(st))
    fp, hits, approved, disabled = wait_fp(a, role, st, 1)
    c.equal("learned at threshold 1", f"{approved}/{disabled}", "true/false")
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = false WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    c.equal("direct UPDATE is_approved = false is a denial", fp_state(a, role, fp), "1/false/true")
    ok("learn hit after the denial", learner.q(st))
    ok("learn hit after the denial", learner.q(st))
    sync_worker(a)
    c.equal("hits counted, denial kept", fp_state(a, role, fp), "3/false/true")
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = true WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    c.equal("direct approval clears the denial", fp_state(a, role, fp), "3/true/false")
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = false, auto_approval_disabled = true WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET auto_approval_disabled = false WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    c.equal("a stated auto_approval_disabled is kept", fp_state(a, role, fp), "3/false/false")
    ok("learn hit on a re-enabled pending row", learner.q(st))
    sync_worker(a)
    c.equal("explicitly re-enabled learning approves again", fp_state(a, role, fp), "4/true/false")
    learner.close()
    return (f"fingerprint {fp}: a direct UPDATE to is_approved = false set auto_approval_disabled and later learn hits did not "
            "reapprove it; a direct approval cleared it; an UPDATE stating auto_approval_disabled kept the stated value")


def pending_fingerprint_denial(c):
    a = admin()
    role = "qa_pd_fppending"
    st = "SELECT count(*) FROM public.pd_orders WHERE id = 51"
    fp_learn_role(a, role, 2)
    approve(a, role, "SELECT")
    learner = Conn("pending-learner", role, DB)
    ok("first hit", learner.q(st))
    fp = wait_fp(a, role, st, 1)[0]
    c.equal("the fingerprint is pending", fp_state(a, role, fp), "1/false/false")
    must(a, f"UPDATE public.sql_firewall_query_fingerprints SET is_approved = false "
            f"WHERE fingerprint = '{fp}' AND role_name = '{role}'")
    c.equal("direct false-to-false assignment records a denial", fp_state(a, role, fp), "1/false/true")
    ok("second hit", learner.q(st))
    sync_worker(a)
    c.equal("threshold reached without reopening the denial", fp_state(a, role, fp), "2/false/true")
    learner.close()
    return "a direct denial on an already-pending fingerprint remained denied after the Learn threshold was reached"


# ---------------------------------------------------------------------------
# P5-03: decision history
# ---------------------------------------------------------------------------
HIST = ("SELECT coalesce(string_agg(format('%s %s %s %s/%s %s/%s %s/%s', source, operation, session_role, "
        "coalesce(old_command_type, new_command_type, '-'), coalesce(old_role_name, new_role_name, '-'), "
        "coalesce(old_is_approved::text, '-'), coalesce(new_is_approved::text, '-'), "
        "coalesce(old_auto_approval_disabled::text, '-'), coalesce(new_auto_approval_disabled::text, '-')), ' ; ' ORDER BY change_id), '(none)') "
        "FROM public.sql_firewall_policy_history WHERE {where}")


def history(c):
    a = admin()
    role, writer = "qa_pd_hist", "qa_pd_writer"
    learn_role(a, role)
    learn_role(a, writer, [f"GRANT SELECT, UPDATE ON public.sql_firewall_command_approvals TO {writer}"])
    where = f"coalesce(new_role_name, old_role_name) = '{role}'"
    approve(a, role, "INSERT")
    must(a, f"SELECT public.sql_firewall_revoke_command('{role}', 'INSERT')")
    w = admin(label="rolled-back writer")
    must(w, "BEGIN")
    must(w, f"SELECT public.sql_firewall_approve_command('{role}', 'DELETE')")
    must(w, "ROLLBACK")
    ok("learn-mode execution", once(role, Q))
    sync_worker(a)
    c.equal("learned SELECT", command_state(a, role, "SELECT"), "true")
    # A table grant does not make a non-superuser a policy writer
    # (sql_firewall_guard): the change is refused and leaves no history.
    c.equal("non-superuser writer with a table grant is refused",
            once(writer, f"UPDATE public.sql_firewall_command_approvals SET is_approved = false WHERE role_name = '{role}' AND command_type = 'SELECT'"),
            "ERR 42501 sql_firewall: only a superuser session can change sql_firewall_command_approvals; "
            "table privileges granted to other roles do not delegate firewall administration")
    must(a, f"UPDATE public.sql_firewall_command_approvals SET is_approved = false WHERE role_name = '{role}' AND command_type = 'SELECT'")
    must(a, f"DELETE FROM public.sql_firewall_command_approvals WHERE role_name = '{role}' AND command_type = 'INSERT'")
    got = value(a, HIST.format(where=where))
    want = " ; ".join([
        f"administrator INSERT {SU} INSERT/{role} -/true -/-",
        f"administrator UPDATE {SU} INSERT/{role} true/false -/-",
        f"learn INSERT {SU} SELECT/{role} -/true -/-",
        f"administrator UPDATE {SU} SELECT/{role} true/false -/-",
        f"administrator DELETE {SU} INSERT/{role} false/- -/-",
    ])
    c.equal("history (source operation session_role command/role old/new approved old/new disabled)", got, want)
    c.equal("no history row from the refused writer",
            value(a, f"SELECT count(*) FROM public.sql_firewall_policy_history WHERE session_role = '{writer}'"), "0")
    c.equal("installation identity of the rows",
            value(a, f"SELECT count(*) FILTER (WHERE extension_oid = (SELECT oid FROM pg_extension WHERE extname = 'sql_firewall') "
                     f"AND database_oid = (SELECT oid FROM pg_database WHERE datname = current_database()) "
                     f"AND system_identifier = (SELECT system_identifier FROM pg_control_system())) || '/' || count(*) "
                     f"FROM public.sql_firewall_policy_history WHERE {where}"), "5/5")
    c.equal("epochs of administrator rows increase in commit order",
            value(a, f"SELECT bool_and(e > p) FROM (SELECT policy_epoch AS e, lag(policy_epoch) OVER (ORDER BY change_id) AS p "
                     f"FROM public.sql_firewall_policy_history WHERE {where} AND source = 'administrator') s WHERE p IS NOT NULL"), "t")
    c.equal("ordinary role cannot read the history",
            once(role, "SELECT count(*) FROM public.sql_firewall_policy_history"),
            "ERR 42501 permission denied for table sql_firewall_policy_history")
    fp = value(a, HIST.format(where="policy_table = 'query_fingerprints' AND operation = 'TRUNCATE'"))
    c.equal("TRUNCATE recorded (from the fingerprint scenario)", fp, f"administrator TRUNCATE {SU} -/- -/- -/-")
    return ("management functions, direct superuser DML, and the worker's learned approval are recorded with source, session "
            "and effective role, and before/after values; a non-superuser holding a table grant was refused and left no row; "
            "the rolled-back approval left no row")


# ---------------------------------------------------------------------------
# P5-04: a queued event does not authorize a different role with the same name
# ---------------------------------------------------------------------------
def role_lifecycle(c):
    a = admin()
    dropped, renamed = "qa_pd_drop", "qa_pd_ren"
    learn_role(a, dropped)
    learn_role(a, renamed)
    pause_worker(a)
    ok("learn-mode execution of the role to be recreated", once(dropped, Q))
    ok("learn-mode execution of the role to be renamed", once(renamed, Q))
    old_oid = value(a, f"SELECT oid FROM pg_roles WHERE rolname = '{dropped}'")
    must(a, f"DROP OWNED BY {dropped}")
    must(a, f"DROP ROLE {dropped}")
    learn_role(a, dropped)
    new_oid = value(a, f"SELECT oid FROM pg_roles WHERE rolname = '{dropped}'")
    c.equal("recreated role has a new OID", old_oid != new_oid, True)
    must(a, f"ALTER ROLE {renamed} RENAME TO {renamed}2")
    offset = log_offset()
    resume_worker(a)
    sync_worker(a)
    discarded(c, "event of the dropped role", offset, dropped, "SELECT", "role")
    discarded(c, "event of the renamed role", offset, renamed, "SELECT", "role")
    c.equal("recreated role: no approval learned from the old role", command_state(a, dropped, "SELECT"), "absent")
    c.equal("renamed role: nothing stored under either name",
            command_state(a, renamed, "SELECT") + "," + command_state(a, renamed + "2", "SELECT"), "absent,absent")
    ok("learn-mode execution of the recreated role", once(dropped, Q))
    sync_worker(a)
    c.equal("the recreated role learns its own observation", command_state(a, dropped, "SELECT"), "true")
    return ("learn events queued for a role that was then dropped and recreated with the same name, or renamed, were discarded "
            "(logged with both OIDs); the recreated role's own observation was learned")


def role_membership(c):
    a = admin()
    owner, member = "qa_pd_owner", "qa_pd_member"
    for role in (owner, member):
        setup_role(a, role, [DB], [f"GRANT SELECT ON public.pd_orders TO {role}",
                                   f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'enforce'"])
    must(a, f"GRANT {owner} TO {member}")
    approve(a, owner, "SELECT")
    approve(a, member, "SET", "RESET")
    c.expect("owner with its approval", once(owner, Q), "allow", owner, "SELECT")
    c.expect("member: the owner's approval is not inherited", once(member, Q), "norule", member, "SELECT")
    m = Conn("member", member, DB)
    c.equal("member SET ROLE owner", m.q(f"SET ROLE {owner}"), "OK")
    c.expect("after SET ROLE the current role's policy applies", m.q(Q), "allow", owner, "SELECT")
    c.expect("RESET ROLE is inspected as the owner (no approval)", m.q("RESET ROLE"), "norule", owner, "RESET")
    approve(a, owner, "RESET")
    c.equal("RESET ROLE once the owner has it", m.q("RESET ROLE"), "OK")
    c.expect("back to the member's own policy", m.q(Q), "norule", member, "SELECT")
    m.close()
    return ("a member of an approved role got no approval from the membership; after SET ROLE the statements were decided "
            "with the current role's policy, including the RESET ROLE that ends it")


def main():
    x = admin(label="setup")
    must(x, "CREATE TABLE public.pd_orders (id integer)")
    must(x, "INSERT INTO public.pd_orders VALUES (1), (2)")
    x.close()
    run("command_denial", "queued learn approval vs. a later denial", command_denial)
    run("command_delete", "queued learn approval vs. a later delete", command_delete)
    run("command_other_key", "administrator changes to other keys", command_other_key)
    run("command_same_transaction", "a later administrator decision in the observation transaction", command_same_transaction)
    run("fingerprint_delete", "queued fingerprint hits vs. a later delete", fingerprint_delete)
    run("fingerprint_block", "queued fingerprint hits vs. a later block", fingerprint_block)
    run("fingerprint_truncate", "queued fingerprint hit vs. TRUNCATE", fingerprint_truncate)
    run("manual_denial", "manual fingerprint denial is final for learn", manual_fingerprint_denial)
    run("pending_denial", "direct denial of a pending fingerprint", pending_fingerprint_denial)
    run("history", "decision history", history)
    run("role_lifecycle", "queued events across DROP/CREATE and RENAME ROLE", role_lifecycle)
    run("role_membership", "membership and SET ROLE", role_membership)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
