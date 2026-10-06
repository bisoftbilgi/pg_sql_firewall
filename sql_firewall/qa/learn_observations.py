#!/usr/bin/env python3
"""Learn observations count only committed transactions
(qa/tests/104_learn_observations.sh).

Reuses the libpq driver of qa/policy_cache.py. A learn observation is
published to the event ring when its top-level transaction commits. Two kinds
of evidence are combined:

  - sql_firewall_queue_statistics(): cluster-wide publication counters. This
    test is the only client of the cluster while it runs (the harness runs
    tests serially), and canaries are blocked-query events, so a zero delta of
    approval_events and fingerprint_events across a step proves that the step
    published no learn event. Each absence check has a positive control: the
    same statement committed moves the counter.
  - The persisted fingerprint hit count and approval rows after a canary was
    delivered (events are applied in ring order).
"""
import os, threading, time

import policy_cache as pc
from policy_cache import (Infra, Conn, admin, must, value, once, run, setup_role, approve, sync_worker)

DB = os.environ["QA_PC_DB"]
THRESHOLD = 3
ST_OK = "SELECT 10 / (id - 1) FROM public.lo_t WHERE id = 2"
ST_FAIL = "SELECT 10 / (id - 1) FROM public.lo_t WHERE id = 1"  # same identity; division by zero at run time


def counters(a):
    out = value(a, "SELECT approval_events || ',' || fingerprint_events || ',' || learn_observations_dropped "
                   "FROM public.sql_firewall_queue_statistics()")
    ap, fp, dropped = (int(x) for x in out.split(","))
    return ap, fp, dropped


def delta(before, after):
    return tuple(y - x for x, y in zip(before, after))


def learn_role(a, role, threshold=THRESHOLD):
    setup_role(a, role, [DB], [f"GRANT SELECT ON public.lo_t TO {role}",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.mode = 'learn'",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.enable_fingerprint_learning = 'on'",
                               f"ALTER ROLE {role} IN DATABASE {DB} SET sql_firewall.fingerprint_learn_threshold = {threshold}"])


def fp_state(a, role, sample=ST_OK):
    """'hits/approved' of the role's row for the identity of SAMPLE's shape, or 'absent'."""
    return value(a, f"SELECT coalesce((SELECT string_agg(hit_count || '/' || is_approved, ',') "
                    f"FROM public.sql_firewall_query_fingerprints WHERE role_name = '{role}' "
                    f"AND normalized_query LIKE '%FROM \"public\" . \"lo_t\"%' AND command_type = 'SELECT'), 'absent')")


def command_state(a, role, command):
    return value(a, f"SELECT coalesce((SELECT is_approved::text FROM public.sql_firewall_command_approvals "
                    f"WHERE role_name = '{role}' AND command_type = '{command}'), 'absent')")


def step(c, what, conn, statement, want_ok=True):
    out = conn.q(statement)
    if want_ok and not out.startswith("OK"):
        raise Infra(f"{what}: {out}")
    return out


def threshold_boundary(c):
    a = admin()
    role = "qa_lo_thr"
    learn_role(a, role)
    approve(a, role, "SELECT")  # the fingerprint threshold is under test
    u = Conn("learner", role, DB)
    for n in range(1, THRESHOLD + 2):
        before = counters(a)
        step(c, f"execution {n}", u, ST_OK)
        published = delta(before, counters(a))[1]
        sync_worker(a)
        want = f"{min(n, THRESHOLD)}/{'true' if n >= THRESHOLD else 'false'}"
        c.equal(f"after committed execution {n} (threshold {THRESHOLD})", fp_state(a, role), want)
        c.equal(f"execution {n}: fingerprint events published", published, 1 if n <= THRESHOLD else 0)
    u.close()
    return (f"threshold {THRESHOLD}: executions 1..{THRESHOLD - 1} left the fingerprint pending with that many hits, execution "
            f"{THRESHOLD} approved it, execution {THRESHOLD + 1} of the approved identity published no learn event")


def not_committed(c):
    a = admin()
    role = "qa_lo_abort"
    learn_role(a, role)
    approve(a, role, "SELECT", "BEGIN", "ROLLBACK", "COMMIT", "SAVEPOINT", "RELEASE", "SET", "PREPARE TRANSACTION")
    u = Conn("learner", role, DB)
    step(c, "first committed execution", u, ST_OK)
    sync_worker(a)
    c.equal("baseline", fp_state(a, role), "1/false")

    def absent(what, statements, allow_error_at=None):
        before = counters(a)
        for i, statement in enumerate(statements):
            out = u.q(statement)
            if i == allow_error_at:
                c.equal(f"{what}: statement fails", out.startswith("ERR"), True)
            elif not out.startswith("OK"):
                raise Infra(f"{what}: {statement}: {out}")
        after = counters(a)
        c.equal(f"{what}: no learn event published (approval, fingerprint, dropped deltas)", delta(before, after), (0, 0, 0))
        sync_worker(a)
        c.equal(f"{what}: hit count unchanged", fp_state(a, role), "1/false")

    absent("ROLLBACK", ["BEGIN", ST_OK, ST_OK, "ROLLBACK"])
    absent("failed statement (autocommit)", [ST_FAIL], allow_error_at=0)
    absent("failed statement, transaction then rolled back", ["BEGIN", ST_OK, ST_FAIL, "ROLLBACK"], allow_error_at=2)
    absent("cancelled statement", ["BEGIN", "SET LOCAL statement_timeout = '50ms'",
                                   "SELECT pg_sleep(2), id FROM public.lo_t WHERE id = 2",
                                   "ROLLBACK"], allow_error_at=2)
    absent("ROLLBACK TO SAVEPOINT", ["BEGIN", "SAVEPOINT a", ST_OK, "ROLLBACK TO SAVEPOINT a", "ROLLBACK"])
    absent("PREPARE TRANSACTION then COMMIT PREPARED", ["BEGIN", ST_OK, "PREPARE TRANSACTION 'qa_lo_2pc'"])
    must(a, "COMMIT PREPARED 'qa_lo_2pc'")
    sync_worker(a)
    c.equal("after COMMIT PREPARED: prepared observations are not counted", fp_state(a, role), "1/false")

    # Positive controls: the same statements committed are counted.
    before = counters(a)
    for statement in ("BEGIN", "SAVEPOINT a", ST_OK, "ROLLBACK TO SAVEPOINT a", ST_OK, "SAVEPOINT b", ST_OK, "RELEASE SAVEPOINT b", "COMMIT"):
        step(c, "savepoint mix", u, statement)
    after = counters(a)
    c.equal("committed: fingerprint events published", delta(before, after)[1] > 0, True)
    sync_worker(a)
    c.equal("committed after ROLLBACK TO and RELEASE: the two surviving executions counted", fp_state(a, role), "3/true")
    u.close()
    return ("ROLLBACK, a failed statement, a cancelled statement, ROLLBACK TO SAVEPOINT, and PREPARE TRANSACTION published no "
            "learn event and left the hit count unchanged; a committed transaction's surviving executions (after ROLLBACK TO "
            "and RELEASE) were counted exactly")


def exception_block(c):
    a = admin()
    role = "qa_lo_exc"
    learn_role(a, role)
    approve(a, role, "SELECT", "DO")
    u = Conn("learner", role, DB)
    body = ("DO $$ BEGIN "
            "PERFORM 10 / (id - 1) FROM public.lo_t WHERE id = 2; "
            "BEGIN PERFORM 10 / (id - 1) FROM public.lo_t WHERE id = 2; RAISE EXCEPTION 'qa_lo'; "
            "EXCEPTION WHEN raise_exception THEN NULL; END; "
            "END $$")
    step(c, "DO with an exception block", u, body)
    sync_worker(a)
    c.equal("nested statement: counted outside the rolled-back block, not inside it",
            value(a, f"SELECT string_agg(hit_count::text, ',') FROM public.sql_firewall_query_fingerprints "
                     f"WHERE role_name = '{role}' AND sample_query LIKE 'SELECT 10 / (id - 1)%'"), "1")
    u.close()
    return ("a nested statement executed by a function counts as an observation; its execution inside an exception block that "
            "rolled back did not count")


def coalesced(c):
    a = admin()
    role = "qa_lo_coal"
    learn_role(a, role, threshold=10)
    u = Conn("learner", role, DB)
    before = counters(a)
    for statement in ("BEGIN", ST_OK, ST_OK, ST_OK, "COMMIT"):
        step(c, "one transaction", u, statement)
    after = counters(a)
    ap, fp, _ = delta(before, after)
    c.equal("one transaction: learn events published (approval, fingerprint)", (ap, fp), (3, 3))
    sync_worker(a)
    c.equal("three executions counted from one event", fp_state(a, role), "3/false")
    c.equal("commands learned", ",".join(command_state(a, role, x) for x in ("BEGIN", "SELECT", "COMMIT")), "true,true,true")
    u.close()
    return ("three executions in one committed transaction were published as one fingerprint event with three hits and "
            "counted as three; BEGIN, SELECT and COMMIT were one approval and one fingerprint event each")


def concurrent(c):
    a = admin()
    role = "qa_lo_conc"
    sessions, each = 8, 5
    learn_role(a, role, threshold=1000)
    approve(a, role, "SELECT")
    conns = [Conn(f"learner-{i}", role, DB) for i in range(sessions)]
    errors = []

    def work(conn):
        for _ in range(each):
            out = conn.q(ST_OK)
            if not out.startswith("OK"):
                errors.append(out)

    threads = [threading.Thread(target=work, args=(conn,)) for conn in conns]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise Infra(f"concurrent executions failed: {errors[:3]}")
    sync_worker(a)
    c.equal(f"{sessions} sessions x {each} committed executions", fp_state(a, role), f"{sessions * each}/false")
    for conn in conns:
        conn.close()
    return f"{sessions} concurrent sessions each committing {each} executions produced exactly {sessions * each} hits"


def capacity(c):
    a = admin()
    role = "qa_lo_cap"
    learn_role(a, role, threshold=1000)
    approve(a, role, "SELECT", "BEGIN", "COMMIT")
    u = Conn("learner", role, DB)
    before = counters(a)
    step(c, "BEGIN", u, "BEGIN")
    limit = int(value(a, "SELECT capacity FROM public.sql_firewall_queue_statistics()"))
    # The BEGIN itself holds one fingerprint observation.
    for i in range(limit + 1):
        step(c, "distinct statement", u, f"SELECT 1 AS qa_lo_c{i:05d}")
    step(c, "COMMIT", u, "COMMIT")
    after = counters(a)
    ap, fp, dropped = delta(before, after)
    c.equal("observations published at the limit", fp, limit)
    # BEGIN plus limit + 1 SELECTs plus COMMIT: limit + 3 observations.
    c.equal("observations beyond the limit dropped and counted", dropped, 3)
    u.close()
    return (f"a transaction making {limit + 3} distinct learn observations published {limit} at commit; the 3 beyond the "
            "limit were not recorded and were counted in learn_observations_dropped")


def main():
    x = admin(label="setup")
    must(x, "CREATE TABLE public.lo_t (id integer)")
    must(x, "INSERT INTO public.lo_t VALUES (1), (2)")
    x.close()
    run("threshold_boundary", "threshold N-1, N, N+1 over committed executions", threshold_boundary)
    run("not_committed", "rollback, failure, cancel, savepoint, prepare", not_committed)
    run("exception_block", "nested statement in an exception block", exception_block)
    run("coalesced", "several executions in one transaction", coalesced)
    run("concurrent", "concurrent sessions", concurrent)
    run("capacity", "per-transaction observation limit", capacity)


if __name__ == "__main__":
    try:
        main()
    except Infra as exc:
        pc.emit("INFRA", "setup", str(exc))
