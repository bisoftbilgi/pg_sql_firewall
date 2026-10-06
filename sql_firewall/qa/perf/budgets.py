#!/usr/bin/env python3
"""Evaluates the docs/PERFORMANCE.md budgets P1-P8 on a qa/perf/bench.sh run.

Usage: budgets.py RUN_DIR   (prints a Markdown report; exit 0 all pass, 1 any fail)

Medians over the interleaved repetitions are compared (Part 1, correction 3).
A run with PERF_ONLY=p4p7 measures P4 and P7; PERF_ONLY=p7 measures P7.
Both record P6. Other budgets are reported as not measured, not as passed.
"""
import csv
import re
import statistics
import sys
from pathlib import Path

run = Path(sys.argv[1])
rows = list(csv.DictReader(open(run / "results.csv")))
manifest = {}
for line in open(run / "manifest.txt"):
    if "=" in line:
        k, v = line.rstrip("\n").split("=", 1)
        manifest[k] = v


def f(x):
    return float(x) if x not in ("", None) else float("nan")


def sel(cfg, w, clients="8", rate=""):
    return [r for r in rows if r["config"] == cfg and r["workload"] == w and r["clients"] == clients and r["rate"] == rate]


def med(cfg, w, key, clients="8"):
    vals = [f(r[key]) for r in sel(cfg, w, clients)]
    return statistics.median(vals) if vals else float("nan")


def loss(cfg, w):
    a, b = med("A", w, "tps"), med(cfg, w, "tps")
    return 1 - b / a, a, b


results = []
only = manifest.get("perf_only", "all")
SKIP = {"P1", "P2", "P3", "P5", "P8"} if only in ("p4p7", "p7") else set()
if only == "p7":
    SKIP.add("P4")


def budget(pid, ok, text):
    if pid in SKIP:
        results.append((pid, "NOT MEASURED", f"PERF_ONLY={only} run"))
    else:
        results.append((pid, "PASS" if ok else "FAIL", text))


# P1
parts, ok = [], True
for w in ("W1", "W2"):
    l, a, b = loss("B", w)
    ok &= l <= 0.05
    parts.append(f"{w}: A {a:,.0f} tps, B {b:,.0f} tps, loss {l:.1%}")
budget("P1", ok, "B vs A throughput loss <= 5%: " + "; ".join(parts))

# P2
l, a, b = loss("E", "W2")
pa, pe = med("A", "W2", "p99_ms"), med("E", "W2", "p99_ms")
budget("P2", l <= 0.30 and pe <= 1.5 * pa,
       f"E vs A on W2: A {a:,.0f} tps, E {b:,.0f} tps, loss {l:.1%} (<= 30%); p99 A {pa:.2f} ms, E {pe:.2f} ms, ratio {pe / pa:.2f} (<= 1.5)")

# P3
parts, ok = [], True
for w in ("W1", "W3"):
    l, a, b = loss("F", w)
    ok &= l <= 0.40
    parts.append(f"{w}: A {a:,.0f}, F {b:,.0f} tps, loss {l:.1%}")
budget("P3", ok, "F vs A throughput loss <= 40%: " + "; ".join(parts))

# P4
p4 = sel("E", "W1", "8", "2000")
if p4:
    r = p4[0]
    lost = int(r["act_skipped"]) + int(r["act_rejected"]) + int(r["act_publish_failed"])
    lag = f(r["act_lag_p99_s"])
    budget("P4", lost == 0 and lag <= 2.0 and int(r["duration"]) >= 300 and r["failed"] == "0",
           f"E at 2,000/s for {r['duration']} s: achieved {f(r['tps']):,.0f} tps, lost records {lost} (skipped {r['act_skipped']}, rejected {r['act_rejected']}, publish failed {r['act_publish_failed']}), write lag p99 {lag:.3f} s (<= 2 s)")
else:
    budget("P4", False, "no 2,000/s run in results.csv")
sweep = []
best = None
for r in sorted((r for r in rows if r["config"] == "E" and r["rate"]), key=lambda r: int(r["rate"])):
    lost = int(r["act_skipped"]) + int(r["act_rejected"]) + int(r["act_publish_failed"])
    sweep.append(f"{int(r['rate']):,}/s -> {f(r['tps']):,.0f} tps, lost {lost}, lag p99 {r['act_lag_p99_s']} s")
    if lost == 0:
        best = r
p4_info = "offered-rate sweep (not a budget): " + "; ".join(sweep)
if best:
    p4_info += f". Highest loss-free offered rate: {int(best['rate']):,}/s (achieved {f(best['tps']):,.0f} tps)"

# P5
a5, e5 = sel("A", "W5"), sel("E", "W5")
if a5 and e5:
    d = f(e5[0]["lat_avg_ms"]) - f(a5[0]["lat_avg_ms"])
    budget("P5", d <= 5.0, f"W5 (new connection per transaction): average latency A {f(a5[0]['lat_avg_ms']):.2f} ms, E {f(e5[0]['lat_avg_ms']):.2f} ms, added {d:.2f} ms (<= 5 ms)")
else:
    budget("P5", False, "W5 rows missing")


# P6
def mb(s):
    m = re.match(r"(\d+)\s*(kB|MB|GB)", s or "")
    if not m:
        return float("nan")
    return int(m.group(1)) * {"kB": 1 / 1024, "MB": 1, "GB": 1024}[m.group(2)]


sa, sb = mb(manifest.get("shared_memory_size_A")), mb(manifest.get("shared_memory_size_B"))
budget("P6", sb - sa <= 64, f"shared_memory_size A {manifest.get('shared_memory_size_A')}, B {manifest.get('shared_memory_size_B')}: added {sb - sa:.0f} MB (<= 64 MB)")

# P7
long_out = (run / "pgbench" / "long.out").read_text() if (run / "pgbench" / "long.out").exists() else ""
progress = [(float(t), float(rate)) for t, rate in re.findall(
    r"^progress: ([0-9.]+) s, ([0-9.]+) tps", long_out, re.M)]
failed_match = re.search(r"number of failed transactions: (\d+)", long_out)
failed = int(failed_match.group(1)) if failed_match else -1
aborted = "aborted" in long_out
samples = list(csv.DictReader(open(run / "long_samples.csv"))) if (run / "long_samples.csv").exists() else []
max_rows = max((int(s["activity_rows"]) for s in samples if s["activity_rows"].isdigit()), default=-1)
anon = manifest.get("long_consumer_anon_kb", "").split("->")
growth_kb = int(anon[1]) - int(anon[0]) if len(anon) == 2 and all(x.isdigit() for x in anon) else None
growth_label = f"{growth_kb / 1024:.1f} MB" if growth_kb is not None else "unavailable"
errors = manifest.get("server_errors", "?")
duration_match = re.search(r"^duration: (\d+) s", long_out, re.M)
total_match = re.search(r"number of transactions actually processed: (\d+)", long_out)


def transaction_windows():
    """Time-weighted minute intervals, completed by the terminal total.

    pgbench often prints its last progress line at 1740, not 1800 seconds.
    Minute TPS are rounded by pgbench, so historical windows are approximate;
    never substitute the last five printed lines for the final 300 seconds.
    """
    if not duration_match or not total_match:
        raise ValueError("terminal duration/transaction summary missing")
    duration, total = int(duration_match.group(1)), int(total_match.group(1))
    if duration < 1800:
        raise ValueError(f"duration {duration}s; P7 requires at least 1800s")
    actual = float(manifest.get("long_runtime_seconds", duration))
    if actual < 1800:
        raise ValueError(f"workload stopped after {actual:.3f}s")
    intervals, end, counted = [], 0.0, 0.0
    for time, rate in progress:
        if not end < time <= duration or time - end > 75 or rate < 0:
            raise ValueError("missing or invalid progress intervals")
        intervals.append((end, time, rate))
        counted += (time - end) * rate
        end = time
    tail = duration - end
    if not progress or tail > 75 or total < counted - duration * 0.1:
        raise ValueError("long run lacks complete interval coverage")
    if tail > 0:
        intervals.append((end, duration, max(0.0, total - counted) / tail))

    def mean_between(start, stop):
        return sum(max(0.0, min(stop, right) - max(start, left)) * rate
                   for left, right, rate in intervals) / (stop - start)

    return duration, total / duration, mean_between(0, 300), mean_between(duration - 300, duration)


try:
    duration, tps_avg, first, last = transaction_windows()
    drift = (last - first) / first if first > 0 else float("inf")
    # W2 records BEGIN, three UPDATEs, SELECT, INSERT, END: seven per transaction.
    bound = 200000 + 30 * tps_avg * 7
    ok = failed == 0 and not aborted and abs(drift) <= 0.15 and growth_kb is not None and growth_kb <= 20 * 1024 and 0 <= max_rows <= bound and errors == "0"
    budget("P7", ok,
           f"{duration / 60:g} min at 4 clients: failed {failed}{', aborted clients' if aborted else ''}; "
           f"TPS first/final 300 s approximately {first:,.2f}/{last:,.2f} ({drift:+.1%}; budget ±15%); "
           f"consumer RSS growth {growth_label} (<= 20 MB); activity rows max {max_rows:,} "
           f"(<= {bound:,.0f}); server log ERROR/PANIC lines {errors}")
except ValueError as exc:
    budget("P7", False, f"long run incomplete: {exc}")

# A separate integrity check: routine-load loss is not the accepted crash-loss
# limit, and it must not disappear behind a throughput/retention verdict.
terminal_loss = manifest.get("long_loss_delta")
if terminal_loss is not None:
    losses = [int(x) for x in terminal_loss.split(",")[:3]]
    caught = manifest.get("long_caught_up") == "yes"
    published = int(manifest.get("long_published_delta", "-1"))
    written = int(manifest.get("long_written", "-1"))
    consistent = published >= 0 and written >= 0 and published == written + sum(losses[:2])
    budget("P7.audit", len(losses) == 3 and all(x >= 0 for x in losses) and sum(losses) == 0 and caught and consistent,
           f"terminal losses {sum(losses)} (skipped/rejected/publish-failed {terminal_loss}); "
           f"caught up {caught}; published {published}, written {written}; accounting consistent {consistent}")
else:
    skipped = int(samples[-1]["skipped"]) - int(samples[0]["skipped"]) if samples else -1
    results.append(("P7.audit", "NOT VERIFIED", f"terminal counters absent; sampled skipped-position increase {skipped} is a lower bound"))

# P8
l, a, b = loss("E", "W4")
budget("P8", l <= 0.50, f"W4 (8 kB statement), E vs A: A {a:,.0f}, E {b:,.0f} tps, loss {l:.1%} (<= 50%)")

print(f"| budget | result | measured |\n|---|---|---|")
for pid, res, text in results:
    print(f"| {pid} | {res} | {text} |")
print()
print(p4_info)
if only != "all":
    sys.exit(0 if all(r in ("PASS", "NOT MEASURED") for _, r, _ in results) else 1)
print()
print("Throughput by configuration (median of repetitions, 8 clients, tps):")
print()
print("| config | W1 | W2 | W3 | W4 | W5 |")
print("|---|---|---|---|---|---|")
for cfg in "ABCDEFG":
    print("| " + cfg + " | " + " | ".join(f"{med(cfg, w, 'tps'):,.0f}" for w in ("W1", "W2", "W3", "W4", "W5")) + " |")
print()
print("CPU ms per 1,000 transactions (median):")
print()
print("| config | W1 | W2 | W3 |")
print("|---|---|---|---|")
for cfg in "ABCDEFG":
    print("| " + cfg + " | " + " | ".join(f"{med(cfg, w, 'cpu_ms_per_1k_tx'):,.0f}" for w in ("W1", "W2", "W3")) + " |")
print()
print("Concurrency sweep W1 (tps): " + "; ".join(
    f"{cfg} c={c}: {med(cfg, 'W1', 'tps', c):,.0f}" for cfg in ("A", "E") for c in ("1", "8", "32")))
sys.exit(0 if all(r in ("PASS", "NOT MEASURED") for _, r, _ in results) else 1)
