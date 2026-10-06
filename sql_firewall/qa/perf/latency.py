"""Latency summary of pgbench --log lines on stdin: avg,p50,p95,p99 in ms."""
import sys

values = []
for line in sys.stdin:
    fields = line.split()
    # client transaction_no time_us script_no epoch epoch_us [lag]; failed: "failed"/"skipped"
    if len(fields) >= 3 and fields[2].isdigit():
        values.append(int(fields[2]))
if not values:
    print(",,,")
    sys.exit(0)
values.sort()


def pct(p):
    return values[min(len(values) - 1, int(round(p / 100.0 * (len(values) - 1))))] / 1000.0


print(f"{sum(values) / len(values) / 1000.0:.3f},{pct(50):.3f},{pct(95):.3f},{pct(99):.3f}")
