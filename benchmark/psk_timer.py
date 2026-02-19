#!/usr/bin/env python3
import argparse, subprocess, time, statistics, csv, os

parser = argparse.ArgumentParser()
parser.add_argument("--cmd", required=True)
parser.add_argument("--iters", type=int, default=50)
parser.add_argument("--out", default="psk_times.csv")
args = parser.parse_args()

rows = []
for i in range(args.iters):
    t0 = time.perf_counter()
    proc = subprocess.run(args.cmd, shell=True, capture_output=True)
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0)*1000.0
    success = (proc.returncode == 0)
    key = proc.stdout.decode().strip()[:64]
    rows.append((i+1, elapsed_ms, success, key))
    print(f"iter={i+1} {elapsed_ms:.3f}ms success={success}")

with open(args.out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(("iter","ms","success","psk_preview"))
    w.writerows(rows)

times = [r[1] for r in rows if r[2]]
print("summary: n=%d mean=%.3f median=%.3f stdev=%.3f" % (len(times), statistics.mean(times), statistics.median(times), statistics.stdev(times) if len(times)>1 else 0.0))
print("wrote", args.out)

