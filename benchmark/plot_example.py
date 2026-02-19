#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import sys

csv_file = sys.argv[1] if len(sys.argv)>1 else "bench_results/example/tls_ping.csv"
df = pd.read_csv(csv_file, names=["time","tcp_ms","tls_ms","total_ms","status","info"], header=0)
df_ok = df[df.status == "OK"]
# CDF of TLS latency
vals = df_ok.tls_ms.sort_values().values
p = (np.arange(len(vals)) + 1) / len(vals)
plt.figure()
plt.plot(vals, p)
plt.xlabel("TLS handshake time (ms)")
plt.ylabel("CDF")
plt.grid(True)
plt.savefig("tls_latency_cdf.png", dpi=200)
print("Saved tls_latency_cdf.png")

