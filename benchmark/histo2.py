import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import re
import numpy as np

# ---- CONFIG ----
LOG_FILE = "ai_static_psk.log"   # change if your log file has a different name
BIN_COUNT = 10                   # number of bins in histogram
# ----------------

def parse_latencies(filename):
    ai_lat = []
    static_lat = []
    with open(filename) as f:
        for line in f:
            # Match patterns like: PSK_TYPE=AI TransactionLatency_ms=3389
            match = re.search(r'PSK_TYPE=(\w+)\s+TransactionLatency_ms=(\d+)', line)
            if match:
                psk_type = match.group(1)
                latency = int(match.group(2))
                if psk_type.upper() == "AI":
                    ai_lat.append(latency)
                elif psk_type.upper() == "STATIC":
                    static_lat.append(latency)
    return ai_lat, static_lat


def summary(name, data):
    if not data:
        print(f"No data for {name}")
        return
    print(f"--- {name} ---")
    print(f"Count: {len(data)}")
    print(f"Mean: {np.mean(data):.2f} ms")
    print(f"Median: {np.median(data):.2f} ms")
    print(f"Std Dev: {np.std(data):.2f} ms")
    print(f"Min: {np.min(data)} ms")
    print(f"Max: {np.max(data)} ms\n")


def plot_histogram(ai, static):
    plt.hist(static, bins=BIN_COUNT, alpha=0.6, label='Static PSK', color='red')
    plt.hist(ai, bins=BIN_COUNT, alpha=0.6, label='AI PSK', color='green')
    plt.xlabel('Transaction Latency (ms)')
    plt.ylabel('Frequency')
    plt.title('Histogram of TLS-PSK Transaction Latency (AI vs Static)')
    plt.legend()
    plt.grid(True)
    plt.show()


# ---- Main ----
ai_lat, static_lat = parse_latencies(LOG_FILE)

summary("AI PSK", ai_lat)
summary("Static PSK", static_lat)
plot_histogram(ai_lat, static_lat)

plt.savefig('hist.png')


min_len = min(len(ai_lat), len(static_lat))
ai, static = ai_lat[:min_len], static_lat[:min_len]

x = np.arange(min_len)
width = 0.4

plt.figure(figsize=(12,6))
plt.bar(x - width/2, static, width, label="Static PSK", color='red', alpha=0.6)
plt.bar(x + width/2, ai, width, label="RTD PSK", color='green', alpha=0.6)

plt.xlabel("Sample Index")
plt.ylabel("Transaction Latency (ms)")
plt.title("Comparison of TLS-PSK Transaction Latencies (RTD vs Static)")
plt.legend()
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("psk_sample_comparison.png")
plt.show()
