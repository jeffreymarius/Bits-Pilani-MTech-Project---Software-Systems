import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
import re
import numpy as np

def parse_latency(file, label, metric):
    latencies = []
    with open(file) as f:
        for line in f:
            pattern = rf'PSK_TYPE={label} {metric}_ms=([\d.]+)'
            match = re.search(pattern, line)
            if match:
                latencies.append(int(match.group(1)))
    return latencies

def plot_histogram(static, ai, metric, title):
    plt.hist(static, bins=20, alpha=0.6, label='Static PSK', color='red')
    plt.hist(ai, bins=20, alpha=0.6, label='AI PSK', color='green')
    plt.xlabel(f'{metric} (ms)')
    plt.ylabel('Frequency')
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.show()

def summary(name, data):
    print(f"--- {name} ---")
    print(f"Count: {len(data)}")
    print(f"Mean: {np.mean(data):.0f} ms")
    print(f"Median: {np.median(data):0f} ms")
    print(f"Std Dev: {np.std(data):.0f} ms")
    print(f"Min: {np.min(data):.0f} ms")
    print(f"Max: {np.max(data):.0f} ms\n")

# Parse both types
static_handshake = parse_latency('static_psk.log', 'STATIC', 'TransactionLatency_ms')
ai_handshake = parse_latency('ai_psk.log', 'AI', 'TransactionLatency_ms')

#static_trans = parse_latency('static_psk.log', 'STATIC', 'TransactionLatency')
#ai_trans = parse_latency('ai_psk.log', 'AI', 'TransactionLatency')

# Summary
summary("Static PSK Handshake", static_handshake)
summary("AI PSK Handshake", ai_handshake)
#summary("Static PSK Transaction", static_trans)
#summary("AI PSK Transaction", ai_trans)

# Plot histograms
plot_histogram(static_handshake, ai_handshake, 'HandshakeLatency', 'Handshake Latency Comparison (AI vs Static PSK)')
#plot_histogram(static_trans, ai_trans, 'TransactionLatency', 'OMCI Transaction Latency Comparison (AI vs Static PSK)')

plt.savefig('hist.png')

