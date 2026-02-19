#!/usr/bin/env bash
set -euo pipefail

# --------- CONFIG (edit if needed) ----------
SERVER_BIN="../vomciFunction/vomciFunction -tls"         # server binary / start command (full path or command)
CLIENT_BIN="../voltmf/voltmf -tls1.3"                # client binary / start command (if needed)
SERVER_PORT=50051
SERVER_HOST=127.0.0.1
PSK_ENV_VAR_NAME="PSK_KEY"           # env var name your apps read for PSK
EXPERIMENT_DIR="./bench_results"
WARMUP_SECONDS=15
RUN_SECONDS=30

CONCURRENCY_LIST=(1 10 50 200)
PAYLOAD_LIST=(0 1024 65536 1048576)  # 0 = handshake-only, else bytes for long-lived transfer
REPEATS=5
TLS_PING_BIN="./tls_ping"            # compiled from tls_ping.go (see below)
PSK_GEN_CMD="./generate_psk.sh"      # script that prints the PSK to stdout (your AI model wrapper)
# --------------------------------------------

mkdir -p "$EXPERIMENT_DIR"
timestamp() { date +"%Y%m%d-%H%M%S"; }

# helper to start server with PSK set; adjust to how your server reads PSK
start_server_with_psk() {
  # stop any existing server listening on port
  pkill -f "$SERVER_BIN" || true
  # start server in background with PSK env var
  nohup $SERVER_BIN > "$EXPERIMENT_DIR/server.log" 2>&1 &
  sleep 1
}

stop_server() {
  pkill -f "$SERVER_BIN" || true
  sleep 1
}


# Record system info
uname -a > "$EXPERIMENT_DIR/system-info.txt"
go version >> "$EXPERIMENT_DIR/system-info.txt" 2>&1 || true
openssl version >> "$EXPERIMENT_DIR/system-info.txt" 2>&1 || true

# main loop
for mode in "AI_PSK" "CERT"; do
  echo "==== MODE: $mode ===="
  for c in "${CONCURRENCY_LIST[@]}"; do
    for payload in "${PAYLOAD_LIST[@]}"; do
      for r in $(seq 1 $REPEATS); do
        RUN_ID="$(timestamp)-${mode}-c${c}-p${payload}-r${r}"
        OUTDIR="$EXPERIMENT_DIR/$RUN_ID"
        mkdir -p "$OUTDIR"

          start_server_with_psk

        # warmup
        echo "Warmup for ${WARMUP_SECONDS}s (concurrency=${c}, payload=${payload})..."
        timeout "${WARMUP_SECONDS}s" $CLIENT_BIN  --concurrency $c  --duration 5 > /dev/null 2>&1 || true

        # capture pcap during run
        sudo timeout "${RUN_SECONDS}s" tcpdump -i any -w "$OUTDIR/capture.pcap" host $SERVER_HOST and port $SERVER_PORT &
        TCPDUMP_PID=$!

        # run perf stat on server process (if server binary exists)
        if pgrep -f "$SERVER_BIN" >/dev/null; then
          SERVER_PID=$(pgrep -f "$SERVER_BIN" | head -n1)
          sudo perf stat -p "$SERVER_PID" -o "$OUTDIR/perf.txt" -- sleep $RUN_SECONDS &
          PERF_PID=$!
        fi

        # run the TLS ping bench; it will produce per-connection CSV on stdout
        echo "Running test -> output: $OUTDIR/tls_ping.csv"
        timeout "${RUN_SECONDS}s" $CLIENT_BIN  --concurrency $c  --duration $RUN_SECONDS > "$OUTDIR/tls_ping.csv" 2>&1 || true

        # wait for background captures to end
        wait ${TCPDUMP_PID} 2>/dev/null || true
        wait ${PERF_PID:-0} 2>/dev/null || true

        # collect server log copy
        cp "$OUTDIR/../server.log" "$OUTDIR/" || true

        # basic summary
        awk -F, 'NR>1 { sum += $4; count++ } END { if(count>0) printf("avg_tls_ms=%.3f\n", sum/count); else print "no_samples" }' "$OUTDIR/tls_ping.csv" > "$OUTDIR/summary.txt" || true

        echo "Result saved to $OUTDIR"
        # small cooldown
        sleep 3
      done
    done
  done
  stop_server
done

echo "All runs completed. Results in $EXPERIMENT_DIR"

