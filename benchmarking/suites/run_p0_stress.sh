#!/bin/bash

# ==============================================================================
# GhostPEP Phase 0 Benchmarking Suite
# Role: Senior DevOps & Performance Engineer
# Description: Automated stress test for Legacy Userspace SPA (Iptables)
# ==============================================================================

## --- 1. Konfigurasi & Variabel ---
VM1_IP=${1:-"192.168.1.10"} # IP VM1 (Generator), override via arg $1
VM1_USER=${2:-"root"}       # User VM1, override via arg $2
SSH_KEY=${3:-""}            # Opsional: Path ke SSH Identity File (e.g. /home/user/.ssh/id_ed25519)

# Jika SSH_KEY tidak diberikan, coba detect jika kita jalan via sudo
if [[ -z "$SSH_KEY" && -n "$SUDO_USER" ]]; then
    # Default ke key standar user yang manggil sudo
    SSH_KEY="/home/$SUDO_USER/.ssh/id_ed25519"
fi

SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
if [[ -f "$SSH_KEY" ]]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
    echo "[*] Using SSH Identity: $SSH_KEY"
fi

# Pre-flight: Check Dependencies
for cmd in tcpdump pidstat; do
    if ! command -v $cmd &> /dev/null; then
        echo "[-] Error: '$cmd' not found. Please install the required tools:"
        echo "    sudo apt update && sudo apt install -y tcpdump sysstat"
        exit 1
    fi
done

# Dynamic Interface Detection: Use path to VM1
IFACE=$(ip route get "$VM1_IP" | awk '{print $5;exit}')
if [[ -z "$IFACE" ]]; then
    IFACE="eth0"
    echo "[!] Warning: Could not detect interface for $VM1_IP. Falling back to $IFACE."
else
    echo "[*] Detected interface for communication with $VM1_IP: $IFACE"
fi

TARGET_PORT=1234
RECEIVER_PATH="vm2_receiver/phase0_legacy/receiver.py"
LOG_DIR="results/raw_logs"
RAW_LOG="$LOG_DIR/p0_baseline.log"
CPU_LOG="$LOG_DIR/p0_cpu_usage.log"
TEMP_APP_LOG="p0_app_temp.log"
SYSTEM_METRICS_LOG="$LOG_DIR/p0_system_wide.csv"

# Pastikan folder log tersedia
mkdir -p "$LOG_DIR"

# Reset logs for fresh run
> "$RAW_LOG"
> "$CPU_LOG"
> "$TEMP_APP_LOG"
echo "timestamp,src_ip,identity,latency_us" > "$LOG_DIR/p0_events.csv"
echo "timestamp,cpu_usage_%,ram_avail_mb,rx_bytes_sec,tx_bytes_sec" > "$SYSTEM_METRICS_LOG"

# Global PIDs
RECEIVER_PID=""
PIDSTAT_PID=""
TCPDUMP_PID=""
SYS_MONITOR_PID=""

# --- 2. Robust Cleanup Trap ---
# Rationale: Ensure processes are killed even if script fails or is aborted.
cleanup() {
    echo -e "\n[*] Cleaning up background processes..."
    [[ -n "$RECEIVER_PID" ]] && kill $RECEIVER_PID 2>/dev/null
    [[ -n "$PIDSTAT_PID" ]] && kill $PIDSTAT_PID 2>/dev/null
    [[ -n "$TCPDUMP_PID" ]] && kill $TCPDUMP_PID 2>/dev/null
    [[ -n "$SYS_MONITOR_PID" ]] && kill $SYS_MONITOR_PID 2>/dev/null
    iptables -F
    iptables -P INPUT ACCEPT
    echo "[+] Cleanup complete."
}
trap cleanup EXIT

# --- 3. Pre-flight Checks ---
# Pastikan dijalankan sebagai root (wajib untuk iptables & tcpdump)
if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: Skrip ini harus dijalankan dengan sudo / root!"
   exit 1
fi

# Cek apakah file receiver ada
if [[ ! -f "$RECEIVER_PATH" ]]; then
    echo "[-] Error: File receiver tidak ditemukan di $RECEIVER_PATH"
    exit 1
fi

echo "[+] GhostPEP Phase 0 Benchmark Started."
echo "--- SYSTEM METRICS ---" > "$RAW_LOG"

VM2_IP=$(hostname -I | awk '{print $1}')
GENERATOR_CMD="source \$HOME/.cargo/env && cd identity-driven-spa-xdp/vm1_generator && cargo run --release -- --target $VM2_IP --port $TARGET_PORT --identity 1001 --secret 'my-secret'"

# Helper to start tcpdump
start_tcpdump() {
    local pcap_name=$1
    # Removed 2> /dev/null to allow error visibility during startup
    tcpdump -i "$IFACE" udp port $TARGET_PORT -tt -v -w "$LOG_DIR/$pcap_name" &
    TCPDUMP_PID=$!
    sleep 1 # Give tcpdump time to bind
}

stop_tcpdump() {
    if [[ -n "$TCPDUMP_PID" ]]; then
        kill $TCPDUMP_PID 2>/dev/null
        TCPDUMP_PID=""
    fi
}

log_marker() {
    local marker="$1"
    echo -e "\n==========================================================" >> "$RAW_LOG"
    echo "[MARKER] $marker" >> "$RAW_LOG"
    echo "==========================================================" >> "$CPU_LOG"
    echo "[MARKER] $marker" >> "$CPU_LOG"
    echo "==========================================================" >> "$TEMP_APP_LOG"
    echo "[MARKER] $marker" >> "$TEMP_APP_LOG"
    if [[ -f "$LOG_DIR/p0_events.csv" ]]; then
        echo "# [MARKER] $marker" >> "$LOG_DIR/p0_events.csv"
    fi
    echo "# [MARKER] $marker" >> "$SYSTEM_METRICS_LOG"
}

# --- Background System Monitor ---
monitor_system() {
    local prev_idle=0 prev_total=0 prev_rx=0 prev_tx=0
    if [[ -f /proc/stat ]]; then
        read -r cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
        prev_total=$((user+nice+system+idle+iowait+irq+softirq+steal))
        prev_idle=$idle
    fi
    local rx_tx rx tx
    rx_tx=$(grep "$IFACE" /proc/net/dev 2>/dev/null | awk -F: '{print $2}' | awk '{print $1, $9}')
    prev_rx=$(echo $rx_tx | awk '{print $1}')
    prev_tx=$(echo $rx_tx | awk '{print $2}')
    [[ -z "$prev_rx" ]] && prev_rx=0
    [[ -z "$prev_tx" ]] && prev_tx=0

    while true; do
        sleep 1
        now=$(date +"%T")
        
        # CPU Log
        read -r cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
        total=$((user+nice+system+idle+iowait+irq+softirq+steal))
        diff_idle=$((idle - prev_idle))
        diff_total=$((total - prev_total))
        cpu_usage=0
        [[ $diff_total -gt 0 ]] && cpu_usage=$((100 * (diff_total - diff_idle) / diff_total))
        prev_idle=$idle
        prev_total=$total

        # RAM Log
        ram_free=$(free -m | awk 'NR==2{print $7}')

        # Network Log
        rx_tx=$(grep "$IFACE" /proc/net/dev 2>/dev/null | awk -F: '{print $2}' | awk '{print $1, $9}')
        rx=$(echo $rx_tx | awk '{print $1}')
        tx=$(echo $rx_tx | awk '{print $2}')
        [[ -z "$rx" ]] && rx=0
        [[ -z "$tx" ]] && tx=0
        diff_rx=$((rx - prev_rx))
        diff_tx=$((tx - prev_tx))
        prev_rx=$rx
        prev_tx=$tx

        echo "$now,$cpu_usage,$ram_free,$diff_rx,$diff_tx" >> "$SYSTEM_METRICS_LOG"
    done
}
echo "[*] Starting System Wide Monitoring (CPU, RAM, Net) continuously..."
monitor_system &
SYS_MONITOR_PID=$!

# ==============================================================================
# SCENARIO 1: NO FIREWALL
# Rationale: Baseline unrestricted baseline networking performance.
# ==============================================================================
echo "----------------------------------------------------------------"
echo "[*] SCENARIO 1: No Firewall"
log_marker "START_SCENARIO_1: No Firewall"

# Clean iptables, accept all
iptables -F
iptables -P INPUT ACCEPT

start_tcpdump "p0_sc1_no_firewall.pcap"

echo "[*] Triggering Generator (1000 packets @ 50 PPS)..."
ssh $SSH_OPTS $VM1_USER@$VM1_IP "$GENERATOR_CMD --count 1000 --rate 50"
stop_tcpdump
sleep 2

# ==============================================================================
# SCENARIO 2: STATIC FIREWALL (DROP)
# Rationale: System behavior when blindly dropping all incoming UDP packets on the firewall.
# ==============================================================================
echo "----------------------------------------------------------------"
echo "[*] SCENARIO 2: Static Firewall (Drop All)"
log_marker "START_SCENARIO_2: Static Firewall (Drop All)"

# Set strict drop
iptables -F
iptables -P INPUT DROP
# Izinkan Loopback & Established connections (biar SSH lu gak putus)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

start_tcpdump "p0_sc2_static_drop.pcap"

echo "[*] Triggering Generator (1000 packets @ 50 PPS)..."
ssh $SSH_OPTS $VM1_USER@$VM1_IP "$GENERATOR_CMD --count 1000 --rate 50"
stop_tcpdump
sleep 2

# ==============================================================================
# SCENARIO 3: PHASE 0 SPA (USERS PACE)
# Rationale: Benchmarking the baseline SPA Python implementation.
# ==============================================================================
echo "----------------------------------------------------------------"
echo "[*] SCENARIO 3: Phase 0 SPA (Legacy Userspace)"
log_marker "START_SCENARIO_3: Phase 0 SPA (Legacy Userspace)"

# Allow SPA port manually
iptables -A INPUT -p udp --dport $TARGET_PORT -j ACCEPT

# Start Legacy Receiver
echo "[*] Launching Legacy Receiver in background..."
python3 "$RECEIVER_PATH" --port $TARGET_PORT --secret "my-secret" --log-file "$LOG_DIR/p0_events.csv" >> "$TEMP_APP_LOG" 2>&1 &
RECEIVER_PID=$!
sleep 2

if [[ -n "$RECEIVER_PID" ]]; then
    pidstat -p $RECEIVER_PID -u -r 1 >> "$CPU_LOG" &
    PIDSTAT_PID=$!
fi

echo "[*] Running Sequence 1 (Low Load: 100 packets @ 1 PPS)..."
log_marker "SCENARIO 3 - SEQUENCE 1: Low Load (1 PPS)"
start_tcpdump "p0_sc3_spa_low.pcap"
ssh $SSH_OPTS $VM1_USER@$VM1_IP "$GENERATOR_CMD --count 100 --rate 1"
stop_tcpdump
sleep 2

echo "[*] Running Sequence 2 (Sustained Load: 1000 packets @ 50 PPS)..."
log_marker "SCENARIO 3 - SEQUENCE 2: Sustained Load (50 PPS)"
start_tcpdump "p0_sc3_spa_sustained.pcap"
ssh $SSH_OPTS $VM1_USER@$VM1_IP "$GENERATOR_CMD --count 1000 --rate 50"
stop_tcpdump
sleep 2

echo "[*] Running Sequence 3 (Stress Test: 5000 packets @ Max Rate)..."
log_marker "SCENARIO 3 - SEQUENCE 3: Stress Test (Max Rate)"
start_tcpdump "p0_sc3_spa_stress.pcap"
ssh $SSH_OPTS $VM1_USER@$VM1_IP "$GENERATOR_CMD --count 5000 --rate 0"
stop_tcpdump

echo "----------------------------------------------------------------"
echo "[!!!] AUTOMATED SEQUENCES COMPLETE [!!!]"
echo "[*] The SPA Receiver is still running (PID: $RECEIVER_PID)."
echo "[*] You can now perform the manual DDoS Simulation (hping3) from VM1."
echo "[*] Monitoring CPU usage via pidstat in background..."
echo "----------------------------------------------------------------"
log_marker "SCENARIO 3 - MANUAL Phase: DDoS Simulation"
read -p "[PAUSE] Press [ENTER] when you are finished with the Manual Stress Test to stop and clean up..."
echo "----------------------------------------------------------------"

# --- 7. Final Consolidation ---
echo "[*] Consolidating logs into $RAW_LOG..."
sleep 2
cat "$CPU_LOG" >> "$RAW_LOG" 2>/dev/null
echo -e "\n--- APPLICATION LOGS ---" >> "$RAW_LOG"
cat "$TEMP_APP_LOG" >> "$RAW_LOG" 2>/dev/null

rm "$TEMP_APP_LOG" "$CPU_LOG" 2>/dev/null

echo "[+] BENCHMARK PHASE 0 COMPLETE"
echo "[+] Results saved to: $RAW_LOG"