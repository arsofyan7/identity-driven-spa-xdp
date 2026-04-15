#!/bin/bash

# ==============================================================================
# GhostPEP Phase 0 Benchmarking Suite
# Role: Senior DevOps & Performance Engineer
# Description: Automated stress test for Legacy Userspace SPA (Iptables)
# ==============================================================================

# --- 1. Konfigurasi & Variabel ---
IFACE="eth0" # Sesuaikan dengan interface VM2 lu
TARGET_PORT=1234
RECEIVER_PATH="vm2_receiver/phase0_legacy/receiver.py"
LOG_DIR="results/raw_logs"
RAW_LOG="$LOG_DIR/p0_baseline.log"
CPU_LOG="$LOG_DIR/p0_cpu_usage.log"
PACKET_LOG="$LOG_DIR/p0_packets.pcap"
TEMP_APP_LOG="p0_app_temp.log"

# Pastikan folder log tersedia
mkdir -p "$LOG_DIR"

# --- 2. Pre-flight Checks ---
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

# --- 3. Environment Setup (Hardening) ---
echo "[*] Cleaning up iptables and setting default DROP policy..."
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Izinkan Loopback & Established connections (biar SSH lu gak putus)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Izinkan port SPA (UDP)
iptables -A INPUT -p udp --dport $TARGET_PORT -j ACCEPT

# --- 4. Process Management ---
echo "[*] Launching Legacy Receiver in background..."
python3 "$RECEIVER_PATH" > "$TEMP_APP_LOG" 2>&1 &
RECEIVER_PID=$!

# Beri waktu listener untuk binding socket
sleep 2

if ps -p $RECEIVER_PID > /dev/null; then
   echo "[+] Receiver is running (PID: $RECEIVER_PID)"
else
   echo "[-] Error: Receiver failed to start."
   exit 1
fi

# --- 5. Metrics Collection (The Core) ---
echo "[*] Starting metrics collection (pidstat & tcpdump)..."
# Rekam CPU & Memory setiap 1 detik untuk PID Receiver
pidstat -p $RECEIVER_PID -u -r 1 > "$CPU_LOG" &
PIDSTAT_PID=$!

# Rekam arrival time paket untuk analisa latensi hardware vs software
tcpdump -i $IFACE udp port $TARGET_PORT -tt -v -w "$PACKET_LOG" 2> /dev/null &
TCPDUMP_PID=$!

# --- 6. Test Execution Trigger ---
echo "----------------------------------------------------------------"
echo ">>> ACTION REQUIRED <<<"
echo "Silahkan jalankan vm1_generator sekarang di VM1."
echo "Contoh: cargo run --bin generator -- run --phase 0 --target $(hostname -I | awk '{print $1}') --secret 'my-secret'"
echo "----------------------------------------------------------------"

read -p "[?] Tekan [ENTER] jika pengiriman paket dari VM1 sudah selesai..." -n 1 -r

# --- 7. Cleanup & Logging ---
echo -e "\n[*] Cleaning up processes..."
kill $RECEIVER_PID
kill $PIDSTAT_PID
kill $TCPDUMP_PID

# Berikan waktu proses I/O selesai
sleep 2

# Konsolidasi Log ke file final
echo "--- SYSTEM METRICS ---" > "$RAW_LOG"
cat "$CPU_LOG" >> "$RAW_LOG"
echo -e "\n--- APPLICATION LOGS ---" >> "$RAW_LOG"
cat "$TEMP_APP_LOG" >> "$RAW_LOG"

# Hapus file temporary
rm "$TEMP_APP_LOG" "$CPU_LOG"

# --- 8. Summary Sederhana ---
TOTAL_AUTH=$(grep -c "Access Granted" "$RAW_LOG")
echo "----------------------------------------------------------------"
echo "[+] BENCHMARK PHASE 0 COMPLETE"
echo "[+] Results saved to: $RAW_LOG"
echo "[+] PCAP file saved to: $PACKET_LOG"
echo "[+] Total Identity Verified: $TOTAL_AUTH packets"
echo "----------------------------------------------------------------"

# Kembalikan policy ke ACCEPT (opsional, untuk kemudahan dev)
# iptables -P INPUT ACCEPT