# VM2 Receiver (The Gatekeeper)
# Rationale: Python represents the "Traditional Userspace Proxy" which suffers from context-switching and system-call overhead.

import socket
import struct
import hmac
import hashlib
import time
import subprocess
import threading
import argparse
import os

def remove_iptables_rule(src_ip):
    # This line executes the command to remove the iptables rule
    # Rationale: Clean up the firewall rule to revoke access after the session timer expires.
    print(f"[*] Removing iptables rule for {src_ip}...")
    res = subprocess.run(["iptables", "-D", "INPUT", "-s", src_ip, "-j", "ACCEPT"], capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[-] Successfully removed rule for {src_ip}")
    else:
        print(f"[!] Error removing rule: {res.stderr.strip()}")

def delayed_cleanup(src_ip, ttl):
    """Wait for TTL and then remove the iptables rule in a background thread."""
    print(f"[+] SPA Valid. Opening access for {src_ip} for {ttl} seconds (background thread)...")
    time.sleep(ttl)
    remove_iptables_rule(src_ip)
    print(f"[-] TTL Expired. Removing access for {src_ip}.")

def verify_and_process(data, addr, secret_key, ttl, log_file=None):
    src_ip = addr[0]
    print(f"[DEBUG] Received {len(data)} bytes from {src_ip}")
    
    # Measure processing time from recv() to validation completion
    start_time = time.perf_counter_ns()
    
    if len(data) != 44:
        print(f"[FAILED] Invalid packet length: {len(data)} (Expected 44)")
        return

    try:
        identity_id, timestamp, signature = struct.unpack('<IQ32s', data)
    except struct.error as e:
        print(f"[FAILED] Struct unpack error: {e}")
        return

    payload = struct.pack('<IQ', identity_id, timestamp)
    expected_mac = hmac.new(secret_key.encode('utf-8'), payload, hashlib.sha256).digest()
    
    if hmac.compare_digest(signature, expected_mac):
        print(f"[+] HMAC Valid for ID {identity_id}")
        
        # Execute iptables to allow traffic
        print(f"[*] Executing iptables -I INPUT -s {src_ip} -j ACCEPT...")
        res = subprocess.run(["iptables", "-I", "INPUT", "-s", src_ip, "-j", "ACCEPT"], capture_output=True, text=True)
        
        if res.returncode != 0:
            print(f"[!] iptables command FAILED: {res.stderr.strip()}")
            return

        end_time = time.perf_counter_ns()
        processing_time_us = (end_time - start_time) / 1000.0
        
        print(f"Valid SPA from {src_ip} (ID: {identity_id}). Processing time: {processing_time_us:.2f} us")
        
        if log_file:
            try:
                # Open with line buffering to ensure markers added by the orchestrator aren't overwritten/corrupted
                with open(log_file, "a", buffering=1) as f:
                    f.write(f"{time.time():.6f},{src_ip},{identity_id},{processing_time_us:.2f}\n")
            except Exception as e:
                print(f"[!] Log error: {e}")
        
        # Launch TTL Window in a background thread (Non-blocking)
        # Rationale: Simplicity preferred; overlapping rules are harmless for Phase 0 benchmarking.
        threading.Thread(target=delayed_cleanup, args=(src_ip, ttl), daemon=True).start()
    else:
        print(f"[FAILED] Signature mismatch for ID {identity_id}.")
        pass

def main():
    # Root Check
    if os.name != 'nt' and os.geteuid() != 0:
        print("[!] WARNING: This script must be run as root to manage iptables rules.")
        print("[*] Try: sudo python3 receiver.py ...")

    parser = argparse.ArgumentParser(description="VM2 Legacy Receiver Phase 0 (MULTI-THREADED)")
    parser.add_argument("--port", type=int, default=1234, help="UDP Port to listen on")
    parser.add_argument("--secret", type=str, required=True, help="Shared secret for HMAC")
    parser.add_argument("--log-file", type=str, default="results/raw_logs/p0_events.csv", help="Path to CSV log file")
    parser.add_argument("--ttl", type=int, default=10, help="Authorization Window (seconds)")
    args = parser.parse_args()

    # Initialize log file with header if it doesn't exist
    if args.log_file:
        log_dir = os.path.dirname(args.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        if not os.path.exists(args.log_file):
            with open(args.log_file, "w") as f:
                f.write("timestamp,src_ip,identity,latency_us\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    
    print(f"[*] GhostPEP Phase 0 Receiver listening on UDP {args.port}...")
    
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            verify_and_process(data, addr, args.secret, args.ttl, args.log_file)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        sock.close()


        # Opsional: tambahin fungsi buat flush iptables di sini biar bener-bener bersih

if __name__ == "__main__":
    main()
