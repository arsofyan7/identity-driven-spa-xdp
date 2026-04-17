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
    # This line executes a sleep before removing the rule
    # Rationale: NIST Zero Trust requirement for session-based access - access is granted temporarily.
    time.sleep(30)
    
    # This line executes the command to remove the iptables rule
    # Rationale: Clean up the firewall rule to revoke access after the session timer expires.
    subprocess.run(["iptables", "-D", "INPUT", "-s", src_ip, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Removed iptables rule for {src_ip}")

def verify_and_process(data, addr, secret_key, log_file=None):
    # This line records the start time
    # Rationale: Measure processing time from recv() to subprocess.run() completion in microseconds.
    start_time = time.perf_counter_ns()
    
    # This line unpacks the binary payload assuming little-endian u32 (identity), u64 (timestamp), 32s (hmac)
    # Rationale: Interoperability with Rust's bincode serialization of primitives.
    try:
        identity_id, timestamp, signature = struct.unpack('<IQ32s', data)
    except struct.error:
        # Invalid packet format
        return

    # This line packs the identity and timestamp back to verify the HMAC
    # Rationale: We reconstruct the payload exactly as the generator signed it.
    payload = struct.pack('<IQ', identity_id, timestamp)
    
    # This line computes the expected HMAC
    # Rationale: Validate the cryptographic proof.
    expected_mac = hmac.new(secret_key.encode('utf-8'), payload, hashlib.sha256).digest()
    
    # This line securely compares the provided signature with the expected HMAC
    # Rationale: Use hmac.compare_digest to mitigate timing attacks during signature verification.
    if hmac.compare_digest(signature, expected_mac):
        src_ip = addr[0]
        
        # This line issues an iptables command to allow traffic from the source IP
        # Rationale: Grants network-level access, acting as the dynamic perimeter defined by SPA.
        subprocess.run(["iptables", "-I", "INPUT", "-s", src_ip, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # This line records the end time after iptables execution
        # Rationale: Captures the full latency cost of userspace processing and shell execution (Phase 0 overhead).
        end_time = time.perf_counter_ns()
        processing_time_us = (end_time - start_time) / 1000.0
        
        print(f"Valid SPA from {src_ip} (ID: {identity_id}). Processing time: {processing_time_us:.2f} us")
        
        if log_file:
            with open(log_file, "a") as f:
                f.write(f"{time.time()},{src_ip},{identity_id},{processing_time_us:.2f}\n")
        
        # This line spawns a delayed background thread for cleanup
        # Rationale: Implements the "Cleanup Timer" without blocking the receiver loop.
        threading.Thread(target=remove_iptables_rule, args=(src_ip,), daemon=True).start()
    else:
        # This line drops invalid packets silently
        # Rationale: The essence of SPA is stealth; we do not respond to unauthorized access attempts.
        pass

def main():
    # This line parses command-line arguments
    # Rationale: Allows dynamic configuration of the listening port and secret key for testing across different environments.
    parser = argparse.ArgumentParser(description="VM2 Legacy Receiver Phase 0")
    parser.add_argument("--port", type=int, default=8080, help="UDP Port to listen on")
    parser.add_argument("--secret", type=str, required=True, help="Shared secret for HMAC")
    parser.add_argument("--log-file", type=str, default="results/phase0_receiver_log.csv", help="Path to CSV log file")
    args = parser.parse_args()

    # Initialize log file
    if args.log_file and not os.path.exists(args.log_file):
        os.makedirs(os.path.dirname(args.log_file), exist_ok=True)
        with open(args.log_file, "w") as f:
            f.write("TIMESTAMP,SRC_IP,ID,LATENCY_US\n")

    # This line opens a standard UDP socket
    # Rationale: UDP is standard for SPA since it is connectionless and easily filtered.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    
    print(f"Listening for SPA packets on UDP {args.port}...")
    
    try:
        # This line continuously listens for incoming datagrams
        # Rationale: Polling loop typical of userspace daemons.
        while True:
            # We expect 4 bytes for ID, 8 for timestamp, 32 for HMAC = 44 bytes total.
            data, addr = sock.recvfrom(1024)
            if len(data) == 44:
                verify_and_process(data, addr, args.secret, args.log_file)
    except KeyboardInterrupt:
        print("\n[!] GhostPEP Receiver stopped by user.")
    finally:
        print("[*] Cleaning up resources and closing socket...")
        sock.close()
        # Opsional: tambahin fungsi buat flush iptables di sini biar bener-bener bersih

if __name__ == "__main__":
    main()
