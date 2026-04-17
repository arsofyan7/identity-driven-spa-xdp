# SOP: Phase 0 - Legacy Baseline Benchmarking

## 1. Objective
The primary goal of Phase 0 is to establish a **performance baseline** using the traditional Userspace-driven Single Packet Authorization (SPA) method (Python + Iptables). This data will serve as the "Legacy" point of comparison for the subsequent eBPF/XDP implementation in Phase 1.

## 2. Prerequisites
Ensure both Virtual Machines (VMs) are configured and can communicate over the internal network.

### 2.1 Virtual Machine 1 (Generator/Client)
* **Tools:** `cargo` (Rust toolchain), `hping3`.
* **Network:** Static IP assigned and reachable by VM2.
* **Clock Sync:** Ensure time is synchronized with VM2 to maintain log integrity.
* **Access:** Ensure VM2 can SSH into VM1 without a password prompt.

### 2.2 Virtual Machine 2 (Receiver/Gateway)
* **Tools:** `python3`, `iptables`, `sysstat` (for `pidstat`), `tcpdump`.
* **Privileges:** All benchmarking scripts and firewall commands must be executed with `sudo`.
* **Directory:** Project repository initialized with `results/raw_logs/` folder present.

---

## 3. Test Procedures

### Scenario 1: Functional Logic Validation
*Verify that the Identity-Driven SPA successfully triggers the dynamic firewall rules.*

1. **On VM2 (Receiver):** Start the legacy receiver manually.
   ```bash
   python3 vm2_receiver/phase0_legacy/receiver.py --secret "your-shared-secret" --ttl <xx in sec>
   ```
2. **On VM1 (Generator):** Send a single authorized SPA packet.
   ```bash
   cargo run --bin vm1_generator -- --target <VM2_IP> --identity <id-number> --secret "your-shared-secret"
   ```
3. **Verification:** Inspect the Iptables chain on VM2.
   ```bash
   sudo iptables -L -n
   ```
   **Expected Result:** A new `ACCEPT` rule for VM1's source IP should be visible in the `INPUT` chain.
---

### Scenario 2: Multi-Scenario Automated Benchmarking
*Measure the authorization latency, baseline hardware throughput, and system stability under 3 distinct networking firewall scenarios (No Firewall, Static Drop, SPA).*

1. **On VM2 (Receiver):** Execute the automated benchmarking suite, providing VM1's IP and User. The script will automatically trigger the generator via SSH.
   ```bash
   chmod +x benchmarking/suites/run_p0_stress.sh
   sudo ./benchmarking/suites/run_p0_stress.sh <VM1_IP> <VM1_USER>
   ```
2. **Observation:** The script runs 3 major scenarios and their respective sequences automatically:
   - **Scenario 1:** No Firewall (1000 packets)
   - **Scenario 2:** Static Firewall Drop (1000 packets)
   - **Scenario 3:** Phase 0 SPA Legacy (100 @ 1 PPS, 1000 @ 50 PPS, 5000 @ Max Rate)
   
3. **Completion:** The script will automatically separate the PCAP captures for each sequence, terminate background processes, and consolidate the execution logs upon completion.
---

### Scenario 3: Resilience & Stress Test (DDoS Simulation)
*Evaluate system behavior and resource exhaustion under a high-volume unauthorized traffic flood.*

1. **On VM2 (Receiver):** Start the `run_p0_stress.sh` script.
2. **On VM1 (Generator):** Bombard the SPA listener port using `hping3` to simulate a DDoS attack.
   ```bash
   sudo hping3 --flood --udp -p 1234 <VM2_IP>
   ```
3. **Observation:** Open a second terminal on VM2 and run `htop`. Monitor the **%CPU** of the Python process and the **%si** (Software Interrupts) overhead.
4. **Finalization:** Stop `hping3` after 30 seconds and press **[ENTER]** on VM2 to save the results.

---

## 4. Data Collection & Analysis
Benchmark outputs are stored in `results/raw_logs/`.

* **`phase0_receiver_log.csv`**: Structured log of payload validation and latency (`timestamp,src_ip,identity,latency_us`).
* **`p0_baseline.log`**: Combined application logs and CPU/RAM `pidstat` utilization data.
* **Separated Traffic Captures**: Raw network traffic captured via `tcpdump` sorted explicitly by scenario:
  * `p0_sc1_no_firewall.pcap`
  * `p0_sc2_static_drop.pcap`
  * `p0_sc3_spa_low.pcap`
  * `p0_sc3_spa_sustained.pcap`
  * `p0_sc3_spa_stress.pcap`

### Quick Latency Analysis
To calculate the average processing latency (in microseconds) directly from the CSV:
```bash
awk -F',' 'NR>1 {sum+=$4; count++} END {if (count > 0) print "Average Latency:", sum/count, "us"; else print "No data found."}' results/raw_logs/phase0_receiver_log.csv
```

---

## 5. Environment Cleanup
Restore the gateway to a neutral state to ensure no interference with future eBPF-based tests.

1. **Flush Iptables:**
   ```bash
   sudo iptables -F
   sudo iptables -P INPUT ACCEPT
   ```
2. **Terminate Background Processes:**
   ```bash
   sudo pkill tcpdump
   sudo pkill python3
   ```

---

## 6. NIST SP 800-207 Alignment
According to NIST Zero Trust tenets, the system must maintain a **"Default Deny"** posture. Throughout these tests, verify that all unauthorized traffic is strictly dropped at the **Policy Enforcement Point (PEP)** until a valid cryptographic identity is verified.
```