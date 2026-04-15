# Identity-Driven SPA via eBPF for Stealthy Zero Trust Gateways

![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)
![NIST Compliance](https://img.shields.io/badge/NIST%20SP%20800--207-Compliant-blue)
![Status](https://img.shields.io/badge/Status-Phase%200%20(Baseline)-orange)

Identity-Driven Single Packet Authorization (SPA) using eBPF/XDP for Stealthy Zero Trust Gateways, based on NIST SP 800-207.

## Overview

This project explores the implementation of a high-performance, identity-driven Zero Trust Architecture (ZTA). By leveraging Single Packet Authorization (SPA) and offloading the validation process to the kernel level using eBPF/XDP, we achieve near-zero overhead and maximum stealth for the gateway. 

Conventional SPA implementations often rely on userspace processing, which can be vulnerable to resource exhaustion. This research demonstrates a transition from legacy userspace processing (Phase 0) to hardware-accelerated, kernel-level validation (Phase 1).

## Architecture

The following diagram illustrates the flow of the Identity-Driven SPA packet from the generator to the gatekeeper.

```mermaid
graph LR
    subgraph VM1 ["VM1: The Generator"]
        A[Client Application] -->|HMAC + Identity| B(SPA Packet)
    end

    subgraph VM2 ["VM2: The Gatekeeper"]
        B --> C{XDP Hook / eBPF}
        C -->|Authorized| D[Unblock IP / Forward]
        C -->|Unauthorized| E[Drop Packet]
        D --> F[Protected Service]
    end

    style VM1 fill:#f9f,stroke:#333,stroke-width:2px
    style VM2 fill:#bbf,stroke:#333,stroke-width:2px
```

## Getting Started (Phase 0: Baseline)

Follow these steps to run the legacy Phase 0 simulation, which uses standard userspace processing.

### 1. Prerequisites
- Rust (for the generator)
- Python 3.x (for the receiver)

### 2. Run the Gatekeeper (Receiver)
Navigate to the receiver directory and run the legacy Python script:
```bash
cd vm2_receiver/phase0_legacy
python receiver.py
```

### 3. Run the Client (Generator)
In a separate terminal, run the Rust-based packet generator:
```bash
cd vm1_generator
cargo run -- --phase p0
```

## Research Roadmap
- [x] **Phase 0**: Legacy Userspace Implementation (HMAC + Python/Iptables).
- [/] **Phase 1**: eBPF/XDP Optimization (Rust Aya/C + Kernel Hook).
- [ ] **Phase 2**: Benchmarking and Metric Aggregation under Stress.

## References
- NIST SP 800-207: Zero Trust Architecture.
- eBPF/XDP Documentation: [ebpf.io](https://ebpf.io/)
