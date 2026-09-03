# eBPF Network Threat Detector

A high-performance network security monitor utilizing a hybrid XDP (ingress) and TCX (egress) eBPF architecture to detect, rate-limit, and drop malicious traffic at line rate.

## Overview
This project implements a custom eBPF agent that hooks directly into the Linux network stack to provide high-speed observability and active mitigation. By leveraging both XDP (eXpress Data Path) and TCX (Traffic Control), the detector identifies both external volumetric attacks and internal compromise behaviors.

## Architecture
*   **Kernel Space (eBPF):** C-based eBPF programs attached to network interfaces. 
    *   **XDP Hook:** Executes in the network driver before kernel memory allocation, acting as a high-speed shield against inbound volumetric floods.
    *   **TCX Hook:** Executes at the socket layer to monitor outbound application traffic, allowing for payload size and destination inspection.
*   **High-Performance State Management:** Utilizes `LRU_HASH`  maps to track thousands of connections concurrently without risking kernel memory exhaustion from spoofed IPs.
*   **Decoupled Telemetry (Ring Buffers):** Emits lightweight threat alerts via eBPF Ring Buffers to a Go-based user-space agent, ensuring the network stack is never blocked by logging overhead.

## Threat Detection Engine
1.  **SYN Flood Mitigation:** The XDP hook tracks inbound TCP SYN packets per source IP. If an IP breaches the rate-limit threshold (1,000 packets/sec), it is instantly dropped at line rate.
2.  **Data Exfiltration Detection:** The TCX hook tracks outbound byte volume per destination IP. If a single connection attempts to transmit over 100MB of raw data, the connection is severed to prevent intellectual property theft.
3.  **DNS Tunneling Detection:** Inspects outbound UDP port 53 traffic. If a DNS query exceeds normal limits (e.g., > 256 bytes), it is flagged as anomalous payload stuffing and dropped.

## Build Instructions
Ensure you have `clang`, `llvm`, `make`, and `go` installed.

1. **Generate the vmlinux header:**
   ```bash
   make vmlinux
   ```
2. **Compile the eBPF bytecode and Go agent:**
   ```bash
   make
   ```
3. **Run the monitor:**
   ```bash
   sudo ./src/user/agent
   ```