# eBPF Network Threat Detector

A high-performance network security monitor utilizing a hybrid XDP (ingress) and TCX (egress) eBPF architecture to detect, rate-limit, and drop malicious traffic at line rate.

## Overview
This project implements a custom eBPF agent that hooks directly into the Linux network stack to provide high-speed observability and active mitigation. By leveraging both XDP (eXpress Data Path) and TCX (Traffic Control), the detector identifies both external volumetric attacks and internal compromise behaviors without adding overhead to the kernel routing table.

## Architecture
*   **Kernel Space (eBPF):** C-based eBPF programs attached to network interfaces. 
    *   **XDP Hook:** Executes in the network driver before kernel memory allocation, acting as a high-speed shield against inbound volumetric floods and Layer 2 attacks.
    *   **TCX Hook:** Executes at the socket layer to monitor outbound application traffic, allowing for payload size, destination inspection, and behavioral timing analysis.
*   **High-Performance State Management:** Utilizes `LRU_HASH` maps to track thousands of connections concurrently without risking kernel memory exhaustion from spoofed IPs.
*   **Decoupled Telemetry (Ring Buffers):** Emits lightweight threat alerts via eBPF Ring Buffers to a Go-based user-space agent, ensuring the network stack is never blocked by logging overhead.

## Threat Detection Engine

### Ingress Defenses (XDP)
1.  **ARP Spoofing Prevention (Layer 2):** Validates inbound ARP Replies against a trusted IP-to-MAC memory map, dropping poisoned frames at the driver level before the OS routing table is compromised.
2.  **SYN Flood Mitigation (Layer 4):** Tracks inbound TCP SYN packets per source IP. If an IP breaches the rate-limit threshold (1,000 packets/sec), it is instantly dropped at line rate.
3.  **Port-Scan Detection (Layer 4):** Tracks the number of unique destination ports targeted by a single IP within a rolling 1-second time window using bounded unrolled loops, dropping packets if reconnaissance behavior is detected.
4.  **UDP Amplification Mitigation (Layer 4):** Inspects inbound UDP traffic from frequently abused reflection ports (e.g., NTP, Memcached) and drops abnormally massive payloads at wire speed.

### Egress Defenses (TCX)
5.  **C2 Beaconing Detection:** Analyzes the timing variance (jitter) between outbound TCP SYN connection attempts to web ports (80/443). Identifies and terminates programmatic malware heartbeats that exhibit zero human variance.
6.  **Data Exfiltration Detection (Layer 7):** Tracks outbound byte volume per destination IP. If a single background process attempts to transmit over 100MB of raw data, the connection is severed to prevent intellectual property theft.
7.  **DNS Tunneling Detection (Layer 7):** Inspects outbound UDP port 53 traffic. If a DNS query exceeds normal limits (e.g., > 256 bytes), it is flagged as anomalous payload stuffing and dropped.

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