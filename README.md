# eBPF Network Threat Detector

A high-performance network security monitor utilizing a hybrid XDP (ingress) and TCX (egress) eBPF architecture to detect and drop malicious traffic at line rate.

## Architecture
*   **Kernel Space (eBPF):** C-based eBPF programs attached to XDP (for pre-routing packet drops) and TCX (for socket-aware egress monitoring).
*   **User Space (Go):** A concurrent Go agent utilizing `cilium/ebpf` to manage eBPF maps, ring buffers, and threat heuristics.
