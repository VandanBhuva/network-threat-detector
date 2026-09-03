#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Shared map to hold packet counts. 
// Key 0 = Ingress (XDP), Key 1 = Egress (TCX)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} pkt_count SEC(".maps");

// The Ingress Hook (Fast Path)
SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&pkt_count, &key);
    if (value) {
        // Atomic increment to prevent race conditions across CPU cores
        __sync_fetch_and_add(value, 1);
    }
    // Always pass the packet for this testing phase
    return XDP_PASS;
}

// The Egress Hook (Socket-aware)
SEC("tcx/egress")
int tcx_egress(struct __sk_buff *skb) {
    __u32 key = 1;
    __u64 *value = bpf_map_lookup_elem(&pkt_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    // TCX_PASS is essentially 0 (same as TC_ACT_OK)
    return TCX_PASS; 
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";