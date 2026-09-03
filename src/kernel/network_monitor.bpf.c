#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define THRESHOLD 1000 // SYN packets per window
#define TIME_WINDOW_NS 1000000000ULL // 1 second

// Helper for byte-swapping (endianness)
#define bpf_htons(x) __builtin_bswap16(x)

struct rate_limit {
    __u64 last_update;
    __u32 count;
};

// LRU Hash map to prevent memory exhaustion from spoofed IPs
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // Source IPv4 Address
    __type(value, struct rate_limit);
    __uint(max_entries, 65536);
} syn_tracker SEC(".maps");

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
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IPv4 Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. Parse TCP Header (Accounting for variable IP header length)
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // 4. Detect SYN Packet (SYN set, ACK not set)
    if (tcp->syn && !tcp->ack) {
        __u32 src_ip = ip->saddr;
        __u64 now = bpf_ktime_get_ns();
        
        struct rate_limit *rl = bpf_map_lookup_elem(&syn_tracker, &src_ip);
        if (rl) {
            if (now - rl->last_update > TIME_WINDOW_NS) {
                // Time window passed, reset counter
                rl->count = 1;
                rl->last_update = now;
            } else {
                rl->count++;
                if (rl->count > THRESHOLD) {
                    // Drop the malicious packet at line rate
                    return XDP_DROP;
                }
            }
        } else {
            // First time seeing this IP send a SYN
            struct rate_limit new_rl = { .last_update = now, .count = 1 };
            bpf_map_update_elem(&syn_tracker, &src_ip, &new_rl, BPF_ANY);
        }
    }

    // Pass everything else and increment the generic test counter
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&pkt_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
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