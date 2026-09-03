#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "event.h"

// --------------------------------------------------------
// CONSTANTS & MACROS
// --------------------------------------------------------
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define DNS_PORT 53
#define ARPOP_REPLY 2

#define SYN_THRESHOLD 1000                  // Max SYN packets per window
#define TIME_WINDOW_NS 1000000000ULL    // 1 second windoe
#define EXFIL_THRESHOLD 104857600       // 100 MB outbound data limit per IP
#define DNS_TUNNEL_SIZE 256             // Max normal DNS query size in bytes

// Helper for byte-swapping (endianness)
#define bpf_htons(x) __builtin_bswap16(x)

// --------------------------------------------------------
// MAP DEFINITIONS
// --------------------------------------------------------

// The Ring Buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer size
} alerts SEC(".maps");

// Ingress SYN Tracker
// Rate limit structure to track SYN packet counts
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

// Egress Connection Tracker
// Tracks outbound connection state
struct egress_state {
    __u64 byte_count;
    __u64 last_packet_time;
};

// Tracks outbound byte volume per destination IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // Destination IPv4 Address
    __type(value, struct egress_state);
    __uint(max_entries, 65536);
} egress_tracker SEC(".maps");

// Generic packet counter for testing
// Key 0 = Ingress (XDP), Key 1 = Egress (TCX)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} pkt_count SEC(".maps");

// eBPF doesn't have a standard nested ARP struct in vmlinux.h that includes 
// the payload addresses, so we define the standard Ethernet/IPv4 ARP layout.
struct arp_ipv4 {
    __be16 ar_hrd;    // Hardware type
    __be16 ar_pro;    // Protocol type
    __u8   ar_hln;    // Hardware length (6 for MAC)
    __u8   ar_pln;    // Protocol length (4 for IPv4)
    __be16 ar_op;     // ARP opcode (Request or Reply)
    __u8   ar_sha[6]; // Sender MAC address
    __u32  ar_sip;    // Sender IP address
    __u8   ar_tha[6]; // Target MAC address
    __u32  ar_tip;    // Target IP address
} __attribute__((packed));

// Map to hold our trusted IP -> MAC pairings (e.g., our Router's real MAC)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);     // Protected IPv4 Address
    __type(value, __u8[6]); // Expected MAC Address
    __uint(max_entries, 256);
} trusted_macs SEC(".maps");


// Ingress Hook (SYN Flood Shield)
SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // ----------------------------------------------------
    // ARP SPOOFING DETECTOR (LAYER 2)
    // ----------------------------------------------------
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        struct arp_ipv4 *arp = (void *)(eth + 1);
        
        // Verifier bounds check for the ARP payload
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        // We only care about ARP Replies (where poisoning happens)
        if (arp->ar_op == bpf_htons(ARPOP_REPLY)) {
            __u32 sender_ip = arp->ar_sip;
            
            // Look up if this IP is in our protected list (like our gateway)
            __u8 *expected_mac = bpf_map_lookup_elem(&trusted_macs, &sender_ip);
            if (expected_mac) {
                // Compare the MAC claiming to be this IP against our trusted MAC
                // We have to check byte-by-byte because eBPF doesn't have memcmp()
                if (arp->ar_sha[0] != expected_mac[0] ||
                    arp->ar_sha[1] != expected_mac[1] ||
                    arp->ar_sha[2] != expected_mac[2] ||
                    arp->ar_sha[3] != expected_mac[3] ||
                    arp->ar_sha[4] != expected_mac[4] ||
                    arp->ar_sha[5] != expected_mac[5]) {
                    
                    // The MAC doesn't match! Someone is spoofing.
                    // Emit a threat event to the Ring Buffer
                    struct threat_event *e = bpf_ringbuf_reserve(&alerts, sizeof(*e), 0);
                    if (e) {
                        e->timestamp = bpf_ktime_get_ns();
                        e->src_ip = sender_ip;
                        e->dst_ip = arp->ar_tip;
                        e->event_type = 4; // EVENT_TYPE_ARP_SPOOF
                        e->action_taken = ACTION_DROP;
                        bpf_ringbuf_submit(e, 0);
                    }
                    return XDP_DROP;
                }
            }
        }
        return XDP_PASS; // Legitimate ARP traffic
    }

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
                if (rl->count > SYN_THRESHOLD) {
                    // Emit Threat Event
                    struct threat_event *e = bpf_ringbuf_reserve(&alerts, sizeof(*e), 0);
                    if (e) {
                        e->timestamp = now;
                        e->src_ip = src_ip;
                        e->dst_ip = ip->daddr;
                        e->event_type = EVENT_TYPE_SYN_FLOOD;
                        e->action_taken = ACTION_DROP;
                        bpf_ringbuf_submit(e, 0);
                    }

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

// Egress Hook (Exfiltration & DNS tunneling detect)
SEC("tcx/egress")
int tcx_egress(struct __sk_buff *skb) {
    // In TCX, we can access the packet data directly via the skb pointers
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TCX_PASS;

    // Only inspect IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TCX_PASS;

    // 2. Parse IPv4 Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TCX_PASS;

    __u32 dst_ip = ip->daddr;
    __u32 pkt_len = skb->len; // Total packet length from the sk_buff metadata
    __u64 now = bpf_ktime_get_ns();

    // ----------------------------------------------------
    // DATA EXFILTRATION DETECTION
    // ----------------------------------------------------
    // We track the total outbound bytes sent to a specific external IP.
    struct egress_state *state = bpf_map_lookup_elem(&egress_tracker, &dst_ip);
    if (state) {
        // Atomic add because multiple CPU cores might process egress traffic
        __sync_fetch_and_add(&state->byte_count, pkt_len);
        state->last_packet_time = now;
        
        // If a background process sends over 100MB to a single IP, drop it.
        if (state->byte_count > EXFIL_THRESHOLD) {
            struct threat_event *e = bpf_ringbuf_reserve(&alerts, sizeof(*e), 0);
            if (e) {
                e->timestamp = now;
                e->src_ip = ip->saddr;
                e->dst_ip = dst_ip;
                e->event_type = EVENT_TYPE_EXFIL;
                e->action_taken = ACTION_DROP;
                bpf_ringbuf_submit(e, 0);
            }
            return TCX_DROP; 
        }
    } else {
        // First time connecting to this IP: Initialize the state
        struct egress_state new_state = { .byte_count = pkt_len, .last_packet_time = now };
        bpf_map_update_elem(&egress_tracker, &dst_ip, &new_state, BPF_ANY);
    }

    // ----------------------------------------------------
    // DNS TUNNELING DETECTION
    // ----------------------------------------------------
    if (ip->protocol == IPPROTO_UDP) {
        // Calculate where the UDP header starts based on variable IP header length
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        
        // Parse UDP Header
        if ((void *)(udp + 1) <= data_end) {
            
            // Check if outbound traffic is destined for port 53 (DNS)
            if (udp->dest == bpf_htons(DNS_PORT)) {
                
                // Anomalous payload heuristic:
                // Normal DNS queries are small. DNS Tunneling malware stuffs 
                // massive encrypted payloads into the query domains or TXT records.
                // If the UDP payload exceeds our baseline threshold, drop it.
                if (bpf_htons(udp->len) > DNS_TUNNEL_SIZE) {
                    struct threat_event *e = bpf_ringbuf_reserve(&alerts, sizeof(*e), 0);
                    if (e) {
                        e->timestamp = now;
                        e->src_ip = ip->saddr;
                        e->dst_ip = dst_ip;
                        e->event_type = EVENT_TYPE_DNS_TUNNEL;
                        e->action_taken = ACTION_DROP;
                        bpf_ringbuf_submit(e, 0);
                    }
                    return TCX_DROP;
                }
            }
        }
    }

    // Increment the generic test counter for visibility
    __u32 key = 1;
    __u64 *value = bpf_map_lookup_elem(&pkt_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    return TCX_PASS; 
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";