#ifndef __EVENT_H
#define __EVENT_H

#define EVENT_TYPE_SYN_FLOOD  1
#define EVENT_TYPE_EXFIL      2
#define EVENT_TYPE_DNS_TUNNEL 3

#define ACTION_DROP 1

// Shared struct between kernel space and user space.
struct threat_event {
    unsigned long long timestamp;
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned int event_type;
    unsigned int action_taken;
};

#endif /* __EVENT_H */