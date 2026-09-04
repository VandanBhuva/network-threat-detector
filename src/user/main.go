package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetworkMonitor ../kernel/network_monitor.bpf.c -- -I../kernel -Wno-missing-declarations -O2 -g

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "errors"
    "flag"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

// ThreatEvent represents a detected threat event
type ThreatEvent struct {
    Timestamp   uint64
    SrcIP       uint32
    DstIP       uint32
    EventType   uint32
    ActionTaken uint32
}

// Structured JSON payload for SIEM ingestion
type AlertPayload struct {
    Timestamp   string `json:"timestamp"`
    ThreatType  string `json:"threat_type"`
    SrcIP       string `json:"src_ip"`
    DstIP       string `json:"dst_ip"`
    Action      string `json:"action"`
    MitreID     string `json:"mitre_attack_id"`
    MitreName   string `json:"mitre_technique"`
}

// MitreLookup holds the ATT&CK framework context
type MitreLookup struct {
    Name string
    ID   string
}

// Map our internal event IDs to MITRE ATT&CK techniques
var MitreTable = map[uint32]MitreLookup{
    1: {"Direct Network Flood", "T1498.001"},
    2: {"Exfiltration Over Alternative Protocol", "T1048"},
    3: {"Application Layer Protocol: DNS", "T1071.004"},
    4: {"ARP Cache Poisoning", "T1557.002"},
    5: {"Network Service Discovery", "T1046"},
    6: {"Application Layer Protocol: Web Protocols", "T1071.001"},
    7: {"Reflection Amplification", "T1498.002"},
}

// Helper to format IPs
func intToIP(ip uint32) string {
    result := make(net.IP, 4)
    binary.LittleEndian.PutUint32(result, ip)
    return result.String()
}

func main() {
    // ----------------------------------------------------
    // CLI FLAGS
    // ----------------------------------------------------
    ifaceFlag := flag.String("iface", "lo", "Network interface to attach the eBPF hooks to (e.g., lo, eth0, wlan0)")
    gwIPFlag := flag.String("gateway-ip", "192.168.1.1", "IP address of the trusted gateway for ARP protection")
    gwMACFlag := flag.String("gateway-mac", "aa:bb:cc:dd:ee:ff", "MAC address of the trusted gateway for ARP protection")
    flag.Parse()

    // Remove resource limits for eBPF map allocation
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock: %v", err)
    }

    // Load compiled eBPF objects into the kernel
    var objs NetworkMonitorObjects
    if err := LoadNetworkMonitorObjects(&objs, nil); err != nil {
        log.Fatalf("Failed to load objects: %v", err)
    }
    defer objs.Close()

    // Attach to the loopback interface for safe testing
    ifaceName := *ifaceFlag
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        log.Fatalf("Failed to find interface %s: %v", ifaceName, err)
    }

    // 1. Attach XDP Hook (Ingress)
    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.XdpIngress,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatalf("Failed to attach XDP: %v", err)
    }
    defer xdpLink.Close()
    log.Printf("XDP attached to %s (Ingress)", ifaceName)

    // 2. Attach TCX Hook (Egress)
    tcxLink, err := link.AttachTCX(link.TCXOptions{
        Program:   objs.TcxEgress,
        Interface: iface.Index,
        Attach:    ebpf.AttachTCXEgress,
    })
    if err != nil {
        log.Fatalf("Failed to attach TCX: %v (Ensure you are on Linux 6.6+)", err)
    }
    defer tcxLink.Close()
    log.Printf("TCX attached to %s (Egress)", ifaceName)

    // ----------------------------------------------------
    // SEED ARP SPOOFING TRUSTED MAC MAP
    // ----------------------------------------------------
    parsedIP := net.ParseIP(*gwIPFlag)
    if parsedIP == nil {
        log.Fatalf("Invalid gateway IP provided: %s", *gwIPFlag)
    }
    gatewayIP := binary.LittleEndian.Uint32(parsedIP.To4())
    
    realMAC, err := net.ParseMAC(*gwMACFlag)
    if err != nil {
        log.Fatalf("Invalid gateway MAC provided: %v", err)
    }
    var macBytes [6]byte
    copy(macBytes[:], realMAC)

    // Push the trusted pair into the eBPF map
    err = objs.TrustedMacs.Update(&gatewayIP, &macBytes, ebpf.UpdateAny)
    if err != nil {
        log.Fatalf("Failed to seed trusted MAC map: %v", err)
    }
    log.Printf("Seeded ARP protection for gateway %s (%s)", *gwIPFlag, *gwMACFlag)

    // Open Ring Buffer Reader
    rd, err := ringbuf.NewReader(objs.Alerts)
    if err != nil {
        log.Fatalf("Opening ringbuf reader: %s", err)
    }
    defer rd.Close()

    // Graceful shutdown
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-stopper
        log.Println("Detaching hooks and closing ring buffer...")

        // Read kernel metrics from the eBPF map
        var udpDrops, synDrops, dataExfilDrops uint64
        errUdp := objs.DropMetrics.Lookup(uint32(1), &udpDrops)
        errSyn := objs.DropMetrics.Lookup(uint32(2), &synDrops)
        errDataExfil := objs.DropMetrics.Lookup(uint32(3), &dataExfilDrops)
        
        if errUdp == nil && errSyn == nil && errDataExfil == nil {
            log.Println("\n=================================================")
            log.Println("  KERNEL ENFORCEMENT METRICS")
            log.Println("=================================================")
            log.Printf("[+] UDP Amplification Drops : %d", udpDrops)
            log.Printf("[+] SYN Flood Drops         : %d", synDrops)
            log.Printf("[+] Data Exfiltration Drops : %d", dataExfilDrops)
            log.Println("=================================================")
        } else {
            log.Printf("Failed to read metrics map: %v %v", errUdp, errSyn)
        }

        rd.Close()
        os.Exit(0)
    }()

    log.Println("Listening for threat events... Emitting JSON to stdout.")

    for {
        record, err := rd.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                break
            }
            log.Printf("Error reading from ringbuf: %s", err)
            continue
        }

        var event ThreatEvent
        if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
            log.Printf("Parsing ringbuf event: %s", err)
            continue
        }

        var threatType string
        switch event.EventType {
        case 1:
            threatType = "SYN_FLOOD"
        case 2:
            threatType = "DATA_EXFILTRATION"
        case 3:
            threatType = "DNS_TUNNELING"
        case 4:
            threatType = "ARP_SPOOFING"
        case 5:
            threatType = "PORT_SCAN" 
        case 6:
            threatType = "C2_BEACONING"
        case 7:
            threatType = "UDP_AMPLIFICATION" 
        default:
            threatType = "UNKNOWN"
        }

        mitreContext := MitreTable[event.EventType]

        // Construct the SIEM-ready JSON payload
        alert := AlertPayload{
            Timestamp:  time.Now().UTC().Format(time.RFC3339),
            ThreatType: threatType,
            SrcIP:      intToIP(event.SrcIP),
            DstIP:      intToIP(event.DstIP),
            Action:     "DROP", // All our current rules result in drops
            MitreID:    mitreContext.ID,
            MitreName:  mitreContext.Name,
        }

        jsonData, err := json.Marshal(alert)
        if err != nil {
            log.Printf("JSON marshaling failed: %v", err)
            continue
        }

        // Print bare JSON so it can be easily piped into jq or a log shipper
        os.Stdout.Write(append(jsonData, '\n'))
    }
}