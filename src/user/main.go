package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetworkMonitor ../kernel/network_monitor.bpf.c -- -I../kernel -Wno-missing-declarations -O2 -g

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
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
	ifaceName := "lo"
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

	// Graceful shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Polling loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var ingressKey uint32 = 0
	var egressKey uint32 = 1
	var ingressCount, egressCount uint64

	log.Println("Monitoring traffic... Press Ctrl+C to exit.")

	for {
		select {
		case <-ticker.C:
			objs.PktCount.Lookup(&ingressKey, &ingressCount)
			objs.PktCount.Lookup(&egressKey, &egressCount)
			log.Printf("Packets -> Ingress (XDP): %d | Egress (TCX): %d", ingressCount, egressCount)
		case <-stopper:
			log.Println("Detaching hooks and exiting...")
			return
		}
	}
}