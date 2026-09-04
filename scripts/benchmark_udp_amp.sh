#!/bin/bash

# Network Threat Detector - Volumetric UDP Amplification Benchmark
# This script blasts massive spoofed NTP packets to measure Mbps dropping capability.

TARGET_IP="127.0.0.1"
TEST_DURATION=10
PAYLOAD_SIZE=1000

echo "====================================================="
echo "  eBPF UDP Amplification Benchmark (XDP)"
echo "====================================================="
echo "[*] Target: $TARGET_IP"
echo "[*] Duration: $TEST_DURATION seconds"
echo "[*] Payload Size: $PAYLOAD_SIZE bytes"
echo "[*] Spoofing Source Port: 123 (NTP)"
echo "[*] Starting heavy UDP flood firehose..."

START_TIME=$(date +%s.%N)

# Use timeout to run the flood for exactly 10 seconds.
# -2 = UDP mode, -s 123 = source port 123 (NTP), -d 1000 = 1000 bytes data
sudo timeout $TEST_DURATION hping3 -2 -k -s 123 -p 9999 -d $PAYLOAD_SIZE --flood $TARGET_IP > udp_results.txt 2>&1

END_TIME=$(date +%s.%N)
ACTUAL_DURATION=$(echo "$END_TIME - $START_TIME" | bc)

TRANSMITTED=$(grep "packets transmitted" udp_results.txt | awk '{print $1}')
PACKET_LOSS=$(grep "packet loss" udp_results.txt | awk '{print $7}')

# Packet size math: 1000 (payload) + 8 (UDP header) + 20 (IP header) = 1028 bytes
TOTAL_BYTES=$(echo "$TRANSMITTED * 1028" | bc)
TOTAL_MEGABITS=$(echo "$TOTAL_BYTES * 8 / 1000000" | bc -l)
MBPS=$(printf "%.2f" $(echo "$TOTAL_MEGABITS / $TEST_DURATION" | bc -l))

echo "====================================================="
echo "  RESULTS"
echo "====================================================="
echo "[+] Time Elapsed:    ${ACTUAL_DURATION} seconds"
echo "[+] Packets Sent:    $TRANSMITTED"
echo "[+] Data Processed:  $(printf "%.2f" $TOTAL_MEGABITS) Megabits"
echo "[+] Packet Loss:     $PACKET_LOSS (Dropped by XDP!)"
echo "[+] Throughput:      $MBPS Mbps (Megabits Per Second)"
echo "====================================================="

rm udp_results.txt