#!/bin/bash

# Network Threat Detector - Volumetric SYN Flood Benchmark
# This script blasts SYN packets as fast as the hardware allows for 10 seconds.

TARGET_IP="127.0.0.1"
TEST_DURATION=10

echo "====================================================="
echo "  eBPF XDP SYN Flood Benchmark"
echo "====================================================="
echo "[*] Target: $TARGET_IP"
echo "[*] Duration: $TEST_DURATION seconds"
echo "[*] Starting flood firehose..."

START_TIME=$(date +%s.%N)

# Use 'timeout' to kill the infinite --flood after 10 seconds
sudo timeout $TEST_DURATION hping3 -S -p 80 --flood $TARGET_IP > hping3_results.txt 2>&1

END_TIME=$(date +%s.%N)
ACTUAL_DURATION=$(echo "$END_TIME - $START_TIME" | bc)

TRANSMITTED=$(grep "packets transmitted" hping3_results.txt | awk '{print $1}')
PACKET_LOSS=$(grep "packet loss" hping3_results.txt | awk '{print $7}')
PPS=$(echo "$TRANSMITTED / $TEST_DURATION" | bc)

echo "====================================================="
echo "  RESULTS"
echo "====================================================="
echo "[+] Time Elapsed:    ${ACTUAL_DURATION} seconds"
echo "[+] Packets Sent:    $TRANSMITTED"
echo "[+] Packet Loss:     $PACKET_LOSS (Dropped by XDP!)"
echo "[+] Throughput:      $PPS Packets Per Second (PPS)"
echo "====================================================="

rm hping3_results.txt