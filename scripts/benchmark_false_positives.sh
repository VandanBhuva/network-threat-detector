#!/bin/bash

# Network Threat Detector - False-Positive Control Benchmark
# Proves benign traffic passes through untouched while a spoofed volumetric flood is dropped.

ATTACKER_IP="10.9.8.7"      # Spoofed attacker IP
TARGET_IP="127.0.0.2"       # Attack destination (using .2 to isolate the exfil tracker)
BENIGN_IP="127.0.0.1"       # Our legitimate IP
PORT=8080

echo "====================================================="
echo "  eBPF False-Positive Control Benchmark"
echo "====================================================="
echo "[*] Setting up benign local web server on $BENIGN_IP:$PORT..."

# Start a dummy Python web server in the background
python3 -m http.server $PORT --bind $BENIGN_IP > /dev/null 2>&1 &
SERVER_PID=$!

# Give the server a second to boot up
sleep 1

echo "[*] Launching volumetric SYN flood from spoofed Attacker ($ATTACKER_IP)..."
# Run hping3 in the background to flood the network concurrently
sudo hping3 -a $ATTACKER_IP -S -p 80 --flood $TARGET_IP > /dev/null 2>&1 &
HPING_PID=$!

echo "[*] Flood is active! Sending 10 benign requests..."
echo "-----------------------------------------------------"

SUCCESS_COUNT=0
TOTAL_REQUESTS=10

for i in $(seq 1 $TOTAL_REQUESTS); do
    # Perform a curl request and measure the HTTP status code
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$BENIGN_IP:$PORT)
    
    if [ "$HTTP_STATUS" = "200" ]; then
        echo "[+] Request $i: SUCCESS (HTTP 200) - Traffic passed cleanly!"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "[-] Request $i: FAILED (HTTP $HTTP_STATUS) - False positive / Dropped!"
    fi
    sleep 1
done

echo "-----------------------------------------------------"
echo "  RESULTS"
echo "-----------------------------------------------------"
echo "[+] Benign Requests Sent: $TOTAL_REQUESTS"
echo "[+] Benign Requests Won:  $SUCCESS_COUNT"

if [ "$SUCCESS_COUNT" -eq "$TOTAL_REQUESTS" ]; then
    echo "[+] False-Positive Rate:  0% (Perfect!)"
else
    echo "[-] False-Positive Rate:  >0% (Something got dropped)"
fi
echo "====================================================="

# Cleanup background processes
sudo kill -9 $HPING_PID
kill -9 $SERVER_PID