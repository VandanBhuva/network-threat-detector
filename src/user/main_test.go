package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
)

// TestIntToIP verifies the LittleEndian uint32 to IPv4 string conversion
func TestIntToIP(t *testing.T) {
	// Create a mock IP "192.168.1.100"
	mockIPStr := "192.168.1.100"
	parsedIP := net.ParseIP(mockIPStr).To4()
	
	// Convert it to uint32 LittleEndian (how eBPF sends it)
	ipUint := binary.LittleEndian.Uint32(parsedIP)

	// Run our helper function
	result := intToIP(ipUint)

	if result != mockIPStr {
		t.Errorf("intToIP failed: expected %s, got %s", mockIPStr, result)
	}
}

// TestMitreMapping verifies that our event codes map to the correct MITRE ATT&CK techniques
func TestMitreMapping(t *testing.T) {
	// Test Event Type 1 (SYN Flood)
	mitreContext, exists := MitreTable[1]
	
	if !exists {
		t.Fatalf("Event Type 1 missing from MitreTable")
	}

	expectedID := "T1498.001"
	if mitreContext.ID != expectedID {
		t.Errorf("Expected MITRE ID %s, got %s", expectedID, mitreContext.ID)
	}

	expectedName := "Direct Network Flood"
	if mitreContext.Name != expectedName {
		t.Errorf("Expected MITRE Name %s, got %s", expectedName, mitreContext.Name)
	}
}

// TestJSONMarshaling verifies that the SIEM-ready struct marshals correctly with json tags
func TestJSONMarshaling(t *testing.T) {
	alert := AlertPayload{
		Timestamp:  "2026-09-04T12:00:00Z",
		ThreatType: "UDP_AMPLIFICATION",
		SrcIP:      "10.9.8.7",
		DstIP:      "127.0.0.1",
		Action:     "DROP",
		MitreID:    "T1498.002",
		MitreName:  "Reflection Amplification",
	}

	jsonData, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("Failed to marshal AlertPayload: %v", err)
	}

	// Unmarshal back into a generic map to check JSON keys
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify the JSON keys match the SIEM requirements
	if result["threat_type"] != "UDP_AMPLIFICATION" {
		t.Errorf("JSON tag missing or incorrect for threat_type: got %v", result["threat_type"])
	}
	if result["mitre_attack_id"] != "T1498.002" {
		t.Errorf("JSON tag missing or incorrect for mitre_attack_id: got %v", result["mitre_attack_id"])
	}
}