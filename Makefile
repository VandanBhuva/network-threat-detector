# Network Threat Detector Makefile
.PHONY: all generate build clean vmlinux

# Default target runs both generation and compilation
all: generate build

# Generate eBPF bytecode and Go bindings
generate:
	@echo "==> Generating eBPF bytecode and Go bindings..."
	cd src/user && go generate

# Compile the Go user-space agent[cite: 1]
build: generate
	@echo "==> Building the Go agent..."
	cd src/user && go build -o agent .
	@echo "==> Build complete! Run with: sudo ./src/user/agent"

# Clean up build artifacts[cite: 1]
clean:
	@echo "==> Cleaning build artifacts..."
	rm -f src/user/agent
	rm -f src/user/*_bpfeb.go src/user/*_bpfel.go
	rm -f src/user/*_bpfeb.o src/user/*_bpfel.o
	@echo "==> Clean complete."

# Helper to generate vmlinux.h (Requires root and bpftool)[cite: 1]
vmlinux:
	@echo "==> Generating vmlinux.h from running kernel..."
	cd src/kernel && sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "==> vmlinux.h generated."