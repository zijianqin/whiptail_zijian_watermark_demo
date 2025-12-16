#!/bin/bash
set -euo pipefail

############################
# Configuration
############################
IFACE=enp6s0f3
PORT=8080

XDP_PROG=xdp_tcp_msg_seq.c
XDP_OBJ=xdp_tcp_msg_seq.o

SERVER=tcp_server
DROP_FIFO=packet_drop_fifo

FIFO_PATH=/tmp/packet_drop_fifo

############################
# Sanity checks
############################
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Please run as root"
  exit 1
fi

if ! ip link show "$IFACE" &>/dev/null; then
  echo "[ERROR] Interface $IFACE not found"
  exit 1
fi

############################
# Cleanup handler (minimal fix)
############################
cleanup() {
  echo
  echo "[*] Cleaning up..."

  # Kill user-space processes (ignore errors if not running)
  pkill -f "$SERVER" || true
  pkill -f "$DROP_FIFO" || true

  # Detach XDP
  ip link set dev "$IFACE" xdp off || true

  # Remove FIFO
  rm -f "$FIFO_PATH" || true

  echo "[*] Cleanup done"
}

# Run cleanup on Ctrl+C (INT), termination (TERM), and normal exit
trap cleanup INT TERM EXIT

############################
# Cleanup from previous runs (still useful)
############################
echo "[*] Cleaning up old state"
pkill -f "$SERVER" || true
pkill -f "$DROP_FIFO" || true
ip link set dev "$IFACE" xdp off || true
rm -f "$FIFO_PATH"

############################
# Build XDP program
############################
echo "[*] Building XDP program"
clang -O2 -g -target bpf \
  -c "$XDP_PROG" \
  -o "$XDP_OBJ" \
  -I/usr/include/bpf \
  -I/usr/include/$(uname -m)-linux-gnu

############################
# Attach XDP
############################
echo "[*] Attaching XDP program to $IFACE"
ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp

############################
# Build TCP server and eBPF program using MakeFile
############################
echo "[*] Building eBPF program and TCP Server"
make

############################
# Start the TCP server and packet drop FIFO listener
############################
echo "[*] Starting the packet drop listener and TCP server"

# Ensure FIFO exists (packet_drop_fifo likely expects it)
rm -f "$FIFO_PATH"
mkfifo "$FIFO_PATH"

./"$SERVER" &
./"$DROP_FIFO"

# When you Ctrl+C, trap will run cleanup.
