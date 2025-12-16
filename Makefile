# --- CONFIGURATION (Hardcoded Absolute Paths) ---
# This grabs the current folder automatically
ROOT_DIR := $(shell pwd)
LIBBPF_DIR := $(ROOT_DIR)/libbpf/src

# --- TOOLS ---
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

# --- TARGETS ---
.PHONY: all clean

# Default target: Build both applications
all: tcp_server packet_drop_fifo

# ===========================================================================
# 1. TCP SERVER BUILD
#    - Needs -pthread
#    - Does NOT need libbpf
# ===========================================================================
tcp_server: tcp_server_v1.c
	@echo "  CC      tcp_server"
	$(CC) -O2 -Wall -pthread tcp_server_v1.c -o tcp_server


# ===========================================================================
# 2. BPF RUNNER BUILD (packet_drop_fifo)
#    - Needs libbpf, libelf, zlib
#    - Needs vmlinux.h and skeleton generation
# ===========================================================================

# A. Generate vmlinux.h
vmlinux.h:
	@echo "  BPFTOOL vmlinux.h"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# B. Compile BPF Kernel Object
#    -I$(LIBBPF_DIR) allows finding <bpf_helpers.h> directly
packet_drop.bpf.o: packet_drop.bpf.c vmlinux.h
	@echo "  CLANG   packet_drop.bpf.o"
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I$(ROOT_DIR) -I$(LIBBPF_DIR) \
		-c packet_drop.bpf.c -o packet_drop.bpf.o

# C. Generate Skeleton Header
packet_drop.skel.h: packet_drop.bpf.o
	@echo "  GEN-SKEL packet_drop.skel.h"
	$(BPFTOOL) gen skeleton packet_drop.bpf.o > packet_drop.skel.h

# D. Compile Userspace Binary (packet_drop_fifo)
#    - Links against static libbpf.a found in LIBBPF_DIR
packet_drop_fifo: packet_drop_fifo.c packet_drop.skel.h
	@echo "  CLANG   packet_drop_fifo"
	$(CLANG) -g -O2 -Wall \
		-I$(ROOT_DIR) -I$(LIBBPF_DIR) \
		packet_drop_fifo.c $(LIBBPF_DIR)/libbpf.a -lelf -lz -o packet_drop_fifo

# ===========================================================================
# CLEANUP
# ===========================================================================
clean:
	rm -f tcp_server packet_drop_fifo *.o *.skel.h vmlinux.h