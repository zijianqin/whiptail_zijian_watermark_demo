# File Explanation and Usage
## File Explanation
### xdp_tcp_msq_seq.c
This is an xdp program that hooks to the NIC interface. It appends a unique and monotonically increasing sequence number to each packet it sees. This program does not corrupt the packet header so no packet should be dropped in the kernel.

### xdp_tcp_msq_seq_damage.c
This is also an xdp program that hooks to the NIC interface. It has the same functionality as `xdp_tcp_msq_seq.c` except that this program damages the packet header with seq%10==0. So, if we use this program, we should observe packet drops. 

### tcp_server.c
This is a simple TCP server program. It maintains a global frontline for all clients. The frontline is advanced only if we receive a continuous sequence of packets or we detect packet drops in that sequence. This server listens to a FIFO message queue from `packet_drop_fifo.c`, which calls an eBPF program to detect packet drops in the kernel. 

### packet_drop_fifo.c
This program calls the eBPF program `packet_drop.bpf.c` which detects packet drops in the kernel. This program feeds the dropping information to a FIFO message queue from which the TCP server can read.

### packet_drop.bpf.c
This is an eBPF program that detects packet drops in the kernel by tracing the call of kfree_skb() function. This program is called by `packet_drop_fifo.c`.

## Usage
### Note
1. We require the kernel version to be 6.0+. To upgrade the kernel, please run
```bash
sudo apt update
sudo apt install --install-recommends linux-generic-hwe-22.04
```
Then reboot your machine:
```bash
sudo reboot
```

2. Install bpf libraries:
```bash
sudo apt update
sudo apt install -y libbpf-dev
```

### Overall
#### Option1, no packet drop:
Run test.sh. It does everything including hooking the xdp and eBPF program, initializing maps, and starting the tcp server. This uses `xdp_tcp_msq_seq.c`, so we should not observe any packet drop. After the TCP server is started, please start your client process.

#### Option2, packet drop: 
Run test_drop.sh. This uses `xdp_tcp_msq_seq_damage.c`, so we should observe packet drops. After the TCP server is started, please start your client process.