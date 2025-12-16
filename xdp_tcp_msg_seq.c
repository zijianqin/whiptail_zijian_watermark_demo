// xdp_tcp_msg_seq_kern.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Global sequence counter: key=0, value=__u64
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_seq SEC(".maps");

SEC("xdp")
int xdp_tcp_msg_seq(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. IPv4 header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // IP header length
    __u32 ihl = iph->ihl;
    if (ihl < 5)
        return XDP_PASS;

    // 3. TCP header (handle variable IP header length)
    struct tcphdr *tcph = (void *)iph + ihl * 4;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Only touch packets destined to port 8080
    if (bpf_ntohs(tcph->dest) != 8080)
        return XDP_PASS;

    // TCP header length
    __u32 th_len = tcph->doff * 4;
    if (th_len < sizeof(struct tcphdr))
        return XDP_PASS;

    void *payload = (void *)tcph + th_len;

    // We need at least 12 bytes: [8B seq][4B len]
    if (payload + 12 > data_end)
        return XDP_PASS;

    // 4. Get and increment global sequence
    __u32 key = 0;
    __u64 *seq_ptr = bpf_map_lookup_elem(&global_seq, &key);
    if (!seq_ptr)
        return XDP_PASS;

    __u64 seq = *seq_ptr;
    *seq_ptr = seq + 1;

    // 5. Write seq into first 8 bytes of message header
    __builtin_memcpy(payload, &seq, sizeof(seq));
    // Do NOT touch the 4-byte length field (payload+8..+11)

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
