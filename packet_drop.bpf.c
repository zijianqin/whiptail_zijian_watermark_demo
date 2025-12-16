#include "vmlinux.h"
// Flat includes (no bpf/ prefix) for local source build
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_core_read.h>
#include "packet_drop.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} drop_events SEC(".maps");

static __always_inline int extract_seq_from_skb(struct sk_buff *skb,
                                                struct drop_info *info,
                                                __u64 *out_seq)
{
    unsigned char *head;
    __u16 network_header_offset;
    __u16 proto;

    proto = BPF_CORE_READ(skb, protocol);
    if (bpf_ntohs(proto) != ETH_P_IP) return 0;

    head = BPF_CORE_READ(skb, head);
    if (!head) return 0;

    network_header_offset = BPF_CORE_READ(skb, network_header);
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header_offset);

    __u32 ip_hdr_len = iph.ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return 0;
    unsigned char *transport_header = head + network_header_offset + ip_hdr_len;

    __u8 ip_proto = iph.protocol;
    __u16 sport = 0, dport = 0;
    __u64 seq = 0;
    unsigned char *payload_ptr = NULL;

    if (ip_proto == IPPROTO_TCP) {
        struct tcphdr tcph;
        bpf_probe_read_kernel(&tcph, sizeof(tcph), transport_header);
        sport = bpf_ntohs(tcph.source);
        dport = bpf_ntohs(tcph.dest);
        if (dport != 8080) return 0;
        
        __u32 tcp_hdr_len = tcph.doff * 4;
        if (tcp_hdr_len < sizeof(struct tcphdr)) return 0;
        payload_ptr = transport_header + tcp_hdr_len;
    } else if (ip_proto == IPPROTO_UDP) {
        struct udphdr udph;
        bpf_probe_read_kernel(&udph, sizeof(udph), transport_header);
        sport = bpf_ntohs(udph.source);
        dport = bpf_ntohs(udph.dest);
        if (dport != 8080) return 0;
        payload_ptr = transport_header + sizeof(struct udphdr);
    } else {
        return 0;
    }

    bpf_probe_read_kernel(&seq, sizeof(seq), payload_ptr);
    if (seq == 0) return 0;

    info->saddr = iph.saddr;
    info->daddr = iph.daddr;
    info->sport = sport;
    info->dport = dport;
    info->protocol = ip_proto;
    *out_seq = seq;
    return 1;
}

SEC("tp/skb/kfree_skb")
int handle_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct drop_info info = {};
    __u64 seq = 0;

    int ret = extract_seq_from_skb(skb, &info, &seq);
    if (ret == 1) {
        info.ts_ns = bpf_ktime_get_ns();
        info.seq_num = seq;
        bpf_perf_event_output(ctx, &drop_events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";