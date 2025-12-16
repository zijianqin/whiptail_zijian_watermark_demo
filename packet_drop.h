#ifndef __PACKET_DROP_H
#define __PACKET_DROP_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct drop_info {
    __u64 ts_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  _pad8;
    __u16 _pad16;
    __u64 seq_num;
};

#endif