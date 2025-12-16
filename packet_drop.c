#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/resource.h>
// Flat include because we are pointing directly to source dir
#include <libbpf.h> 
#include "packet_drop.h"
#include "packet_drop.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

void print_ts(__u64 ts_ns) {
    struct timespec ts_now, ts_boot;
    clock_gettime(CLOCK_REALTIME, &ts_now);
    clock_gettime(CLOCK_MONOTONIC, &ts_boot);
    time_t event_sec = (ts_ns / 1000000000) + (ts_now.tv_sec - ts_boot.tv_sec);
    long event_nsec = (ts_ns % 1000000000) + (ts_now.tv_nsec - ts_boot.tv_nsec);
    if (event_nsec >= 1000000000) { event_sec++; event_nsec -= 1000000000; }
    else if (event_nsec < 0) { event_sec--; event_nsec += 1000000000; }
    
    struct tm *tm_info = localtime(&event_sec);
    char buffer[26];
    strftime(buffer, 26, "%H:%M:%S", tm_info);
    printf("%s.%09ld", buffer, event_nsec);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct drop_info *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));
    printf("%s:%d -> %s:%d | seq=%llu\n", src, e->sport, dst, e->dport, e->seq_num);
}

void handle_lost_events(void *ctx, int cpu, __u64 cnt) {
    fprintf(stderr, "Lost %llu events on CPU #%d\n", cnt, cpu);
}

int main(int argc, char **argv) {
    struct packet_drop_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = packet_drop_bpf__open_and_load();
    if (!skel) return 1;

    err = packet_drop_bpf__attach(skel);
    if (err) goto cleanup;

    // 1. Setup Options (Only set .sz)
    struct perf_buffer_opts pb_opts = {};
    pb_opts.sz = sizeof(struct perf_buffer_opts);

    // 2. Call perf_buffer__new with 6 arguments
    // Arg 1: Map FD
    // Arg 2: Page Count
    // Arg 3: Sample Callback
    // Arg 4: Lost Callback
    // Arg 5: Context (NULL)
    // Arg 6: Options Ptr
    pb = perf_buffer__new(bpf_map__fd(skel->maps.drop_events), 8, 
                          handle_event, handle_lost_events, NULL, &pb_opts);
                          
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    printf("Running... Ctrl-C to stop.\n");
    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

cleanup:
    perf_buffer__free(pb);
    packet_drop_bpf__destroy(skel);
    return 0;
}