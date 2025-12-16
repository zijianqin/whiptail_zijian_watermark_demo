// packet_drop_fifo.c
// Links against your existing libbpf environment.
// Reads from BPF perf buffer and writes to /tmp/drop_events

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <libbpf.h> // Flat include as per your setup
#include "packet_drop.h"
#include "packet_drop.skel.h"

#define FIFO_PATH "/tmp/drop_events"

static volatile bool exiting = false;
static int fifo_fd = -1;

struct drop_event_out {
    uint64_t seq;
    uint32_t reason;
};

static void sig_handler(int sig) { exiting = true; }

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct drop_info *e = data;
    struct drop_event_out out;
    
    // Convert logic: 
    // We only send the sequence number to the server.
    out.seq = e->seq_num;
    out.reason = 1; // 1 = General Drop

    if (fifo_fd >= 0) {
        ssize_t n = write(fifo_fd, &out, sizeof(out));
        if (n < 0) {
             // If pipe is broken (server restarted), try to ignore or reconnect logic could go here
             // For now, we just print error
             perror("write to fifo");
        } else {
             printf("Sent DROP seq=%d to server\n", out.seq);
        }
    } else {
        printf("Detected DROP seq=%d (FIFO not connected)\n", out.seq);
    }
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

    // 1. Load BPF
    skel = packet_drop_bpf__open_and_load();
    if (!skel) return 1;

    err = packet_drop_bpf__attach(skel);
    if (err) goto cleanup;

    // 2. Open FIFO
    // We open O_WRONLY. This will BLOCK until the server opens it O_RDONLY.
    printf("Waiting for server to open %s...\n", FIFO_PATH);
    fifo_fd = open(FIFO_PATH, O_WRONLY);
    if (fifo_fd < 0) {
        perror("open fifo");
        printf("Did you start ./tcp_server first?\n");
        goto cleanup;
    }
    printf("Connected to server pipe!\n");

    // 3. Start Perf Buffer
    struct perf_buffer_opts pb_opts = {};
    pb_opts.sz = sizeof(struct perf_buffer_opts);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.drop_events), 8, 
                          handle_event, handle_lost_events, NULL, &pb_opts);
    // pb_opts.sample_cb = handle_event;
    // pb_opts.lost_cb = handle_lost_events;

    // pb = perf_buffer__new(bpf_map__fd(skel->maps.drop_events), 8, &pb_opts);
    if (!pb) goto cleanup;

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) break;
    }

cleanup:
    if (fifo_fd >= 0) close(fifo_fd);
    perf_buffer__free(pb);
    packet_drop_bpf__destroy(skel);
    return 0;
}