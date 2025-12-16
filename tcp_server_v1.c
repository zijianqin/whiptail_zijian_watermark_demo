// tcp_server_v1.c
// Compile: gcc -O2 -Wall -pthread tcp_server_v1.c -o tcp_server
// Usage: ./tcp_server

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Helper for hash table (uthash)
#include "uthash.h"

#define SERVER_PORT 8080
#define DROP_FIFO_PATH "/tmp/drop_events"

// ----------------------------------------------------------------------
// Data Structures
// ----------------------------------------------------------------------

// Represents a sequence number stored in a set (Received or Dropped)
typedef struct seq_entry {
    uint64_t seq;
    UT_hash_handle hh;
} seq_entry_t;

// Structure of event sent by the BPF program
struct drop_event {
    uint64_t seq;
    uint32_t reason; // 0 for now
};

// ----------------------------------------------------------------------
// Global State
// ----------------------------------------------------------------------

static uint64_t     g_frontier       = 0;
static seq_entry_t *g_received_set   = NULL;
static seq_entry_t *g_dropped_set    = NULL;
static pthread_mutex_t g_frontier_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile int g_shutdown = 0;
static int g_drop_fd = -1;

// ----------------------------------------------------------------------
// Set Operations
// ----------------------------------------------------------------------

static seq_entry_t *seq_set_find(seq_entry_t *set, uint64_t seq) {
    seq_entry_t *e = NULL;
    HASH_FIND(hh, set, &seq, sizeof(seq), e);
    return e;
}

static void seq_set_add(seq_entry_t **set, uint64_t seq) {
    seq_entry_t *e = seq_set_find(*set, seq);
    if (e) return;
    e = calloc(1, sizeof(*e));
    e->seq = seq;
    HASH_ADD(hh, *set, seq, sizeof(e->seq), e);
}

static void seq_set_del(seq_entry_t **set, seq_entry_t *e) {
    HASH_DEL(*set, e);
    free(e);
}

// ----------------------------------------------------------------------
// Core Logic: Frontier Advancement
// ----------------------------------------------------------------------

// Call this whenever a new item is added to Received or Dropped sets.
static void advance_frontier_locked(void) {
    int changed = 0;
    for (;;) {
        uint64_t next = g_frontier + 1;

        // Check if we Received it
        seq_entry_t *e_recv = seq_set_find(g_received_set, next);
        if (e_recv) {
            g_frontier = next;
            printf("[frontier] >>> Advanced to %" PRIu64 " (Received)\n", g_frontier);
            seq_set_del(&g_received_set, e_recv);
            changed = 1;
            continue;
        }

        // Check if we know it was Dropped
        seq_entry_t *e_drop = seq_set_find(g_dropped_set, next);
        if (e_drop) {
            g_frontier = next;
            printf("[frontier] >>> Advanced to %" PRIu64 " (DROPPED)\n", g_frontier);
            seq_set_del(&g_dropped_set, e_drop);
            changed = 1;
            continue;
        }

        // If neither, we are stuck waiting for 'next'
        if (changed) {
            printf("[frontier] Waiting for %" PRIu64 "...\n", next);
        }
        break;
    }
}

// ----------------------------------------------------------------------
// Thread 1: BPF Drop Listener
// Reads binary structs from the named pipe
// ----------------------------------------------------------------------

static void *drop_listener_thread(void *arg) {
    printf("[drop_thread] Opening FIFO %s...\n", DROP_FIFO_PATH);
    
    // Open blocks until a writer (the BPF tool) also opens it
    g_drop_fd = open(DROP_FIFO_PATH, O_RDONLY);
    if (g_drop_fd < 0) {
        perror("[drop_thread] open fifo");
        return NULL;
    }
    printf("[drop_thread] FIFO connected! Listening for drops...\n");

    while (!g_shutdown) {
        struct drop_event ev;
        ssize_t n = read(g_drop_fd, &ev, sizeof(ev));

        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[drop_thread] read");
            break;
        }
        if (n == 0) {
            // Writer closed pipe, wait for reconnect or exit
            printf("[drop_thread] Pipe closed. Waiting for new BPF runner...\n");
            close(g_drop_fd);
            g_drop_fd = open(DROP_FIFO_PATH, O_RDONLY);
            continue;
        }
        if (n != sizeof(ev)) {
            fprintf(stderr, "[drop_thread] Partial read %zd bytes\n", n);
            continue;
        }

        pthread_mutex_lock(&g_frontier_lock);
        
        // Validation: Don't process duplicates
        if (ev.seq <= g_frontier) {
            // Late arrival
        } else if (seq_set_find(g_received_set, ev.seq)) {
            printf("[drop_thread] Ignored Drop %" PRIu64 " (Already Received)\n", ev.seq);
        } else {
            printf("[drop_thread] Detected DROP: seq=%" PRIu64 "\n", ev.seq);
            seq_set_add(&g_dropped_set, ev.seq);
            advance_frontier_locked();
        }

        pthread_mutex_unlock(&g_frontier_lock);
    }
    return NULL;
}

// ----------------------------------------------------------------------
// Thread 2: TCP Client Handler
// ----------------------------------------------------------------------

static ssize_t read_full(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, (char *)buf + off, len - off, 0);
        if (n <= 0) return n;
        off += n;
    }
    return off;
}

static void *client_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    
    for (;;) {
        uint64_t seq;
        uint32_t len_n, len;

        // 1. Read Seq (8 bytes)
        if (read_full(fd, &seq, sizeof(seq)) <= 0) break;

        // 2. Read Len (4 bytes)
        if (read_full(fd, &len_n, sizeof(len_n)) <= 0) break;
        len = ntohl(len_n);

        // 3. Read Payload
        char *payload = malloc(len);
        if (len > 0 && read_full(fd, payload, len) <= 0) {
            free(payload);
            break;
        }

        // Logic
        pthread_mutex_lock(&g_frontier_lock);
        
        if (seq <= g_frontier) {
             printf("[tcp_thread] Ignored %" PRIu64 " (Duplicate/Late)\n", seq);
        } else if (seq_set_find(g_dropped_set, seq)) {
             printf("[tcp_thread] Recv %" PRIu64 " but was marked DROPPED (Correction)\n", seq);
             // Remove from drop set, move to receive set (or just treat as received)
             seq_set_del(&g_dropped_set, seq_set_find(g_dropped_set, seq));
             seq_set_add(&g_received_set, seq);
             advance_frontier_locked();
        } else {
             printf("[tcp_thread] Recv %" PRIu64 "\n", seq);
             seq_set_add(&g_received_set, seq);
             advance_frontier_locked();
        }

        pthread_mutex_unlock(&g_frontier_lock);
        free(payload);
    }

    close(fd);
    return NULL;
}

int main(void) {
    // 1. Setup FIFO
    unlink(DROP_FIFO_PATH);
    if (mkfifo(DROP_FIFO_PATH, 0666) < 0) {
        perror("mkfifo");
        return 1;
    }

    // 2. Start Drop Listener
    pthread_t drop_tid;
    pthread_create(&drop_tid, NULL, drop_listener_thread, NULL);

    // 3. Start TCP Server
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(SERVER_PORT) };
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    int yes=1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    
    if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(listenfd, 10);
    
    printf("=== Frontier Server Started ===\n");
    printf("1. Run 'sudo ./packet_drop_fifo' in another terminal.\n");
    printf("2. Send packets (some dropped) to port 8080.\n");

    while (!g_shutdown) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd >= 0) {
            pthread_t t;
            pthread_create(&t, NULL, client_thread, (void*)(intptr_t)connfd);
            pthread_detach(t);
        }
    }
    return 0;
}