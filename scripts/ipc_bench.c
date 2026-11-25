// ipc_bench.c — M11 Phase 5 prerequisite: measure import-call round trips.
//
// Two candidate designs for guest->host API dispatch in the native
// execution backend:
//   A) pipe pair: child writes a request, blocks reading the reply;
//      parent reads, dispatches, writes the reply.
//   B) shared-memory ring + eventfd doorbells: child writes a request
//      slot into an mmap'd ring and bumps an eventfd; parent wakes,
//      reads the slot, dispatches, writes the reply slot and bumps the
//      reply eventfd.
//
// The benchmark measures ROUND TRIPS PER SECOND for both, with the same
// 64-byte request/reply payloads both ways, single-threaded ping-pong
// (the exact pattern of a guest import call: block, wake, return).
//
// Build: gcc -O2 -o ipc_bench ipc_bench.c
// Run:   ./ipc_bench [rounds]  (default 200000 per design)

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REQ_SIZE 64
#define RING_SLOTS 64

// ── shared state layout (design B) ────────────────────────────────────────
struct Ring {
    volatile uint64_t req_seq;    // parent publishes consumed seq via reply
    volatile uint64_t rpl_seq;
    uint8_t req[RING_SLOTS][REQ_SIZE];
    uint8_t rpl[RING_SLOTS][REQ_SIZE];
};

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

// eventfd helpers (SYS_eventfd2 for portability inside seccomp-less children)
static int evfd_create(void) {
    return (int)syscall(SYS_eventfd2, 0, 02000000 /* EFD_CLOEXEC */);
}
static void evfd_bump(int fd) {
    uint64_t one = 1;
    ssize_t r = write(fd, &one, sizeof one);
    (void)r;
}
static void evfd_wait(int fd) {
    uint64_t v;
    ssize_t r = read(fd, &v, sizeof v);
    (void)r;
}

// ── design A: pipe ping-pong ──────────────────────────────────────────────
static double bench_pipe(long rounds, long *out_rounds) {
    int req_pipe[2], rpl_pipe[2];
    if (pipe(req_pipe) != 0 || pipe(rpl_pipe) != 0) {
        perror("pipe");
        return -1.0;
    }
    const double t0 = now_sec();
    const pid_t pid = fork();
    if (pid == 0) {
        // child: send request, block for reply
        close(req_pipe[0]);
        close(rpl_pipe[1]);
        uint8_t req[REQ_SIZE], rpl[REQ_SIZE];
        memset(req, 0xAB, sizeof req);
        for (long i = 0; i < rounds; ++i) {
            if (write(req_pipe[1], req, sizeof req) != (ssize_t)sizeof req) _exit(1);
            if (read(rpl_pipe[0], rpl, sizeof rpl) != (ssize_t)sizeof rpl) _exit(1);
        }
        _exit(0);
    }
    close(req_pipe[1]);
    close(rpl_pipe[0]);
    uint8_t req[REQ_SIZE], rpl[REQ_SIZE];
    memset(rpl, 0xCD, sizeof rpl);
    for (long i = 0; i < rounds; ++i) {
        if (read(req_pipe[0], req, sizeof req) != (ssize_t)sizeof req) break;
        if (write(rpl_pipe[1], rpl, sizeof rpl) != (ssize_t)sizeof rpl) break;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    const double t1 = now_sec();
    *out_rounds = rounds;
    (void)status;
    return t1 - t0;
}

// ── design B: shared-memory ring + eventfd doorbells ─────────────────────
static double bench_ring(long rounds, long *out_rounds) {
    struct Ring* ring = mmap(NULL, sizeof(struct Ring),
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ring == MAP_FAILED) {
        perror("mmap");
        return -1.0;
    }
    ring->req_seq = 0;
    ring->rpl_seq = 0;
    int ev_req = evfd_create();
    int ev_rpl = evfd_create();
    if (ev_req < 0 || ev_rpl < 0) {
        perror("eventfd");
        return -1.0;
    }
    const double t0 = now_sec();
    const pid_t pid = fork();
    if (pid == 0) {
        // child: write request slot, bump doorbell, wait for reply
        uint64_t seq = 0;
        uint8_t req[REQ_SIZE];
        memset(req, 0xAB, sizeof req);
        for (long i = 0; i < rounds; ++i) {
            const uint32_t slot = (uint32_t)(seq % RING_SLOTS);
            memcpy((void*)ring->req[slot], req, REQ_SIZE);
            __atomic_store_n(&ring->req_seq, seq + 1, __ATOMIC_RELEASE);
            evfd_bump(ev_req);
            for (;;) {
                const uint64_t done = __atomic_load_n(&ring->rpl_seq, __ATOMIC_ACQUIRE);
                if (done > seq) break;
                evfd_wait(ev_rpl);
            }
            ++seq;
        }
        _exit(0);
    }
    // parent: consume requests, dispatch, publish replies
    uint8_t rpl[REQ_SIZE];
    memset(rpl, 0xCD, sizeof rpl);
    uint64_t handled = 0;
    for (;;) {
        const uint64_t want = handled + 1;
        for (;;) {
            const uint64_t avail = __atomic_load_n(&ring->req_seq, __ATOMIC_ACQUIRE);
            if (avail >= want) break;
            evfd_wait(ev_req);
        }
        if (handled >= (uint64_t)rounds) break;
        const uint32_t slot = (uint32_t)(handled % RING_SLOTS);
        // (dispatch would read ring->req[slot] here)
        memcpy((void*)ring->rpl[slot], rpl, REQ_SIZE);
        ++handled;
        __atomic_store_n(&ring->rpl_seq, handled, __ATOMIC_RELEASE);
        evfd_bump(ev_rpl);
        if (handled >= (uint64_t)rounds) break;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    const double t1 = now_sec();
    *out_rounds = (long)handled;
    (void)status;
    munmap(ring, sizeof(struct Ring));
    close(ev_req);
    close(ev_rpl);
    return t1 - t0;
}

// ── design C: shared-memory ring + eventfd with host-side spin-then-park ──
// Same ring, but the PARENT busy-polls the sequence for a short window
// before parking on the doorbell; the CHILD parks only on the doorbell
// (guest code must block — it cannot spin on the host's scheduler).
static double bench_ring_spin(long rounds, long* out_rounds) {
    struct Ring* ring = mmap(NULL, sizeof(struct Ring),
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ring == MAP_FAILED) {
        perror("mmap");
        return -1.0;
    }
    ring->req_seq = 0;
    ring->rpl_seq = 0;
    int ev_req = evfd_create();
    int ev_rpl = evfd_create();
    if (ev_req < 0 || ev_rpl < 0) {
        perror("eventfd");
        return -1.0;
    }
    const double t0 = now_sec();
    const pid_t pid = fork();
    if (pid == 0) {
        uint64_t seq = 0;
        uint8_t req[REQ_SIZE];
        memset(req, 0xAB, sizeof req);
        for (long i = 0; i < rounds; ++i) {
            const uint32_t slot = (uint32_t)(seq % RING_SLOTS);
            memcpy((void*)ring->req[slot], req, REQ_SIZE);
            __atomic_store_n(&ring->req_seq, seq + 1, __ATOMIC_RELEASE);
            evfd_bump(ev_req);
            for (;;) {
                const uint64_t done = __atomic_load_n(&ring->rpl_seq, __ATOMIC_ACQUIRE);
                if (done > seq) break;
                evfd_wait(ev_rpl);
            }
            ++seq;
        }
        _exit(0);
    }
    uint8_t rpl[REQ_SIZE];
    memset(rpl, 0xCD, sizeof rpl);
    uint64_t handled = 0;
    for (;;) {
        const uint64_t want = handled + 1;
        // Spin-then-park: burn ~20us of CPU before blocking.
        int spins = 0;
        for (;;) {
            const uint64_t avail = __atomic_load_n(&ring->req_seq, __ATOMIC_ACQUIRE);
            if (avail >= want) break;
            if (++spins < 3000) continue;  // ~tens of microseconds
            evfd_wait(ev_req);
            spins = 0;
        }
        if (handled >= (uint64_t)rounds) break;
        const uint32_t slot = (uint32_t)(handled % RING_SLOTS);
        memcpy((void*)ring->rpl[slot], rpl, REQ_SIZE);
        ++handled;
        __atomic_store_n(&ring->rpl_seq, handled, __ATOMIC_RELEASE);
        evfd_bump(ev_rpl);
        if (handled >= (uint64_t)rounds) break;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    const double t1 = now_sec();
    *out_rounds = (long)handled;
    (void)status;
    munmap(ring, sizeof(struct Ring));
    close(ev_req);
    close(ev_rpl);
    return t1 - t0;
}

int main(int argc, char** argv) {
    long rounds = argc > 1 ? strtol(argv[1], NULL, 10) : 200000;
    if (rounds < 1000) rounds = 1000;

    printf("IPC round-trip microbenchmark (%ld rounds each, 64B payload)\n\n", rounds);

    // Warm-up + measurement, twice each; report the best (lowest noise).
    for (int pass = 0; pass < 2; ++pass) {
        long n_pipe = 0, n_ring = 0, n_spin = 0;
        const double dt_pipe = bench_pipe(rounds, &n_pipe);
        const double dt_ring = bench_ring(rounds, &n_ring);
        const double dt_spin = bench_ring_spin(rounds, &n_spin);
        if (dt_pipe < 0 || dt_ring < 0 || dt_spin < 0) return 1;
        printf("pass %d  pipe : %10.0f calls/sec  (%.3f s, %ld round trips)\n",
               pass + 1, (double)n_pipe / dt_pipe, dt_pipe, n_pipe);
        printf("pass %d  ring : %10.0f calls/sec  (%.3f s, %ld round trips)\n",
               pass + 1, (double)n_ring / dt_ring, dt_ring, n_ring);
        printf("pass %d  spin : %10.0f calls/sec  (%.3f s, %ld round trips)\n",
               pass + 1, (double)n_spin / dt_spin, dt_spin, n_spin);
    }
    return 0;
}
