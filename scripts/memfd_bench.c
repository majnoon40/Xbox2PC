// memfd_bench.c — M12 P1 guest-memory ADR prototype: VA identity + shared
// backing (ADR-0009). Standalone, like ipc_bench.c: no project headers.
//
// Questions this answers with numbers (all land in ADR-0009):
//   1. CEILING: which guest VA ranges can a forked child map with
//      MAP_FIXED_NOREPLACE? A forked child inherits the parent's mappings,
//      so probing in this process equals probing in the child (the runtime
//      forks without exec). Built plain and with -fsanitize=address and
//      -fsanitize=thread, because the sanitizer legs must stay green.
//   2. SEMANTICS: after fork, do the parent's writes reach the child?
//      MAP_PRIVATE never (the what-broke entry 16 root cause — the PAL
//      window was anonymous MAP_PRIVATE); MAP_SHARED over one memfd always,
//      in both the inherited window and a child window mapped at guest VAs.
//   3. COST: what the translated model pays per import call that the
//      identity model deletes: the load-bias pointer translation (arithmetic
//      plus a region containment lookup per pointer argument) and the
//      out-buffer double copy (reply slot in, child apply out) versus one
//      direct shared-memory write.
//   4. SETUP: the one-time cost of the child's identity mapping (fork +
//      64 MiB MAP_FIXED_NOREPLACE + per-region mprotect) versus fork alone;
//      and the first-touch COW-fault cost the old model paid for every page
//      the parent had touched before the fork.
//
// Build: gcc -O2 -o memfd_bench memfd_bench.c
//        gcc -O2 -fsanitize=address -o memfd_bench_asan memfd_bench.c
//        gcc -O2 -fsanitize=thread  -o memfd_bench_tsan memfd_bench.c
// Run:   ./memfd_bench            (all sections)
//        ./memfd_bench ceiling    (section 1 only — the sanitizer runs)

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

#define GUEST_BASE 0x20000000ull          /* run path: 0x10000000 * (pid%256+1), pid 1 */
#define GUEST_CAP  (64ull << 20)          /* run_cli space capacity */

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int memfd_new(uint64_t size) {
    int fd = (int)syscall(SYS_memfd_create, "xbox2pc-bench", 1u /* MFD_CLOEXEC */);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)size) != 0) { close(fd); return -1; }
    return fd;
}

/* ── 1. ceiling probe ─────────────────────────────────────────────────── */

static void probe(const char *label, uint64_t base, uint64_t size, int shared) {
    int fd = -1;
    int flags;
    if (shared) {
        fd = memfd_new(size);
        if (fd < 0) { printf("  %-26s %12" PRIx64 " +%6" PRIu64 " MiB  memfd: %s\n",
                             label, base, size >> 20, strerror(errno)); return; }
        flags = MAP_SHARED | MAP_FIXED_NOREPLACE;
    } else {
        flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
    }
    void *p = mmap((void *)(uintptr_t)base, (size_t)size, PROT_NONE, flags, fd, 0);
    if (p != MAP_FAILED) {
        printf("  %-26s %12" PRIx64 " +%6" PRIu64 " MiB  OK (%s)\n",
               label, base, size >> 20, shared ? "shared memfd" : "anon private");
        munmap(p, (size_t)size);
    } else {
        printf("  %-26s %12" PRIx64 " +%6" PRIu64 " MiB  FAIL %s (%s)\n",
               label, base, size >> 20, errno == EEXIST ? "EEXIST (occupied)" :
               strerror(errno), shared ? "shared memfd" : "anon private");
    }
    if (fd >= 0) close(fd);
}

static void bench_ceiling(void) {
    printf("== 1. ceiling: MAP_FIXED_NOREPLACE ranges (this process == forked child) ==\n");
    /* The ranges the model cares about. guest space first (anon = what the
       child must be able to take; shared memfd = what the new model maps),
       then the ranges that would matter for what-broke entries 8 and 13. */
    probe("guest 64 MiB (run path)", GUEST_BASE, GUEST_CAP, 0);
    probe("guest 64 MiB (memfd)", GUEST_BASE, GUEST_CAP, 1);
    probe("guest 1.5 GiB", GUEST_BASE, 1536ull << 20, 0);
    probe("guest 1.75 GiB (to 0x7fff8000)", 0x20000000ull,
          0x7fff8000ull - 0x20000000ull, 0);
    probe("guest to 0x7fff7000 (exact edge)", 0x20000000ull,
          0x7fff7000ull - 0x20000000ull, 0);
    probe("binding range 0x51000000", 0x51000000ull, 0x20000, 0);
    probe("PE default base 0x140000000", 0x140000000ull, 64ull << 20, 0);
    probe("PE default base (memfd)", 0x140000000ull, 64ull << 20, 1);
    printf("  (EEXIST means a sanitizer or the platform already occupies it)\n");
}

/* ── 2. fork semantics ─────────────────────────────────────────────────── */

static void bench_semantics(void) {
    printf("== 2. semantics: parent post-fork writes vs the child's view ==\n");
    const uint64_t pre = 0x1111111111111111ull;
    const uint64_t post = 0x2222222222222222ull;

    /* Old model: anonymous MAP_PRIVATE PAL window. */
    uint64_t *priv = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    /* New model: one memfd, MAP_SHARED window in the parent. */
    int fd = memfd_new(GUEST_CAP);
    uint64_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
    if (priv == MAP_FAILED || fd < 0 || shared == MAP_FAILED) {
        printf("  setup failed\n");
        return;
    }
    *priv = pre;
    *shared = pre;

    int pipefd[2];
    if (pipe(pipefd) != 0) { printf("  pipe failed\n"); return; }
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: reads the inherited windows, then maps the memfd at the
           guest VA (the identity window) and reads through it. */
        close(pipefd[0]);
        uint64_t priv_seen = *priv;
        uint64_t shared_seen = *shared;
        void *id = mmap((void *)(uintptr_t)GUEST_BASE, 4096,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
        uint64_t identity_seen = id != MAP_FAILED
            ? *(uint64_t *)((uintptr_t)GUEST_BASE) : 0;
        int identity_ok = id != MAP_FAILED;
        uint64_t report[3] = {priv_seen, shared_seen, identity_seen};
        if (write(pipefd[1], &identity_ok, sizeof identity_ok) != (ssize_t)sizeof identity_ok)
            _exit(90);
        if (write(pipefd[1], report, sizeof report) != (ssize_t)sizeof report)
            _exit(91);
        _exit(0);
    }
    close(pipefd[1]);
    /* Parent writes AFTER the fork (what the bridge does on every call). */
    *priv = post;
    *shared = post;
    int identity_ok = 0;
    uint64_t report[3] = {0, 0, 0};
    (void)!read(pipefd[0], &identity_ok, sizeof identity_ok);
    (void)!read(pipefd[0], report, sizeof report);
    int status = 0;
    waitpid(pid, &status, 0);

    printf("  MAP_PRIVATE  window: parent wrote 0x%" PRIx64 " -> child saw 0x%"
           PRIx64 "  %s\n", post, report[0],
           report[0] == post ? "VISIBLE" : "STALE (entry 16 root cause)");
    printf("  MAP_SHARED   window: parent wrote 0x%" PRIx64 " -> child saw 0x%"
           PRIx64 "  %s\n", post, report[1],
           report[1] == post ? "VISIBLE" : "STALE");
    printf("  identity window at guest VA 0x%" PRIx64 ": %s",
           (uint64_t)GUEST_BASE, identity_ok ? "mapped, " : "MAP_FIXED_NOREPLACE FAILED, ");
    printf("child saw 0x%" PRIx64 "  %s\n", report[2],
           report[2] == post ? "VISIBLE" : "STALE");
    close(pipefd[0]);
    munmap(priv, 4096);
    munmap(shared, 4096);
    close(fd);
}

/* ── 3. per-call costs ─────────────────────────────────────────────────── */

/* A stand-in for the runtime's sorted region map: the translation does an
   arithmetic rebias plus a containment lookup per pointer argument. */
#define REGION_COUNT 10
static struct { uint64_t va, size; } regions[REGION_COUNT];

static int find_containing(uint64_t va) {
    for (int i = 0; i < REGION_COUNT; ++i)
        if (va >= regions[i].va && va < regions[i].va + regions[i].size)
            return i;
    return -1;
}

static void bench_cost(void) {
    printf("== 3. per-call cost: what the identity model deletes ==\n");
    for (int i = 0; i < REGION_COUNT; ++i) {
        regions[i].va = GUEST_BASE + (uint64_t)i * (1ull << 20);
        regions[i].size = 1ull << 20;
    }
    const int64_t load_bias = 0x7f0000000000ull - (int64_t)GUEST_BASE;
    uint64_t wire_args[4] = {0x7f0000000000ull + 0x1000ull, 0x7f0000000000ull + 0x2000ull,
                             0x7f0000000000ull + 0x3000ull, 0x7f0000000000ull + 0x4000ull};

    /* (a) load-bias pointer translation, 4 pointer args per call */
    {
        enum { N = 20000000 };
        volatile uint64_t sink = 0;
        double t0 = now_ns();
        for (int i = 0; i < N; ++i) {
            for (int a = 0; a < 4; ++a) {
                const int64_t guest = (int64_t)wire_args[a] - load_bias;
                if (guest >= 0 && find_containing((uint64_t)guest) >= 0)
                    sink += (uint64_t)guest;   /* translated: use guest VA */
            }
        }
        double dt = now_ns() - t0;
        printf("  translate 4 ptr args (rebias + region lookup): %6.1f ns/call"
               "  [%.0fM calls]\n", dt / N, N / 1e6);
    }

    /* (b) out-buffer double copy: 48-byte payload into a 256-byte reply
       slot, then the child applies it (copy out) — per call. */
    {
        enum { N = 20000000 };
        static uint8_t slot[256];
        static uint8_t out[48];
        memset(out, 0xAB, sizeof out);
        double t0 = now_ns();
        for (int i = 0; i < N; ++i) {
            memcpy(slot + 56, out, 48);            /* parent fills reply */
            memcpy((void *)out, slot + 56, 48);     /* child applies       */
        }
        double dt = now_ns() - t0;
        printf("  out double copy (48 B, reply slot + apply): %6.1f ns/call\n",
               dt / N);
    }

    /* (c) direct shared write: 48 bytes into the mapped guest buffer. */
    {
        enum { N = 20000000 };
        int fd = memfd_new(4096);
        uint8_t *guest = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        static uint8_t out[48];
        memset(out, 0xAB, sizeof out);
        double t0 = now_ns();
        for (int i = 0; i < N; ++i)
            memcpy(guest, out, 48);                 /* parent writes once */
        double dt = now_ns() - t0;
        printf("  direct shared write (48 B, MAP_SHARED):      %6.1f ns/call\n",
               dt / N);
        munmap(guest, 4096);
        close(fd);
    }
}

/* ── 4. one-time setup + first-touch cost ──────────────────────────────── */

static void bench_setup(void) {
    printf("== 4. one-time setup (fork) and first-touch COW cost ==\n");
    enum { N = 30 };
    /* (a) fork alone */
    {
        double t0 = now_ns();
        for (int i = 0; i < N; ++i) {
            pid_t pid = fork();
            if (pid == 0) _exit(0);
            int st; waitpid(pid, &st, 0);
        }
        printf("  fork + exit alone:                              %6.0f us/run\n",
               (now_ns() - t0) / N / 1e3);
    }
    /* (b) fork + child maps the identity window (64 MiB PROT_NONE shared
       memfd + 10 per-region mprotects) */
    {
        int fd = memfd_new(GUEST_CAP);
        double t0 = now_ns();
        for (int i = 0; i < N; ++i) {
            pid_t pid = fork();
            if (pid == 0) {
                void *p = mmap((void *)(uintptr_t)GUEST_BASE, (size_t)GUEST_CAP,
                               PROT_NONE, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
                if (p == MAP_FAILED) _exit(80);
                for (int r = 0; r < 10; ++r)
                    if (mprotect((void *)(uintptr_t)(GUEST_BASE + (uint64_t)r * 4096),
                                 4096, PROT_READ | PROT_WRITE) != 0)
                        _exit(81);
                _exit(0);
            }
            int st; waitpid(pid, &st, 0);
            if (WEXITSTATUS(st) != 0) { printf("  identity map FAILED: %d\n", WEXITSTATUS(st)); break; }
        }
        printf("  fork + identity map (64 MiB + 10 mprotects):    %6.0f us/run\n",
               (now_ns() - t0) / N / 1e3);
        close(fd);
    }
    /* (c) first-touch cost in the child: parent touches PAGES pages before
       the fork; the child writes them. MAP_PRIVATE pays a COW fault per
       page; MAP_SHARED does not. Reported as ns per page. */
    {
        enum { PAGES = 256 };
        uint64_t *priv = mmap(NULL, PAGES * 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int fd = memfd_new(PAGES * 4096);
        uint64_t *sh = mmap(NULL, PAGES * 4096, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
        for (int i = 0; i < PAGES; ++i) { priv[i * 512] = 1; sh[i * 512] = 1; }
        int pipefd[2];
        pipe(pipefd);
        pid_t pid = fork();
        if (pid == 0) {   /* child: touch every page, measure both models */
            close(pipefd[0]);
            double t0 = now_ns();
            for (int i = 0; i < PAGES; ++i) priv[i * 512] = 2;
            double t1 = now_ns();
            for (int i = 0; i < PAGES; ++i) sh[i * 512] = 2;
            double t2 = now_ns();
            double rep[2] = {(t1 - t0) / PAGES, (t2 - t1) / PAGES};
            if (write(pipefd[1], rep, sizeof rep) != (ssize_t)sizeof rep) _exit(92);
            _exit(0);
        }
        close(pipefd[1]);
        double rep[2] = {0, 0};
        (void)!read(pipefd[0], rep, sizeof rep);
        int st; waitpid(pid, &st, 0);
        close(pipefd[0]);
        printf("  child first write, %d touched pages: MAP_PRIVATE %6.0f ns/page"
               "  MAP_SHARED %6.0f ns/page\n", PAGES, rep[0], rep[1]);
        munmap(priv, PAGES * 4096);
        munmap(sh, PAGES * 4096);
        close(fd);
    }
}

int main(int argc, char **argv) {
    const char *only = argc > 1 ? argv[1] : NULL;
    if (!only || strcmp(only, "ceiling") == 0) bench_ceiling();
    if (!only) {
        bench_semantics();
        bench_cost();
        bench_setup();
    }
    return 0;
}
