#pragma once
// xbox2pc/platform.hpp — Platform Abstraction Layer (PAL) interfaces.
//
// Layer rules (docs/platform-abstraction.md):
//   1. Platform-independent runtime components (object manager, handles,
//      process/thread models, sync model, service registry) must call ONLY
//      these interfaces — never <pthread.h>/<windows.h>/<chrono> clocks or
//      any host API directly.
//   2. Implementations of these interfaces live in host backends
//      (pal_linux.cpp today; a future pal_win32.cpp would be added there).
//   3. If an interface has no working backend, methods report
//      PlatformUnsupported — never a silent fake.
//
// M3 scope — working Linux backend: threads, mutexes, condition variables,
// events (cv-based), binary semaphores, counting semaphores, monotonic
// clock, anonymous mmaps, file IO. Virtual memory protection changes are
// provided but page-attribute granularity follows host limits (documented).
//
// Evidence note: Xbox-side facts used by layer contracts are cited in the
// docs; nothing here claims to reproduce undocumented Xbox kernel internals.

#include <cstdint>
#include <memory>
#include <string>

#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::pal {

using rt::Result;
using rt::RuntimeErrc;

// ── time ───────────────────────────────────────────────────────────────────
// Monotonic nanoseconds since an arbitrary epoch (never wall clock; immune
// to NTP jumps). All PAL waits/timeout math use this clock.
using MonotonicNs = std::int64_t;

MonotonicNs now_ns();  // defined in the host backend

// Timeout helper: absolute deadline from a relative millisecond timeout
// (0 = wait forever is expressed as timeout_ns < 0 at call sites via
// kInfiniteTimeout below).
inline constexpr MonotonicNs kInfiniteTimeout = -1;

// ── threading ──────────────────────────────────────────────────────────────

// Thread start routine contract: returns an exit code.
using ThreadFn = void* (*)(void*);

// Host thread representation (opaque, backend-owned).
struct HostThread {
    std::uint64_t id = 0;  // host thread identifier (backend-defined)
};

class PalThread {
public:
    virtual ~PalThread() = default;

    virtual Result<HostThread> start(ThreadFn fn, void* arg) = 0;
    virtual Result<void> join() = 0;
    virtual Result<void> detach() = 0;
    // A cooperative suspension flag the runtime checks at safe points; M3
    // does NOT reproduce Xbox scheduler preemption (documented exclusion).
    virtual Result<void> request_stop() = 0;
    virtual bool stop_requested() const = 0;
    virtual HostThread id() const = 0;
};

// Factory implemented by the backend (keeps PAL users backend-agnostic).
std::unique_ptr<PalThread> make_host_thread();

// ── synchronization primitives ─────────────────────────────────────────────

class PalMutex {
public:
    virtual ~PalMutex() = default;
    virtual Result<void> lock() = 0;
    virtual Result<void> unlock() = 0;
    virtual bool try_lock() = 0;
};

class PalCondvar {
public:
    virtual ~PalCondvar() = default;
    // Atomically unlock `m` and block; relock before returning.
    virtual Result<void> wait(PalMutex& m) = 0;
    // Timed wait: Ok on signal, Timeout on deadline. timeout_ns < 0 = forever.
    virtual Result<void> wait_for_ns(PalMutex& m, MonotonicNs timeout_ns) = 0;
    virtual Result<void> notify_one() = 0;
    virtual Result<void> notify_all() = 0;
};

class PalSemaphore {
public:
    virtual ~PalSemaphore() = default;
    virtual Result<void> acquire() = 0;               // blocking
    virtual Result<void> try_acquire() = 0;
    virtual Result<void> release(std::uint32_t count = 1) = 0;
    virtual std::int64_t value() const = 0;            // best-effort debug view
};

class PalEvent {
public:
    virtual ~PalEvent() = default;
    virtual Result<void> set() = 0;                    // make signalled
    virtual Result<void> reset() = 0;                  // clear
    virtual bool is_set() const = 0;
    // Ok when signalled; Timeout on deadline. timeout_ns < 0 = forever.
    virtual Result<void> wait_ns(MonotonicNs timeout_ns) = 0;
};

std::unique_ptr<PalMutex> make_mutex();
std::unique_ptr<PalCondvar> make_condvar();
std::unique_ptr<PalSemaphore> make_semaphore(std::int64_t initial,
                                              std::int64_t max);
std::unique_ptr<PalEvent> make_event(bool initially_set, bool auto_reset);

// ── memory ─────────────────────────────────────────────────────────────────

// Anonymous memory region allocated by the backend (Linux: mmap; a Windows
// backend would use VirtualAlloc). Reserve/commit granularity follows host
// page size; M3 models regions, NOT Xbox GPU/VirtualDisk addressing
// (documented exclusion).
class PalMemoryRegion {
public:
    virtual ~PalMemoryRegion() = default;

    virtual void* base() const = 0;
    virtual std::uint64_t size() const = 0;
    // No-execute / read-write protections as far as the host allows;
    // errors are surfaced, never ignored (never silently discard errors).
    virtual Result<void> protect(bool read, bool write, bool exec) = 0;
};

// reserve = reserve address space without committing; commit = accessible.
std::unique_ptr<PalMemoryRegion> reserve_memory(std::uint64_t size);
std::unique_ptr<PalMemoryRegion> commit_memory(std::uint64_t size);
std::uint64_t host_page_size();
std::string host_backend_name();  // "linux-mmap" etc.

// ── filesystem (host-restricted) ──────────────────────────────────────────
//
// M3 provides typed file objects over the host FS for testing/runtime state
// persistence. Full Xbox filesystem emulation is an explicit exclusion.

class PalFile {
public:
    virtual ~PalFile() = default;
    virtual Result<std::uint64_t> read(void* buf, std::uint64_t len) = 0;
    virtual Result<std::uint64_t> write(const void* buf, std::uint64_t len) = 0;
    virtual Result<std::uint64_t> seek(std::int64_t offset, bool from_end) = 0;
    virtual Result<std::uint64_t> size() const = 0;
    virtual Result<void> close() = 0;
    virtual bool is_open() const = 0;
};

enum class FileOpenMode { ReadExisting, WriteNew, ReadWriteAppend };

Result<std::unique_ptr<PalFile>> open_file(const std::string& host_path,
                                           FileOpenMode mode);

// ── backend identification ────────────────────────────────────────────────

struct PalInfo {
    std::string backend;      // e.g. "linux-mmap" / "linux-pthreads"
    std::string os_name;      // host OS string
    std::uint64_t page_size;
    std::string clock;        // e.g. "clock_gettime(CLOCK_MONOTONIC)"
};

PalInfo describe_backend();

}  // namespace xbox2pc::pal
