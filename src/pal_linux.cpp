// pal_linux.cpp — Linux host backend for the PAL interfaces.
//
// Everything host-specific in M3 lives in this single translation unit: any
// future Windows backend would be pal_win32.cpp behind the same header.
// The backend surfaces real errors (errno) through Result — nothing is
// silently ignored, and unsupported operations report PlatformUnsupported.

#include "xbox2pc/platform.hpp"

#include <algorithm>
#include <atomic>
#include <climits>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits>
#include <time.h>
#include <unistd.h>

namespace xbox2pc::pal {
namespace {

std::string errno_string(const char* what) {
    return std::string(what) + ": " + std::strerror(errno);
}

Result<void> errno_result(const char* what) {
    return Result<void>(RuntimeErrc::PlatformError, errno_string(what));
}

// Computes an absolute CLOCK_REALTIME deadline from a non-negative relative
// nanosecond timeout without signed integer overflow.
timespec realtime_deadline_from_ns(MonotonicNs timeout_ns) {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    const std::int64_t add_sec = timeout_ns / 1'000'000'000LL;
    const std::int64_t add_nsec = timeout_ns % 1'000'000'000LL;
    std::int64_t total_nsec = static_cast<std::int64_t>(ts.tv_nsec) + add_nsec;
    std::int64_t carry_sec = total_nsec / 1'000'000'000LL;
    total_nsec %= 1'000'000'000LL;
    constexpr std::int64_t kMaxSec =
        static_cast<std::int64_t>(std::numeric_limits<time_t>::max());
    const std::int64_t cur_sec = static_cast<std::int64_t>(ts.tv_sec);
    if (add_sec > kMaxSec - cur_sec ||
        carry_sec > kMaxSec - (cur_sec + add_sec)) {
        ts.tv_sec = std::numeric_limits<time_t>::max();
        ts.tv_nsec = 999'999'999L;
        return ts;
    }
    ts.tv_sec = static_cast<time_t>(cur_sec + add_sec + carry_sec);
    ts.tv_nsec = static_cast<long>(total_nsec);
    return ts;
}

}  // namespace

// ── threading backend ──────────────────────────────────────────────────────
//
// pthread_create may start the child before the parent returns; the gated
// design below holds the trampoline on a mutex/condvar gate until start()
// has fully initialized the launch record, so no torn reads are possible.

namespace {

// Launch record handed to the gated trampoline (fn + arg only).
struct ThreadStart {
    ThreadFn fn;
    void* arg;
};

struct SpawnGate {
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
    bool released = false;
};

void* gated_trampoline(void* p);

class LinuxThreadGated : public PalThread {
public:
    Result<HostThread> start(ThreadFn fn, void* arg) override {
        if (started_) {
            return Result<HostThread>(RuntimeErrc::InvalidState,
                                      "thread already started");
        }
        spawn_ = std::make_unique<SpawnGate>();
        spawn_->m = PTHREAD_MUTEX_INITIALIZER;
        spawn_->cv = PTHREAD_COND_INITIALIZER;
        start_ = ThreadStart{fn, arg};
        const int rc = pthread_create(&thread_, nullptr, gated_trampoline, this);
        if (rc != 0) {
            errno = rc;
            return Result<HostThread>(RuntimeErrc::PlatformError,
                                      "pthread_create: " + std::string(std::strerror(rc)));
        }
        // Release the gate only after pthread_create returned (start_ fully
        // initialized in this thread).
        pthread_mutex_lock(&spawn_->m);
        spawn_->released = true;
        pthread_cond_broadcast(&spawn_->cv);
        pthread_mutex_unlock(&spawn_->m);
        started_ = true;
        return Result<HostThread>(HostThread{static_cast<std::uint64_t>(thread_)});
    }

    Result<void> join() override {
        if (!started_ || joined_ || detached_) {
            return Result<void>(RuntimeErrc::InvalidState, "thread not joinable");
        }
        void* code = nullptr;
        const int rc = pthread_join(thread_, &code);
        if (rc != 0) {
            errno = rc;
            return Result<void>(RuntimeErrc::PlatformError,
                                "pthread_join: " + std::string(std::strerror(rc)));
        }
        joined_ = true;
        exit_code_ = reinterpret_cast<std::uint64_t>(code);
        return Result<void>::ok_result();
    }

    Result<void> detach() override {
        if (!started_ || joined_ || detached_) {
            return Result<void>(RuntimeErrc::InvalidState, "thread not detachable");
        }
        const int rc = pthread_detach(thread_);
        if (rc != 0) {
            errno = rc;
            return Result<void>(RuntimeErrc::PlatformError,
                                "pthread_detach: " + std::string(std::strerror(rc)));
        }
        detached_ = true;
        return Result<void>::ok_result();
    }

    Result<void> request_stop() override {
        stop_flag_ = true;
        return Result<void>::ok_result();
    }

    bool stop_requested() const override { return stop_flag_.load(); }

    HostThread id() const override {
        return HostThread{static_cast<std::uint64_t>(thread_)};
    }

    // M4: pthread_setname_np truncates to 16 bytes INCLUDING the NUL —
    // documented host limit (Linux), not an Xbox behavior.
    Result<void> set_name(const std::string& name) override {
        if (!started_) {
            return Result<void>(RuntimeErrc::InvalidState,
                                "thread not started");
        }
        char buf[16];
        const std::size_t n = name.size() < sizeof(buf) - 1
                                  ? name.size()
                                  : sizeof(buf) - 1;
        std::memcpy(buf, name.c_str(), n);
        buf[n] = '\0';
        const int rc = pthread_setname_np(thread_, buf);
        if (rc != 0) {
            errno = rc;
            return Result<void>(RuntimeErrc::PlatformError,
                                "pthread_setname_np: " +
                                    std::string(std::strerror(rc)));
        }
        return Result<void>::ok_result();
    }

    std::uint64_t exit_code() const { return exit_code_; }

private:
    friend void* gated_trampoline(void* p);
    ThreadStart start_;
    std::unique_ptr<SpawnGate> spawn_;
    pthread_t thread_ = 0;
    std::atomic<bool> stop_flag_{false};
    bool started_ = false;
    bool joined_ = false;
    bool detached_ = false;
    std::uint64_t exit_code_ = 0;
};

void* gated_trampoline(void* p) {
    LinuxThreadGated* self = static_cast<LinuxThreadGated*>(p);
    pthread_mutex_lock(&self->spawn_->m);
    while (!self->spawn_->released) {
        pthread_cond_wait(&self->spawn_->cv, &self->spawn_->m);
    }
    pthread_mutex_unlock(&self->spawn_->m);
    const ThreadFn fn = self->start_.fn;
    void* const arg = self->start_.arg;
    return fn(arg);
}

}  // namespace

HostThread current_thread() {
    return HostThread{static_cast<std::uint64_t>(pthread_self())};
}

std::unique_ptr<PalThread> make_host_thread() {
    return std::make_unique<LinuxThreadGated>();
}

// ── mutex/condvar/semaphore/event backends ────────────────────────────────

namespace {

class LinuxMutex : public PalMutex {
public:
    // Ownership model (race-free by construction):
    //   * lock()/try_lock()/condvar-reacquire store the acquiring thread as
    //     owner BEFORE the caller can observe success, so any subsequent
    //     unlock by that thread sees itself as owner.
    //   * unlock() never stores 0: clearing would race with a concurrent
    //     lock() storing a new owner (A's store-0 could land after B's
    //     store-B, making B's unlock falsely fail). Instead, a second
    //     unlock by the same thread detects the stale state with a
    //     trylock(): if the mutex was truly released, trylock acquires it
    //     (making the pending unlock valid again) and unlock proceeds; if
    //     another thread owns it, EPERM/LockNotOwned is returned.
    // ERRORCHECK pthread type is the second line of defense.
    LinuxMutex() {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
        pthread_mutex_init(&m_, &attr);
        pthread_mutexattr_destroy(&attr);
    }
    ~LinuxMutex() override { pthread_mutex_destroy(&m_); }

    Result<void> lock() override {
        const int rc = pthread_mutex_lock(&m_);
        if (rc != 0) {
            errno = rc;
            return Result<void>(RuntimeErrc::PlatformError,
                                "pthread_mutex_lock: " + std::string(std::strerror(rc)));
        }
        owner_.store(pthread_self(), std::memory_order_release);
        return Result<void>::ok_result();
    }

    Result<void> unlock() override {
        const pthread_t self = pthread_self();
        const pthread_t owner = owner_.load(std::memory_order_acquire);
        if (owner == 0) {
            // No lock() completed yet — either unlocked (and this caller
            // never locked) or racing a first acquisition; both are
            // LockNotOwned for THIS caller.
            return Result<void>(RuntimeErrc::LockNotOwned, "mutex not locked");
        }
        if (!pthread_equal(owner, self)) {
            return Result<void>(RuntimeErrc::LockNotOwned,
                                "unlock by non-owner");
        }
        // Same thread as the recorded owner. Two cases:
        //   (a) the caller still holds the mutex -> plain unlock is valid;
        //   (b) the caller already unlocked (owner is stale-but-ours) ->
        //       trylock acquires the free mutex, making unlock valid and
        //       re-recording ownership; both paths end unlocked.
        // Distinguishing (a) from (b) without a race requires probing.
        const int probe = pthread_mutex_trylock(&m_);
        if (probe == EBUSY) {
            // (a): held — by us (owner matches); safe to unlock.
            const int rc = pthread_mutex_unlock(&m_);
            if (rc == 0) return Result<void>::ok_result();
            if (rc == EPERM) {
                return Result<void>(RuntimeErrc::LockNotOwned, "pthread_mutex_unlock");
            }
            errno = rc;
            return Result<void>(RuntimeErrc::PlatformError,
                                "pthread_mutex_unlock: " + std::string(std::strerror(rc)));
        }
        if (probe == 0) {
            // (b): was free — this is a double unlock. Acquired by the
            // probe; release it and report the error.
            pthread_mutex_unlock(&m_);
            return Result<void>(RuntimeErrc::LockNotOwned, "mutex not locked");
        }
        errno = probe;
        return Result<void>(RuntimeErrc::PlatformError,
                            "pthread_mutex_trylock probe: " +
                                std::string(std::strerror(probe)));
    }

    bool try_lock() override {
        const int rc = pthread_mutex_trylock(&m_);
        if (rc == 0) {
            owner_.store(pthread_self(), std::memory_order_release);
            return true;
        }
        return false;
    }

private:
    friend class LinuxCondvar;  // condvar waits need the raw pthread mutex + owner refresh
    pthread_mutex_t m_;
    std::atomic<pthread_t> owner_{0};
};

class LinuxCondvar : public PalCondvar {
public:
    LinuxCondvar() { pthread_cond_init(&cv_, nullptr); }
    ~LinuxCondvar() override { pthread_cond_destroy(&cv_); }

    Result<void> wait(PalMutex& m) override {
        auto* lm = dynamic_cast<LinuxMutex*>(&m);
        if (lm == nullptr) {
            return Result<void>(RuntimeErrc::PlatformUnsupported,
                                "condvar backend expects LinuxMutex");
        }
        const int rc = pthread_cond_wait(&cv_, &lm->m_);
        if (rc != 0) {
            errno = rc;
            return Result<void>(RuntimeErrc::PlatformError,
                                "pthread_cond_wait: " + std::string(std::strerror(rc)));
        }
        // The wait re-acquired the mutex internally (bypassing lock()):
        // refresh the ownership record so this thread's unlock() works.
        lm->owner_.store(pthread_self(), std::memory_order_release);
        return Result<void>::ok_result();
    }

    Result<void> wait_for_ns(PalMutex& m, MonotonicNs timeout_ns) override {
        auto* lm = dynamic_cast<LinuxMutex*>(&m);
        if (lm == nullptr) {
            return Result<void>(RuntimeErrc::PlatformUnsupported,
                                "condvar backend expects LinuxMutex");
        }
        if (timeout_ns < 0) return wait(m);
        // pthread_cond_timedwait takes an ABSOLUTE deadline; the PAL contract
        // is relative — convert once per call.
        const timespec ts = realtime_deadline_from_ns(timeout_ns);
        const int rc = pthread_cond_timedwait(&cv_, &lm->m_, &ts);
        if (rc == 0) {
            // Re-acquired internally: refresh ownership (see wait()).
            lm->owner_.store(pthread_self(), std::memory_order_release);
            return Result<void>::ok_result();
        }
        if (rc == ETIMEDOUT) {
            // Timed out BUT the mutex IS re-acquired before returning per
            // pthread semantics — refresh ownership for the caller's unlock.
            lm->owner_.store(pthread_self(), std::memory_order_release);
            return Result<void>(RuntimeErrc::Timeout, "wait_for_ns deadline");
        }
        errno = rc;
        return Result<void>(RuntimeErrc::PlatformError,
                            "pthread_cond_timedwait: " + std::string(std::strerror(rc)));
    }

    Result<void> notify_one() override {
        pthread_cond_signal(&cv_);
        return Result<void>::ok_result();
    }
    Result<void> notify_all() override {
        pthread_cond_broadcast(&cv_);
        return Result<void>::ok_result();
    }

private:
    pthread_cond_t cv_;
};

// ── semaphore/event backends ───────────────────────────────────────────────
//
// Note on timeout semantics: the PAL contract is RELATIVE (wait up to
// timeout_ns); pthread_cond_timedwait needs an ABSOLUTE deadline, so every
// timed wait converts once per call (see LinuxEvent::timed_wait_locked).

}  // namespace


namespace {

class LinuxSemaphore : public PalSemaphore {
public:
    LinuxSemaphore(std::int64_t initial, std::int64_t max)
        : max_(max), value_(initial) {
        pthread_mutex_init(&m_, nullptr);
        pthread_cond_init(&cv_, nullptr);
    }
    ~LinuxSemaphore() override {
        pthread_mutex_destroy(&m_);
        pthread_cond_destroy(&cv_);
    }

    Result<void> acquire() override {
        pthread_mutex_lock(&m_);
        while (value_ <= 0) {
            const int rc = pthread_cond_wait(&cv_, &m_);
            if (rc != 0) {
                pthread_mutex_unlock(&m_);
                errno = rc;
                return Result<void>(RuntimeErrc::PlatformError,
                                    "sem acquire: " + std::string(std::strerror(rc)));
            }
        }
        --value_;
        pthread_mutex_unlock(&m_);
        return Result<void>::ok_result();
    }

    Result<void> try_acquire() override {
        pthread_mutex_lock(&m_);
        const bool got = value_ > 0;
        if (got) --value_;
        pthread_mutex_unlock(&m_);
        return got ? Result<void>::ok_result()
                   : Result<void>(RuntimeErrc::Timeout, "try_acquire: zero count");
    }

    Result<void> release(std::uint32_t count) override {
        if (count == 0) {
            return Result<void>(RuntimeErrc::InvalidArgument, "release(0)");
        }
        pthread_mutex_lock(&m_);
        const std::int64_t delta = static_cast<std::int64_t>(count);
        if (value_ > max_ || delta > max_ - value_) {
            pthread_mutex_unlock(&m_);
            return Result<void>(RuntimeErrc::InvalidState,
                                "semaphore overflow: count would exceed max");
        }
        value_ += delta;
        if (count == 1) {
            pthread_cond_signal(&cv_);
        } else {
            pthread_cond_broadcast(&cv_);
        }
        pthread_mutex_unlock(&m_);
        return Result<void>::ok_result();
    }

    std::int64_t value() const override {
        pthread_mutex_lock(&m_);
        const std::int64_t v = value_;
        pthread_mutex_unlock(&m_);
        return v;
    }

private:
    mutable pthread_mutex_t m_;
    pthread_cond_t cv_;
    const std::int64_t max_;
    std::int64_t value_;
};

class LinuxEvent : public PalEvent {
public:
    LinuxEvent(bool initially_set, bool auto_reset)
        : set_(initially_set), auto_reset_(auto_reset) {
        pthread_mutex_init(&m_, nullptr);
        pthread_cond_init(&cv_, nullptr);
    }
    ~LinuxEvent() override {
        pthread_mutex_destroy(&m_);
        pthread_cond_destroy(&cv_);
    }

    Result<void> set() override {
        pthread_mutex_lock(&m_);
        set_ = true;
        if (auto_reset_) {
            // Wake one waiter; the flag drops as soon as one thread wakes.
            pthread_cond_signal(&cv_);
        } else {
            pthread_cond_broadcast(&cv_);
        }
        pthread_mutex_unlock(&m_);
        return Result<void>::ok_result();
    }

    Result<void> reset() override {
        pthread_mutex_lock(&m_);
        set_ = false;
        pthread_mutex_unlock(&m_);
        return Result<void>::ok_result();
    }

    bool is_set() const override {
        pthread_mutex_lock(&m_);
        const bool v = set_;
        pthread_mutex_unlock(&m_);
        return v;
    }

    Result<void> wait_ns(MonotonicNs timeout_ns) override {
        pthread_mutex_lock(&m_);
        if (auto_reset_) {
            while (!set_) {
                if (timeout_ns < 0) {
                    const int rc = pthread_cond_wait(&cv_, &m_);
                    if (rc != 0) {
                        pthread_mutex_unlock(&m_);
                        errno = rc;
                        return Result<void>(RuntimeErrc::PlatformError,
                                            "event wait: " + std::string(std::strerror(rc)));
                    }
                } else {
                    const auto [ok, expired] = timed_wait_locked(timeout_ns);
                    if (!ok) {
                        pthread_mutex_unlock(&m_);
                        return expired
                            ? Result<void>(RuntimeErrc::Timeout, "event wait deadline")
                            : Result<void>(RuntimeErrc::PlatformError, "event wait");
                    }
                }
            }
            set_ = false;  // consumed by this waiter
            pthread_mutex_unlock(&m_);
            return Result<void>::ok_result();
        }
        // Manual reset: broadcast wakes all; flag stays set until reset().
        while (!set_) {
            if (timeout_ns < 0) {
                const int rc = pthread_cond_wait(&cv_, &m_);
                if (rc != 0) {
                    pthread_mutex_unlock(&m_);
                    errno = rc;
                    return Result<void>(RuntimeErrc::PlatformError,
                                        "event wait: " + std::string(std::strerror(rc)));
                }
            } else {
                const auto [ok, expired] = timed_wait_locked(timeout_ns);
                if (!ok) {
                    pthread_mutex_unlock(&m_);
                    return expired
                        ? Result<void>(RuntimeErrc::Timeout, "event wait deadline")
                        : Result<void>(RuntimeErrc::PlatformError, "event wait");
                }
            }
        }
        pthread_mutex_unlock(&m_);
        return Result<void>::ok_result();
    }

private:
    // Helper: pthread_cond_timedwait with the RELATIVE PAL timeout
    // converted to an ABSOLUTE CLOCK_REALTIME deadline. Returns
    // (acquired, timed_out); spurious wakeups re-loop with remaining time.
    std::pair<bool, bool> timed_wait_locked(MonotonicNs timeout_ns) {
        const timespec ts = realtime_deadline_from_ns(timeout_ns);
        for (;;) {
            const int rc = pthread_cond_timedwait(&cv_, &m_, &ts);
            if (rc == 0) return {true, false};
            if (rc == ETIMEDOUT) return {false, true};
            if (rc == EINTR) continue;  // spurious: retry with remaining time
            return {false, false};      // host error
        }
    }

    mutable pthread_mutex_t m_;
    pthread_cond_t cv_;
    bool set_;
    const bool auto_reset_;
};

}  // namespace

std::unique_ptr<PalMutex> make_mutex() { return std::make_unique<LinuxMutex>(); }
std::unique_ptr<PalCondvar> make_condvar() { return std::make_unique<LinuxCondvar>(); }
std::unique_ptr<PalSemaphore> make_semaphore(std::int64_t initial,
                                              std::int64_t max) {
    return std::make_unique<LinuxSemaphore>(initial, max);
}
std::unique_ptr<PalEvent> make_event(bool initially_set, bool auto_reset) {
    return std::make_unique<LinuxEvent>(initially_set, auto_reset);
}

// ── memory backend ─────────────────────────────────────────────────────────

namespace {

class LinuxMemoryRegion : public PalMemoryRegion {
public:
    ~LinuxMemoryRegion() override {
        if (base_ != nullptr) {
            munmap(base_, static_cast<std::size_t>(size_));
        }
    }

    Result<void> map(std::uint64_t size, bool commit, bool exec) {
        const long page = sysconf(_SC_PAGESIZE);
        const std::uint64_t psize = page > 0 ? static_cast<std::uint64_t>(page) : 4096;
        if (size == 0 || size > (~0ull) - (psize - 1)) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "mapping size is zero or overflows page alignment");
        }
        const std::uint64_t aligned = ((size - 1) / psize + 1) * psize;
        const int prot = commit ? (PROT_READ | PROT_WRITE) : PROT_NONE;
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS | (exec ? 0 : MAP_NORESERVE);
        void* base = mmap(nullptr, static_cast<std::size_t>(aligned),
                          static_cast<int>(prot), flags, -1, 0);
        if (base == MAP_FAILED) {
            return Result<void>(RuntimeErrc::OutOfResources,
                                errno_string("mmap"));
        }
        base_ = base;
        size_ = aligned;
        return Result<void>::ok_result();
    }

    void* base() const override { return base_; }
    std::uint64_t size() const override { return size_; }

    Result<void> protect(bool read, bool write, bool exec) override {
        if (base_ == nullptr) {
            return Result<void>(RuntimeErrc::InvalidState, "region unmapped");
        }
        int prot = PROT_NONE;
        if (read) prot |= PROT_READ;
        if (write) prot |= PROT_WRITE;
        if (exec) prot |= PROT_EXEC;
        if (mprotect(base_, static_cast<std::size_t>(size_), prot) != 0) {
            return errno_result("mprotect");
        }
        return Result<void>::ok_result();
    }

    Result<void> protect_subrange(std::uint64_t offset, std::uint64_t size,
                                   bool read, bool write, bool exec) override {
        if (base_ == nullptr) {
            return Result<void>(RuntimeErrc::InvalidState, "region unmapped");
        }
        if (offset >= size_ || size == 0 || size > size_ - offset) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "subrange out of bounds");
        }
        int prot = PROT_NONE;
        if (read) prot |= PROT_READ;
        if (write) prot |= PROT_WRITE;
        if (exec) prot |= PROT_EXEC;
        auto* addr = static_cast<std::uint8_t*>(base_) + offset;
        if (mprotect(addr, static_cast<std::size_t>(size), prot) != 0) {
            return errno_result("mprotect(subrange)");
        }
        return Result<void>::ok_result();
    }

    Result<void> commit_subrange(std::uint64_t offset,
                                 std::uint64_t size) override {
        if (base_ == nullptr) {
            return Result<void>(RuntimeErrc::InvalidState, "region unmapped");
        }
        if (offset >= size_ || size == 0 || size > size_ - offset) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "subrange out of bounds");
        }
        // Linux: reserved (PROT_NONE) -> committed is an mprotect to RW.
        auto* addr = static_cast<std::uint8_t*>(base_) + offset;
        if (mprotect(addr, static_cast<std::size_t>(size),
                     PROT_READ | PROT_WRITE) != 0) {
            return errno_result("mprotect(commit)");
        }
        return Result<void>::ok_result();
    }
    Result<void> decommit_subrange(std::uint64_t offset,
                                   std::uint64_t size) override {
        if (base_ == nullptr)
            return Result<void>(RuntimeErrc::InvalidState, "region unmapped");
        if (offset >= size_ || size == 0 || size > size_ - offset)
            return Result<void>(RuntimeErrc::InvalidArgument, "subrange out of bounds");
        auto* addr = static_cast<std::uint8_t*>(base_) + offset;
        if (mprotect(addr, static_cast<std::size_t>(size), PROT_NONE) != 0)
            return errno_result("mprotect(decommit)");
        if (madvise(addr, static_cast<std::size_t>(size), MADV_DONTNEED) != 0)
            return errno_result("madvise(MADV_DONTNEED)");
        return Result<void>::ok_result();
    }


private:
    void* base_ = nullptr;
    std::uint64_t size_ = 0;
};

}  // namespace

std::unique_ptr<PalMemoryRegion> reserve_memory(std::uint64_t size) {
    auto r = std::make_unique<LinuxMemoryRegion>();
    if (r->map(size, false, false).ok()) return r;
    return nullptr;
}

std::unique_ptr<PalMemoryRegion> commit_memory(std::uint64_t size) {
    auto r = std::make_unique<LinuxMemoryRegion>();
    if (r->map(size, true, false).ok()) return r;
    return nullptr;
}

std::uint64_t host_page_size() {
    const long page = sysconf(_SC_PAGESIZE);
    return page > 0 ? static_cast<std::uint64_t>(page) : 4096;
}

std::string host_backend_name() { return "linux-mmap"; }

// ── filesystem backend ────────────────────────────────────────────────────

namespace {

class LinuxFile : public PalFile {
public:
    ~LinuxFile() override {
        if (fd_ >= 0) ::close(fd_);
    }

    static Result<std::unique_ptr<PalFile>> open(const std::string& path,
                                                 FileOpenMode mode) {
        int flags = 0;
        switch (mode) {
            case FileOpenMode::ReadExisting: flags = O_RDONLY; break;
            case FileOpenMode::WriteNew:
                flags = O_WRONLY | O_CREAT | O_EXCL;
                break;
            case FileOpenMode::ReadWriteAppend:
                flags = O_RDWR | O_CREAT | O_APPEND;
                break;
        }
        // Refuse a final-component symlink even if it is swapped in after
        // the VFS's lstat-style preflight. Intermediate components still
        // require the prefix checks in HostDirBackend.
        flags |= O_NOFOLLOW | O_CLOEXEC;
        const int fd = ::open(path.c_str(), flags, 0644);
        if (fd < 0) {
            const int en = errno;
            if (en == EEXIST) {
                return Result<std::unique_ptr<PalFile>>(
                    RuntimeErrc::AlreadyExists, "open: file already exists");
            }
            if (en == ELOOP) {
                return Result<std::unique_ptr<PalFile>>(
                    RuntimeErrc::InvalidArgument, "open: symlink rejected");
            }
            errno = en;
            return Result<std::unique_ptr<PalFile>>(
                RuntimeErrc::IoError, errno_string("open"));
        }
        auto f = std::make_unique<LinuxFile>();
        f->fd_ = fd;
        return Result<std::unique_ptr<PalFile>>(std::move(f));
    }

    Result<std::uint64_t> read(void* buf, std::uint64_t len) override {
        if (fd_ < 0) return Result<std::uint64_t>(RuntimeErrc::InvalidState, "closed");
        if (len == 0) return Result<std::uint64_t>(0);
        if (buf == nullptr) {
            return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "null read buffer");
        }
        const std::uint64_t bounded =
            std::min<std::uint64_t>(len, static_cast<std::uint64_t>(SSIZE_MAX));
        const ssize_t n = ::read(fd_, buf, static_cast<std::size_t>(bounded));
        if (n < 0) return Result<std::uint64_t>(RuntimeErrc::IoError, errno_string("read"));
        return Result<std::uint64_t>(static_cast<std::uint64_t>(n));
    }

    Result<std::uint64_t> write(const void* buf, std::uint64_t len) override {
        if (fd_ < 0) return Result<std::uint64_t>(RuntimeErrc::InvalidState, "closed");
        if (len == 0) return Result<std::uint64_t>(0);
        if (buf == nullptr) {
            return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "null write buffer");
        }
        const std::uint64_t bounded =
            std::min<std::uint64_t>(len, static_cast<std::uint64_t>(SSIZE_MAX));
        const ssize_t n = ::write(fd_, buf, static_cast<std::size_t>(bounded));
        if (n < 0) return Result<std::uint64_t>(RuntimeErrc::IoError, errno_string("write"));
        return Result<std::uint64_t>(static_cast<std::uint64_t>(n));
    }

    Result<std::uint64_t> seek(std::int64_t offset, bool from_end) override {
        if (fd_ < 0) return Result<std::uint64_t>(RuntimeErrc::InvalidState, "closed");
        const off_t pos = ::lseek(fd_, static_cast<off_t>(offset),
                                  from_end ? SEEK_END : SEEK_SET);
        if (pos < 0) return Result<std::uint64_t>(RuntimeErrc::IoError, errno_string("lseek"));
        return Result<std::uint64_t>(static_cast<std::uint64_t>(pos));
    }

    Result<std::uint64_t> size() const override {
        if (fd_ < 0) return Result<std::uint64_t>(RuntimeErrc::InvalidState, "closed");
        struct stat st{};
        if (::fstat(fd_, &st) != 0) {
            return Result<std::uint64_t>(RuntimeErrc::IoError, errno_string("fstat"));
        }
        return Result<std::uint64_t>(static_cast<std::uint64_t>(st.st_size));
    }

    Result<void> close() override {
        if (fd_ < 0) return Result<void>(RuntimeErrc::InvalidState, "already closed");
        if (::close(fd_) != 0) return errno_result("close");
        fd_ = -1;
        return Result<void>::ok_result();
    }

    bool is_open() const override { return fd_ >= 0; }

private:
    int fd_ = -1;
};

}  // namespace

Result<std::unique_ptr<PalFile>> open_file(const std::string& host_path,
                                           FileOpenMode mode) {
    return LinuxFile::open(host_path, mode);
}

// ── time + info ───────────────────────────────────────────────────────────

MonotonicNs now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<MonotonicNs>(ts.tv_sec) * 1'000'000'000LL +
           static_cast<MonotonicNs>(ts.tv_nsec);
}

PalInfo describe_backend() {
    PalInfo info;
    info.backend = "linux-pthreads+mmap";
    info.os_name = "Linux";
    info.page_size = host_page_size();
    info.clock = "clock_gettime(CLOCK_MONOTONIC)";
    return info;
}

// ── M5: host directory/metadata operations ──────────────────────────────

namespace {

// errno translation for directory ops; distinguish NotFound where the
// syscall reports ENOENT (typed NotFound beats IoError for VFS semantics).
Result<void> errno_dir_result(const char* what, int en) {
    if (en == ENOENT) {
        return Result<void>(RuntimeErrc::NotFound,
                            std::string(what) + ": path does not exist");
    }
    if (en == EEXIST) {
        return Result<void>(RuntimeErrc::AlreadyExists,
                            std::string(what) + ": already exists");
    }
    if (en == ENOTEMPTY) {
        return Result<void>(RuntimeErrc::InvalidState,
                            std::string(what) + ": directory not empty");
    }
    if (en == EACCES || en == EPERM) {
        return Result<void>(RuntimeErrc::PlatformError,
                            std::string(what) + ": permission denied");
    }
    errno = en;
    return Result<void>(RuntimeErrc::IoError,
                        std::string(what) + ": " + std::string(std::strerror(en)));
}

}  // namespace

Result<bool> host_path_is_symlink(const std::string& host_path) {
    struct stat st {};
    if (::lstat(host_path.c_str(), &st) != 0) {
        const int en = errno;
        if (en == ENOENT) {
            return Result<bool>(false);  // absent = not a link
        }
        return Result<bool>(RuntimeErrc::IoError,
                            std::string("lstat: ") + std::strerror(en));
    }
    return Result<bool>(S_ISLNK(st.st_mode));
}

Result<PalFileInfo> stat_host_path(const std::string& host_path) {
    struct stat st {};
    if (::stat(host_path.c_str(), &st) != 0) {
        const int en = errno;
        if (en == ENOENT) {
            PalFileInfo missing;
            missing.exists = false;
            return Result<PalFileInfo>(missing);
        }
        return Result<PalFileInfo>(RuntimeErrc::IoError,
                                   std::string("stat: ") + std::strerror(en));
    }
    PalFileInfo info;
    info.exists = true;
    info.is_directory = S_ISDIR(st.st_mode);
    info.size = S_ISREG(st.st_mode)
        ? static_cast<std::uint64_t>(st.st_size)
        : 0;
    return Result<PalFileInfo>(info);
}

Result<void> create_host_directory(const std::string& host_path) {
    if (::mkdir(host_path.c_str(), 0755) != 0) {
        return errno_dir_result("mkdir", errno);
    }
    return Result<void>::ok_result();
}

Result<void> remove_host_directory(const std::string& host_path) {
    if (::rmdir(host_path.c_str()) != 0) {
        return errno_dir_result("rmdir", errno);
    }
    return Result<void>::ok_result();
}

Result<void> remove_host_file(const std::string& host_path) {
    if (::unlink(host_path.c_str()) != 0) {
        return errno_dir_result("unlink", errno);
    }
    return Result<void>::ok_result();
}

Result<std::vector<PalDirEntry>> list_host_directory(const std::string& host_path) {
    DIR* dir = ::opendir(host_path.c_str());
    if (dir == nullptr) {
        const int en = errno;
        auto r = errno_dir_result("opendir", en);
        return Result<std::vector<PalDirEntry>>(r.errc(), r.context());
    }
    std::vector<PalDirEntry> out;
    errno = 0;
    while (struct dirent* de = ::readdir(dir)) {
        const std::string name = de->d_name;
        if (name == "." || name == "..") continue;
        PalDirEntry e;
        e.name = name;
        // d_type is a hint on some filesystems; fall back to stat.
        if (de->d_type == DT_DIR) {
            e.is_directory = true;
        } else if (de->d_type == DT_UNKNOWN || de->d_type == DT_REG) {
            struct stat st {};
            const std::string full = host_path + "/" + name;
            if (::lstat(full.c_str(), &st) == 0) {
                e.is_directory = S_ISDIR(st.st_mode);
            } else {
                e.is_directory = false;  // unstatable entry: report as file
            }
        } else {
            e.is_directory = false;
        }
        out.push_back(std::move(e));
        errno = 0;
    }
    const int read_en = errno;
    ::closedir(dir);
    if (read_en != 0) {
        return Result<std::vector<PalDirEntry>>(
            RuntimeErrc::IoError,
            std::string("readdir: ") + std::strerror(read_en));
    }
    return Result<std::vector<PalDirEntry>>(std::move(out));
}

Result<void> remove_host_tree(const std::string& host_path) {
    // lstat, not stat: a symlink to a directory must be unlinked, never
    // recursively traversed outside the requested tree.
    struct stat root_st {};
    if (::lstat(host_path.c_str(), &root_st) != 0) {
        return errno_dir_result("lstat", errno);
    }
    if (S_ISLNK(root_st.st_mode) || !S_ISDIR(root_st.st_mode)) {
        return remove_host_file(host_path);
    }
    auto listing = list_host_directory(host_path);
    if (!listing.ok()) {
        return Result<void>(listing.errc(), listing.context());
    }
    for (const auto& e : listing.value()) {
        const std::string child = host_path + "/" + e.name;
        if (e.is_directory) {
            auto sub = remove_host_tree(child);
            if (!sub.ok()) return sub;
        } else {
            auto del = remove_host_file(child);
            if (!del.ok()) return del;
        }
    }
    return remove_host_directory(host_path);
}

}  // namespace xbox2pc::pal
