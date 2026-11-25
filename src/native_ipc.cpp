// native_ipc.cpp — M11 Phase 5 import-call ring transport (ADR-0001).
#include "xbox2pc/native_ipc.hpp"

#if defined(__linux__) && defined(__x86_64__)
#include <cerrno>
#include <fcntl.h>
#include <chrono>
#include <cstring>

namespace xbox2pc::rt::exec::native {

namespace {

// Bounded host spin window before parking: ~3000 relaxed loads, measured
// at tens of microseconds on CI-class hardware (ADR-0001 numbers).
constexpr int kSpinIters = 3000;

void evfd_bump(int fd) {
    const std::uint64_t one = 1;
    ssize_t r;
    do {
        r = ::write(fd, &one, sizeof one);
    } while (r < 0 && errno == EINTR);
}

bool evfd_wait(int fd) {
    std::uint64_t v;
    ssize_t r;
    do {
        r = ::read(fd, &v, sizeof v);
    } while (r < 0 && errno == EINTR);
    return r == sizeof v;
}

void slot_store(std::uint8_t* slot, const void* data, std::uint32_t len) {
    std::memcpy(slot, data, len);
}

void slot_load(void* out, const std::uint8_t* slot, std::uint32_t len) {
    std::memcpy(out, slot, len);
}

std::uint64_t seq_load(const volatile std::uint64_t* s) {
    return __atomic_load_n(const_cast<const std::uint64_t*>(s), __ATOMIC_ACQUIRE);
}

void seq_store(volatile std::uint64_t* s, std::uint64_t v) {
    __atomic_store_n(s, v, __ATOMIC_RELEASE);
}

}  // namespace

ImportRing* ImportRing::create() {
    void* mapping = ::mmap(nullptr, sizeof(RingPage),
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return nullptr;
    auto* page = static_cast<RingPage*>(mapping);
    page->req_seq = 0;
    page->rpl_seq = 0;
    // eventfd(0): semaphore semantics — each bump is one token.
    const int ev_req = static_cast<int>(::syscall(SYS_eventfd2, 0, 0));
    const int ev_rpl = static_cast<int>(::syscall(SYS_eventfd2, 0, 0));
    if (ev_req < 0 || ev_rpl < 0) {
        ::munmap(mapping, sizeof(RingPage));
        if (ev_req >= 0) ::close(ev_req);
        if (ev_rpl >= 0) ::close(ev_rpl);
        return nullptr;
    }
    auto* ring = new ImportRing();
    ring->page_ = page;
    ring->ev_req_ = ev_req;
    ring->ev_rpl_ = ev_rpl;
    return ring;
}

ImportRing::~ImportRing() {
    if (page_ != nullptr) ::munmap(page_, sizeof(RingPage));
    if (ev_req_ >= 0) ::close(ev_req_);
    if (ev_rpl_ >= 0) ::close(ev_rpl_);
}

bool ImportRing::child_call(const RequestSlot& request, ReplySlot& out_reply) {
    const std::uint64_t seq = seq_load(&page_->req_seq);   // our last publish
    const std::uint32_t slot = static_cast<std::uint32_t>(seq % kRingSlots);
    slot_store(page_->req[slot], &request, sizeof(RequestSlot));
    seq_store(&page_->req_seq, seq + 1);
    evfd_bump(ev_req_);
    // The child NEVER spins unbounded: park on the reply doorbell and
    // re-check after every wake (spurious wakes are tolerated).
    for (;;) {
        const std::uint64_t done = seq_load(&page_->rpl_seq);
        if (done > seq) {
            slot_load(&out_reply, page_->rpl[slot], sizeof(ReplySlot));
            return true;
        }
        if (!evfd_wait(ev_rpl_)) return false;   // parent gone: fatal
    }
}

bool ImportRing::parent_wait_request(std::uint64_t* seq_in, RequestSlot& out_request) {
    const std::uint64_t want = *seq_in + 1;
    // Spin-then-park: bounded burn, then block on the doorbell.
    for (;;) {
        const std::uint64_t avail = seq_load(&page_->req_seq);
        if (avail >= want) {
            const std::uint32_t slot = static_cast<std::uint32_t>((*seq_in) % kRingSlots);
            slot_load(&out_request, page_->req[slot], sizeof(RequestSlot));
            *seq_in = want;   // advance the caller's cursor
            return true;
        }
        int spins = 0;
        while (spins < kSpinIters) {
            if (seq_load(&page_->req_seq) >= want) break;
            ++spins;
        }
        if (spins < kSpinIters) continue;   // spin window caught it
        if (!evfd_wait(ev_req_)) return false;   // child gone
    }
}

void ImportRing::parent_reply(std::uint64_t seq, const ReplySlot& reply) {
    const std::uint32_t slot = static_cast<std::uint32_t>(seq % kRingSlots);
    slot_store(page_->rpl[slot], &reply, sizeof(ReplySlot));
    seq_store(&page_->rpl_seq, seq + 1);
    evfd_bump(ev_rpl_);
}

void ImportRing::parent_drain() {
    // Consume any unread doorbell tokens so a reused doorbell fd state
    // stays clean (principally a teardown hygiene step). NON-BLOCKING:
    // the caller runs this after reaping the child; with no token
    // pending it must return immediately.
    const int flags = ::fcntl(ev_req_, F_GETFL, 0);
    if (flags >= 0) (void)::fcntl(ev_req_, F_SETFL, flags | O_NONBLOCK);
    std::uint64_t v;
    while (::read(ev_req_, &v, sizeof v) == static_cast<ssize_t>(sizeof v)) {}
    if (flags >= 0) (void)::fcntl(ev_req_, F_SETFL, flags);
}

}  // namespace xbox2pc::rt::exec::native

#endif  // __linux__ && __x86_64__
