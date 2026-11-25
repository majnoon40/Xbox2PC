#pragma once
// xbox2pc/native_ipc.hpp — M11 Phase 5 import-call ring transport (ADR-0001).
//
// Shared-memory request/reply ring with eventfd doorbells for the
// native-execution child <-> parent import-call path. The guest child
// blocks on the reply doorbell (never spins unbounded); the parent
// spin-then-parks (bounded window) so back-to-back calls avoid one
// context switch. Sequence counters (release/acquire) fully order
// events: determinism does not depend on wake timing.
//
// Layout: one page, 64 slots x 256B request and reply banks.
// Wire format (fixed offsets in each 256B slot):
//   request: [u32 call_class][u32 api_index][u64 args[4]][u64 aux0..3]
//   reply:   [u32 status][u32 exit_code][u64 rax][u64 aux0..3][u192 pad]
// call_class selects the operation:
//   0 = API_CALL (api_index indexes the request's api_bindings vector,
//                 args are the four Microsoft-x64 register slots)
//   1 = EXIT_PROCESS (exit_code in args[0])
// status: 0 = ok (rax valid), 1 = dispatched-but-rejected (error text is
//   parent-side only), 2 = unknown api_index, 3 = fatal protocol error.

#include <cstdint>

#if defined(__linux__) && defined(__x86_64__)
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace xbox2pc::rt::exec::native {

constexpr std::uint32_t kRingSlots = 64;
constexpr std::uint32_t kSlotBytes = 256;
constexpr std::uint32_t kMaxApiArgs = 4;

enum class CallClass : std::uint32_t {
    ApiCall = 0,
    ExitProcess = 1,
};

enum class ReplyStatus : std::uint32_t {
    Ok = 0,
    Rejected = 1,
    UnknownApi = 2,
    Fatal = 3,
};

// Fixed-offset wire accessors (both sides compile the same view).
struct RequestSlot {
    std::uint32_t call_class;   // CallClass
    std::uint32_t api_index;    // index into ExecutionRequest::api_bindings
    std::uint64_t args[kMaxApiArgs];
    std::uint64_t aux[4];       // reserved (future: out pointers, lengths)
};
struct ReplySlot {
    std::uint32_t status;       // ReplyStatus
    std::uint32_t exit_code;    // ExitProcess code
    std::uint64_t rax;
    std::uint64_t aux[4];
};

// Shared page. Volatile sequence counters; all publishes use release
// stores, all observes use acquire loads (see the ADR protocol sketch).
struct alignas(4096) RingPage {
    volatile std::uint64_t req_seq;   // child publishes
    volatile std::uint64_t rpl_seq;   // parent publishes
    std::uint8_t req[kRingSlots][kSlotBytes];
    std::uint8_t rpl[kRingSlots][kSlotBytes];
};
static_assert(sizeof(RingPage) == 4096 + 2 * kRingSlots * kSlotBytes,
              "ring page layout");

// One endpoint of the transport. Shared ownership of the mapping + the
// two doorbells; destroyed once by whichever side outlives the other.
class ImportRing {
public:
    // Creates the shared page + doorbells. Returns nullptr on failure
    // (the caller maps this to a typed runtime error).
    static ImportRing* create();
    ~ImportRing();

    ImportRing(const ImportRing&) = delete;
    ImportRing& operator=(const ImportRing&) = delete;

    // ── child side ──
    // Publish one request and block until the matching reply exists.
    // Returns false when the parent is gone (doorbell closed) — the child
    // must treat that as fatal and _exit.
    bool child_call(const RequestSlot& request, ReplySlot& out_reply);

    // ── parent side ──
    // Spin-then-park wait for the next request (seq == *seq_in + 1).
    // Returns false when the child is gone.
    bool parent_wait_request(std::uint64_t* seq_in, RequestSlot& out_request);
    // Publish a reply and ring the child doorbell.
    void parent_reply(std::uint64_t seq, const ReplySlot& reply);
    // Drain any unread doorbell tokens (call after reaping the child).
    void parent_drain();

    // Raw page pointer (the child uses it across fork).
    RingPage* page() { return page_; }
    int request_doorbell() const { return ev_req_; }
    int reply_doorbell() const { return ev_rpl_; }

private:
    ImportRing() = default;
    RingPage* page_ = nullptr;
    int ev_req_ = -1;   // child -> parent
    int ev_rpl_ = -1;   // parent -> child
};

}  // namespace xbox2pc::rt::exec::native

#endif  // __linux__ && __x86_64__
