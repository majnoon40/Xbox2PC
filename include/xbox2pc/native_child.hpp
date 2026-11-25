#pragma once
// xbox2pc/native_child.hpp — M11 Phase 5 child-side import thunks + TEB.
//
// Everything here runs INSIDE the forked child (post-fork, pre-entry).
// The child must not allocate or touch the C++ runtime beyond trivial
// syscalls: these helpers are freestanding where possible.
//
// Thunk layout (one page at the synthetic binding base, guest VA):
//   slot i at 0x51000000 + i*32:
//     mov r10, i        (49 C7 C2 ii ii ii ii)
//     int3              (CC)
//     ret               (C3)
//     (pad to 32 bytes)
// A guest call lands on the slot, the int3 traps, the child's SIGTRAP
// handler reads r10 = import index, performs the ring round trip,
// writes RAX, and advances RIP past the int3 — execution continues at
// the ret, returning to the guest caller with the API result in RAX.
//
// The GS base is installed with arch_prctl(ARCH_SET_GS) pointing at the
// mapped guest TEB, so guest `mov rax, gs:[0x30]`-style TEB access works.

#include <cstdint>

#if defined(__linux__) && defined(__x86_64__)

#include <csignal>
#include <sys/ucontext.h>

namespace xbox2pc::rt::exec::native {

// Synthetic binding page constants (must match execution_engine.hpp's
// kBindingBase; kept separate to avoid pulling engine types into the child).
constexpr std::uint64_t kThunkPageBase = 0x51000000ull;
constexpr std::uint32_t kThunkStride = 32;          // bytes per import slot
constexpr std::uint32_t kMaxThunkImports = 2048;    // binding range / stride

// Per-import metadata the child needs (prepared parent-side, inherited
// through the fork as plain data).
struct ImportThunkTable {
    std::uint32_t count = 0;                        // imports bound
    std::uint64_t iat_vas[kMaxThunkImports] = {0};  // guest VA of each IAT slot
    std::uint64_t iat_values[kMaxThunkImports] = {0}; // original slot contents
};

// Child state shared with the SIGTRAP handler (single thread: plain data).
struct ChildRunState {
    void* ring = nullptr;              // ImportRing* (opaque here)
    ImportThunkTable* imports = nullptr;
    std::uint64_t teb_host = 0;        // host address of the guest TEB
    volatile std::uint64_t exit_code = 0;
    volatile bool exit_requested = false;
    volatile bool faulted = false;
    volatile long fault_signal = 0;
};

// Install GS = teb_host. Returns false on arch_prctl failure.
bool child_install_gs(std::uint64_t teb_host);

// Write the thunk page at [thunk_host, +4096): slot i encodes import i.
// Returns false when the mapping is bad.
bool child_write_thunks(void* thunk_host, std::uint32_t import_count);

// Rewrite every IAT slot in child memory to point at its thunk.
// Guest VAs are rebased by load_bias (host_entry - guest_entry): the
// child dereferences HOST addresses, never raw guest VAs.
// Returns false when a slot is unreadable/writable-check fails.
bool child_patch_iats(const ImportThunkTable& imports, std::int64_t load_bias);

// SIGTRAP handler: dispatch through the ring, fix up the context.
// Installed by child_install_traps(); also catches fatal signals
// (SIGSEGV/SIGILL/SIGFPE/SIGBUS) and records them for the parent.
void child_install_traps(ChildRunState* state);
void child_handle_trap(int signal, siginfo_t* info, void* ucontext_v);

// The guest entry call (Microsoft x64). Defined in the .cpp with the
// ms_abi attribute; the caller passes host-resolved entry + 4 register
// arguments. When host_rsp is nonzero the child first switches onto the
// guest stack (RSP = host_rsp - 8 with the completion sentinel planted
// as the return address, matching the deterministic engine's entry
// contract) so guest code that touches [rsp] sees a valid frame. The
// caller passes the HOST address of the guest stack top — the child
// never dereferences raw guest VAs.
std::uint64_t child_invoke_entry(void* host_entry,
                                 std::uint64_t host_rsp,
                                 std::uint64_t completion_sentinel,
                                 std::uint64_t a0, std::uint64_t a1,
                                 std::uint64_t a2, std::uint64_t a3);

}  // namespace xbox2pc::rt::exec::native

#endif  // __linux__ && __x86_64__
