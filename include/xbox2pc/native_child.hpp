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
// guest TEB, so guest `mov rax, gs:[0x30]`-style TEB access works.
//
// ADR-0009: the guest address space is one memfd the parent maps
// MAP_SHARED; the child re-maps the same object at the guest VAs with
// MAP_FIXED_NOREPLACE, so guest VA == child host VA everywhere in the
// space. The child therefore dereferences guest VAs directly (the entry,
// the stack top, the TEB and every pointer argument on the wire), and
// no load-bias translation exists on either side.

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

// ADR-0009: the child's identity-mapping plan, serialized parent-side from
// the AddressSpace before the fork (plain data, inherited COW). The child
// maps [space_base, space_base + space_size) over the space's memfd with
// MAP_FIXED_NOREPLACE PROT_NONE, then re-applies each committed region's
// protection — mirroring, at fork time, exactly what the parent's window
// carries (the same semantics fork itself used to provide by inheriting
// the window).
struct GuestIdentityMap {
    static constexpr std::uint32_t kMaxRegions = 64;
    std::uint64_t space_base = 0;   // guest VA of the space start
    std::uint64_t space_size = 0;   // capacity in bytes
    std::uint32_t region_count = 0; // committed regions below
    int fd = -1;                    // the space's memfd
    struct Region {
        std::uint64_t offset;       // from space_base (page-aligned)
        std::uint64_t size;         // page-aligned length
        std::uint32_t prot;         // PROT_* bits for the child's mapping
        std::uint32_t pad = 0;
    } regions[kMaxRegions];
};

// Child state shared with the SIGTRAP handler (single thread: plain data).
struct ChildRunState {
    void* ring = nullptr;              // ImportRing* (opaque here)
    ImportThunkTable* imports = nullptr;
    GuestIdentityMap* identity = nullptr;  // set before child_map_guest_identity
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

// ADR-0009: map the space's memfd at the guest VAs so guest VA == host VA
// in this child, then re-apply every committed region's protection.
// MAP_FIXED_NOREPLACE: a collision (sanitizer shadow, a library) fails
// the run honestly instead of unmapping something. Returns false on
// failure; the caller maps the failure to a distinct child exit code.
bool child_map_guest_identity(const GuestIdentityMap& plan);

// SIGTRAP handler: dispatch through the ring, fix up the context.
// Installed by child_install_traps(); also catches fatal signals
// (SIGSEGV/SIGILL/SIGFPE/SIGBUS) and records them for the parent.
void child_install_traps(ChildRunState* state);
void child_handle_trap(int signal, siginfo_t* info, void* ucontext_v);

// The guest entry call (Microsoft x64). Defined in the .cpp with the
// ms_abi attribute; the caller passes the entry and 4 register arguments.
// When guest_rsp is nonzero the child first switches onto the guest stack
// (RSP = guest_rsp - 8 with the completion sentinel planted as the return
// address, matching the deterministic engine's entry contract) so guest
// code that touches [rsp] sees a valid frame. ADR-0009: with the identity
// mapping installed, the entry VA and the stack top ARE host addresses in
// the child — the caller passes them unchanged.
std::uint64_t child_invoke_entry(void* host_entry,
                                 std::uint64_t host_rsp,
                                 std::uint64_t completion_sentinel,
                                 std::uint64_t a0, std::uint64_t a1,
                                 std::uint64_t a2, std::uint64_t a3);

}  // namespace xbox2pc::rt::exec::native

#endif  // __linux__ && __x86_64__
