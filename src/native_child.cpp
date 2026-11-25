// native_child.cpp — M11 Phase 5 child-side import thunks, TEB/GS, traps.
//
// Everything in this file runs in the forked child between fork() and
// _exit(): no allocations, no exceptions, no locks — the parent's C++
// runtime state is frozen copy-on-write and must stay untouched.
#include "xbox2pc/native_child.hpp"

#if defined(__linux__) && defined(__x86_64__)

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "xbox2pc/native_ipc.hpp"

namespace xbox2pc::rt::exec::native {

namespace {

// The single-threaded child's run state; installed by child_install_traps.
ChildRunState* g_state = nullptr;

// x86-64 register indices in ucontext_t's gregs array (glibc layout).
constexpr int kRegRax = 8;
constexpr int kRegRip = 16;
constexpr int kRegR10 = 12;

}  // namespace

bool child_install_gs(std::uint64_t teb_host) {
    // ARCH_SET_GS = 0x1001 (arch_prctl(2)).
    return ::syscall(SYS_arch_prctl, 0x1001, teb_host) == 0;
}

bool child_write_thunks(void* thunk_host, std::uint32_t import_count) {
    if (import_count > kMaxThunkImports) return false;
    auto* page = static_cast<std::uint8_t*>(thunk_host);
    if (page == nullptr) return false;
    std::memset(page, 0xCC, 4096);   // fill with int3: stray landings trap too
    for (std::uint32_t i = 0; i < import_count; ++i) {
        std::uint8_t* slot = page + static_cast<std::size_t>(i) * kThunkStride;
        // mov r10, imm32   49 C7 C2 <imm32>
        slot[0] = 0x49; slot[1] = 0xC7; slot[2] = 0xC2;
        slot[3] = static_cast<std::uint8_t>(i);
        slot[4] = static_cast<std::uint8_t>(i >> 8);
        slot[5] = static_cast<std::uint8_t>(i >> 16);
        slot[6] = static_cast<std::uint8_t>(i >> 24);
        slot[7] = 0xCC;   // int3
        slot[8] = 0xC3;   // ret
        // remaining bytes stay 0xCC (never executed: ret at slot[8])
    }
    return true;
}

bool child_patch_iats(const ImportThunkTable& imports) {
    for (std::uint32_t i = 0; i < imports.count && i < kMaxThunkImports; ++i) {
        const std::uint64_t va = imports.iat_vas[i];
        if (va == 0) continue;
        auto* slot = reinterpret_cast<std::uint64_t*>(va);
        // The parent validated every IAT VA against the guest mapping
        // before the fork; the child store is safe there. (A bad VA
        // would have failed parent-side validation with a typed error.)
        slot[0] = kThunkPageBase + static_cast<std::uint64_t>(i) * kThunkStride;
    }
    return true;
}

void child_handle_trap(int signal, siginfo_t* info, void* ucontext_v) {
    (void)info;
    auto* uc = static_cast<ucontext_t*>(ucontext_v);
    if (g_state == nullptr) _exit(125);

    if (signal != SIGTRAP) {
        // Structured fault: record and stop the world. The parent reads
        // the outcome from the ring protocol; there is nothing to resume.
        g_state->faulted = true;
        g_state->fault_signal = signal;
        // Unblock and re-raise so the default disposition terminates the
        // child (the parent classifies it from wait status).
        ::signal(signal, SIG_DFL);
        ::raise(signal);
        return;
    }

    // SIGTRAP from a thunk int3: RIP points AFTER the int3 (kernel bumps it).
    // Locate the slot: RIP-1 is the int3 address.
    const std::uint64_t rip = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[kRegRip]);
    const std::uint64_t int3_va = rip - 1;
    if (int3_va < kThunkPageBase ||
        int3_va >= kThunkPageBase + 4096) {
        // A trap outside the thunk page is not ours: fatal.
        g_state->faulted = true;
        g_state->fault_signal = SIGTRAP;
        ::signal(SIGTRAP, SIG_DFL);
        ::raise(SIGTRAP);
        return;
    }
    const std::uint32_t index =
        static_cast<std::uint32_t>((int3_va - kThunkPageBase) / kThunkStride);
    if (index >= (g_state->imports != nullptr ? g_state->imports->count : 0)) {
        g_state->faulted = true;
        g_state->fault_signal = SIGILL;
        ::signal(SIGILL, SIG_DFL);
        ::raise(SIGILL);
        return;
    }

    auto* ring = static_cast<ImportRing*>(g_state->ring);
    RequestSlot request{};
    request.call_class = static_cast<std::uint32_t>(CallClass::ApiCall);
    request.api_index = index;
    // The four Microsoft x64 argument registers.
    request.args[0] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[9]);   // RCX
    request.args[1] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[10]);  // RDX
    request.args[2] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[14]);  // R8
    request.args[3] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[15]);  // R9

    ReplySlot reply{};
    if (!ring->child_call(request, reply)) _exit(124);   // parent gone

    if (reply.status == static_cast<std::uint32_t>(ReplyStatus::Ok)) {
        uc->uc_mcontext.gregs[kRegRax] =
            static_cast<greg_t>(reply.rax);
        // Resume at the ret (RIP already past int3).
        return;
    }
    if (reply.status == static_cast<std::uint32_t>(ReplyStatus::Fatal)) {
        _exit(123);
    }
    // Rejected / unknown API: deliver a deterministic failure value the
    // caller can observe (documented ABI: failed Win32 calls return a
    // failure code in RAX; GetLastError-style detail stays parent-side).
    uc->uc_mcontext.gregs[kRegRax] = 0;
}

void child_install_traps(ChildRunState* state) {
    g_state = state;
    struct sigaction trap{};
    trap.sa_sigaction = child_handle_trap;
    trap.sa_flags = SA_SIGINFO;
    ::sigemptyset(&trap.sa_mask);
    ::sigaction(SIGTRAP, &trap, nullptr);
    // Structured faults: record + default-terminate through the handler.
    for (int s : {SIGSEGV, SIGILL, SIGFPE, SIGBUS}) {
        struct sigaction fa{};
        fa.sa_sigaction = child_handle_trap;
        fa.sa_flags = SA_SIGINFO;
        ::sigemptyset(&fa.sa_mask);
        ::sigaction(s, &fa, nullptr);
    }
}

std::uint64_t child_invoke_entry(void* host_entry,
                                 std::uint64_t a0, std::uint64_t a1,
                                 std::uint64_t a2, std::uint64_t a3) {
    using GuestEntry = std::uint64_t (__attribute__((ms_abi)) *)(
        std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    return reinterpret_cast<GuestEntry>(host_entry)(a0, a1, a2, a3);
}

}  // namespace xbox2pc::rt::exec::native

#endif  // __linux__ && __x86_64__
