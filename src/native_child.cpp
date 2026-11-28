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

// x86-64 register indices in ucontext_t's gregs array (glibc
// sys/ucontext.h): R8=0 R9=1 R10=2 R11=3 R12=4 R13=5 R14=6 R15=7
// RDI=8 RSI=9 RBP=10 RBX=11 RDX=12 RAX=13 RCX=14 RSP=15 RIP=16.
constexpr int kRegR8 = 0;
constexpr int kRegR9 = 1;
constexpr int kRegRax = 13;
constexpr int kRegRcx = 14;
constexpr int kRegRdx = 12;
constexpr int kRegRsp = 15;
constexpr int kRegRip = 16;

// Async-signal-safe diagnostic writer (no libc printf).
void diag_fault(int signal, unsigned long long rip, unsigned long long addr,
                unsigned long long extra1 = 0, unsigned long long extra2 = 0) {
    char buf[160];
    std::size_t n = 0;
    auto put = [&](char c) { if (n + 1 < sizeof buf) buf[n++] = c; };
    auto put_hex = [&](unsigned long long v) {
        char tmp[20]; int len = 0;
        while (v > 0 && len < 19) { tmp[len++] = "0123456789abcdef"[v & 0xF]; v >>= 4; }
        if (len == 0) tmp[len++] = '0';
        while (len > 0) put(tmp[--len]);
    };
    auto put_dec = [&](long long v) {
        char tmp[24]; int len = 0;
        if (v < 0) { put('-'); v = -v; }
        if (v == 0) tmp[len++] = '0';
        while (v > 0 && len < 23) { tmp[len++] = static_cast<char>('0' + (v % 10)); v /= 10; }
        while (len > 0) put(tmp[--len]);
    };
    const char* msg = "[child] fatal signal ";
    while (*msg) put(*msg++);
    put_dec(signal);
    msg = " rip=0x"; while (*msg) put(*msg++);
    put_hex(rip);
    msg = " addr=0x"; while (*msg) put(*msg++);
    put_hex(addr);
    msg = " x1=0x"; while (*msg) put(*msg++);
    put_hex(extra1);
    msg = " x2=0x"; while (*msg) put(*msg++);
    put_hex(extra2);
    put('\n');
    (void)::write(2, buf, n);
}
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

bool child_patch_iats(const ImportThunkTable& imports, std::int64_t load_bias) {
    for (std::uint32_t i = 0; i < imports.count && i < kMaxThunkImports; ++i) {
        const std::uint64_t va = imports.iat_vas[i];
        if (va == 0) continue;
        // Rebase: guest VA -> host address in THIS process.
        const std::int64_t host = static_cast<std::int64_t>(va) + load_bias;
        auto* slot = reinterpret_cast<std::uint64_t*>(host);
        // The parent validated every IAT VA against the guest mapping
        // before the fork; the rebased store is safe there.
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
        // Diagnostic line for triage (async-signal-safe: write only).
        diag_fault(signal,
                   static_cast<unsigned long long>(uc->uc_mcontext.gregs[kRegRip]),
                   reinterpret_cast<unsigned long long>(info->si_addr));
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
    request.args[0] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[kRegRcx]);
    request.args[1] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[kRegRdx]);
    request.args[2] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[kRegR8]);
    request.args[3] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[kRegR9]);
    // Aux: the child's frame state at the trap (host addresses; the
    // parent rebases via the load bias).
    request.aux[0] = static_cast<std::uint64_t>(uc->uc_mcontext.gregs[kRegRsp]);
    // The import call's return address, read directly from the child's
    // stack (host memory; the parent rebases it to a guest VA).
    request.aux[1] = *reinterpret_cast<std::uint64_t*>(
        uc->uc_mcontext.gregs[kRegRsp]);

    ReplySlot reply{};
    if (!ring->child_call(request, reply)) _exit(124);   // parent gone

    if (reply.status == static_cast<std::uint32_t>(ReplyStatus::Ok)) {
        if (reply.aux[0] != 0) {
            // Terminate-after-reply contract (ExitProcess): the parent
            // dispatched the exit; the child ends here with the code.
            ::_exit(static_cast<int>(reply.exit_code & 0xFF));
        }
        uc->uc_mcontext.gregs[kRegRax] =
            static_cast<greg_t>(reply.rax);
        // Resume at the ret (RIP already past int3).
        return;
    }
    if (reply.status == static_cast<std::uint32_t>(ReplyStatus::GotoHandler)) {
        // SEH control transfer: continue at the language handler with
        // the establisher frame. The handler runs as guest code; its
        // return continues the normal (unwound) frame.
        uc->uc_mcontext.gregs[kRegRip] =
            static_cast<greg_t>(reply.aux[1]);
        uc->uc_mcontext.gregs[kRegRsp] =
            static_cast<greg_t>(reply.aux[2]);
        uc->uc_mcontext.gregs[kRegRax] = 0;
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
                                 std::uint64_t host_rsp,
                                 std::uint64_t completion_sentinel,
                                 std::uint64_t a0, std::uint64_t a1,
                                 std::uint64_t a2, std::uint64_t a3) {
    using GuestEntry = std::uint64_t (__attribute__((ms_abi)) *)(
        std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
    if (host_rsp != 0) {
        // Plant the sentinel as the entry's return address and switch
        // onto the guest stack (host address). 16-byte alignment per
        // [MS-X64STACK]: at the CALL target RSP+8 is 16-aligned, so an
        // RSP ending in 8 with the return slot at [rsp] is the standard
        // entry shape.
        auto* ret_slot = reinterpret_cast<std::uint64_t*>(host_rsp - 8);
        *ret_slot = completion_sentinel;
        // Inline stack switch + call: preserve nothing of the host frame
        // (this never returns through here on the guest stack).
        // All inputs live in EXPLICIT registers before the switch:
        // after RSP moves to the guest stack, no operand may reference
        // the (switched-away) host frame.
        register std::uint64_t r_rsp asm("r12") = host_rsp - 8;
        register std::uint64_t r_entry asm("r13") =
            reinterpret_cast<std::uint64_t>(host_entry);
        register std::uint64_t r_a0 asm("r14") = a0;
        register std::uint64_t r_a1 asm("r15") = a1;
        register std::uint64_t r_a2 asm("rdi") = a2;
        register std::uint64_t r_a3 asm("rsi") = a3;
        std::uint64_t value;
        asm volatile(
            "movq %%rsp, %%rbx\n\t"      // save host RSP (callee-saved)
            "movq %%r12, %%rsp\n\t"      // switch to the guest stack
            "movq %%r14, %%rcx\n\t"
            "movq %%r15, %%rdx\n\t"
            "movq %%rdi, %%r8\n\t"
            "movq %%rsi, %%r9\n\t"
            "callq *%%r13\n\t"
            "movq %%rax, %[out]\n\t"
            "movq %%rbx, %%rsp\n\t"      // restore host RSP
            : [out] "=r"(value)
            : "r"(r_rsp), "r"(r_entry), "r"(r_a0), "r"(r_a1), "r"(r_a2), "r"(r_a3)
            : "rcx", "rdx", "r8", "r9", "rax", "rbx", "memory");
        return value;
    }
    return reinterpret_cast<GuestEntry>(host_entry)(a0, a1, a2, a3);
}

}  // namespace xbox2pc::rt::exec::native

#endif  // __linux__ && __x86_64__
