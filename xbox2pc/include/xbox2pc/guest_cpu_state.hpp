#pragma once
// xbox2pc/guest_cpu_state.hpp — M8 guest CPU state model (x86-64).
//
// Design (docs/guest-cpu-state.md):
//   - Platform-independent state representation: 16 GPRs + RIP + RFLAGS,
//     16 XMM registers (128-bit), MXCSR, x87 FCW. YMM/ZMM deliberately
//     NOT modeled: no M8 backend consumes them and storage alone must
//     never imply AVX/AVX2/AVX-512 support.
//   - Deterministic initialization: every architectural field has a
//     documented power-on/standard value (MS-X64CC: MXCSR 0x1F80,
//     FPCSR exception masks + double precision + round-to-nearest).
//   - Snapshot/restore are exact value copies; validate() checks the
//     CPU-level invariants (RSP alignment/non-overflow, RIP != 0,
//     RFLAGS reserved bits) — lifecycle checks live one layer up
//     (execution context), memory checks in guest memory.
//   - Serialization is a stable diagnostics format (magic + version),
//     not an ABI: round-trip equality is the contract.
//
// Evidence: [MS-X64CC] x64 calling convention (register set, volatile/
//            nonvolatile classification, MXCSR/FPCSR standard values)
//            https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt::cpu {

// ── register ids ──────────────────────────────────────────────────────────

enum class Gpr : std::uint8_t {
    Rax = 0, Rcx, Rdx, Rbx, Sp, Bp, Si, Di,
    R8, R9, R10, R11, R12, R13, R14, R15,
};
constexpr std::size_t kGprCount = 16;
const char* gpr_to_name(Gpr r);
std::optional<Gpr> gpr_from_name(const std::string& name);

constexpr std::size_t kXmmCount = 16;

// RFLAGS documented bits: CF=0, bit1=1 fixed, PF=2, AF=4, ZF=6, SF=7,
// TF=8, IF=9, DF=10, OF=11; 3/5/12..31 reserved.
inline constexpr std::uint32_t kFlagCF = 1u << 0;
inline constexpr std::uint32_t kFlagFixed1 = 1u << 1;
inline constexpr std::uint32_t kFlagPF = 1u << 2;
inline constexpr std::uint32_t kFlagAF = 1u << 4;
inline constexpr std::uint32_t kFlagZF = 1u << 6;
inline constexpr std::uint32_t kFlagSF = 1u << 7;
inline constexpr std::uint32_t kFlagTF = 1u << 8;
inline constexpr std::uint32_t kFlagIF = 1u << 9;
inline constexpr std::uint32_t kFlagDF = 1u << 10;
inline constexpr std::uint32_t kFlagOF = 1u << 11;
// Deterministic reset value: bit1 fixed + IF set (implementation
// convention; all other architectural state zero).
inline constexpr std::uint64_t kRflagsReset = 0x0000000000000202ull;
// Documented standard values [MS-X64CC]:
inline constexpr std::uint32_t kMxcsrStandard = 0x1F80u;   // masks + nearest
inline constexpr std::uint32_t kFcwStandard = 0x027Fu;      // x87: masks,
                                                            // double, nearest

// ── the state ─────────────────────────────────────────────────────────────

struct CpuState {
    std::uint64_t gprs[kGprCount] = {0};
    std::uint64_t rip = 0;
    std::uint64_t rflags = kRflagsReset;
    std::array<std::array<std::uint8_t, 16>, kXmmCount> xmm = {};
    std::uint32_t mxcsr = kMxcsrStandard;
    std::uint32_t fcw = kFcwStandard;

    // Deterministic reset to the documented initial state.
    void reset();

    // Explicit access (enum-checked).
    std::uint64_t reg(Gpr r) const { return gprs[static_cast<std::size_t>(r)]; }
    void set_reg(Gpr r, std::uint64_t v) { gprs[static_cast<std::size_t>(r)] = v; }

    // RFLAGS helpers.
    bool flag(std::uint32_t mask) const { return (rflags & mask) != 0; }
    void set_flag(std::uint32_t mask, bool on) {
        if (on) rflags |= mask; else rflags &= ~static_cast<std::uint64_t>(mask);
    }

    bool operator==(const CpuState& o) const {
        return std::equal(std::begin(gprs), std::end(gprs), std::begin(o.gprs)) &&
               rip == o.rip && rflags == o.rflags && xmm == o.xmm &&
               mxcsr == o.mxcsr && fcw == o.fcw;
    }
    bool operator!=(const CpuState& o) const { return !(*this == o); }

    // CPU-level invariants. Returns problem list (empty = valid):
    // RSP 8-byte aligned + within (4096, 2^63); RIP != 0; RFLAGS
    // reserved bits clean (except bit 1); no upper-32 garbage.
    std::vector<std::string> validate() const;
};

// ── snapshots ─────────────────────────────────────────────────────────────

// Exact value copy of a CpuState with stable serialization.
struct CpuSnapshot {
    CpuState state;

    // Stable diagnostics serialization: magic 'X2PC', kind 'S', version 1,
    // little-endian fixed order (RAX..R15, RIP, RFLAGS, MXCSR, FCW, XMM
    // 16×16 bytes). Deserialization validates size/magic/version and the
    // CPU invariants.
    std::vector<std::uint8_t> serialize() const;
    static Result<CpuSnapshot> deserialize(const std::uint8_t* data,
                                           std::size_t size);

    bool operator==(const CpuSnapshot& o) const { return state == o.state; }
    bool operator!=(const CpuSnapshot& o) const { return !(*this == o); }
};

// Convenience: snapshot/restore on a state (refuses invalid snapshots).
Result<void> snapshot_into(const CpuState& from, CpuSnapshot& out);
Result<void> restore_into(const CpuSnapshot& snap, CpuState& to);

}  // namespace xbox2pc::rt::cpu
