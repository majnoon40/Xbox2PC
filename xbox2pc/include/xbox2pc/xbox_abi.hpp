#pragma once
// xbox2pc/xbox_abi.hpp — M8 Xbox x64 ABI foundation.
//
// Design (docs/xbox-x64-abi.md): models the Microsoft x64 calling
// convention — the ABI documented for Xbox-class Windows-derived x64
// targets — from opened reference pages. NOTHING is guessed: every
// rule below cites [MS-X64CC] or [MS-X64STACK].
//
//   [MS-X64CC]    x64 calling convention
//                 https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
//   [MS-X64STACK] x64 stack usage
//                 https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170
//
// Documented facts implemented:
//   - Integer/pointer args 1..4 -> RCX, RDX, R8, R9 (left to right);
//     args 5+ -> stack, right-to-left packing, 8-byte aligned [MS-X64CC].
//   - FP/double args 1..4 -> XMM0..XMM3 by POSITION (the integer and
//     FP register classes are independent per position) [MS-X64CC].
//   - Shadow (home) space: caller always reserves 32 bytes so the
//     callee can home RCX/RDX/R8/R9 [MS-X64CC] [MS-X64STACK].
//   - Stack: 16-byte aligned; RSP 16-aligned before the call pushes the
//     return address [MS-X64STACK]; return address sits at [RSP] on
//     entry; stack args begin at [RSP+8]+32 (after return addr + shadow).
//   - Returns: scalars <= 64 bits in RAX; floats/doubles/__m128 in
//     XMM0 [MS-X64CC]. Aggregate returns > 64 bits: hidden pointer in
//     RCX, returned in RAX (implemented as an explicit return kind).
//   - Volatile: RAX RCX RDX R8-R11 XMM0-5 (+YMM/ZMM upper when present
//     — N/A here). Nonvolatile: RBX RBP RDI RSI RSP R12-R15 XMM6-15
//     [MS-X64CC]. M8 marshalling preserves the nonvolatile set exactly;
//     volatile state is documented as undefined after a call.
//   - Varargs: FP values duplicated into the corresponding GP registers
//     [MS-X64CC] (Modeled as an explicit abi::CallKind).
//
// Xbox-specific deviations: NONE are documented to xbox2pc's knowledge
// for user-mode x64 code; every Xbox-specific claim stays unverified and
// is therefore NOT implemented. The layer supports ONE convention and
// rejects everything else with structured errors.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt::abi {

using cpu::CpuState;
using cpu::Gpr;

// ── argument model ─────────────────────────────────────────────────────────

enum class ArgKind : std::uint8_t {
    Int,       // 8-byte integer/pointer/enum-class value
    Ptr,       // guest pointer (validated through guest memory)
    F32,       // float (occupies an XMM slot at its position)
    F64,       // double (occupies an XMM slot at its position)
    VecF32x4,  // __m128-by-value: NOT supported — rejected (documented:
               // m128 is passed by reference; value-passing a vector is
               // unsupported in M8's model)
    Struct,    // aggregate <= 64 bits passed as integer (caller supplies
               // the raw 8-byte value); larger aggregates must be
               // passed as Ptr (documented rule)
};
const char* arg_kind_to_name(ArgKind k);
std::optional<ArgKind> arg_kind_from_name(const std::string& name);

struct ArgSpec {
    ArgKind kind = ArgKind::Int;
    // For Ptr: the maximum byte length the runtime will read/write
    // through it (strings include NUL; buffers their documented size).
    // 0 = pointer not dereferenced by the bridge.
    std::uint64_t deref_size = 0;
    // For Ptr: the pointer is an OUT (write) parameter (default in).
    bool is_out = false;
    // For Struct: the aggregate's documented size in {1,2,4,8}.
    std::uint32_t struct_size = 8;
};

// A call's ABI description. Built by the caller of the ABI layer.
struct CallSpec {
    std::vector<ArgSpec> args;
    enum class ReturnKind : std::uint8_t { Void, Int, F32, F64, Hidden };
    ReturnKind ret = ReturnKind::Void;
    // Varargs: FP args are ALSO copied into the GP registers at their
    // positions [MS-X64CC "Varargs"].
    bool varargs = false;
};

// ── value input / return output ───────────────────────────────────────────

struct ArgValue {
    ArgKind kind = ArgKind::Int;
    std::uint64_t int_v = 0;   // Int/Ptr/Struct raw value
    double f64_v = 0.0;        // F32 widened / F64
    // Ptr: the raw guest VA (validated by the bridge, not here).
    std::uint64_t ptr_va = 0;
};

struct ReturnValue {
    CallSpec::ReturnKind kind = CallSpec::ReturnKind::Void;
    std::uint64_t int_v = 0;
    double f64_v = 0.0;
};

// ── the ABI operations ────────────────────────────────────────────────────

// 1. Validate a CallSpec (arg counts, supported kinds, deref sizes,
//    varargs constraints). Typed rejections for anything the model
//    doesn't support — never silently accepted.
Result<void> validate_call(const CallSpec& spec);

// 2. Compute the call's stack requirements.
struct CallLayout {
    std::uint32_t gp_reg_args = 0;     // args in RCX/RDX/R8/R9 (<= 4)
    std::uint32_t xmm_reg_args = 0;    // args in XMM0..3 (<= 4)
    std::uint32_t stack_args = 0;      // args 5+ (8 bytes each)
    std::uint64_t total_stack_bytes = 0;  // shadow 32 + stack args 8n,
                                          // 16-byte aligned
};
Result<CallLayout> compute_layout(const CallSpec& spec);

// 3. Prepare a guest function call on a CPU state:
//    - writes GP/XMM argument registers,
//    - writes stack arguments + return address at the CURRENT RSP
//      (the caller supplies a valid, 16-byte-aligned RSP pointing at a
//      free region; the return address is [RSP] per [MS-X64STACK]),
//    - adjusts RSP by the documented frame delta (shadow + stack args,
//      keeping 16-byte alignment; the return address remains at the
//      bottom of the caller's frame),
//    - sets RIP to the callee entry.
//    Guest memory writes go through the provided writer (the bridge
//    passes guest memory). Returns the callee-side view for validation.
struct StackWriter {
    // The bridge's bound writer into guest memory (RW-checked).
    // Writes exactly at (guest_va, len); returns typed errors.
    void* ctx = nullptr;
    Result<void> (*write)(void* ctx, std::uint64_t va, const void* src,
                          std::size_t len) = nullptr;
};

Result<void> prepare_call(CpuState& cpu, std::uint64_t callee_va,
                          const CallSpec& spec, const std::vector<ArgValue>& values,
                          const StackWriter& writer);

// 4. Extract arguments from a guest CPU state (imported-API entry path):
//    reads GP/XMM registers + stack slots (via the bound reader) into
//    values. The reader is guest memory (R-checked stack reads).
struct StackReader {
    void* ctx = nullptr;
    Result<std::uint64_t> (*read64)(void* ctx, std::uint64_t va) = nullptr;
};

Result<std::vector<ArgValue>> extract_args(const CpuState& cpu,
                                           const CallSpec& spec,
                                           const StackReader& reader);

// 5. Convert a ReturnValue into guest return state: sets RAX or XMM0
//    per [MS-X64CC], restores RSP past the frame (caller-owned state),
//    and leaves volatile registers as-is (documented undefined).
Result<void> write_return(CpuState& cpu, const CallSpec& spec,
                          const ReturnValue& value);

// 6. Validate register preservation across a call: the nonvolatile set
//    (RBX RBP RDI RSI R12-15 XMM6-15) must be unchanged [MS-X64CC].
//    Returns the list of violated registers (empty = preserved).
std::vector<std::string> check_preserved(const CpuState& before,
                                         const CpuState& after);

// ── documented facts exposed for tests/CLI ────────────────────────────────

inline constexpr std::size_t kShadowSpaceBytes = 32;   // [MS-X64CC]
inline constexpr std::size_t kStackAlignment = 16;      // [MS-X64STACK]
inline constexpr std::size_t kMaxRegArgs = 4;

const char* abi_doc_summary();   // one-line evidence summary (CLI abi-info)

}  // namespace xbox2pc::rt::abi
