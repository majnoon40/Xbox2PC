#pragma once
// xbox2pc/x64_decoder.hpp — M9 structured x86-64 instruction decoder.
//
// Pure function: instruction bytes in, a structured instruction out. The
// decoder has NO dependency on the runtime, on guest memory or on the
// interpreter's arithmetic helpers, so it can be fuzzed on arbitrary byte
// buffers and reused by static analysis (docs/instruction-decoder.md).
//
// Contract:
//   - Every byte sequence gets exactly one of four statuses:
//       Ok           — a completely decoded instruction inside the supported
//                      matrix (docs/x86-64-instruction-support.md)
//       Truncated    — the buffer ends before the instruction is complete
//       Invalid      — never a valid x86-64 instruction (#UD on hardware)
//       Unsupported  — a valid x86-64 encoding the interpreter does not
//                      execute (explicitly rejected, never treated as NOP)
//   - RIP-relative and relative operands are stored relative to the
//     instruction address; the executor forms absolute addresses.
//   - Flag metadata (flags_effect) is the architectural flag-definedness
//     table used by the interpreter AND by the differential test harness.
//
// The decoder is NOT a complete x86-64 disassembler: SIMD, VEX/EVEX, x87,
// string, three-byte-map and privileged encodings are rejected with their
// class, and nothing here claims complete ISA coverage.

#include <cstddef>
#include <cstdint>
#include <string>

namespace xbox2pc::rt::x64 {

inline constexpr std::size_t kMaxInstructionBytes = 15;
inline constexpr std::uint8_t kNoReg = 0xFF;

// RFLAGS bit masks (values equal the architectural bit positions).
inline constexpr std::uint32_t kRfCf = 1u << 0;
inline constexpr std::uint32_t kRfPf = 1u << 2;
inline constexpr std::uint32_t kRfAf = 1u << 4;
inline constexpr std::uint32_t kRfZf = 1u << 6;
inline constexpr std::uint32_t kRfSf = 1u << 7;
inline constexpr std::uint32_t kRfTf = 1u << 8;
inline constexpr std::uint32_t kRfIf = 1u << 9;
inline constexpr std::uint32_t kRfDf = 1u << 10;
inline constexpr std::uint32_t kRfOf = 1u << 11;

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    Truncated = 1,
    Invalid = 2,
    Unsupported = 3,
};

enum class RejectClass : std::uint8_t {
    None = 0,
    NeedMoreBytes,       // status Truncated
    TooLong,             // > 15 bytes (invalid on hardware: #GP)
    BadOpcode,           // Invalid: no such instruction in 64-bit mode
    BadOperandSize,      // Invalid: encoding not valid at this operand size
    BadModRm,            // Invalid: /digit (or mod) has no defined form
    BadPrefix,           // Invalid: LOCK/REP/66 where not permitted
    UnsupportedValid,    // valid, not interpreted (generic)
    UnsupportedMap,      // valid: 0F 38 / 0F 3A / VEX / EVEX maps
    UnsupportedSimd,     // valid: SSE / SSE2 / AVX legacy / MMX / x87
    UnsupportedString,   // valid: string operations
    UnsupportedAtomic,   // valid: LOCK / CMPXCHG / XADD family
    UnsupportedPrivileged,  // valid: traps in user mode (I/O, HLT, system)
};

enum class Mnemonic : std::uint8_t {
    Invalid = 0,
    // integer ALU
    Add, Or, Adc, Sbb, And, Sub, Xor, Cmp, Test,
    // data movement / conversion
    Mov, Movzx, Movsx, Movsxd, Lea, Xchg, Bswap, Cbw, Cwd,
    // inc/dec/unary/multiply/divide
    Inc, Dec, Neg, Not, Mul, Imul, Div, Idiv,
    // shift / rotate / bit
    Rol, Ror, Rcl, Rcr, Shl, Shr, Sar,
    Bt, Bts, Btr, Btc, Bsf, Bsr, Tzcnt, Lzcnt, Popcnt,
    // control flow
    Jmp, Jcc, Call, Ret, Loop, Loope, Loopne, Jrcxz, Cmovcc, Setcc,
    // stack / flags
    Push, Pop, Pushf, Popf, Lahf, Sahf, Leave,
    Clc, Stc, Cmc, Cld, Std,
    // traps / hints
    Nop, Int3, Ud2,
};

enum class OpKind : std::uint8_t { None = 0, Reg, Mem, Imm, Rel };

enum class Segment : std::uint8_t { None = 0, Cs, Ds, Es, Fs, Gs, Ss };

enum class Group : std::uint8_t {
    Alu = 0, DataMovement, MulDiv, ShiftRotate, BitOps, ControlFlow, StackFlags,
    Convert, TrapHint,
};

struct Operand {
    OpKind kind = OpKind::None;
    std::uint8_t bits = 0;      // operand width in bits (8/16/32/64)
    std::uint8_t reg = kNoReg;  // OpKind::Reg: GPR index 0..15 (raw index;
                                // byte registers follow the REX rule)
    // OpKind::Mem
    Segment seg = Segment::None;
    bool rip_relative = false;
    bool addr32 = false;        // 67h: 32-bit address size
    std::uint8_t base = kNoReg;     // GPR index or kNoReg
    std::uint8_t index = kNoReg;
    std::uint8_t scale = 1;          // 1/2/4/8
    std::int64_t disp = 0;
    // OpKind::Imm / Rel
    std::uint64_t imm = 0;      // raw encoded value, zero-extended
    std::uint8_t imm_bits = 0;  // encoding width (8/16/32/64)
};

struct Decoded {
    Mnemonic mnem = Mnemonic::Invalid;
    std::uint8_t length = 0;
    std::uint8_t rex = 0;            // 0 when absent
    std::uint8_t opcode = 0;         // final opcode byte
    std::uint8_t map = 0;            // 0 = one-byte, 1 = 0F two-byte
    std::uint8_t op_size = 32;       // effective operand size (bits)
    std::uint8_t addr_size = 64;     // effective address size (bits)
    std::uint8_t cc = 0;             // condition code 0..15 (Jcc/SETcc/CMOVcc)
    bool has_66 = false;
    bool has_67 = false;
    bool has_f2 = false;
    bool has_f3 = false;
    bool has_lock = false;
    bool is_endbr = false;           // F3 0F 1E /r (endbr32/64)
    std::uint64_t rip = 0;           // instruction address (for display)
    Operand ops[3];
    std::uint8_t op_count = 0;
};

// Architectural flag behaviour of one instruction:
//   affected — flags the instruction may change
//   defined  — subset of affected whose result the architecture defines
// The interpreter must leave (affected & ~defined) unchanged.
struct FlagEffect {
    std::uint32_t affected = 0;
    std::uint32_t defined = 0;
};

struct DecodeResult {
    DecodeStatus status = DecodeStatus::Truncated;
    Decoded ins;        // valid iff status == Ok
    RejectClass reject = RejectClass::None;
    const char* reason = "not decoded";
    // Bytes accounted for when decoding stopped:
    //   Ok          — equal to ins.length
    //   Truncated   — bytes accepted before the buffer ran out (<= len); the
    //                 instruction needs MORE than len bytes, so a caller that
    //                 fetches incrementally must fetch further, never advance
    //                 RIP by this value
    //   Invalid /
    //   Unsupported — bytes examined before the reject (<= 15); informational
    std::uint8_t consumed = 0;
};

// Decode one instruction at guest address `rip` from `len` bytes.
DecodeResult decode(const std::uint8_t* data, std::size_t len, std::uint64_t rip);

// Names / metadata.
const char* status_name(DecodeStatus s);
const char* reject_class_name(RejectClass r);
const char* mnemonic_name(Mnemonic m);
std::string mnemonic_text(const Decoded& d);   // includes the cc suffix
Group instruction_group(Mnemonic m);
bool is_branch(Mnemonic m);              // any control transfer
bool is_block_terminator(Mnemonic m);    // ends a basic block (jmp/ret/call
                                         // to a known-no-return point is the
                                         // caller's decision; here: jmp, ret)
bool is_call(Mnemonic m);
bool is_return(Mnemonic m);             // RET only

// Architectural condition evaluation (spec metadata, no arithmetic helpers
// shared with the interpreter's data path).
bool condition_holds(std::uint8_t cc, std::uint64_t rflags);
FlagEffect flags_effect(const Decoded& d, const std::uint64_t* gprs);

// Intel-syntax rendering (no address / bytes prefix). Register-only and
// memory operands are size-qualified; relative operands show the absolute
// target address computed from d.rip.
std::string format_instruction(const Decoded& d);
std::string register_name(std::uint8_t reg, std::uint8_t bits, bool rex_present);
std::string operand_size_text(std::uint8_t bits);

const char* condition_suffix(std::uint8_t cc);

// Value helpers (pure, overflow-safe).
std::uint64_t operand_size_mask(std::uint8_t bits);
std::int64_t sign_extend(std::uint64_t v, std::uint8_t from_bits);

// Absolute target of a relative branch (JMP/Jcc/CALL rel8/rel32):
// next_instruction + sign_extend(displacement). Returns 0 when the decoded
// instruction carries no relative operand.
std::uint64_t branch_target(const Decoded& d);

}  // namespace xbox2pc::rt::x64
