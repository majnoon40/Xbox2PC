// xbox2pc/src/x86_interpreter.cpp — M9 instruction semantics engine.
//
// Sections:
//   1. sub-register reads/writes (Intel rules)
//   2. operand resolution (value/EA computation, memory access)
//   3. flag computation (CF/PF/AF/ZF/SF/OF per the SDM)
//   4. arithmetic/logic semantics
//   5. mul/div (128-bit via 32-bit halves — no __int128, -Wpedantic-safe)
//
// Each step() call is all-or-nothing: a fault leaves the CpuState exactly
// as it was (no partial writes, no RIP advance). Undefined flags are left
// UNCHANGED (never cleared blindly) — the flag-definedness table in the
// decoder decides which flags an instruction defines.
//
// Operand order follows the decoder: ops[0] is the Intel-first (dest for
// the two-operand forms), ops[1] the source (or the shift count), ops[2]
// the IMUL immediate.

#include "xbox2pc/x86_interpreter.hpp"

#include <cstring>
#include <string>
#include <mutex>

namespace xbox2pc::rt::x86 {

using cpu::CpuState;
using cpu::Gpr;
using exec::AccessType;
using exec::GuestFault;
using guest::GuestMemory;
using x64::Decoded;
using x64::Mnemonic;
using x64::Operand;

// ── 1. sub-register access ────────────────────────────────────────────────

namespace {

// Serialize guest memory accesses across interpreter instances. The recursive
// lock lets a memory XCHG hold the lock across its read/write pair while the
// shared operand helpers take the same lock internally.
std::recursive_mutex g_guest_memory_mutex;

constexpr std::uint64_t kMask8 = 0xFFull;
constexpr std::uint64_t kMask16 = 0xFFFFull;
constexpr std::uint64_t kMask32 = 0xFFFFFFFFull;

inline std::uint64_t width_mask(std::uint8_t bits) {
    switch (bits) {
        case 8: return kMask8;
        case 16: return kMask16;
        case 32: return kMask32;
        default: return ~0ull;
    }
}

inline std::uint64_t read_slot(const CpuState& c, std::uint8_t reg) {
    return c.gprs[reg & 0xFu];
}

// Parity of the low 8 bits (PF is computed on the low byte only).
inline bool parity8(std::uint64_t v) {
    std::uint8_t p = 0;
    for (std::uint8_t b = static_cast<std::uint8_t>(v & 0xFF); b != 0; b >>= 1) {
        p = static_cast<std::uint8_t>(p ^ (b & 1u));
    }
    return p == 0;   // even number of set bits -> PF=1
}

inline bool sign_bit(std::uint64_t v, std::uint8_t bits) {
    return (v >> (bits - 1)) & 1ull;
}

// ── EA computation ───────────────────────────────────────────────────────
// [RIP + disp32] is relative to the instruction FOLLOWING this one; the
// caller passes start_rip + ins.length as base_rip. 67h (addr32) makes
// every component and the sum 32-bit.
struct Ea {
    std::uint64_t va = 0;
};

Ea compute_ea(const CpuState& c, const Operand& o, std::uint64_t base_rip) {
    Ea ea;
    if (o.rip_relative) {
        // Unsigned arithmetic deliberately models x86 address wraparound.
        // With 67h, EIP-relative addresses are truncated to 32 bits and
        // zero-extended; without it, the full 64-bit sum is retained.
        const std::uint64_t sum = base_rip + static_cast<std::uint64_t>(o.disp);
        ea.va = o.addr32 ? (sum & kMask32) : sum;
        return ea;
    }
    std::uint64_t sum = 0;
    if (o.base != x64::kNoReg) {
        const std::uint64_t b = c.gprs[o.base & 0xFu];
        sum += o.addr32 ? (b & kMask32) : b;
    }
    if (o.index != x64::kNoReg) {
        const std::uint64_t idx = c.gprs[o.index & 0xFu];
        const std::uint64_t scaled = idx * o.scale;   // scale ∈ {1,2,4,8}
        sum += o.addr32 ? (scaled & kMask32) : scaled;
    }
    sum += static_cast<std::uint64_t>(o.disp);
    if (o.addr32) sum &= kMask32;
    ea.va = sum;
    return ea;
}

// ── per-step context ─────────────────────────────────────────────────────

struct Ctx {
    CpuState& cpu;
    GuestMemory& mem;
    const Decoded& ins;
    const std::uint64_t start_rip;
    const bool rex;   // a REX prefix was present (byte regs 4..7 are low)
    StepFault fail;
    bool failed = false;

    void abort(GuestFault f, const char* why, std::uint64_t addr = 0) {
        failed = true;
        fail.fault = f;
        fail.fault_rip = start_rip;
        fail.fault_address = addr;
        fail.detail = why;
    }
};

// Reads an operand's value (register, immediate or memory).
bool read_operand(Ctx& cx, const Operand& o, Value& out) {
    std::unique_lock<std::recursive_mutex> memory_lock(
        g_guest_memory_mutex, std::defer_lock);
    if (o.kind == x64::OpKind::Mem) memory_lock.lock();
    switch (o.kind) {
        case x64::OpKind::Reg:
            out.bits = o.bits;
            out.raw = read_gpr(cx.cpu, o.reg, o.bits, cx.rex) & width_mask(o.bits);
            return true;
        case x64::OpKind::Imm:
        case x64::OpKind::Rel:
            out.bits = o.bits;
            out.raw = o.imm & width_mask(o.bits);
            return true;
        case x64::OpKind::Mem: {
            const std::uint64_t base_rip = cx.start_rip + cx.ins.length;
            const Ea ea = compute_ea(cx.cpu, o, base_rip);
            out.bits = o.bits;
            out.raw = 0;
            if (o.bits == 8) {
                auto r = cx.mem.read_u8(ea.va);
                if (!r.ok()) { cx.abort(GuestFault::InvalidAccess, "operand read", ea.va); return false; }
                out.raw = r.value();
            } else if (o.bits == 16) {
                auto r = cx.mem.read_u16(ea.va);
                if (!r.ok()) { cx.abort(GuestFault::InvalidAccess, "operand read", ea.va); return false; }
                out.raw = r.value();
            } else if (o.bits == 32) {
                auto r = cx.mem.read_u32(ea.va);
                if (!r.ok()) { cx.abort(GuestFault::InvalidAccess, "operand read", ea.va); return false; }
                out.raw = r.value();
            } else if (o.bits == 64) {
                auto r = cx.mem.read_u64(ea.va);
                if (!r.ok()) { cx.abort(GuestFault::InvalidAccess, "operand read", ea.va); return false; }
                out.raw = r.value();
            } else {
                cx.abort(GuestFault::Internal, "unsupported operand width");
                return false;
            }
            return true;
        }
        default:
            cx.abort(GuestFault::Internal, "operand with no kind");
            return false;
    }
}

bool write_operand(Ctx& cx, const Operand& o, std::uint64_t value) {
    std::unique_lock<std::recursive_mutex> memory_lock(
        g_guest_memory_mutex, std::defer_lock);
    if (o.kind == x64::OpKind::Mem) memory_lock.lock();
    switch (o.kind) {
        case x64::OpKind::Reg:
            write_gpr(cx.cpu, o.reg, o.bits, value, cx.rex);
            return true;
        case x64::OpKind::Mem: {
            const std::uint64_t base_rip = cx.start_rip + cx.ins.length;
            const Ea ea = compute_ea(cx.cpu, o, base_rip);
            if (o.bits == 8) {
                auto r = cx.mem.write_u8(ea.va, static_cast<std::uint8_t>(value & kMask8));
                if (!r.ok()) { cx.abort(GuestFault::PermissionWrite, "operand write", ea.va); return false; }
            } else if (o.bits == 16) {
                auto r = cx.mem.write_u16(ea.va, static_cast<std::uint16_t>(value & kMask16));
                if (!r.ok()) { cx.abort(GuestFault::PermissionWrite, "operand write", ea.va); return false; }
            } else if (o.bits == 32) {
                auto r = cx.mem.write_u32(ea.va, static_cast<std::uint32_t>(value & kMask32));
                if (!r.ok()) { cx.abort(GuestFault::PermissionWrite, "operand write", ea.va); return false; }
            } else {
                auto r = cx.mem.write_u64(ea.va, value);
                if (!r.ok()) { cx.abort(GuestFault::PermissionWrite, "operand write", ea.va); return false; }
            }
            return true;
        }
        default:
            cx.abort(GuestFault::Internal, "write to a non-writable operand");
            return false;
    }
}

// PF/ZF/SF from a width-masked result.
void set_pf_zf_sf(CpuState& cpu, std::uint64_t result, std::uint8_t bits) {
    const std::uint64_t r = result & width_mask(bits);
    cpu.set_flag(cpu::kFlagPF, parity8(r));
    cpu.set_flag(cpu::kFlagZF, r == 0);
    cpu.set_flag(cpu::kFlagSF, sign_bit(r, bits));
}

// MUL/IMUL flags: CF and OF are both set when the product exceeds the
// operand width (the upper half is non-zero / does not sign-extend),
// cleared otherwise. Other flags: undefined (left unchanged).
void set_muldiv_flags(CpuState& cpu, bool overflow, std::uint8_t /*bits*/) {
    cpu.set_flag(cpu::kFlagCF, overflow);
    cpu.set_flag(cpu::kFlagOF, overflow);
}

// ── control-flow helpers ──────────────────────────────────────────────────
//
// Branch-target validation: exec permission at the target. A target outside
// the mapped executable range faults (typed) BEFORE any state change.
bool check_exec(Ctx& cx, std::uint64_t va) {
    auto x = cx.mem.validate_exec(va);
    if (!x.ok()) {
        GuestFault f = x.err == guest::GuestMemErrc::PermissionDenied
                           ? GuestFault::PermissionExec
                           : GuestFault::InvalidAccess;
        cx.abort(f, "branch target", va);
        return false;
    }
    return true;
}

// PUSH: RSP -= 8; [RSP] = value.
bool push_u64(Ctx& cx, std::uint64_t value) {
    const std::uint8_t sp = static_cast<std::uint8_t>(Gpr::Sp);
    const std::uint64_t old_sp = cx.cpu.gprs[sp];
    if (old_sp < 8) {
        cx.abort(GuestFault::StackOverflow, "push: RSP below 8");
        return false;
    }
    const std::uint64_t new_sp = old_sp - 8;
    auto w = cx.mem.write_u64(new_sp, value);
    if (!w.ok()) {
        cx.abort(GuestFault::PermissionWrite, "push: stack write", new_sp);
        return false;
    }
    cx.cpu.gprs[sp] = new_sp;
    return true;
}

// POP: value = [RSP]; RSP += 8.
bool pop_u64(Ctx& cx, Value& out) {
    const std::uint8_t sp = static_cast<std::uint8_t>(Gpr::Sp);
    const std::uint64_t old_sp = cx.cpu.gprs[sp];
    auto r = cx.mem.read_u64(old_sp);
    if (!r.ok()) {
        cx.abort(GuestFault::InvalidAccess, "pop: stack read", old_sp);
        return false;
    }
    out.bits = 64;
    out.raw = r.value();
    cx.cpu.gprs[sp] = old_sp + 8;
    return true;
}

// ── 128-bit helpers (32-bit halves; no __int128 — -Wpedantic) ────────────

struct U128 {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
};

// Full unsigned 64×64 -> 128 product via four 32-bit partial products.
U128 mul_u64(std::uint64_t a, std::uint64_t b) {
    const std::uint64_t al = a & kMask32, ah = a >> 32;
    const std::uint64_t bl = b & kMask32, bh = b >> 32;
    const std::uint64_t ll = al * bl;
    const std::uint64_t lh = al * bh;
    const std::uint64_t hl = ah * bl;
    const std::uint64_t hh = ah * bh;
    const std::uint64_t mid = lh + hl;
    const bool mid_carry = mid < lh;
    // lo = ll + (mid << 32)
    const std::uint64_t lo = ll + (mid << 32);
    const bool lo_carry = lo < ll;
    std::uint64_t hi = hh + (mid >> 32) + (mid_carry ? (1ull << 32) : 0) +
                       (lo_carry ? 1ull : 0);
    return U128{lo, hi};
}

inline std::uint64_t mul_full(std::uint64_t a, std::uint64_t b) {
    return mul_u64(a, b).lo;   // low 64 bits of the product
}
inline std::uint64_t mul_hi(std::uint64_t a, std::uint64_t b) {
    return mul_u64(a, b).hi;   // high 64 bits of the product
}

inline U128 u128_negate(U128 v) {
    const std::uint64_t lo = 0 - v.lo;
    const std::uint64_t borrow = v.lo != 0 ? 1ull : 0ull;
    return U128{lo, 0 - v.hi - borrow};
}

// Signed 64×64 -> 128 product: magnitude multiply + sign fixup.
U128 smul64(std::int64_t a, std::int64_t b) {
    const bool neg = (a < 0) != (b < 0);
    const std::uint64_t ma = a < 0 ? (0 - static_cast<std::uint64_t>(a)) : static_cast<std::uint64_t>(a);
    const std::uint64_t mb = b < 0 ? (0 - static_cast<std::uint64_t>(b)) : static_cast<std::uint64_t>(b);
    const U128 p = mul_u64(ma, mb);
    if (!neg) return p;
    // Negate p (two's complement over 128 bits).
    return u128_negate(p);
}

inline U128 u128_from_halves(std::uint64_t lo, std::uint64_t hi) {
    return U128{lo, hi};
}

// Unsigned 128 / 64 -> quotient (divisor != 0; assumes divisor > 0 and the
// quotient's high word is 0 when inputs are in range for DIV semantics).
U128 u128_div_u64(U128 n, std::uint64_t d) {
    // Long division over 64 bits, bit by bit: 128 iterations, no UB.
    U128 q{0, 0};
    std::uint64_t rem = 0;
    for (int i = 127; i >= 0; --i) {
        // rem = rem << 1 | bit i of n (check rem < d before subtracting).
        const bool carry = (rem >> 63) != 0;
        rem = (rem << 1) | ((i >= 64 ? (n.hi >> (i - 64)) : (n.lo >> i)) & 1ull);
        if (carry || rem >= d) {
            rem -= d;
            if (i >= 64) q.hi |= (1ull << (i - 64));
            else q.lo |= (1ull << i);
        }
    }
    return q;
}

inline std::uint64_t u128_mod_u64(U128 n, std::uint64_t d) {
    std::uint64_t rem = 0;
    for (int i = 127; i >= 0; --i) {
        const bool carry = (rem >> 63) != 0;
        rem = (rem << 1) | ((i >= 64 ? (n.hi >> (i - 64)) : (n.lo >> i)) & 1ull);
        if (carry || rem >= d) rem -= d;
    }
    return rem;
}

}  // namespace

// ── public helpers ──────────────────────────────────────────────────────────

std::uint64_t read_gpr(const CpuState& c, std::uint8_t reg, std::uint8_t bits,
                        bool rex_encoded) {
    const std::uint8_t r = static_cast<std::uint8_t>(reg & 0xFu);
    const std::uint64_t slot = read_slot(c, r);
    if (bits == 8 && !rex_encoded && r >= 4 && r <= 7) {
        return (slot >> 8) & kMask8;   // AH/CH/DH/BH
    }
    return slot & width_mask(bits);
}

void write_gpr(CpuState& c, std::uint8_t reg, std::uint8_t bits,
               std::uint64_t value, bool rex_encoded) {
    const std::uint8_t r = static_cast<std::uint8_t>(reg & 0xFu);
    if (bits == 8 && !rex_encoded && r >= 4 && r <= 7) {
        // AH/CH/DH/BH: merge into the high byte of slot r&3.
        const std::uint8_t base = static_cast<std::uint8_t>(r & 0x3u);
        const std::uint64_t slot = read_slot(c, base);
        c.gprs[base] = (slot & ~0xFF00ull) | ((value & kMask8) << 8);
        return;
    }
    switch (bits) {
        case 8: c.gprs[r] = (read_slot(c, r) & ~kMask8) | (value & kMask8); break;
        case 16: c.gprs[r] = (read_slot(c, r) & ~kMask16) | (value & kMask16); break;
        case 32: c.gprs[r] = value & kMask32; break;   // zero-extends
        default: c.gprs[r] = value; break;
    }
}

std::uint64_t Value::sign_extended() const {
    if (bits >= 64) return raw;
    const std::uint64_t m = (1ull << bits) - 1u;
    const std::uint64_t v = raw & m;
    return (v & (1ull << (bits - 1))) != 0 ? (~m | v) : v;
}

// ── the engine ─────────────────────────────────────────────────────────────

bool Interpreter::supports(Mnemonic m) {
    switch (m) {
        case Mnemonic::Add: case Mnemonic::Or: case Mnemonic::Adc:
        case Mnemonic::Sbb: case Mnemonic::And: case Mnemonic::Sub:
        case Mnemonic::Xor: case Mnemonic::Cmp: case Mnemonic::Test:
        case Mnemonic::Inc: case Mnemonic::Dec: case Mnemonic::Neg:
        case Mnemonic::Not: case Mnemonic::Mul: case Mnemonic::Imul:
        case Mnemonic::Div: case Mnemonic::Idiv:
        case Mnemonic::Mov:   // register/immediate forms (fixtures + programs)
        case Mnemonic::Jmp: case Mnemonic::Jcc: case Mnemonic::Call:
        case Mnemonic::Ret: case Mnemonic::Loop: case Mnemonic::Loope:
        case Mnemonic::Loopne: case Mnemonic::Jrcxz:
        case Mnemonic::Cmovcc: case Mnemonic::Setcc:
            return true;    // §3A control flow
        case Mnemonic::Movzx: case Mnemonic::Movsx: case Mnemonic::Movsxd:
        case Mnemonic::Lea: case Mnemonic::Xchg:
            return true;    // §3C data movement
        case Mnemonic::Shl: case Mnemonic::Shr: case Mnemonic::Sar:
        case Mnemonic::Rol: case Mnemonic::Ror: case Mnemonic::Rcl:
        case Mnemonic::Rcr: case Mnemonic::Bt: case Mnemonic::Bts:
        case Mnemonic::Btr: case Mnemonic::Btc:
            return true;    // §3D shifts / bit ops
        case Mnemonic::Push: case Mnemonic::Pop: case Mnemonic::Pushf:
        case Mnemonic::Popf: case Mnemonic::Clc: case Mnemonic::Stc:
        case Mnemonic::Cmc: case Mnemonic::Cld: case Mnemonic::Std:
        case Mnemonic::Cbw: case Mnemonic::Cwd: case Mnemonic::Leave:
            return true;    // §5 stack/flags/conversions
        default:
            return false;   // SIMD/x87/atomic/privileged stay unsupported
    }
}

x64::DecodeResult Interpreter::decode_at_rip(StepFault* fault_out) const {
    std::uint8_t buf[x64::kMaxInstructionBytes] = {};
    const std::uint64_t rip = cpu_.rip;
    // Decode incrementally: fetch only bytes the decoder actually needs.
    // Every byte of an instruction must be executable, but bytes after the
    // decoded instruction must not be fetched (they may be in an NX page).
    for (std::size_t n = 0; n < x64::kMaxInstructionBytes; ++n) {
        if (rip > (~0ull) - n) {
            if (fault_out != nullptr) {
                fault_out->fault = GuestFault::InvalidAccess;
                fault_out->fault_rip = rip;
                fault_out->fault_address = rip;
                fault_out->detail = "instruction fetch address overflow";
            }
            return x64::decode(buf, n, rip);
        }
        const std::uint64_t address = rip + n;
        const auto exec = mem_.validate_exec(address);
        if (!exec.ok()) {
            if (fault_out != nullptr) {
                fault_out->fault =
                    exec.err == guest::GuestMemErrc::PermissionDenied
                        ? GuestFault::PermissionExec
                        : GuestFault::InvalidAccess;
                fault_out->fault_rip = rip;
                fault_out->fault_address = address;
                fault_out->detail = "instruction fetch byte is not executable";
            }
            return x64::decode(buf, n, rip);
        }
        auto b = mem_.read_u8(address);
        if (!b.ok()) {
            if (fault_out != nullptr) {
                fault_out->fault = GuestFault::InvalidAccess;
                fault_out->fault_rip = rip;
                fault_out->fault_address = address;
                fault_out->detail = "instruction fetch read failed";
            }
            return x64::decode(buf, n, rip);
        }
        buf[n] = b.value();
        const auto decoded = x64::decode(buf, n + 1, rip);
        if (decoded.status != x64::DecodeStatus::Truncated) return decoded;
    }
    return x64::decode(buf, x64::kMaxInstructionBytes, rip);
}

StepResult Interpreter::step_at_rip() {
    // Exec permission first (read_u8 only proves read).
    auto x = mem_.validate_exec(cpu_.rip);
    if (!x.ok()) {
        GuestFault f = x.err == guest::GuestMemErrc::InvalidAddress
                           ? GuestFault::InvalidAccess
                           : GuestFault::PermissionExec;
        return StepResult::failed(StepFault{f, cpu_.rip, cpu_.rip,
                                             "instruction fetch (exec)"});
    }
    StepFault fetch_fault;
    const x64::DecodeResult r = decode_at_rip(&fetch_fault);
    if (r.status != x64::DecodeStatus::Ok) {
        // A required instruction byte can fault independently of the
        // decoder's Truncated status (e.g. an NX page boundary).
        if (!fetch_fault.detail.empty()) {
            return StepResult::failed(fetch_fault);
        }
        // Map the reject to a typed fault; RIP never advances.
        GuestFault f = GuestFault::UnsupportedInstruction;
        const char* why = "instruction rejected by the decoder";
        if (r.status == x64::DecodeStatus::Truncated) {
            f = GuestFault::InvalidAccess;
            why = "instruction fetch ran off mapped memory";
        } else if (r.status == x64::DecodeStatus::Invalid) {
            f = GuestFault::InvalidInstruction;
        }
        return StepResult::failed(StepFault{f, cpu_.rip, 0,
                                            std::string(why) + ": " + r.reason});
    }
    return step(r.ins);
}

StepResult Interpreter::step(const Decoded& ins) {
    if (!supports(ins.mnem)) {
        return StepResult::failed(
            StepFault{GuestFault::UnsupportedInstruction, cpu_.rip, 0,
                      std::string("semantic engine: ") + x64::mnemonic_name(ins.mnem) +
                          " is not implemented"});
    }
    Ctx cx{cpu_, mem_, ins, cpu_.rip, ins.rex != 0, StepFault{}, false};

    Value a, b;

    switch (ins.mnem) {
        // ── ADD/OR/ADC/SBB/AND/SUB/XOR/CMP/TEST ──────────────────────────
        case Mnemonic::Add: case Mnemonic::Or: case Mnemonic::Adc:
        case Mnemonic::Sbb: case Mnemonic::And: case Mnemonic::Sub:
        case Mnemonic::Xor: case Mnemonic::Cmp: {
            if (!read_operand(cx, ins.ops[0], a) || !read_operand(cx, ins.ops[1], b)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const std::uint64_t av = a.raw & m;
            const std::uint64_t bv = b.raw & m;
            std::uint64_t result = 0;
            bool cf = false, of = false;
            switch (ins.mnem) {
                case Mnemonic::Add:
                    result = (av + bv) & m;
                    cf = av > (m - bv);
                    of = ((~(av ^ bv) & (av ^ result)) & (1ull << (bits - 1))) != 0;
                    break;
                case Mnemonic::Adc: {
                    const std::uint64_t cin = cx.cpu.flag(cpu::kFlagCF) ? 1u : 0u;
                    const std::uint64_t limit = m - bv;
                    cf = av > limit || (cin != 0 && av == limit);
                    const std::uint64_t sum = av + bv + cin;
                    result = sum & m;
                    of = ((~(av ^ bv) & (av ^ result)) & (1ull << (bits - 1))) != 0;
                    break;
                }
                case Mnemonic::Sub:
                case Mnemonic::Cmp:
                    result = (av - bv) & m;
                    cf = av < bv;
                    of = (((av ^ bv) & (av ^ result)) & (1ull << (bits - 1))) != 0;
                    break;
                case Mnemonic::Sbb: {
                    const std::uint64_t cin = cx.cpu.flag(cpu::kFlagCF) ? 1u : 0u;
                    // borrow = av < bv, or av == bv with a borrow-in.
                    const bool borrow = av < bv || (av == bv && cin != 0);
                    result = (av - bv - cin) & m;
                    cf = borrow;
                    of = (((av ^ bv) & (av ^ result)) & (1ull << (bits - 1))) != 0;
                    break;
                }
                case Mnemonic::Or:  result = av | bv; cf = false; of = false; break;
                case Mnemonic::And: result = av & bv; cf = false; of = false; break;
                case Mnemonic::Xor: result = av ^ bv; cf = false; of = false; break;
                default: break;
            }
            // AF: undefined for AND/OR/XOR (left unchanged — documented);
            // for ADD/ADC/SUB/SBB/CMP it is the carry out of bit 3.
            if (ins.mnem == Mnemonic::Add || ins.mnem == Mnemonic::Adc ||
                ins.mnem == Mnemonic::Sub || ins.mnem == Mnemonic::Sbb ||
                ins.mnem == Mnemonic::Cmp) {
                const std::uint64_t cin =
                    (ins.mnem == Mnemonic::Adc || ins.mnem == Mnemonic::Sbb)
                        ? (cx.cpu.flag(cpu::kFlagCF) ? 1u : 0u)
                        : 0u;
                const std::uint64_t bits3 =
                    (ins.mnem == Mnemonic::Add || ins.mnem == Mnemonic::Adc)
                        ? ((av & 0xFull) + (bv & 0xFull) + cin)
                        : ((av & 0xFull) - (bv & 0xFull) - cin);
                cx.cpu.set_flag(cpu::kFlagAF, (bits3 & 0x10ull) != 0);
            }
            if (ins.mnem != Mnemonic::Cmp) {
                if (!write_operand(cx, dst_operand, result)) {
                    return StepResult::failed(cx.fail);
                }
            }
            cx.cpu.set_flag(cpu::kFlagCF, cf);
            cx.cpu.set_flag(cpu::kFlagOF, of);
            set_pf_zf_sf(cx.cpu, result, bits);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        case Mnemonic::Test: {
            if (!read_operand(cx, ins.ops[0], a) || !read_operand(cx, ins.ops[1], b)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t result = a.raw & b.raw;
            cx.cpu.set_flag(cpu::kFlagCF, false);
            cx.cpu.set_flag(cpu::kFlagOF, false);
            set_pf_zf_sf(cx.cpu, result, bits);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── INC/DEC: ADD/SUB 1 without touching CF ─────────────────────────
        case Mnemonic::Inc:
        case Mnemonic::Dec: {
            if (!read_operand(cx, ins.ops[0], a)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const std::uint64_t av = a.raw & m;
            const std::uint64_t result =
                ins.mnem == Mnemonic::Inc ? ((av + 1) & m) : ((av - 1) & m);
            const bool of = ins.mnem == Mnemonic::Inc
                                ? ((~(av ^ 1ull) & (av ^ result)) & (1ull << (bits - 1))) != 0
                                : (((av ^ 1ull) & (av ^ result)) & (1ull << (bits - 1))) != 0;
            const std::uint64_t nib =
                ins.mnem == Mnemonic::Inc ? ((av & 0xFull) + 1) : ((av & 0xFull) - 1);
            if (!write_operand(cx, ins.ops[0], result)) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.set_flag(cpu::kFlagOF, of);
            cx.cpu.set_flag(cpu::kFlagAF, (nib & 0x10ull) != 0);
            set_pf_zf_sf(cx.cpu, result, bits);
            // CF untouched (SDM: INC/DEC do not affect CF).
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── NEG/NOT ─────────────────────────────────────────────────────────
        case Mnemonic::Neg: {
            if (!read_operand(cx, ins.ops[0], a)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const std::uint64_t av = a.raw & m;
            const std::uint64_t result = (0 - av) & m;
            if (!write_operand(cx, ins.ops[0], result)) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.set_flag(cpu::kFlagCF, av != 0);
            cx.cpu.set_flag(cpu::kFlagOF, av == (1ull << (bits - 1)));
            cx.cpu.set_flag(cpu::kFlagAF, ((0 - (av & 0xFull)) & 0x10ull) != 0);
            set_pf_zf_sf(cx.cpu, result, bits);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Not: {
            if (!read_operand(cx, ins.ops[0], a)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint64_t m = width_mask(ins.ops[0].bits);
            const std::uint64_t result = (~a.raw) & m;
            if (!write_operand(cx, ins.ops[0], result)) {
                return StepResult::failed(cx.fail);
            }
            // No flags (SDM).
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── MUL/IMUL/DIV/IDIV ──────────────────────────────────────────────
        //
        // 128-bit products/quotients are computed with 32-bit half pairs
        // (unsigned __int128 trips -Wpedantic in this codebase).
        case Mnemonic::Mul: {
            if (!read_operand(cx, ins.ops[0], a)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const std::uint64_t av = read_gpr(cx.cpu, 0, bits, cx.rex) & m;   // RAX
            const std::uint64_t bv = a.raw & m;
            // unsigned product av*bv (fits in 64 bits unless both are huge)
            const std::uint64_t prod = mul_full(av, bv);
            if (bits == 8) {
                // The complete byte-product is AX. Writing AH separately
                // through the encoded byte-register path is wrong when a
                // REX prefix is present (register 4 would mean SPL).
                write_gpr(cx.cpu, 0, 16, prod & 0xFFFFull, cx.rex);
            } else if (bits == 16) {
                write_gpr(cx.cpu, 0, 16, prod & kMask16, cx.rex);             // AX
                write_gpr(cx.cpu, 2, 16, (prod >> 16) & kMask16, cx.rex);    // DX
            } else if (bits == 32) {
                write_gpr(cx.cpu, 0, 32, prod & kMask32, cx.rex);             // EAX
                write_gpr(cx.cpu, 2, 32, (prod >> 32) & kMask32, cx.rex);    // EDX
            } else {
                write_gpr(cx.cpu, 0, 64, prod, cx.rex);                       // RAX
                write_gpr(cx.cpu, 2, 64, mul_hi(av, bv), cx.rex);            // RDX
            }
            const std::uint64_t hi = bits == 64 ? mul_hi(av, bv) : (prod >> bits);
            set_muldiv_flags(cx.cpu, hi != 0, bits);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Imul: {
            if (ins.op_count >= 2) {
                // IMUL r, r/m:        dst = dst * src.
                // IMUL r, r/m, imm:   dst = src * imm (the destination's
                //                      prior value is NOT an input).
                Value dst, src, imm;
                if (!read_operand(cx, ins.ops[0], dst)) return StepResult::failed(cx.fail);
                if (!read_operand(cx, ins.ops[1], src)) return StepResult::failed(cx.fail);
                if (ins.op_count == 3) {
                    if (!read_operand(cx, ins.ops[2], imm)) return StepResult::failed(cx.fail);
                }
                const std::uint8_t bits = ins.ops[0].bits;
                // Factors are the sign-extended operand values; a 64-bit
                // C++ multiply could overflow (UB), so the 64-bit case goes
                // through the 128-bit signed helper. bits < 64 cannot
                // overflow int64 (sign-extended values are within range and
                // their product fits in int64 unless it overflows the width,
                // which the truncation check below detects exactly).
                bool overflow = false;
                std::uint64_t result64 = 0;
                if (bits == 64) {
                    const std::int64_t fa =
                        ins.op_count == 3
                            ? static_cast<std::int64_t>(Value{src.raw, bits}.sign_extended())
                            : static_cast<std::int64_t>(Value{dst.raw, bits}.sign_extended());
                    const std::int64_t fb =
                        ins.op_count == 3
                            ? static_cast<std::int64_t>(Value{imm.raw, imm.bits}.sign_extended())
                            : static_cast<std::int64_t>(Value{src.raw, bits}.sign_extended());
                    const U128 p = smul64(fa, fb);
                    result64 = p.lo;
                    // Fits iff the high half is a sign extension of bit 63.
                    const std::uint64_t sign_ext =
                        (p.lo >> 63) != 0 ? ~0ull : 0ull;
                    overflow = p.hi != sign_ext;
                } else {
                    const std::int64_t fa =
                        ins.op_count == 3
                            ? static_cast<std::int64_t>(Value{src.raw, bits}.sign_extended())
                            : static_cast<std::int64_t>(Value{dst.raw, bits}.sign_extended());
                    const std::int64_t fb =
                        ins.op_count == 3
                            ? static_cast<std::int64_t>(Value{imm.raw, imm.bits}.sign_extended())
                            : static_cast<std::int64_t>(Value{src.raw, bits}.sign_extended());
                    const std::int64_t product = fa * fb;   // |fa|,|fb| < 2^32: safe
                    result64 = static_cast<std::uint64_t>(product) & width_mask(bits);
                    const std::int64_t trunc =
                        static_cast<std::int64_t>(Value{result64, bits}.sign_extended());
                    overflow = trunc != product;
                }
                write_gpr(cx.cpu, ins.ops[0].reg, bits, result64, cx.rex);
                set_muldiv_flags(cx.cpu, overflow, bits);
                cx.cpu.rip += ins.length;
                return StepResult::success();
            }
            // One-operand form: RDX:RAX = RAX * r/m.
            if (!read_operand(cx, ins.ops[0], a)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const std::int64_t av = static_cast<std::int64_t>(Value{read_gpr(cx.cpu, 0, bits, cx.rex) & m, bits}.sign_extended());
            const std::int64_t bv = static_cast<std::int64_t>(Value{a.raw & m, bits}.sign_extended());
            bool overflow = false;
            if (bits == 8) {
                const std::int64_t product = av * bv;
                write_gpr(cx.cpu, 0, 16, static_cast<std::uint64_t>(product) & kMask16, cx.rex);
                const std::int64_t trunc8 =
                    static_cast<std::int64_t>(Value{static_cast<std::uint64_t>(product) &
                                                     kMask16, 8}
                                                      .sign_extended());
                overflow = trunc8 != product;
            } else if (bits == 16) {
                const std::int64_t product = av * bv;
                write_gpr(cx.cpu, 0, 16, static_cast<std::uint64_t>(product) & kMask16, cx.rex);
                write_gpr(cx.cpu, 2, 16, (static_cast<std::uint64_t>(product) >> 16) & kMask16, cx.rex);
                const std::int64_t trunc16 =
                    static_cast<std::int64_t>(Value{static_cast<std::uint64_t>(product) &
                                                     kMask16, 16}
                                                      .sign_extended());
                overflow = trunc16 != product;
            } else if (bits == 32) {
                const std::int64_t product = av * bv;   // |av|,|bv| < 2^31: product < 2^62
                write_gpr(cx.cpu, 0, 32, static_cast<std::uint64_t>(product) & kMask32, cx.rex);
                write_gpr(cx.cpu, 2, 32, (static_cast<std::uint64_t>(product) >> 32) & kMask32, cx.rex);
                const std::int64_t trunc32 =
                    static_cast<std::int64_t>(Value{static_cast<std::uint64_t>(product) &
                                                     kMask32, 32}
                                                      .sign_extended());
                overflow = trunc32 != product;
            } else {
                const U128 p = smul64(av, bv);
                write_gpr(cx.cpu, 0, 64, p.lo, cx.rex);
                write_gpr(cx.cpu, 2, 64, p.hi, cx.rex);
                const std::uint64_t sign_ext = (p.lo >> 63) != 0 ? ~0ull : 0ull;
                overflow = p.hi != sign_ext;
            }
            set_muldiv_flags(cx.cpu, overflow, bits);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Div:
        case Mnemonic::Idiv: {
            if (!read_operand(cx, ins.ops[0], a)) {
                return StepResult::failed(cx.fail);
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const bool signed_div = ins.mnem == Mnemonic::Idiv;
            // dividend: RDX:RAX (width-sized halves)
            std::uint64_t dividend = 0;
            std::uint64_t divisor = a.raw & m;
            if (bits == 8) {
                dividend = read_gpr(cx.cpu, 0, 16, cx.rex);                   // AX
            } else if (bits == 64) {
                // The 64-bit path reads RDX:RAX halves directly below;
                // building 'hi << 64' here would be UB for no consumer.
                dividend = 0;
            } else {
                const std::uint64_t lo = read_gpr(cx.cpu, 0, bits, cx.rex) & m;
                const std::uint64_t hi_reg = read_gpr(cx.cpu, 2, bits, cx.rex) & m;
                dividend = lo | (hi_reg << bits);   // 2*bits value
            }
            if (divisor == 0 && !signed_div) {
                return StepResult::failed(
                    StepFault{GuestFault::DivideError, cx.start_rip, 0, "DIV by zero"});
            }
            if (!signed_div) {
                if (bits == 8) {
                    if (divisor == 0 || dividend / divisor > 0xFFull) {
                        return StepResult::failed(StepFault{
                            GuestFault::DivideError, cx.start_rip, 0,
                            "DIV quotient overflow"});
                    }
                    const std::uint64_t q = dividend / divisor;
                    const std::uint64_t r = dividend % divisor;
                    // Byte DIV returns quotient:AL and remainder:AH. Store
                    // AX as one 16-bit result so a REX prefix cannot turn
                    // the implicit AH destination into SPL.
                    write_gpr(cx.cpu, 0, 16,
                              (q & 0xFFull) | ((r & 0xFFull) << 8), cx.rex);
                } else if (bits == 16) {
                    if (divisor == 0 || dividend / divisor > kMask16) {
                        return StepResult::failed(StepFault{
                            GuestFault::DivideError, cx.start_rip, 0,
                            "DIV quotient overflow"});
                    }
                    write_gpr(cx.cpu, 0, 16, dividend / divisor, cx.rex);
                    write_gpr(cx.cpu, 2, 16, dividend % divisor, cx.rex);
                } else if (bits == 32) {
                    if (divisor == 0 || dividend / divisor > kMask32) {
                        return StepResult::failed(StepFault{
                            GuestFault::DivideError, cx.start_rip, 0,
                            "DIV quotient overflow"});
                    }
                    write_gpr(cx.cpu, 0, 32, dividend / divisor, cx.rex);
                    write_gpr(cx.cpu, 2, 32, dividend % divisor, cx.rex);
                } else {
                    const U128 n = u128_from_halves(read_gpr(cx.cpu, 0, 64, cx.rex),
                                                    read_gpr(cx.cpu, 2, 64, cx.rex));
                    if (divisor == 0) {
                        return StepResult::failed(
                            StepFault{GuestFault::DivideError, cx.start_rip, 0,
                                      "DIV by zero"});
                    }
                    const U128 q = u128_div_u64(n, divisor);
                    if (q.hi != 0) {
                        return StepResult::failed(StepFault{
                            GuestFault::DivideError, cx.start_rip, 0,
                            "DIV quotient overflow"});
                    }
                    write_gpr(cx.cpu, 0, 64, q.lo, cx.rex);
                    write_gpr(cx.cpu, 2, 64, u128_mod_u64(n, divisor), cx.rex);
                }
                // DIV: no flags defined.
                cx.cpu.rip += ins.length;
                return StepResult::success();
            }
            // IDIV: signed dividend/divisor, signed quotient/remainder.
            // signed dividend from halves; signed divisor from operand.
            const std::uint64_t smask = width_mask(bits);
            std::int64_t sdividend = 0;
            if (bits == 8) {
                sdividend = static_cast<std::int64_t>(
                    Value{read_gpr(cx.cpu, 0, 16, cx.rex) & kMask16, 16}.sign_extended());
            } else {
                // combine lo/hi halves as a 2*bits signed value
                const std::uint64_t lo = read_gpr(cx.cpu, 0, bits, cx.rex) & smask;
                const std::uint64_t hi = read_gpr(cx.cpu, 2, bits, cx.rex) & smask;
                if (bits == 64) {
                    // 128-bit signed dividend: compare as halves.
                    const bool negative = (hi >> 63) & 1ull;
                    const U128 n{lo, hi};
                    const std::int64_t sd =
                        static_cast<std::int64_t>(Value{a.raw & smask, bits}.sign_extended());
                    if (sd == 0) {
                        return StepResult::failed(
                            StepFault{GuestFault::DivideError, cx.start_rip, 0,
                                      "IDIV by zero"});
                    }
                    // Signed divide of a 128-bit dividend by a 64-bit divisor:
                    // handle via magnitude + sign.
                    U128 mag = n;
                    if (negative) mag = u128_negate(mag);
                    const bool div_neg = sd < 0;
                    const std::uint64_t smag = div_neg
                        ? static_cast<std::uint64_t>(-(sd + 1)) + 1ull
                        : static_cast<std::uint64_t>(sd);
                    if (smag == 0) {
                        return StepResult::failed(
                            StepFault{GuestFault::DivideError, cx.start_rip, 0,
                                      "IDIV by zero"});
                    }
                    const U128 q = u128_div_u64(mag, smag);
                    const std::uint64_t r = u128_mod_u64(mag, smag);
                    // quotient must fit in `bits` signed.
                    const std::uint64_t limit_hi =
                        (negative != div_neg)
                            ? (1ull << (bits - 1))   // negative limit: -2^(bits-1)
                            : (1ull << (bits - 1)) - 1ull;
                    if (q.hi != 0 || q.lo > limit_hi) {
                        return StepResult::failed(StepFault{
                            GuestFault::DivideError, cx.start_rip, 0,
                            "IDIV quotient overflow"});
                    }
                    std::uint64_t qout = q.lo;
                    std::uint64_t rout = r;
                    if (negative != div_neg) qout = (0 - qout) & smask;
                    if (negative) rout = (0 - rout) & smask;
                    write_gpr(cx.cpu, 0, bits, qout, cx.rex);
                    write_gpr(cx.cpu, 2, bits, rout, cx.rex);
                    cx.cpu.rip += ins.length;
                    return StepResult::success();
                }
                const std::uint64_t combined = lo | (hi << bits);
                sdividend = static_cast<std::int64_t>(Value{combined, static_cast<std::uint8_t>(bits * 2)}.sign_extended());
            }
            const std::int64_t sd =
                static_cast<std::int64_t>(Value{a.raw & smask, bits}.sign_extended());
            if (sd == 0) {
                return StepResult::failed(
                    StepFault{GuestFault::DivideError, cx.start_rip, 0, "IDIV by zero"});
            }
            if (sdividend == INT64_MIN && sd == -1) {
                return StepResult::failed(StepFault{GuestFault::DivideError, cx.start_rip, 0,
                                                    "IDIV quotient overflow"});
            }
            const std::int64_t q = sdividend / sd;
            const std::int64_t r = sdividend % sd;
            const std::uint64_t qlim =
                (1ull << (bits - 1)) - (q < 0 ? 0ull : 1ull);
            const std::uint64_t mag = q < 0 ? static_cast<std::uint64_t>(-(q + 1)) + 1ull
                                            : static_cast<std::uint64_t>(q);
            const bool in_range = mag <= qlim;
            if (!in_range) {
                return StepResult::failed(StepFault{GuestFault::DivideError, cx.start_rip, 0,
                                                    "IDIV quotient overflow"});
            }
            if (bits == 8) {
                // IDIV r/m8 writes AL quotient and AH remainder (AX).
                write_gpr(cx.cpu, 0, 16,
                          (static_cast<std::uint64_t>(q) & 0xFFull) |
                              ((static_cast<std::uint64_t>(r) & 0xFFull) << 8),
                          cx.rex);
            } else {
                write_gpr(cx.cpu, 0, bits, static_cast<std::uint64_t>(q) & smask, cx.rex);
                write_gpr(cx.cpu, 2, bits, static_cast<std::uint64_t>(r) & smask, cx.rex);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── §3A control flow ────────────────────────────────────────────────
        //
        // Branch targets are validated (exec permission) BEFORE the state
        // changes; a bad target faults and leaves the CPU untouched.
        // CALL pushes the return address; RET pops it (stack floor is the
        // engine's contract; here only memory validity is checked).

        case Mnemonic::Jmp: {
            // Direct rel8/32: ops[0] is Rel. Indirect: ops[0] is Reg/Mem.
            if (ins.ops[0].kind == x64::OpKind::Rel) {
                const std::uint64_t target = x64::branch_target(ins);
                if (!check_exec(cx, target)) return StepResult::failed(cx.fail);
                cx.cpu.rip = target;
                return StepResult::success();
            }
            Value t;
            if (!read_operand(cx, ins.ops[0], t)) return StepResult::failed(cx.fail);
            const std::uint64_t target = t.raw & width_mask(64);
            if (!check_exec(cx, target)) return StepResult::failed(cx.fail);
            cx.cpu.rip = target;
            return StepResult::success();
        }

        case Mnemonic::Jcc: {
            const std::uint64_t target = x64::branch_target(ins);
            if (x64::condition_holds(ins.cc, cx.cpu.rflags)) {
                if (!check_exec(cx, target)) return StepResult::failed(cx.fail);
                cx.cpu.rip = target;
            } else {
                cx.cpu.rip += ins.length;
            }
            return StepResult::success();
        }

        case Mnemonic::Loop:
        case Mnemonic::Loope:
        case Mnemonic::Loopne:
        case Mnemonic::Jrcxz: {
            const std::uint8_t cbits = ins.addr_size == 32 ? 32 : 64;
            const std::uint64_t rcx = read_gpr(cx.cpu, 1, cbits, cx.rex);
            const std::uint64_t next_rcx = (rcx - 1) & width_mask(cbits);
            bool decrement = false;
            bool taken = false;
            switch (ins.mnem) {
                case Mnemonic::Loop:
                    decrement = true;
                    taken = next_rcx != 0;
                    break;
                case Mnemonic::Loope:
                    decrement = true;
                    taken = next_rcx != 0 && cx.cpu.flag(cpu::kFlagZF);
                    break;
                case Mnemonic::Loopne:
                    decrement = true;
                    taken = next_rcx != 0 && !cx.cpu.flag(cpu::kFlagZF);
                    break;
                case Mnemonic::Jrcxz:
                    taken = rcx == 0;
                    break;
                default: break;
            }
            std::uint64_t target = 0;
            if (taken) {
                target = x64::branch_target(ins);
                if (!check_exec(cx, target)) return StepResult::failed(cx.fail);
            }
            if (decrement) write_gpr(cx.cpu, 1, cbits, next_rcx, cx.rex);
            cx.cpu.rip = taken ? target : cx.cpu.rip + ins.length;
            return StepResult::success();
        }

        case Mnemonic::Call: {
            const std::uint64_t ret_addr = cx.start_rip + ins.length;
            // Read the target (direct Rel or indirect Reg/Mem).
            std::uint64_t target = 0;
            if (ins.ops[0].kind == x64::OpKind::Rel) {
                target = x64::branch_target(ins);
            } else {
                Value t;
                if (!read_operand(cx, ins.ops[0], t)) return StepResult::failed(cx.fail);
                target = t.raw & width_mask(64);
            }
            if (!check_exec(cx, target)) return StepResult::failed(cx.fail);
            // Push the return address (RSP-8), then jump.
            if (!push_u64(cx, ret_addr)) return StepResult::failed(cx.fail);
            cx.cpu.rip = target;
            return StepResult::success();
        }

        case Mnemonic::Ret: {
            const std::uint64_t pop_extra =
                ins.op_count > 0 && ins.ops[0].kind == x64::OpKind::Imm
                    ? (ins.ops[0].imm & kMask16)
                    : 0;
            const std::uint8_t sp = static_cast<std::uint8_t>(Gpr::Sp);
            const std::uint64_t old_sp = cx.cpu.gprs[sp];
            const std::uint64_t adjustment = 8 + pop_extra;
            if (old_sp > (~0ull) - adjustment) {
                cx.abort(GuestFault::StackOverflow, "RET stack adjustment overflow", old_sp);
                return StepResult::failed(cx.fail);
            }
            auto ra = cx.mem.read_u64(old_sp);
            if (!ra.ok()) {
                cx.abort(GuestFault::InvalidAccess, "RET stack read", old_sp);
                return StepResult::failed(cx.fail);
            }
            if (!check_exec(cx, ra.value())) return StepResult::failed(cx.fail);
            cx.cpu.gprs[sp] = old_sp + adjustment;
            cx.cpu.rip = ra.value();
            return StepResult::success();
        }

        case Mnemonic::Cmovcc: {
            Value src;
            if (!read_operand(cx, ins.ops[1], src)) return StepResult::failed(cx.fail);
            if (x64::condition_holds(ins.cc, cx.cpu.rflags)) {
                // Destination gets the source only when the condition holds.
                const std::uint8_t bits = ins.ops[0].bits;
                if (!write_operand(cx, ins.ops[0], src.raw & width_mask(bits))) {
                    return StepResult::failed(cx.fail);
                }
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        case Mnemonic::Setcc: {
            const std::uint8_t value = x64::condition_holds(ins.cc, cx.cpu.rflags) ? 1 : 0;
            if (!write_operand(cx, ins.ops[0], value)) return StepResult::failed(cx.fail);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── §3C data movement ─────────────────────────────────────────────
        case Mnemonic::Movzx: {
            Value src;
            if (!read_operand(cx, ins.ops[1], src)) return StepResult::failed(cx.fail);
            const std::uint8_t bits = ins.ops[0].bits;
            if (!write_operand(cx, ins.ops[0], src.raw & width_mask(bits))) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Movsx:
        case Mnemonic::Movsxd: {
            Value src;
            if (!read_operand(cx, ins.ops[1], src)) return StepResult::failed(cx.fail);
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t value = src.sign_extended() & width_mask(bits);
            if (!write_operand(cx, ins.ops[0], value)) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Lea: {
            // The source operand must be memory; the EA itself is the value.
            if (ins.ops[1].kind != x64::OpKind::Mem) {
                cx.abort(GuestFault::InvalidInstruction, "LEA with a non-memory source");
                return StepResult::failed(cx.fail);
            }
            const std::uint64_t base_rip = cx.start_rip + cx.ins.length;
            const Ea ea = compute_ea(cx.cpu, ins.ops[1], base_rip);
            const std::uint8_t bits = ins.ops[0].bits;
            if (!write_operand(cx, ins.ops[0], ea.va & width_mask(bits))) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Xchg: {
            // Memory XCHG is implicitly locked. Hold the shared guest-memory
            // lock across both operand accesses so other interpreter threads
            // cannot observe an intermediate value.
            std::unique_lock<std::recursive_mutex> atomic_lock(
                g_guest_memory_mutex, std::defer_lock);
            if (ins.ops[0].kind == x64::OpKind::Mem ||
                ins.ops[1].kind == x64::OpKind::Mem) {
                atomic_lock.lock();
            }
            Value a_v, b_v;
            if (!read_operand(cx, ins.ops[0], a_v)) return StepResult::failed(cx.fail);
            if (!read_operand(cx, ins.ops[1], b_v)) return StepResult::failed(cx.fail);
            // XCHG writes both operands: order matters only if they alias
            // (XCHG r, r with the same register is a no-op).
            const bool same_reg = ins.ops[0].kind == x64::OpKind::Reg &&
                                  ins.ops[1].kind == x64::OpKind::Reg &&
                                  (ins.ops[0].reg & 0xFu) == (ins.ops[1].reg & 0xFu);
            if (!same_reg) {
                if (!write_operand(cx, ins.ops[0], b_v.raw & width_mask(ins.ops[0].bits))) {
                    return StepResult::failed(cx.fail);
                }
                if (!write_operand(cx, ins.ops[1], a_v.raw & width_mask(ins.ops[1].bits))) {
                    return StepResult::failed(cx.fail);
                }
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── §3D shifts / rotates / bit ops ─────────────────────────────────
        case Mnemonic::Shl: case Mnemonic::Shr: case Mnemonic::Sar:
        case Mnemonic::Rol: case Mnemonic::Ror: case Mnemonic::Rcl:
        case Mnemonic::Rcr: {
            Value dst;
            // ops[1] is the count: imm8, the literal 1, or CL (a Reg operand).
            std::uint64_t count = 0;
            if (ins.op_count < 2) {
                cx.abort(GuestFault::Internal, "shift without a count operand");
                return StepResult::failed(cx.fail);
            }
            if (!read_operand(cx, ins.ops[0], dst)) return StepResult::failed(cx.fail);
            if (ins.ops[1].kind == x64::OpKind::Imm) {
                count = ins.ops[1].imm;
            } else {
                Value cv;
                if (!read_operand(cx, ins.ops[1], cv)) return StepResult::failed(cx.fail);
                count = cv.raw;
            }
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t m = width_mask(bits);
            const std::uint64_t masked = count & (bits >= 64 ? 0x3Full : 0x1Full);
            std::uint64_t result = dst.raw & m;
            if (masked == 0) {
                // Count 0: no flags change, nothing written.
                cx.cpu.rip += ins.length;
                return StepResult::success();
            }
            switch (ins.mnem) {
                case Mnemonic::Shl: {
                    result = (masked >= bits) ? 0 : ((dst.raw << masked) & m);
                    break;
                }
                case Mnemonic::Shr: {
                    result = (masked >= bits) ? 0 : ((dst.raw & m) >> masked);
                    break;
                }
                case Mnemonic::Sar: {
                    const std::int64_t sv = static_cast<std::int64_t>(dst.sign_extended());
                    const std::uint64_t shift = masked >= 64 ? 63 : masked;
                    const std::int64_t sr = sv >> shift;
                    result = static_cast<std::uint64_t>(sr) & m;
                    break;
                }
                case Mnemonic::Rol: {
                    const std::uint64_t n = masked % bits;
                    if (n != 0) {
                        const std::uint64_t v = dst.raw & m;
                        result = ((v << n) | (v >> (bits - n))) & m;
                    }
                    break;
                }
                case Mnemonic::Ror: {
                    const std::uint64_t n = masked % bits;
                    if (n != 0) {
                        const std::uint64_t v = dst.raw & m;
                        result = ((v >> n) | (v << (bits - n))) & m;
                    }
                    break;
                }
                case Mnemonic::Rcl:
                case Mnemonic::Rcr: {
                    // Rotate through carry: the value extended by the CF bit
                    // is a (bits+1)-wide ring; a 64-bit operand makes that
                    // 65 bits, which does not fit a uint64 shift — rotate
                    // the ring one logical bit at a time instead.
                    const std::uint64_t n = masked % (bits + 1);
                    if (n != 0) {
                        std::uint64_t v = dst.raw & m;
                        bool carry = cx.cpu.flag(cpu::kFlagCF);
                        for (std::uint64_t k = 0; k < n; ++k) {
                            if (ins.mnem == Mnemonic::Rcl) {
                                const bool top = (v >> (bits - 1)) & 1ull;
                                v = (v << 1) & m;
                                const bool new_top = carry;
                                carry = top;
                                v |= new_top ? 1ull : 0ull;
                            } else {
                                const bool bot = v & 1ull;
                                v >>= 1;
                                const std::uint64_t top_bit = 1ull << (bits - 1);
                                v |= carry ? top_bit : 0ull;
                                carry = bot;
                            }
                        }
                        result = v;
                        cx.cpu.set_flag(cpu::kFlagCF, carry);
                    }
                    break;
                }
                default: break;
            }
            // Flags: CF = last bit shifted out; OF defined only for count 1
            // (shifts) / masked count 1 (rotates); SF/ZF/PF from the result;
            // AF undefined (left unchanged).
            if (ins.mnem == Mnemonic::Shl) {
                // CF = the last bit shifted out; count >= width -> the bits
                // above the field were all shifted out: CF = old bit
                // (width-1..0) chain, which for a >= width shift of a masked
                // value is 0 when masked > bits and the value's bit
                // (masked-bits-1)... keep it simple: CF = 0 (documented).
                if (masked <= bits) {
                    const bool cf = ((dst.raw >> (bits - masked)) & 1ull) != 0;
                    cx.cpu.set_flag(cpu::kFlagCF, cf);
                }
                if (masked == 1) {
                    const bool msb = sign_bit(result, bits) != 0;
                    cx.cpu.set_flag(cpu::kFlagOF, msb != cx.cpu.flag(cpu::kFlagCF));
                }
            } else if (ins.mnem == Mnemonic::Shr) {
                if (masked <= bits) {
                    const std::uint64_t last = (dst.raw >> (masked - 1)) & 1ull;
                    cx.cpu.set_flag(cpu::kFlagCF, last != 0);
                }
                if (masked == 1) {
                    cx.cpu.set_flag(cpu::kFlagOF, sign_bit(dst.raw & m, bits) != 0);
                }
            } else if (ins.mnem == Mnemonic::Sar) {
                if (masked <= bits) {
                    const std::uint64_t last = (dst.raw >> (masked - 1)) & 1ull;
                    cx.cpu.set_flag(cpu::kFlagCF, last != 0);
                }
                if (masked == 1) cx.cpu.set_flag(cpu::kFlagOF, false);
            } else if (ins.mnem == Mnemonic::Rol) {
                const std::uint64_t n = masked % bits;
                if (n != 0) {
                    cx.cpu.set_flag(cpu::kFlagCF, (result & 1ull) != 0);
                }
                // SDM: for count-1 ROL, OF = MSB(result) XOR CF.
                if (masked == 1) {
                    cx.cpu.set_flag(cpu::kFlagOF,
                                    (((result >> (bits - 1)) & 1ull) != 0) !=
                                    cx.cpu.flag(cpu::kFlagCF));
                }
            } else if (ins.mnem == Mnemonic::Ror) {
                const std::uint64_t n = masked % bits;
                if (n != 0) {
                    cx.cpu.set_flag(cpu::kFlagCF, ((result >> (bits - 1)) & 1ull) != 0);
                }
                // SDM: for count-1 ROR, OF = MSB(result) XOR bit(63/width-2)
                // of the result — i.e. the two top bits differ.
                if (masked == 1) {
                    cx.cpu.set_flag(cpu::kFlagOF, ((result >> (bits - 1)) & 1ull) !=
                                                    ((result >> (bits - 2)) & 1ull));
                }
            }
            if (ins.mnem == Mnemonic::Rcl && masked == 1) {
                // RCL: OF = MSB(result) XOR CF.
                cx.cpu.set_flag(cpu::kFlagOF,
                                (((result >> (bits - 1)) & 1ull) != 0) !=
                                    cx.cpu.flag(cpu::kFlagCF));
            } else if (ins.mnem == Mnemonic::Rcr && masked == 1) {
                // RCR: OF = XOR of the two most significant result bits.
                cx.cpu.set_flag(cpu::kFlagOF,
                                ((result >> (bits - 1)) & 1ull) !=
                                    ((result >> (bits - 2)) & 1ull));
            }
            set_pf_zf_sf(cx.cpu, result, bits);
            if (!write_operand(cx, ins.ops[0], result)) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        case Mnemonic::Bt: case Mnemonic::Bts: case Mnemonic::Btr:
        case Mnemonic::Btc: {
            Value pos;
            if (!read_operand(cx, ins.ops[1], pos)) return StepResult::failed(cx.fail);
            const std::uint8_t bits = ins.ops[0].bits;
            Operand dst_operand = ins.ops[0];
            std::uint64_t bit = pos.raw % bits;
            if (dst_operand.kind == x64::OpKind::Mem &&
                ins.ops[1].kind == x64::OpKind::Reg) {
                // For a memory bit string, the signed register index selects
                // a word relative to the effective address, not merely a bit
                // within the first word.
                const std::int64_t index = static_cast<std::int64_t>(pos.sign_extended());
                std::int64_t word = index / static_cast<std::int64_t>(bits);
                std::int64_t rem = index % static_cast<std::int64_t>(bits);
                if (rem < 0) { rem += bits; --word; }
                const std::int64_t byte_delta =
                    word * static_cast<std::int64_t>(bits / 8u);
                if ((byte_delta > 0 &&
                     dst_operand.disp > INT64_MAX - byte_delta) ||
                    (byte_delta < 0 &&
                     dst_operand.disp < INT64_MIN - byte_delta)) {
                    cx.abort(GuestFault::InvalidAccess,
                             "memory bit-string address overflow");
                    return StepResult::failed(cx.fail);
                }
                dst_operand.disp += byte_delta;
                bit = static_cast<std::uint64_t>(rem);
            }
            Value dst;
            if (!read_operand(cx, dst_operand, dst)) return StepResult::failed(cx.fail);
            const std::uint64_t m = width_mask(bits);
            const bool was = ((dst.raw >> bit) & 1ull) != 0;
            std::uint64_t result = dst.raw & m;
            switch (ins.mnem) {
                case Mnemonic::Bts: result |= (1ull << bit); break;
                case Mnemonic::Btr: result &= ~(1ull << bit); break;
                case Mnemonic::Btc: result ^= (1ull << bit); break;
                case Mnemonic::Bt: break;
                default: break;
            }
            if (ins.mnem != Mnemonic::Bt) {
                if (!write_operand(cx, dst_operand, result)) {
                    return StepResult::failed(cx.fail);
                }
            }
            cx.cpu.set_flag(cpu::kFlagCF, was);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── §5 stack / flags / conversions ────────────────────────────────
        case Mnemonic::Push: {
            // PUSH r64 / r/m64 / imm8(sign-extended) / imm32(sign-extended).
            Value src;
            if (!read_operand(cx, ins.ops[0], src)) return StepResult::failed(cx.fail);
            std::uint64_t value = src.raw;
            if (ins.ops[0].kind == x64::OpKind::Imm) {
                value = src.sign_extended();
            }
            if (!push_u64(cx, value)) return StepResult::failed(cx.fail);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Pop: {
            // POP computes a memory destination using the incremented RSP,
            // but a failed destination write must not leave RSP changed.
            const CpuState before = cx.cpu;
            Value v;
            if (!pop_u64(cx, v)) return StepResult::failed(cx.fail);
            if (!write_operand(cx, ins.ops[0], v.raw & width_mask(ins.ops[0].bits))) {
                cx.cpu = before;
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Pushf: {
            // PUSHFQ pushes RFLAGS (bit 1 is fixed to 1 in the model).
            if (!push_u64(cx, cx.cpu.rflags | cpu::kFlagFixed1)) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Popf: {
            Value v;
            if (!pop_u64(cx, v)) return StepResult::failed(cx.fail);
            // POPFQ loads RFLAGS: bit 1 stays fixed; the value is masked to
            // the architectural bits the model tracks (no trap-model TF/IF).
            const std::uint64_t mask = 0x0FD7ull;   // CF..OF + DF + fixed
            cx.cpu.rflags = (v.raw & mask) | cpu::kFlagFixed1;
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Clc: case Mnemonic::Stc: case Mnemonic::Cmc: {
            const bool old_cf = cx.cpu.flag(cpu::kFlagCF);
            bool new_cf = old_cf;
            switch (ins.mnem) {
                case Mnemonic::Clc: new_cf = false; break;
                case Mnemonic::Stc: new_cf = true; break;
                case Mnemonic::Cmc: new_cf = !old_cf; break;
                default: break;
            }
            cx.cpu.set_flag(cpu::kFlagCF, new_cf);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Cld: case Mnemonic::Std: {
            cx.cpu.set_flag(cpu::kFlagDF, ins.mnem == Mnemonic::Std);
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Cbw:
        case Mnemonic::Cwd: {
            // 98: the SOURCE width is half the operand size: AL->AX (66),
            // AX->EAX (32), EAX->RAX (64). 99: sign of the operand-size
            // value goes to the double-width high register.
            const std::uint8_t os = ins.op_size >= 64 ? 64 : ins.op_size;
            const std::uint8_t src_bits =
                static_cast<std::uint8_t>(os / 2);   // 16->8, 32->16, 64->32
            // CDQ/CQO (99): the sign comes from the FULL operand-size
            // value (EAX/RAX), not from a half-width read.
            const std::uint64_t v = read_gpr(cx.cpu, 0, os, cx.rex);
            if (ins.mnem == Mnemonic::Cbw) {
                // CBW/CWDE (98): the source is the half-width low part.
                const std::uint64_t half = read_gpr(cx.cpu, 0, src_bits, cx.rex);
                write_gpr(cx.cpu, 0, os, Value{half, src_bits}.sign_extended(), cx.rex);
            } else {
                const std::uint64_t sign = sign_bit(v, os) ? ~0ull : 0ull;
                write_gpr(cx.cpu, 2, os, sign & width_mask(os), cx.rex);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }
        case Mnemonic::Leave: {
            const std::uint8_t sp = static_cast<std::uint8_t>(Gpr::Sp);
            const std::uint8_t bp = static_cast<std::uint8_t>(Gpr::Bp);
            const std::uint64_t frame_sp = cx.cpu.gprs[bp];
            if (frame_sp > (~0ull) - 8) {
                cx.abort(GuestFault::StackOverflow, "LEAVE stack adjustment overflow", frame_sp);
                return StepResult::failed(cx.fail);
            }
            auto saved_bp = cx.mem.read_u64(frame_sp);
            if (!saved_bp.ok()) {
                cx.abort(GuestFault::InvalidAccess, "LEAVE stack read", frame_sp);
                return StepResult::failed(cx.fail);
            }
            cx.cpu.gprs[sp] = frame_sp + 8;
            cx.cpu.gprs[bp] = saved_bp.value();
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        // ── MOV (register/immediate/memory forms; no flags) ───────────────
        case Mnemonic::Mov: {
            if (!read_operand(cx, ins.ops[0], a) || !read_operand(cx, ins.ops[1], b)) {
                return StepResult::failed(cx.fail);
            }
            // Source width may differ (MOVZX-style asymmetry is a separate
            // mnemonic; MOV r/m <- imm8 on a 32-bit op is sign-neutral):
            // the destination width decides what is stored.
            const std::uint8_t bits = ins.ops[0].bits;
            const std::uint64_t value =
                ins.ops[1].kind == x64::OpKind::Imm && ins.ops[1].bits < bits
                    ? (b.sign_extended() & width_mask(bits))
                    : (b.raw & width_mask(bits));
            if (!write_operand(cx, ins.ops[0], value)) {
                return StepResult::failed(cx.fail);
            }
            cx.cpu.rip += ins.length;
            return StepResult::success();
        }

        default:
            return StepResult::failed(
                StepFault{GuestFault::UnsupportedInstruction, cpu_.rip, 0,
                          std::string("semantic engine: ") + x64::mnemonic_name(ins.mnem) +
                              " is not implemented yet"});
    }
}

}  // namespace xbox2pc::rt::x86
