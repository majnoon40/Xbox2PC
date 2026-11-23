// xbox2pc/x64_decoder.cpp — M9 structured x86-64 decoder implementation.
//
// Decode order (docs/instruction-decoder.md):
//   legacy prefixes -> REX (applies only as the last prefix) -> map byte
//   -> opcode class -> ModRM/SIB/displacement -> immediates -> validity
//   checks (REP, 16-bit stack/branch sizes, LOCK).
// Every reject carries a class so callers can distinguish "never valid"
// (Invalid) from "valid but not interpreted" (Unsupported).

#include "xbox2pc/x64_decoder.hpp"

#include <cstdio>

namespace xbox2pc::rt::x64 {

namespace {

struct Fail {
    RejectClass cls = RejectClass::None;
    const char* reason = "";
};

constexpr std::uint8_t imm_bits_for(std::uint8_t op_size) {
    return op_size == 64u ? 32u : op_size;   // 64-bit operands take imm32
}

// ALU opcode groups 0..7 (opcodes x0..x5 and 80/81/83 digits).
constexpr Mnemonic kAlu[8] = {
    Mnemonic::Add, Mnemonic::Or,  Mnemonic::Adc, Mnemonic::Sbb,
    Mnemonic::And, Mnemonic::Sub, Mnemonic::Xor, Mnemonic::Cmp,
};

// Group 2 (shifts/rotates), digits 0..5 and 7; digit 6 is not defined.
constexpr Mnemonic kShift[8] = {
    Mnemonic::Rol,  Mnemonic::Ror, Mnemonic::Rcl, Mnemonic::Rcr,
    Mnemonic::Shl,  Mnemonic::Shr, Mnemonic::Invalid, Mnemonic::Sar,
};

// Group 3 (F6/F7): TEST uses /0 only.
constexpr Mnemonic kGroup3[8] = {
    Mnemonic::Test, Mnemonic::Invalid, Mnemonic::Not,  Mnemonic::Neg,
    Mnemonic::Mul,  Mnemonic::Imul,    Mnemonic::Div,  Mnemonic::Idiv,
};

// 0F BA /4../7.
constexpr Mnemonic kBtImm[8] = {
    Mnemonic::Invalid, Mnemonic::Invalid, Mnemonic::Invalid, Mnemonic::Invalid,
    Mnemonic::Bt,      Mnemonic::Bts,     Mnemonic::Btr,     Mnemonic::Btc,
};

bool is_16bit_stack_or_branch(Mnemonic m) {
    switch (m) {
        case Mnemonic::Push: case Mnemonic::Pop: case Mnemonic::Pushf:
        case Mnemonic::Popf: case Mnemonic::Call: case Mnemonic::Jmp:
        case Mnemonic::Jcc: case Mnemonic::Ret: case Mnemonic::Loop:
        case Mnemonic::Loope: case Mnemonic::Loopne: case Mnemonic::Jrcxz:
        case Mnemonic::Leave:
            return true;
        default:
            return false;
    }
}

// Instructions for which a LOCK prefix is architecturally permitted (the
// decoder still rejects them: atomics are not interpreted).
bool is_rmw(Mnemonic m) {
    switch (m) {
        case Mnemonic::Add: case Mnemonic::Or: case Mnemonic::Adc:
        case Mnemonic::Sbb: case Mnemonic::And: case Mnemonic::Sub:
        case Mnemonic::Xor: case Mnemonic::Inc: case Mnemonic::Dec:
        case Mnemonic::Neg: case Mnemonic::Not: case Mnemonic::Xchg:
        case Mnemonic::Bt: case Mnemonic::Bts: case Mnemonic::Btr:
        case Mnemonic::Btc:
            return true;
        default:
            return false;
    }
}

std::uint64_t read_le(const std::uint8_t* p, std::uint8_t bytes) {
    std::uint64_t v = 0;
    for (std::uint8_t k = 0; k < bytes; ++k) {
        v |= static_cast<std::uint64_t>(p[k]) << (8u * k);
    }
    return v;
}

// Shift/rotate count before masking, read from the count operand the decoder
// stores in ops[1]: Imm 1 (D0/D1), Reg CL (D2/D3) or Imm imm8 (C0/C1).
std::uint64_t shift_count_of(const Decoded& d, const std::uint64_t* gprs) {
    if (d.op_count < 2) return 0;
    const Operand& c = d.ops[1];
    if (c.kind == OpKind::Imm) return c.imm;
    if (c.kind == OpKind::Reg) return gprs != nullptr ? gprs[c.reg & 0xFu] : 0;
    return 0;
}

std::string hex_text(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

}  // namespace

// ── the decoder ───────────────────────────────────────────────────────────

DecodeResult decode(const std::uint8_t* data, std::size_t len, std::uint64_t rip) {
    DecodeResult res;
    Decoded d;
    d.rip = rip;
    Fail f;
    std::size_t i = 0;

    auto finish_bad = [&]() -> DecodeResult {
        DecodeStatus st;
        switch (f.cls) {
            case RejectClass::NeedMoreBytes:
                st = DecodeStatus::Truncated;
                break;
            case RejectClass::TooLong:
            case RejectClass::BadOpcode:
            case RejectClass::BadOperandSize:
            case RejectClass::BadModRm:
            case RejectClass::BadPrefix:
                st = DecodeStatus::Invalid;
                break;
            default:
                st = DecodeStatus::Unsupported;
                break;
        }
        res.status = st;
        res.reject = f.cls;
        res.reason = f.reason;
        res.consumed = static_cast<std::uint8_t>(i);
        return res;
    };
    auto set_bad = [&](RejectClass cls, const char* why) {
        f = Fail{cls, why};
    };
    // `k` more bytes must exist in the buffer AND inside the 15-byte limit.
    auto need = [&](std::size_t k) -> bool {
        if (k > len - i) {
            set_bad(RejectClass::NeedMoreBytes,
                    "instruction truncated: buffer ends inside the instruction");
            return false;
        }
        if (i + k > kMaxInstructionBytes) {
            set_bad(RejectClass::TooLong, "instruction exceeds the 15-byte architectural limit");
            return false;
        }
        return true;
    };

    if (data == nullptr || len == 0) {
        i = 0;
        set_bad(RejectClass::NeedMoreBytes, "empty instruction buffer");
        return finish_bad();
    }

    // ── 1. prefixes ────────────────────────────────────────────────────
    bool p66 = false, p67 = false, pf2 = false, pf3 = false, lock = false;
    std::uint8_t rex = 0;
    Segment seg = Segment::None;
    bool at_opcode = false;
    while (!at_opcode) {
        if (i >= kMaxInstructionBytes) {
            set_bad(RejectClass::TooLong, "instruction exceeds the 15-byte architectural limit");
            return finish_bad();
        }
        if (i >= len) {
            set_bad(RejectClass::NeedMoreBytes, "instruction truncated: prefixes reach the end of the buffer");
            return finish_bad();
        }
        const std::uint8_t b = data[i];
        if (b >= 0x40 && b <= 0x4F) {
            // REX applies only as the LAST prefix before the opcode; a
            // later legacy prefix drops it, a later REX replaces it.
            rex = b;
            ++i;
            continue;
        }
        switch (b) {
            case 0x66: p66 = true; break;
            case 0x67: p67 = true; break;
            case 0xF0: lock = true; break;
            case 0xF2: pf2 = true; break;
            case 0xF3: pf3 = true; break;
            case 0x2E: seg = Segment::Cs; break;
            case 0x36: seg = Segment::Ss; break;
            case 0x3E: seg = Segment::Ds; break;
            case 0x26: seg = Segment::Es; break;
            case 0x64: seg = Segment::Fs; break;
            case 0x65: seg = Segment::Gs; break;
            default: at_opcode = true; break;
        }
        if (at_opcode) break;
        rex = 0;   // legacy prefix after a REX drops the REX
        ++i;
    }

    // ── 2. map byte(s) ─────────────────────────────────────────────────
    std::uint8_t op = data[i];
    ++i;
    if (op == 0x0F) {
        d.map = 1;
        if (!need(1)) return finish_bad();
        op = data[i];
        ++i;
        if (op == 0x38 || op == 0x3A) {
            set_bad(RejectClass::UnsupportedMap, "three-byte opcode map (0F 38 / 0F 3A) is not decoded");
            return finish_bad();
        }
    }
    d.opcode = op;
    d.rex = rex;
    d.has_66 = p66;
    d.has_67 = p67;
    d.has_f2 = pf2;
    d.has_f3 = pf3;
    d.has_lock = lock;
    d.op_size = (rex & 0x08u) != 0 ? 64u : (p66 ? 16u : 32u);
    d.addr_size = p67 ? 32u : 64u;
    const std::uint8_t os = d.op_size;
    const std::uint8_t rex_r = static_cast<std::uint8_t>((rex >> 2) & 0x1u);
    const std::uint8_t rex_x = static_cast<std::uint8_t>((rex >> 1) & 0x1u);
    const std::uint8_t rex_b = static_cast<std::uint8_t>(rex & 0x1u);
    const unsigned lo = op & 0xFu;

    // ── 3. operand builders ────────────────────────────────────────────
    std::uint8_t mod = 0, reg3 = 0, rm3 = 0;   // raw ModRM fields
    Operand a;

    auto push = [&](const Operand& o) {
        if (d.op_count < 3) {
            d.ops[d.op_count] = o;
            ++d.op_count;
        }
    };
    auto reg_op = [&](std::uint8_t bits, std::uint8_t r) {
        Operand o;
        o.kind = OpKind::Reg;
        o.bits = bits;
        o.reg = r;
        return o;
    };
    auto reg_field = [&]() {
        return static_cast<std::uint8_t>(reg3 | static_cast<std::uint8_t>(rex_r << 3));
    };
    auto rm_field = [&]() {
        return static_cast<std::uint8_t>(rm3 | static_cast<std::uint8_t>(rex_b << 3));
    };
    auto read_modrm = [&]() -> bool {
        if (!need(1)) return false;
        const std::uint8_t m = data[i];
        ++i;
        mod = static_cast<std::uint8_t>(m >> 6);
        reg3 = static_cast<std::uint8_t>((m >> 3) & 0x7u);
        rm3 = static_cast<std::uint8_t>(m & 0x7u);
        return true;
    };
    // Memory operand from an already-read ModRM (mod != 3).
    auto make_mem = [&](std::uint8_t bits, Operand& o) -> bool {
        o = Operand{};
        o.kind = OpKind::Mem;
        o.bits = bits;
        o.seg = seg;
        o.addr32 = d.addr_size == 32u;
        bool sib = false;
        bool disp8 = false;
        bool disp32 = false;
        if (rm3 == 4) {
            sib = true;
        } else if (rm3 == 5 && mod == 0) {
            o.rip_relative = true;   // [RIP + disp32]
            disp32 = true;
        } else {
            o.base = rm_field();
        }
        if (sib) {
            if (!need(1)) return false;
            const std::uint8_t s = data[i];
            ++i;
            const std::uint8_t idx3 = static_cast<std::uint8_t>((s >> 3) & 0x7u);
            const std::uint8_t base3 = static_cast<std::uint8_t>(s & 0x7u);
            o.scale = static_cast<std::uint8_t>(1u << (s >> 6));
            // Index field 100 with REX.X=0 means "no index"; with REX.X=1 it is R12.
            if (idx3 != 4 || rex_x != 0) {
                o.index = static_cast<std::uint8_t>(idx3 | static_cast<std::uint8_t>(rex_x << 3));
            }
            if (base3 == 5 && mod == 0) {
                disp32 = true;   // [disp32 + index*scale]
            } else {
                o.base = static_cast<std::uint8_t>(base3 | static_cast<std::uint8_t>(rex_b << 3));
            }
        }
        if (mod == 1) {
            disp8 = true;
        } else if (mod == 2) {
            disp32 = true;
        }
        if (disp8) {
            if (!need(1)) return false;
            o.disp = static_cast<std::int8_t>(data[i]);
            ++i;
        } else if (disp32) {
            if (!need(4)) return false;
            o.disp = static_cast<std::int32_t>(static_cast<std::uint32_t>(read_le(data + i, 4)));
            i += 4;
        }
        return true;
    };
    // r/m operand from an already-read ModRM (register or memory).
    auto rm_after_modrm = [&](std::uint8_t bits, Operand& o) -> bool {
        if (mod == 3) {
            o = reg_op(bits, rm_field());
            return true;
        }
        return make_mem(bits, o);
    };
    auto make_rm = [&](std::uint8_t bits, Operand& o) -> bool {
        if (!read_modrm()) return false;
        return rm_after_modrm(bits, o);
    };
    auto imm_op = [&](std::uint8_t bits, OpKind kind) -> bool {
        const std::size_t nbytes = bits / 8u;
        if (!need(nbytes)) return false;
        Operand o;
        o.kind = kind;
        o.bits = bits;
        o.imm_bits = bits;
        o.imm = read_le(data + i, static_cast<std::uint8_t>(nbytes));
        i += nbytes;
        push(o);
        return true;
    };
    // Intel order: r/m first, then the reg field.
    auto rm_reg = [&](std::uint8_t rbits, std::uint8_t gbits) -> bool {
        if (!make_rm(rbits, a)) return false;
        push(a);
        push(reg_op(gbits, reg_field()));
        return true;
    };
    // Intel order: reg field first, then r/m.
    auto reg_rm = [&](std::uint8_t gbits, std::uint8_t rbits) -> bool {
        if (!read_modrm()) return false;
        const Operand g = reg_op(gbits, reg_field());
        if (!rm_after_modrm(rbits, a)) return false;
        push(g);
        push(a);
        return true;
    };
    // Consume a ModRM/SIB/displacement without producing an operand (the
    // 0F 18..1F hint/NOP group: memory forms never access memory).
    auto skip_modrm = [&]() -> bool {
        Operand scratch;
        return make_rm(8, scratch);
    };

    // ── 4. opcode classes ──────────────────────────────────────────────
    if (d.map == 0 && op < 0x40u && (op & 7u) <= 5u) {
        // 00..3D: two-operand ALU forms (opcode = operation << 3 | form).
        d.mnem = kAlu[op >> 3];
        switch (op & 7u) {
            case 0:
                if (!rm_reg(8, 8)) return finish_bad();
                break;
            case 1:
                if (!rm_reg(os, os)) return finish_bad();
                break;
            case 2:
                if (!reg_rm(8, 8)) return finish_bad();
                break;
            case 3:
                if (!reg_rm(os, os)) return finish_bad();
                break;
            case 4:
                push(reg_op(8, 0));
                if (!imm_op(8, OpKind::Imm)) return finish_bad();
                break;
            default:
                push(reg_op(os, 0));
                if (!imm_op(imm_bits_for(os), OpKind::Imm)) return finish_bad();
                break;
        }
    } else if (d.map == 0) {
        switch (op) {
            // Never valid in 64-bit mode.
            case 0x06: case 0x07: case 0x0E: case 0x16: case 0x17:
            case 0x1E: case 0x1F: case 0x27: case 0x2F: case 0x37:
            case 0x3F: case 0x60: case 0x61: case 0x82: case 0x9A:
            case 0xCA: case 0xCB: case 0xCE: case 0xD4: case 0xD5:
            case 0xD6:
                set_bad(RejectClass::BadOpcode, "opcode has no valid form in 64-bit mode");
                return finish_bad();
            case 0x62:
                set_bad(RejectClass::UnsupportedMap, "EVEX-encoded instruction (AVX-512) is not decoded");
                return finish_bad();
            case 0xC4: case 0xC5:
                set_bad(RejectClass::UnsupportedMap, "VEX-encoded instruction (AVX) is not decoded");
                return finish_bad();
            case 0x63:   // MOVSXD r64, r/m32 (REX.W required)
                if ((rex & 0x08u) == 0) {
                    set_bad(RejectClass::BadOpcode, "63 without REX.W is ARPL: not valid in 64-bit mode");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Movsxd;
                if (!reg_rm(64, 32)) return finish_bad();
                break;
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54:
            case 0x55: case 0x56: case 0x57:   // PUSH r64
                d.mnem = Mnemonic::Push;
                push(reg_op(64, static_cast<std::uint8_t>((op & 7u) | (rex_b << 3))));
                break;
            case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C:
            case 0x5D: case 0x5E: case 0x5F:   // POP r64
                d.mnem = Mnemonic::Pop;
                push(reg_op(64, static_cast<std::uint8_t>((op & 7u) | (rex_b << 3))));
                break;
            case 0x68:
                d.mnem = Mnemonic::Push;
                if (!imm_op(32, OpKind::Imm)) return finish_bad();
                break;
            case 0x6A:
                d.mnem = Mnemonic::Push;
                if (!imm_op(8, OpKind::Imm)) return finish_bad();
                break;
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:   // INS/OUTS
                set_bad(RejectClass::UnsupportedString, "port string operations are not interpreted");
                return finish_bad();
            case 0x69:
            case 0x6B:   // IMUL r, r/m, imm
                d.mnem = Mnemonic::Imul;
                if (!reg_rm(os, os)) return finish_bad();
                if (!imm_op(op == 0x6B ? 8u : imm_bits_for(os), OpKind::Imm)) return finish_bad();
                break;
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
            case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
            case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
                d.mnem = Mnemonic::Jcc;
                d.cc = static_cast<std::uint8_t>(lo);
                if (!imm_op(8, OpKind::Rel)) return finish_bad();
                break;
            case 0x80: case 0x81: case 0x83:   // ALU r/m, imm
            {
                const std::uint8_t isz = op == 0x80 ? 8u : os;
                if (!make_rm(isz, a)) return finish_bad();
                d.mnem = kAlu[reg3];
                push(a);
                const std::uint8_t ib = op == 0x83 ? 8u : imm_bits_for(isz);
                if (!imm_op(ib, OpKind::Imm)) return finish_bad();
                break;
            }
            case 0x84:
            case 0x85:   // TEST r/m, reg
                d.mnem = Mnemonic::Test;
                if (!rm_reg(op == 0x84 ? 8u : os, op == 0x84 ? 8u : os)) return finish_bad();
                break;
            case 0x86:
            case 0x87:   // XCHG r/m, reg
                d.mnem = Mnemonic::Xchg;
                if (!rm_reg(op == 0x86 ? 8u : os, op == 0x86 ? 8u : os)) return finish_bad();
                break;
            case 0x88:
            case 0x89:   // MOV r/m, reg
                d.mnem = Mnemonic::Mov;
                if (!rm_reg(op == 0x88 ? 8u : os, op == 0x88 ? 8u : os)) return finish_bad();
                break;
            case 0x8A:
            case 0x8B:   // MOV reg, r/m
                d.mnem = Mnemonic::Mov;
                if (!reg_rm(op == 0x8A ? 8u : os, op == 0x8A ? 8u : os)) return finish_bad();
                break;
            case 0x8C: case 0x8E:
                set_bad(RejectClass::UnsupportedValid, "segment register move (MOV Sreg) is not interpreted");
                return finish_bad();
            case 0x8D:   // LEA reg, m
                if (os == 16u) {
                    set_bad(RejectClass::BadOperandSize, "LEA with a 16-bit operand size is invalid in 64-bit mode");
                    return finish_bad();
                }
                if (!read_modrm()) return finish_bad();
                if (mod == 3) {
                    set_bad(RejectClass::BadModRm, "LEA requires a memory operand (mod=11 is not allowed)");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Lea;
                push(reg_op(os, reg_field()));
                if (!make_mem(os, a)) return finish_bad();
                push(a);
                break;
            case 0x8F:   // POP r/m (/0 only)
                if (!read_modrm()) return finish_bad();
                if (reg3 != 0) {
                    set_bad(RejectClass::BadModRm, "8F with a digit other than 0 is not a defined form");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Pop;
                if (!rm_after_modrm(os == 16u ? 16u : 64u, a)) return finish_bad();
                push(a);
                break;
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94:
            case 0x95: case 0x96: case 0x97:   // XCHG eAX, reg (90 = NOP; F3 90 = PAUSE)
                if (op == 0x90 && pf3) {
                    d.mnem = Mnemonic::Nop;
                    break;
                }
                d.mnem = Mnemonic::Xchg;
                push(reg_op(os, 0));
                push(reg_op(os, static_cast<std::uint8_t>(lo | (rex_b << 3))));
                break;
            case 0x98:
                d.mnem = Mnemonic::Cbw;
                break;
            case 0x99:
                d.mnem = Mnemonic::Cwd;
                break;
            case 0x9B:
                set_bad(RejectClass::UnsupportedValid, "x87 WAIT/FWAIT is not interpreted");
                return finish_bad();
            case 0x9C:
                d.mnem = Mnemonic::Pushf;
                break;
            case 0x9D:
                d.mnem = Mnemonic::Popf;
                break;
            case 0x9E:
                d.mnem = Mnemonic::Sahf;
                break;
            case 0x9F:
                d.mnem = Mnemonic::Lahf;
                break;
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:   // MOV AL/eAX <-> moffs
            {
                d.mnem = Mnemonic::Mov;
                const std::uint8_t mbits = d.addr_size == 32u ? 32u : 64u;
                const std::size_t nb = mbits / 8u;
                if (!need(nb)) return finish_bad();
                Operand m;
                m.kind = OpKind::Mem;
                m.bits = (op == 0xA0 || op == 0xA2) ? 8u : os;
                m.seg = seg;
                m.addr32 = mbits == 32u;
                m.disp = static_cast<std::int64_t>(read_le(data + i, static_cast<std::uint8_t>(nb)));
                i += nb;
                const bool load = (op == 0xA0 || op == 0xA1);
                if (load) {
                    push(reg_op(m.bits, 0));
                    push(m);
                } else {
                    push(m);
                    push(reg_op(m.bits, 0));
                }
                break;
            }
            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
                set_bad(RejectClass::UnsupportedString, "string operations are not interpreted");
                return finish_bad();
            case 0xA8:
                d.mnem = Mnemonic::Test;
                push(reg_op(8, 0));
                if (!imm_op(8, OpKind::Imm)) return finish_bad();
                break;
            case 0xA9:
                d.mnem = Mnemonic::Test;
                push(reg_op(os, 0));
                if (!imm_op(imm_bits_for(os), OpKind::Imm)) return finish_bad();
                break;
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:   // MOV r8, imm8
                d.mnem = Mnemonic::Mov;
                push(reg_op(8, static_cast<std::uint8_t>(lo | (rex_b << 3))));
                if (!imm_op(8, OpKind::Imm)) return finish_bad();
                break;
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:   // MOV eAX..r15, imm
                d.mnem = Mnemonic::Mov;
                push(reg_op(os, static_cast<std::uint8_t>((op - 0xB8u) | (rex_b << 3))));
                if (!imm_op(os == 64u ? 64u : imm_bits_for(os), OpKind::Imm)) return finish_bad();
                break;
            case 0xC0: case 0xC1: case 0xD0: case 0xD1:
            case 0xD2: case 0xD3:   // group 2: shifts and rotates
            {
                const std::uint8_t ssz = (op == 0xC0 || op == 0xD0) ? 8u : os;
                if (!make_rm(ssz, a)) return finish_bad();
                if (kShift[reg3] == Mnemonic::Invalid) {
                    set_bad(RejectClass::BadModRm, "shift/rotate digit 6 is not a defined form");
                    return finish_bad();
                }
                d.mnem = kShift[reg3];
                push(a);
                Operand count;
                count.bits = 8;
                if (op <= 0xC1) {            // imm8 count follows the r/m operand
                    if (!need(1)) return finish_bad();
                    count.kind = OpKind::Imm;
                    count.imm = data[i];
                    count.imm_bits = 8;
                    ++i;
                } else if (op <= 0xD1) {     // count is the literal 1 (not encoded)
                    count.kind = OpKind::Imm;
                    count.imm = 1;
                } else {                     // count is CL
                    count.kind = OpKind::Reg;
                    count.reg = 1;
                }
                push(count);
                break;
            }
            case 0xC2:   // RET imm16
                d.mnem = Mnemonic::Ret;
                if (!imm_op(16, OpKind::Imm)) return finish_bad();
                break;
            case 0xC3:
                d.mnem = Mnemonic::Ret;
                break;
            case 0xC6:
            case 0xC7:   // MOV r/m, imm (/0 only)
            {
                const std::uint8_t isz = op == 0xC6 ? 8u : os;
                if (!make_rm(isz, a)) return finish_bad();
                if (reg3 != 0) {
                    set_bad(RejectClass::BadModRm, "C6/C7 with a digit other than 0 is not a defined MOV form");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Mov;
                push(a);
                if (!imm_op(isz == 8u ? 8u : imm_bits_for(isz), OpKind::Imm)) return finish_bad();
                break;
            }
            case 0xC8:
                set_bad(RejectClass::UnsupportedValid, "ENTER is not interpreted");
                return finish_bad();
            case 0xC9:
                d.mnem = Mnemonic::Leave;
                break;
            case 0xCC:
                d.mnem = Mnemonic::Int3;
                break;
            case 0xCD:
                set_bad(RejectClass::UnsupportedValid, "INT n (software interrupt) is not interpreted");
                return finish_bad();
            case 0xCF:
                set_bad(RejectClass::UnsupportedPrivileged, "IRET is a privileged instruction");
                return finish_bad();
            case 0xD7:
                set_bad(RejectClass::UnsupportedValid, "XLAT is not interpreted");
                return finish_bad();
            case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF:
                set_bad(RejectClass::UnsupportedSimd, "x87 instructions are not interpreted");
                return finish_bad();
            case 0xE0:
                d.mnem = Mnemonic::Loopne;
                if (!imm_op(8, OpKind::Rel)) return finish_bad();
                break;
            case 0xE1:
                d.mnem = Mnemonic::Loope;
                if (!imm_op(8, OpKind::Rel)) return finish_bad();
                break;
            case 0xE2:
                d.mnem = Mnemonic::Loop;
                if (!imm_op(8, OpKind::Rel)) return finish_bad();
                break;
            case 0xE3:
                d.mnem = Mnemonic::Jrcxz;
                if (!imm_op(8, OpKind::Rel)) return finish_bad();
                break;
            case 0xE4: case 0xE5: case 0xE6: case 0xE7:
            case 0xEC: case 0xED: case 0xEE: case 0xEF:
                set_bad(RejectClass::UnsupportedPrivileged, "IN/OUT are privileged instructions");
                return finish_bad();
            case 0xE8:
                d.mnem = Mnemonic::Call;
                if (!imm_op(32, OpKind::Rel)) return finish_bad();
                break;
            case 0xE9:
                d.mnem = Mnemonic::Jmp;
                if (!imm_op(32, OpKind::Rel)) return finish_bad();
                break;
            case 0xEB:
                d.mnem = Mnemonic::Jmp;
                if (!imm_op(8, OpKind::Rel)) return finish_bad();
                break;
            case 0xF1:
                set_bad(RejectClass::UnsupportedValid, "INT1 (ICEBP) is not interpreted");
                return finish_bad();
            case 0xF4:
                set_bad(RejectClass::UnsupportedPrivileged, "HLT is a privileged instruction");
                return finish_bad();
            case 0xF5:
                d.mnem = Mnemonic::Cmc;
                break;
            case 0xF6:
            case 0xF7:   // group 3
            {
                const std::uint8_t isz = op == 0xF6 ? 8u : os;
                if (!make_rm(isz, a)) return finish_bad();
                if (kGroup3[reg3] == Mnemonic::Invalid) {
                    // F6/F7 /1 is an alternate encoding of TEST on real hardware;
                    // it is explicitly not interpreted instead of being called #UD.
                    set_bad(RejectClass::UnsupportedValid,
                            "F6/F7 /1 (alternate TEST encoding) is not interpreted");
                    return finish_bad();
                }
                d.mnem = kGroup3[reg3];
                push(a);
                if (reg3 == 0) {
                    if (!imm_op(isz == 8u ? 8u : imm_bits_for(isz), OpKind::Imm)) return finish_bad();
                }
                break;
            }
            case 0xF8:
                d.mnem = Mnemonic::Clc;
                break;
            case 0xF9:
                d.mnem = Mnemonic::Stc;
                break;
            case 0xFA: case 0xFB:
                set_bad(RejectClass::UnsupportedPrivileged, "CLI/STI are privileged instructions");
                return finish_bad();
            case 0xFC:
                d.mnem = Mnemonic::Cld;
                break;
            case 0xFD:
                d.mnem = Mnemonic::Std;
                break;
            case 0xFE:
                if (!make_rm(8, a)) return finish_bad();
                if (reg3 > 1) {
                    set_bad(RejectClass::BadModRm, "FE with digits 2..7 is not a defined form");
                    return finish_bad();
                }
                d.mnem = reg3 == 0 ? Mnemonic::Inc : Mnemonic::Dec;
                push(a);
                break;
            case 0xFF: {
                if (!read_modrm()) return finish_bad();
                std::uint8_t bsz = os;
                switch (reg3) {
                    case 0:
                    case 1:
                        d.mnem = reg3 == 0 ? Mnemonic::Inc : Mnemonic::Dec;
                        break;
                    case 2:   // near CALL: the operand size is 64 in 64-bit mode
                        if (p66) {
                            set_bad(RejectClass::UnsupportedValid,
                                    "66-prefixed near CALL is not interpreted");
                            return finish_bad();
                        }
                        d.mnem = Mnemonic::Call;
                        bsz = 64;
                        break;
                    case 4:   // near JMP: the operand size is 64 in 64-bit mode
                        if (p66) {
                            set_bad(RejectClass::UnsupportedValid,
                                    "66-prefixed near JMP is not interpreted");
                            return finish_bad();
                        }
                        d.mnem = Mnemonic::Jmp;
                        bsz = 64;
                        break;
                    case 6:   // PUSH r/m: 64-bit unless 66 selects 16 (rejected later)
                        d.mnem = Mnemonic::Push;
                        bsz = os == 16u ? 16u : 64u;
                        break;
                    case 3:
                        set_bad(RejectClass::UnsupportedValid, "far CALL is not interpreted");
                        return finish_bad();
                    case 5:
                        set_bad(RejectClass::UnsupportedValid, "far JMP is not interpreted");
                        return finish_bad();
                    default:
                        set_bad(RejectClass::BadModRm, "FF /7 is not a defined form");
                        return finish_bad();
                }
                if (!rm_after_modrm(bsz, a)) return finish_bad();
                push(a);
                break;
            }
            default:
                set_bad(RejectClass::BadOpcode, "undefined one-byte opcode");
                return finish_bad();
        }
    } else {
        // ── two-byte map (0F xx) ───────────────────────────────────────
        switch (op) {
            case 0x00: case 0x01: case 0x02: case 0x03: case 0x05:
            case 0x06: case 0x07: case 0x08: case 0x09: case 0x20:
            case 0x21: case 0x22: case 0x23: case 0x30: case 0x31:
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36:
            case 0x37: case 0xAA:
                set_bad(RejectClass::UnsupportedPrivileged, "system/privileged instruction");
                return finish_bad();
            case 0x04: case 0x0A: case 0x0C: case 0x0D: case 0x25: case 0x26:
            case 0x27: case 0x39: case 0x3B: case 0x3C: case 0x3D: case 0x3E:
            case 0x3F: case 0xB9: case 0xC4: case 0xC5: case 0xFF:
                set_bad(RejectClass::BadOpcode, "reserved two-byte opcode");
                return finish_bad();
            case 0x0B:
                d.mnem = Mnemonic::Ud2;
                break;
            case 0x0E: case 0x0F:
                set_bad(RejectClass::UnsupportedSimd, "MMX/3DNow! instructions are not interpreted");
                return finish_bad();
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x14: case 0x15: case 0x16: case 0x17:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x2C: case 0x2D: case 0x2E: case 0x2F:
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54:
            case 0x55: case 0x56: case 0x57: case 0x58: case 0x59:
            case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E:
            case 0x5F: case 0x60: case 0x61: case 0x62: case 0x63:
            case 0x64: case 0x65: case 0x66: case 0x67: case 0x68:
            case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D:
            case 0x6E: case 0x6F: case 0x70: case 0x71: case 0x72:
            case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C:
            case 0x7D: case 0x7E: case 0x7F:
            case 0xC2: case 0xC6:
                set_bad(RejectClass::UnsupportedSimd, "SSE/MMX instructions are not interpreted");
                return finish_bad();
            case 0x18: case 0x19: case 0x1A: case 0x1B:
            case 0x1C: case 0x1D: case 0x1E: case 0x1F:   // hint/NOP group
                d.mnem = Mnemonic::Nop;
                d.is_endbr = (op == 0x1E && pf3);
                if (!skip_modrm()) return finish_bad();
                d.cc = rm3;   // ENDBR64 selects r/m 010, ENDBR32 r/m 011
                break;
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                d.mnem = Mnemonic::Cmovcc;
                d.cc = static_cast<std::uint8_t>(lo);
                if (!reg_rm(os, os)) return finish_bad();
                break;
            case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
            case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
            case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
            case 0x8F:
                d.mnem = Mnemonic::Jcc;
                d.cc = static_cast<std::uint8_t>(lo);
                if (!imm_op(32, OpKind::Rel)) return finish_bad();
                break;
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94:
            case 0x95: case 0x96: case 0x97: case 0x98: case 0x99:
            case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E:
            case 0x9F:
                d.mnem = Mnemonic::Setcc;
                d.cc = static_cast<std::uint8_t>(lo);
                if (!make_rm(8, a)) return finish_bad();
                push(a);
                break;
            case 0xA0: case 0xA1: case 0xA8: case 0xA9:
            case 0xB2: case 0xB4: case 0xB5:
                set_bad(RejectClass::UnsupportedValid, "segment register operations are not interpreted");
                return finish_bad();
            case 0xA2:
                set_bad(RejectClass::UnsupportedValid, "CPUID is not interpreted");
                return finish_bad();
            case 0xA3: case 0xAB: case 0xB3: case 0xBB:   // BT/BTS/BTR/BTC r/m, reg
                d.mnem = op == 0xA3   ? Mnemonic::Bt
                         : op == 0xAB ? Mnemonic::Bts
                         : op == 0xB3 ? Mnemonic::Btr
                                      : Mnemonic::Btc;
                if (!rm_reg(os, os)) return finish_bad();
                break;
            case 0xA4: case 0xA5: case 0xAC: case 0xAD:
                set_bad(RejectClass::UnsupportedValid, "SHLD/SHRD are not interpreted");
                return finish_bad();
            case 0xAF:   // IMUL reg, r/m
                d.mnem = Mnemonic::Imul;
                if (!reg_rm(os, os)) return finish_bad();
                break;
            case 0xB0: case 0xB1: case 0xC0: case 0xC1:
                set_bad(RejectClass::UnsupportedAtomic, "CMPXCHG/XADD are not interpreted");
                return finish_bad();
            case 0xB6:   // MOVZX reg, r/m8
                d.mnem = Mnemonic::Movzx;
                if (!reg_rm(os, 8)) return finish_bad();
                break;
            case 0xB7:   // MOVZX reg, r/m16
                if (os == 16u) {
                    set_bad(RejectClass::BadOperandSize, "MOVZX r16, r/m16 is not a valid form");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Movzx;
                if (!reg_rm(os, 16)) return finish_bad();
                break;
            case 0xB8:   // POPCNT reg, r/m (F3 required)
                if (!pf3) {
                    set_bad(RejectClass::BadOpcode, "0F B8 requires the F3 prefix (POPCNT)");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Popcnt;
                if (!reg_rm(os, os)) return finish_bad();
                break;
            case 0xBA:   // BT/BTS/BTR/BTC r/m, imm8 (/4../7)
                if (!make_rm(os, a)) return finish_bad();
                if (kBtImm[reg3] == Mnemonic::Invalid) {
                    set_bad(RejectClass::BadModRm, "0F BA digits 0..3 are not defined forms");
                    return finish_bad();
                }
                d.mnem = kBtImm[reg3];
                push(a);
                if (!imm_op(8, OpKind::Imm)) return finish_bad();
                break;
            case 0xBC:   // BSF / TZCNT (F3)
                d.mnem = pf3 ? Mnemonic::Tzcnt : Mnemonic::Bsf;
                if (!reg_rm(os, os)) return finish_bad();
                break;
            case 0xBD:   // BSR / LZCNT (F3)
                d.mnem = pf3 ? Mnemonic::Lzcnt : Mnemonic::Bsr;
                if (!reg_rm(os, os)) return finish_bad();
                break;
            case 0xBE:   // MOVSX reg, r/m8
                d.mnem = Mnemonic::Movsx;
                if (!reg_rm(os, 8)) return finish_bad();
                break;
            case 0xBF:   // MOVSX reg, r/m16
                if (os == 16u) {
                    set_bad(RejectClass::BadOperandSize, "MOVSX r16, r/m16 is not a valid form");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Movsx;
                if (!reg_rm(os, 16)) return finish_bad();
                break;
            case 0xC3:   // RET (F3 C3 = REP RET, historically emitted)
                d.mnem = Mnemonic::Ret;
                break;
            case 0xC7:
                if (!read_modrm()) return finish_bad();
                if (reg3 == 1) {
                    set_bad(RejectClass::UnsupportedAtomic, "CMPXCHG8B/16B is not interpreted");
                } else {
                    set_bad(RejectClass::UnsupportedValid, "0F C7 group (RDRAND/RDSEED/...) is not interpreted");
                }
                return finish_bad();
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF:   // BSWAP r
                if (os == 16u) {
                    set_bad(RejectClass::BadOperandSize, "BSWAP with a 16-bit operand size is not defined");
                    return finish_bad();
                }
                d.mnem = Mnemonic::Bswap;
                push(reg_op(os, static_cast<std::uint8_t>((op - 0xC8u) | (rex_b << 3))));
                break;
            default:
                // 0xD0..0xFE: SSE / SSE2 / AVX legacy encodings.
                if (op >= 0xD0) {
                    set_bad(RejectClass::UnsupportedSimd, "SSE/MMX instructions are not interpreted");
                } else {
                    set_bad(RejectClass::BadOpcode, "reserved two-byte opcode");
                }
                return finish_bad();
        }
    }

    // ── 5. validity checks ─────────────────────────────────────────────
    if (pf2 || pf3) {
        const bool allowed = pf3 && !pf2 &&
                             (d.mnem == Mnemonic::Nop || d.mnem == Mnemonic::Ret ||
                              d.mnem == Mnemonic::Tzcnt || d.mnem == Mnemonic::Lzcnt ||
                              d.mnem == Mnemonic::Popcnt);
        if (!allowed) {
            set_bad(RejectClass::BadPrefix, "REP/REPNE prefix is not valid for this instruction");
            return finish_bad();
        }
    }
    if (os == 16u && is_16bit_stack_or_branch(d.mnem)) {
        set_bad(RejectClass::UnsupportedValid, "16-bit stack/branch operand size is not interpreted");
        return finish_bad();
    }
    if (lock) {
        if (is_rmw(d.mnem) && d.op_count > 0 && d.ops[0].kind == OpKind::Mem) {
            set_bad(RejectClass::UnsupportedAtomic, "LOCK-prefixed (atomic) instructions are not interpreted");
        } else {
            set_bad(RejectClass::BadPrefix, "LOCK prefix is not permitted on this instruction");
        }
        return finish_bad();
    }

    d.length = static_cast<std::uint8_t>(i);
    res.status = DecodeStatus::Ok;
    res.ins = d;
    res.reject = RejectClass::None;
    res.reason = "";
    res.consumed = d.length;
    return res;
}

// ── names + metadata ─────────────────────────────────────────────────────

const char* status_name(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok: return "ok";
        case DecodeStatus::Truncated: return "truncated";
        case DecodeStatus::Invalid: return "invalid";
        case DecodeStatus::Unsupported: return "unsupported";
    }
    return "?";
}

const char* reject_class_name(RejectClass r) {
    switch (r) {
        case RejectClass::None: return "none";
        case RejectClass::NeedMoreBytes: return "need-more-bytes";
        case RejectClass::TooLong: return "too-long";
        case RejectClass::BadOpcode: return "bad-opcode";
        case RejectClass::BadOperandSize: return "bad-operand-size";
        case RejectClass::BadModRm: return "bad-modrm";
        case RejectClass::BadPrefix: return "bad-prefix";
        case RejectClass::UnsupportedValid: return "unsupported";
        case RejectClass::UnsupportedMap: return "unsupported-map";
        case RejectClass::UnsupportedSimd: return "unsupported-simd";
        case RejectClass::UnsupportedString: return "unsupported-string";
        case RejectClass::UnsupportedAtomic: return "unsupported-atomic";
        case RejectClass::UnsupportedPrivileged: return "unsupported-privileged";
    }
    return "?";
}

const char* mnemonic_name(Mnemonic m) {
    switch (m) {
        case Mnemonic::Invalid: return "invalid";
        case Mnemonic::Add: return "add";
        case Mnemonic::Or: return "or";
        case Mnemonic::Adc: return "adc";
        case Mnemonic::Sbb: return "sbb";
        case Mnemonic::And: return "and";
        case Mnemonic::Sub: return "sub";
        case Mnemonic::Xor: return "xor";
        case Mnemonic::Cmp: return "cmp";
        case Mnemonic::Test: return "test";
        case Mnemonic::Mov: return "mov";
        case Mnemonic::Movzx: return "movzx";
        case Mnemonic::Movsx: return "movsx";
        case Mnemonic::Movsxd: return "movsxd";
        case Mnemonic::Lea: return "lea";
        case Mnemonic::Xchg: return "xchg";
        case Mnemonic::Bswap: return "bswap";
        case Mnemonic::Cbw: return "cbw";
        case Mnemonic::Cwd: return "cwd";
        case Mnemonic::Inc: return "inc";
        case Mnemonic::Dec: return "dec";
        case Mnemonic::Neg: return "neg";
        case Mnemonic::Not: return "not";
        case Mnemonic::Mul: return "mul";
        case Mnemonic::Imul: return "imul";
        case Mnemonic::Div: return "div";
        case Mnemonic::Idiv: return "idiv";
        case Mnemonic::Rol: return "rol";
        case Mnemonic::Ror: return "ror";
        case Mnemonic::Rcl: return "rcl";
        case Mnemonic::Rcr: return "rcr";
        case Mnemonic::Shl: return "shl";
        case Mnemonic::Shr: return "shr";
        case Mnemonic::Sar: return "sar";
        case Mnemonic::Bt: return "bt";
        case Mnemonic::Bts: return "bts";
        case Mnemonic::Btr: return "btr";
        case Mnemonic::Btc: return "btc";
        case Mnemonic::Bsf: return "bsf";
        case Mnemonic::Bsr: return "bsr";
        case Mnemonic::Tzcnt: return "tzcnt";
        case Mnemonic::Lzcnt: return "lzcnt";
        case Mnemonic::Popcnt: return "popcnt";
        case Mnemonic::Jmp: return "jmp";
        case Mnemonic::Jcc: return "jcc";
        case Mnemonic::Call: return "call";
        case Mnemonic::Ret: return "ret";
        case Mnemonic::Loop: return "loop";
        case Mnemonic::Loope: return "loope";
        case Mnemonic::Loopne: return "loopne";
        case Mnemonic::Jrcxz: return "jrcxz";
        case Mnemonic::Cmovcc: return "cmovcc";
        case Mnemonic::Setcc: return "setcc";
        case Mnemonic::Push: return "push";
        case Mnemonic::Pop: return "pop";
        case Mnemonic::Pushf: return "pushfq";
        case Mnemonic::Popf: return "popfq";
        case Mnemonic::Lahf: return "lahf";
        case Mnemonic::Sahf: return "sahf";
        case Mnemonic::Leave: return "leave";
        case Mnemonic::Clc: return "clc";
        case Mnemonic::Stc: return "stc";
        case Mnemonic::Cmc: return "cmc";
        case Mnemonic::Cld: return "cld";
        case Mnemonic::Std: return "std";
        case Mnemonic::Nop: return "nop";
        case Mnemonic::Int3: return "int3";
        case Mnemonic::Ud2: return "ud2";
    }
    return "?";
}

const char* condition_suffix(std::uint8_t cc) {
    static const char* const kSuffix[16] = {
        "o", "no", "b", "ae", "e", "ne", "be", "a",
        "s", "ns", "p", "np", "l", "ge", "le", "g",
    };
    return kSuffix[cc & 0xFu];
}

std::string mnemonic_text(const Decoded& d) {
    switch (d.mnem) {
        case Mnemonic::Jcc:
            return std::string("j") + condition_suffix(d.cc);
        case Mnemonic::Cmovcc:
            return std::string("cmov") + condition_suffix(d.cc);
        case Mnemonic::Setcc:
            return std::string("set") + condition_suffix(d.cc);
        case Mnemonic::Cbw:
            return d.op_size == 16u ? "cbw" : (d.op_size == 32u ? "cwde" : "cdqe");
        case Mnemonic::Cwd:
            return d.op_size == 16u ? "cwd" : (d.op_size == 32u ? "cdq" : "cqo");
        case Mnemonic::Jrcxz:
            return d.addr_size == 32u ? "jecxz" : "jrcxz";
        case Mnemonic::Nop:
            if (d.is_endbr) return (d.cc & 7u) == 2u ? "endbr64" : "endbr32";
            return "nop";
        case Mnemonic::Xchg:
            // 90 (and 66 90): XCHG eAX, eAX is the canonical NOP.
            if (d.op_count == 2 && d.ops[0].kind == OpKind::Reg && d.ops[0].reg == 0 &&
                d.ops[1].kind == OpKind::Reg && d.ops[1].reg == 0) {
                return "nop";
            }
            return "xchg";
        default:
            return mnemonic_name(d.mnem);
    }
}

Group instruction_group(Mnemonic m) {
    switch (m) {
        case Mnemonic::Add: case Mnemonic::Or: case Mnemonic::Adc:
        case Mnemonic::Sbb: case Mnemonic::And: case Mnemonic::Sub:
        case Mnemonic::Xor: case Mnemonic::Cmp: case Mnemonic::Test:
        case Mnemonic::Inc: case Mnemonic::Dec: case Mnemonic::Neg:
        case Mnemonic::Not:
            return Group::Alu;
        case Mnemonic::Mov: case Mnemonic::Movzx: case Mnemonic::Movsx:
        case Mnemonic::Movsxd: case Mnemonic::Lea: case Mnemonic::Xchg:
        case Mnemonic::Bswap:
            return Group::DataMovement;
        case Mnemonic::Mul: case Mnemonic::Imul: case Mnemonic::Div:
        case Mnemonic::Idiv:
            return Group::MulDiv;
        case Mnemonic::Rol: case Mnemonic::Ror: case Mnemonic::Rcl:
        case Mnemonic::Rcr: case Mnemonic::Shl: case Mnemonic::Shr:
        case Mnemonic::Sar:
            return Group::ShiftRotate;
        case Mnemonic::Bt: case Mnemonic::Bts: case Mnemonic::Btr:
        case Mnemonic::Btc: case Mnemonic::Bsf: case Mnemonic::Bsr:
        case Mnemonic::Tzcnt: case Mnemonic::Lzcnt: case Mnemonic::Popcnt:
            return Group::BitOps;
        case Mnemonic::Jmp: case Mnemonic::Jcc: case Mnemonic::Call:
        case Mnemonic::Ret: case Mnemonic::Loop: case Mnemonic::Loope:
        case Mnemonic::Loopne: case Mnemonic::Jrcxz: case Mnemonic::Cmovcc:
        case Mnemonic::Setcc:
            return Group::ControlFlow;
        case Mnemonic::Push: case Mnemonic::Pop: case Mnemonic::Pushf:
        case Mnemonic::Popf: case Mnemonic::Lahf: case Mnemonic::Sahf:
        case Mnemonic::Leave: case Mnemonic::Clc: case Mnemonic::Stc:
        case Mnemonic::Cmc: case Mnemonic::Cld: case Mnemonic::Std:
            return Group::StackFlags;
        case Mnemonic::Cbw: case Mnemonic::Cwd:
            return Group::Convert;
        case Mnemonic::Nop: case Mnemonic::Int3: case Mnemonic::Ud2:
            return Group::TrapHint;
        case Mnemonic::Invalid:
            break;
    }
    return Group::TrapHint;
}

bool is_branch(Mnemonic m) {
    switch (m) {
        case Mnemonic::Jmp: case Mnemonic::Jcc: case Mnemonic::Call:
        case Mnemonic::Ret: case Mnemonic::Loop: case Mnemonic::Loope:
        case Mnemonic::Loopne: case Mnemonic::Jrcxz:
            return true;
        default:
            return false;
    }
}

bool is_block_terminator(Mnemonic m) {
    return m == Mnemonic::Jmp || m == Mnemonic::Ret || m == Mnemonic::Ud2 ||
           m == Mnemonic::Int3;
}

bool is_call(Mnemonic m) {
    return m == Mnemonic::Call;
}

bool is_return(Mnemonic m) {
    return m == Mnemonic::Ret;
}

bool condition_holds(std::uint8_t cc, std::uint64_t rflags) {
    const bool cf = (rflags & kRfCf) != 0;
    const bool zf = (rflags & kRfZf) != 0;
    const bool sf = (rflags & kRfSf) != 0;
    const bool of = (rflags & kRfOf) != 0;
    const bool pf = (rflags & kRfPf) != 0;
    switch (cc & 0xFu) {
        case 0x0: return of;
        case 0x1: return !of;
        case 0x2: return cf;
        case 0x3: return !cf;
        case 0x4: return zf;
        case 0x5: return !zf;
        case 0x6: return cf || zf;
        case 0x7: return !cf && !zf;
        case 0x8: return sf;
        case 0x9: return !sf;
        case 0xA: return pf;
        case 0xB: return !pf;
        case 0xC: return sf != of;
        case 0xD: return sf == of;
        case 0xE: return zf || (sf != of);
        default: return !zf && (sf == of);
    }
}

FlagEffect flags_effect(const Decoded& d, const std::uint64_t* gprs) {
    constexpr std::uint32_t all6 = kRfCf | kRfPf | kRfAf | kRfZf | kRfSf | kRfOf;
    FlagEffect e;
    switch (d.mnem) {
        case Mnemonic::Add: case Mnemonic::Adc: case Mnemonic::Sub:
        case Mnemonic::Sbb: case Mnemonic::Cmp: case Mnemonic::Neg:
            e.affected = all6;
            e.defined = all6;
            break;
        case Mnemonic::And: case Mnemonic::Or: case Mnemonic::Xor:
        case Mnemonic::Test:
            e.affected = all6;                 // AF is undefined for logic ops
            e.defined = all6 & ~kRfAf;
            break;
        case Mnemonic::Inc: case Mnemonic::Dec:   // CF is preserved
            e.affected = kRfPf | kRfAf | kRfZf | kRfSf | kRfOf;
            e.defined = e.affected;
            break;
        case Mnemonic::Mul: case Mnemonic::Imul:
            e.affected = all6;                 // SF/ZF/AF/PF undefined
            e.defined = kRfCf | kRfOf;
            break;
        case Mnemonic::Div: case Mnemonic::Idiv:
            e.affected = all6;                 // all flags undefined
            e.defined = 0;
            break;
        case Mnemonic::Bt: case Mnemonic::Bts: case Mnemonic::Btr:
        case Mnemonic::Btc:
            e.affected = all6;                 // only CF is defined
            e.defined = kRfCf;
            break;
        case Mnemonic::Bsf: case Mnemonic::Bsr:
            e.affected = all6 & ~kRfCf;        // only ZF is defined
            e.defined = kRfZf;
            break;
        case Mnemonic::Tzcnt: case Mnemonic::Lzcnt:
            e.affected = all6;
            e.defined = kRfCf | kRfZf;
            break;
        case Mnemonic::Popcnt:
            e.affected = all6;
            e.defined = kRfZf;
            break;
        case Mnemonic::Shl: case Mnemonic::Shr: case Mnemonic::Sar: {
            const std::uint64_t width = d.op_count > 0 ? d.ops[0].bits : d.op_size;
            const std::uint64_t cnt =
                shift_count_of(d, gprs) & (width >= 64u ? 0x3Full : 0x1Full);
            if (cnt == 0) break;               // count 0: no flag changes
            e.affected = all6;
            e.defined = all6 & ~kRfAf;         // AF undefined
            if (cnt != 1) e.defined &= ~kRfOf; // OF defined for 1-bit shifts only
            if (d.mnem != Mnemonic::Sar && cnt >= width) {
                e.defined &= ~kRfCf;           // SHL/SHR: CF undefined
            }
            break;
        }
        case Mnemonic::Rol: case Mnemonic::Ror: case Mnemonic::Rcl:
        case Mnemonic::Rcr: {
            const std::uint64_t width = d.op_count > 0 ? d.ops[0].bits : d.op_size;
            const std::uint64_t masked =
                shift_count_of(d, gprs) & (width >= 64u ? 0x3Full : 0x1Full);
            if (masked == 0) break;
            const std::uint64_t size = width;
            const bool through_carry =
                d.mnem == Mnemonic::Rcl || d.mnem == Mnemonic::Rcr;
            const std::uint64_t temp =
                masked % (through_carry ? size + 1 : size);
            e.affected = kRfCf | kRfOf;
            if (temp != 0) e.defined |= kRfCf;      // no rotation: CF unchanged
            if (masked == 1) e.defined |= kRfOf;    // OF: 1-bit rotates only
            break;
        }
        case Mnemonic::Clc: case Mnemonic::Stc: case Mnemonic::Cmc:
            e.affected = kRfCf;
            e.defined = kRfCf;
            break;
        case Mnemonic::Cld: case Mnemonic::Std:
            e.affected = kRfDf;
            e.defined = kRfDf;
            break;
        case Mnemonic::Popf:
            // User-mode semantics (IOPL 0): IF cannot change; VM/VIP/VIF/RF
            // are not modeled.
            e.affected = all6 | kRfTf | kRfDf;
            e.defined = e.affected;
            break;
        default:
            break;
    }
    return e;
}

// ── rendering + value helpers ────────────────────────────────────────────

std::string operand_size_text(std::uint8_t bits) {
    switch (bits) {
        case 8: return "byte";
        case 16: return "word";
        case 32: return "dword";
        case 64: return "qword";
        default: return "?";
    }
}

std::string register_name(std::uint8_t reg, std::uint8_t bits, bool rex_present) {
    static const char* const r8_legacy[16] = {
        "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    };
    static const char* const r8_rex[16] = {
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    };
    static const char* const r16[16] = {
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    };
    static const char* const r32[16] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    };
    static const char* const r64[16] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    const std::size_t r = reg & 0xFu;
    switch (bits) {
        case 8: return rex_present ? r8_rex[r] : r8_legacy[r];
        case 16: return r16[r];
        case 32: return r32[r];
        default: return r64[r];
    }
}

std::string format_instruction(const Decoded& d) {
    std::string s = mnemonic_text(d);
    // The canonical NOP (90 / 66 90) is XCHG eAX, eAX: no operands shown.
    if (s == "nop" || s == "endbr64" || s == "endbr32") return s;
    for (std::uint8_t k = 0; k < d.op_count && k < 3; ++k) {
        s += (k == 0) ? " " : ", ";
        const Operand& o = d.ops[k];
        switch (o.kind) {
            case OpKind::Reg:
                s += register_name(o.reg, o.bits, d.rex != 0);
                break;
            case OpKind::Imm:
                s += o.imm_bits == 0 ? std::to_string(o.imm) : hex_text(o.imm);
                break;
            case OpKind::Rel:
                s += hex_text(branch_target(d));
                break;
            case OpKind::Mem: {
                // LEA computes an address: no operand size is shown.
                const bool addr_only = d.mnem == Mnemonic::Lea;
                if (!addr_only) {
                    s += operand_size_text(o.bits);
                    s += " ptr ";
                }
                switch (o.seg) {
                    case Segment::Cs: s += "cs:"; break;
                    case Segment::Ds: s += "ds:"; break;
                    case Segment::Es: s += "es:"; break;
                    case Segment::Fs: s += "fs:"; break;
                    case Segment::Gs: s += "gs:"; break;
                    case Segment::Ss: s += "ss:"; break;
                    case Segment::None: break;
                }
                const std::uint8_t abits = o.addr32 ? 32u : 64u;
                s += '[';
                bool any = false;
                if (o.rip_relative) {
                    s += "rip";
                    any = true;
                }
                if (o.base != kNoReg) {
                    if (any) s += " + ";
                    s += register_name(o.base, abits, true);
                    any = true;
                }
                if (o.index != kNoReg) {
                    if (any) s += " + ";
                    s += register_name(o.index, abits, true);
                    if (o.scale != 1) {
                        s += '*';
                        s += std::to_string(o.scale);
                    }
                    any = true;
                }
                if (o.disp != 0 || !any) {
                    if (any) s += o.disp < 0 ? " - " : " + ";
                    const std::uint64_t mag =
                        o.disp < 0 ? static_cast<std::uint64_t>(-(o.disp + 1)) + 1u
                                   : static_cast<std::uint64_t>(o.disp);
                    s += hex_text(mag);
                }
                s += ']';
                break;
            }
            case OpKind::None:
                break;
        }
    }
    return s;
}

std::uint64_t operand_size_mask(std::uint8_t bits) {
    return bits >= 64u ? ~0ull : ((1ull << bits) - 1u);
}

std::int64_t sign_extend(std::uint64_t v, std::uint8_t from_bits) {
    if (from_bits == 0 || from_bits >= 64) return static_cast<std::int64_t>(v);
    // Shift the field's sign bit up to bit 63, then shift back ARITHMETICALLY.
    const std::uint64_t high = v << (64u - from_bits);
    return static_cast<std::int64_t>(high) >> (64u - from_bits);
}

std::uint64_t branch_target(const Decoded& d) {
    for (std::uint8_t k = 0; k < d.op_count && k < 3; ++k) {
        if (d.ops[k].kind == OpKind::Rel) {
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(d.rip) + d.length +
                                              sign_extend(d.ops[k].imm, d.ops[k].imm_bits));
        }
    }
    return 0;
}

}  // namespace xbox2pc::rt::x64
