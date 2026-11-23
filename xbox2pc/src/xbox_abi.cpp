// xbox2pc/src/xbox_abi.cpp — M8 Xbox x64 ABI implementation.
//
// Every rule cites the opened Microsoft x64 ABI pages (see header).
// Unsupported cases return structured errors — nothing is silently
// accepted.

#include "xbox2pc/xbox_abi.hpp"

#include <cstring>

namespace xbox2pc::rt::abi {

using cpu::Gpr;

namespace {
// Argument positions 1..4 -> GP registers [MS-X64CC].
constexpr Gpr kGpArgRegs[kMaxRegArgs] = {Gpr::Rcx, Gpr::Rdx, Gpr::R8, Gpr::R9};
}  // namespace

const char* arg_kind_to_name(ArgKind k) {
    switch (k) {
        case ArgKind::Int: return "int";
        case ArgKind::Ptr: return "ptr";
        case ArgKind::F32: return "f32";
        case ArgKind::F64: return "f64";
        case ArgKind::VecF32x4: return "vec128";
        case ArgKind::Struct: return "struct";
    }
    return "?";
}

std::optional<ArgKind> arg_kind_from_name(const std::string& name) {
    if (name == "int") return ArgKind::Int;
    if (name == "ptr") return ArgKind::Ptr;
    if (name == "f32") return ArgKind::F32;
    if (name == "f64") return ArgKind::F64;
    if (name == "vec128") return ArgKind::VecF32x4;
    if (name == "struct") return ArgKind::Struct;
    return std::nullopt;
}

const char* abi_doc_summary() {
    return "Microsoft x64 ABI: RCX/RDX/R8/R9 + XMM0-3 by position, 32-byte "
           "shadow space, 16-byte stack alignment, RAX/XMM0 returns, "
           "nonvolatile RBX/RBP/RDI/RSI/R12-R15/XMM6-15 "
           "[MS-X64CC][MS-X64STACK]";
}

Result<void> validate_call(const CallSpec& spec) {
    if (spec.args.size() > 64) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "argument count above the 64 limit");
    }
    for (std::size_t i = 0; i < spec.args.size(); ++i) {
        const auto& a = spec.args[i];
        switch (a.kind) {
            case ArgKind::VecF32x4:
                return Result<void>(RuntimeErrc::PlatformUnsupported,
                                    "arg " + std::to_string(i) +
                                        ": __m128 by value is unsupported "
                                        "(documented: passed by reference)");
            case ArgKind::Ptr:
                if (a.deref_size > (1ull << 20)) {
                    return Result<void>(RuntimeErrc::InvalidArgument,
                                        "arg " + std::to_string(i) +
                                            ": deref size above the 1 MiB "
                                            "guest-op limit");
                }
                break;
            case ArgKind::Struct:
                if (a.struct_size != 1 && a.struct_size != 2 &&
                    a.struct_size != 4 && a.struct_size != 8) {
                    return Result<void>(RuntimeErrc::PlatformUnsupported,
                                        "arg " + std::to_string(i) +
                                            ": aggregate size " +
                                            std::to_string(a.struct_size) +
                                            " not in {1,2,4,8} (documented: "
                                            "larger aggregates pass by "
                                            "reference)");
                }
                break;
            case ArgKind::Int:
            case ArgKind::F32:
            case ArgKind::F64:
                if (a.deref_size != 0 || a.is_out) {
                    return Result<void>(RuntimeErrc::InvalidArgument,
                                        "arg " + std::to_string(i) +
                                            ": deref/out only valid for ptr");
                }
                break;
        }
    }
    if (spec.varargs && spec.args.size() > kMaxRegArgs) {
        return Result<void>(RuntimeErrc::PlatformUnsupported,
                            "varargs beyond 4 positions unsupported "
                            "(documented vararg spill path not modeled)");
    }
    return Result<void>::ok_result();
}

Result<CallLayout> compute_layout(const CallSpec& spec) {
    const auto valid = validate_call(spec);
    if (!valid.ok()) return Result<CallLayout>(valid.errc(), valid.context());
    CallLayout out;
    std::uint32_t gp = 0, xmm = 0, stack = 0;
    for (const auto& a : spec.args) {
        const bool fp = a.kind == ArgKind::F32 || a.kind == ArgKind::F64;
        if (fp) {
            // FP args occupy XMM slots BY POSITION [MS-X64CC]. The slot
            // index is the ARGUMENT position (not the count of FP args).
            const std::size_t pos = gp + xmm + stack;   // argument index
            if (pos < kMaxRegArgs) {
                ++xmm;
            } else {
                ++stack;   // fifth+ FP args spill to the stack
            }
        } else {
            if (gp < kMaxRegArgs) {
                ++gp;
            } else {
                ++stack;
            }
        }
    }
    out.gp_reg_args = gp;
    out.xmm_reg_args = xmm;
    out.stack_args = stack;
    // Frame: shadow space + stack args, 16-byte aligned [MS-X64CC/STACK].
    out.total_stack_bytes = kShadowSpaceBytes + stack * 8;
    const std::uint64_t rem = out.total_stack_bytes % kStackAlignment;
    if (rem != 0) out.total_stack_bytes += kStackAlignment - rem;
    return Result<CallLayout>(out);
}

Result<void> prepare_call(CpuState& cpu, std::uint64_t callee_va,
                          const CallSpec& spec, const std::vector<ArgValue>& values,
                          const StackWriter& writer) {
    if (writer.write == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument, "null stack writer");
    }
    if (values.size() != spec.args.size()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "value count " + std::to_string(values.size()) +
                                " != argument count " +
                                std::to_string(spec.args.size()));
    }
    const auto valid = validate_call(spec);
    if (!valid.ok()) return valid;

    // RSP discipline [MS-X64STACK]: the caller supplies a 16-byte-aligned
    // RSP pointing at free stack memory; we write the return address at
    // [RSP], then the argument frame above it, then push RSP down by the
    // frame size. On return, write_return() restores RSP +8 past the
    // return address slot.
    const std::uint64_t rsp = cpu.reg(Gpr::Sp);
    if ((rsp % 8) != 0 || rsp < 4096) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "caller RSP not usable (alignment/floor)");
    }

    const auto layout_r = compute_layout(spec);
    if (!layout_r.ok()) {
        return Result<void>(layout_r.errc(), layout_r.context());
    }
    // ── frame geometry first: the callee's RSP after the call pushes the
    // return address and the frame (shadow + stack args, 16-aligned)
    // [MS-X64CC][MS-X64STACK]. Stack args live at callee
    // [RSP+8]+32.., the return address AT [callee RSP].
    const auto layout_pre = compute_layout(spec);
    if (!layout_pre.ok()) {
        return Result<void>(layout_pre.errc(), layout_pre.context());
    }
    const std::uint64_t frame = layout_pre.value().total_stack_bytes + 8;
    const std::uint64_t callee_rsp = rsp - frame;
    if ((callee_rsp % 8) != 0 || callee_rsp < 4096) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "callee RSP invalid after frame push");
    }
    const std::uint64_t stack_args_base = callee_rsp + 8 + kShadowSpaceBytes;
    std::uint32_t gp_used = 0, stack_used = 0;
    // Varargs [MS-X64CC]: FP values duplicated into the GP register at
    // the same position.
    std::uint64_t vararg_gp_shadow[kMaxRegArgs] = {0};
    bool vararg_gp_used[kMaxRegArgs] = {false};

    for (std::size_t i = 0; i < spec.args.size(); ++i) {
        const auto& a = spec.args[i];
        const auto& v = values[i];
        const bool fp = a.kind == ArgKind::F32 || a.kind == ArgKind::F64;
        if (fp) {
            const std::size_t pos = i;   // position-indexed XMM slot
            if (pos < kMaxRegArgs) {
                // 64-bit representation of the double into the XMM slot.
                std::uint64_t bits = 0;
                std::memcpy(&bits, &v.f64_v, 8);
                cpu.xmm[pos][0] = static_cast<std::uint8_t>(bits);
                cpu.xmm[pos][1] = static_cast<std::uint8_t>(bits >> 8);
                cpu.xmm[pos][2] = static_cast<std::uint8_t>(bits >> 16);
                cpu.xmm[pos][3] = static_cast<std::uint8_t>(bits >> 24);
                cpu.xmm[pos][4] = static_cast<std::uint8_t>(bits >> 32);
                cpu.xmm[pos][5] = static_cast<std::uint8_t>(bits >> 40);
                cpu.xmm[pos][6] = static_cast<std::uint8_t>(bits >> 48);
                cpu.xmm[pos][7] = static_cast<std::uint8_t>(bits >> 56);
                if (spec.varargs) {
                    vararg_gp_shadow[pos] = bits;
                    vararg_gp_used[pos] = true;
                }
            } else {
                const std::uint64_t slot =
                    stack_args_base + (stack_used++) * 8;
                std::uint64_t bits = 0;
                std::memcpy(&bits, &v.f64_v, 8);
                auto w = writer.write(writer.ctx, slot, &bits, 8);
                if (!w.ok()) return w;
            }
        } else {
            if (gp_used < kMaxRegArgs) {
                cpu.set_reg(kGpArgRegs[gp_used], v.int_v);
                ++gp_used;
            } else {
                const std::uint64_t slot =
                    stack_args_base + (stack_used++) * 8;
                auto w = writer.write(writer.ctx, slot, &v.int_v, 8);
                if (!w.ok()) return w;
            }
        }
    }
    // Varargs duplication AFTER the loop so position slots are correct.
    if (spec.varargs) {
        for (std::size_t p = 0; p < kMaxRegArgs; ++p) {
            if (vararg_gp_used[p]) {
                cpu.set_reg(kGpArgRegs[p], vararg_gp_shadow[p]);
            }
        }
    }

    // ── return address AT [callee RSP] (the documented entry state:
    // [RSP] = return address on function entry [MS-X64STACK]).
    const std::uint64_t ret_to = cpu.rip;   // caller resumes at current RIP
    auto w = writer.write(writer.ctx, callee_rsp, &ret_to, 8);
    if (!w.ok()) return w;

    cpu.set_reg(Gpr::Sp, callee_rsp);
    cpu.rip = callee_va;
    return Result<void>::ok_result();
}

Result<std::vector<ArgValue>> extract_args(const CpuState& cpu,
                                          const CallSpec& spec,
                                          const StackReader& reader) {
    if (reader.read64 == nullptr) {
        return Result<std::vector<ArgValue>>(RuntimeErrc::InvalidArgument,
                                             "null stack reader");
    }
    const auto valid = validate_call(spec);
    if (!valid.ok()) {
        return Result<std::vector<ArgValue>>(valid.errc(), valid.context());
    }
    std::vector<ArgValue> out;
    out.reserve(spec.args.size());
    std::uint32_t gp_used = 0, stack_used = 0;
    // At a callee entry, [RSP] = return address; shadow at RSP+8..+40;
    // stack args at RSP+8+32... [MS-X64STACK].
    const std::uint64_t rsp = cpu.reg(Gpr::Sp);
    const std::uint64_t stack_args_base = rsp + 8 + kShadowSpaceBytes;
    for (std::size_t i = 0; i < spec.args.size(); ++i) {
        const auto& a = spec.args[i];
        ArgValue v;
        v.kind = a.kind;
        const bool fp = a.kind == ArgKind::F32 || a.kind == ArgKind::F64;
        if (fp) {
            const std::size_t pos = i;
            if (pos < kMaxRegArgs) {
                std::uint64_t bits = 0;
                for (int b = 7; b >= 0; --b) {
                    bits = (bits << 8) | cpu.xmm[pos][static_cast<std::size_t>(b)];
                }
                std::memcpy(&v.f64_v, &bits, 8);
            } else {
                auto slot = reader.read64(reader.ctx,
                                          stack_args_base + (stack_used++) * 8);
                if (!slot.ok()) {
                    return Result<std::vector<ArgValue>>(
                        slot.errc(), "stack arg " + std::to_string(i) +
                                         ": " + slot.error_string());
                }
                std::memcpy(&v.f64_v, &slot.value(), 8);
            }
            out.push_back(v);
            continue;
        }
        if (gp_used < kMaxRegArgs) {
            v.int_v = cpu.reg(kGpArgRegs[gp_used]);
            if (a.kind == ArgKind::Ptr) v.ptr_va = v.int_v;
            ++gp_used;
        } else {
            auto slot = reader.read64(reader.ctx,
                                       stack_args_base + (stack_used++) * 8);
            if (!slot.ok()) {
                return Result<std::vector<ArgValue>>(
                    slot.errc(), "stack arg " + std::to_string(i) + ": " +
                                     slot.error_string());
            }
            v.int_v = slot.value();
            if (a.kind == ArgKind::Ptr) v.ptr_va = v.int_v;
        }
        out.push_back(v);
    }
    return Result<std::vector<ArgValue>>(out);
}

Result<void> write_return(CpuState& cpu, const CallSpec& spec,
                          const ReturnValue& value) {
    // RAX for <= 64-bit scalars, XMM0 for FP [MS-X64CC].
    switch (value.kind) {
        case CallSpec::ReturnKind::Void:
            break;
        case CallSpec::ReturnKind::Int:
            cpu.set_reg(Gpr::Rax, value.int_v);
            break;
        case CallSpec::ReturnKind::F32:
        case CallSpec::ReturnKind::F64: {
            std::uint64_t bits = 0;
            std::memcpy(&bits, &value.f64_v, 8);
            for (int b = 0; b < 8; ++b) {
                cpu.xmm[0][static_cast<std::size_t>(b)] =
                    static_cast<std::uint8_t>(bits >> (8 * b));
            }
            break;
        }
        case CallSpec::ReturnKind::Hidden:
            // Hidden aggregate return: pointer returned in RAX [MS-X64CC].
            cpu.set_reg(Gpr::Rax, value.int_v);
            break;
    }
    if (value.kind != spec.ret) {
        // A Void spec must not carry a value; any other mismatch is a
        // marshalling error. (write_return performs its register writes
        // FIRST so the state stays consistent; the typed error stands.)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "return kind mismatch with the call spec");
    }
    // Pop the frame: RSP back to (caller RSP) = callee RSP + frame + 8.
    // The bridge passes the caller RSP through prepare_call's recorded
    // layout; here we accept the simple contract: RSP += 8 (return
    // address popped) and the CALLER restores the frame remainder
    // (documented: the caller owns its stack frame [MS-X64STACK]).
    const std::uint64_t rsp = cpu.reg(Gpr::Sp);
    if (rsp == 0 || rsp + 8 > (1ull << 63)) {
        return Result<void>(RuntimeErrc::InvalidArgument, "RSP overflow on return");
    }
    cpu.set_reg(Gpr::Sp, rsp + 8);
    return Result<void>::ok_result();
}

std::vector<std::string> check_preserved(const CpuState& before,
                                        const CpuState& after) {
    std::vector<std::string> violated;
    // Nonvolatile GP: RBX RBP RDI RSI R12-R15 [MS-X64CC].
    const Gpr nonvolatile[] = {Gpr::Rbx, Gpr::Bp, Gpr::Di, Gpr::Si,
                               Gpr::R12, Gpr::R13, Gpr::R14, Gpr::R15};
    for (Gpr r : nonvolatile) {
        if (before.reg(r) != after.reg(r)) {
            violated.push_back(std::string("nonvolatile ") +
                                cpu::gpr_to_name(r) + " clobbered");
        }
    }
    // Nonvolatile XMM6-15 (full 128 bits) [MS-X64CC].
    for (std::size_t i = 6; i < cpu::kXmmCount; ++i) {
        if (before.xmm[i] != after.xmm[i]) {
            violated.push_back("nonvolatile xmm" + std::to_string(i) +
                               " clobbered");
        }
    }
    return violated;
}

}  // namespace xbox2pc::rt::abi
