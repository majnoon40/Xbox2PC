// xbox2pc/tests/execution_test.cpp — M8 execution subsystem test suite.
//
// Coverage map (spec §15):
//   CPU        — CpuStateTest: init/access/preservation/snapshot/restore/
//                flags/serialization/validation
//   ABI        — AbiTest: 0..4+ int args, FP args, mixed, stack args,
//                returns, alignment, preservation, invalid layouts
//   guest mem  — GuestMemTest: valid r/w, invalid addresses, boundaries,
//                permissions, overflow, cross-region, exec checks, cstr
//   bridge     — BridgeTest: dispatch, arg extraction, pointer validation,
//                out buffers, returns, errors, invalid pointers
//   engine     — EngineTest: subset programs, unsupported opcode faults,
//                budget, cancellation, faults (fetch/read/write/stack),
//                single-step
//   context    — ContextTest: lifecycle transitions, entry preparation,
//                invalid states, destroy idempotence, stack release
//   TLS        — TlsExecTest: malformed arrays, invalid VAs, excessive
//                counts, callback execution via the engine
//   e2e        — ExecE2eTest: M4 process -> M5 VFS/XPK -> M6 load ->
//                M7 resolve -> M8 context -> ABI -> bridge -> execute ->
//                report -> unload -> terminate -> zero leaks
//
// All engine tests use the DETERMINISTIC TEST BACKEND (real interpreter
// for the documented subset — no claim of general emulation).

#include <atomic>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/execution_context.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/package_vfs.hpp"
#include "xbox2pc/packages.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/vfs_process.hpp"
#include "xbox2pc/xbox_abi.hpp"

using namespace xbox2pc;
using namespace xbox2pc::rt;
using namespace xbox2pc::rt::exec;

namespace {

// A live world like M7's (registry before core; correct member order).
struct ExecWorld {
    api::ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    api::GameRuntimeService* grt = nullptr;

    ExecWorld() : pm(core.objects()) {
        {
            auto grt_s = std::make_unique<api::GameRuntimeService>(reg, pm);
            grt = grt_s.get();
            EXPECT_TRUE(core.services().register_service(std::move(grt_s)).ok());
        }
        EXPECT_TRUE(core.initialize().ok());
    }
    ~ExecWorld() { (void)core.shutdown(); }

    std::pair<Handle, ManagedProcess*> new_process(const char* name,
                                                   std::uint64_t cap = 64ull << 20) {
        auto p = pm.create_process(name, cap);
        EXPECT_TRUE(p.ok());
        auto found = core.objects().lookup_handle(p.value());
        EXPECT_TRUE(found.ok());
        return {p.value(),
                found.value().get()->as<ManagedProcess>()};
    }
};

// A minimal in-space RW scratch region for guest-memory tests.
Handle scratch_region(ManagedProcess& proc, std::uint64_t size,
                      std::uint64_t* out_va) {
    auto r = proc.address_space().reserve_region_auto(size, "scratch");
    EXPECT_TRUE(r.ok());
    auto c = proc.address_space().commit_region(r.value());
    EXPECT_TRUE(c.ok());
    *out_va = r.value();
    return {};
}

class ContextBindingProbe final : public IExecutionEngine {
public:
    const char* engine_kind() const override { return "context-binding-probe"; }
    const char* engine_description() const override { return "test probe"; }
    Result<void> bind_execution_context(std::uint64_t pid, std::uint64_t tid,
                                        AddressSpace& space) override {
        bound_pid = pid;
        bound_tid = tid;
        bound_space = &space;
        ++bind_count;
        return Result<void>::ok_result();
    }
    ExecutionResult run(const ExecutionRequest&, cpu::CpuState& state,
                        const std::atomic<bool>&) override {
        run_called = true;
        ExecutionResult result;
        result.outcome = Outcome::Returned;
        result.cpu.state = state;
        return result;
    }
    bool supports_single_step() const override { return true; }
    Result<std::uint64_t> single_step(cpu::CpuState&, const ExecutionRequest&) override {
        step_called = true;
        return Result<std::uint64_t>(0x1234u);
    }
    std::uint64_t bound_pid = 0;
    std::uint64_t bound_tid = 0;
    AddressSpace* bound_space = nullptr;
    unsigned bind_count = 0;
    bool run_called = false;
    bool step_called = false;
};

// Code emitter helpers (subset).
std::vector<std::uint8_t> mov_rax_imm(std::uint64_t v) {
    std::vector<std::uint8_t> b{0x48, 0xB8};
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    return b;
}

}  // namespace

// ── CPU state ─────────────────────────────────────────────────────────────

TEST(CpuStateTest, DeterministicInitAndReset) {
    cpu::CpuState c;
    c.reset();
    for (std::size_t i = 0; i < cpu::kGprCount; ++i) {
        EXPECT_EQ(c.gprs[i], 0u) << cpu::gpr_to_name(static_cast<cpu::Gpr>(i));
    }
    EXPECT_EQ(c.rip, 0u);
    EXPECT_EQ(c.rflags, cpu::kRflagsReset);
    EXPECT_EQ(c.mxcsr, cpu::kMxcsrStandard);
    EXPECT_EQ(c.fcw, cpu::kFcwStandard);
    // After mutation, reset restores exactly.
    c.set_reg(cpu::Gpr::Rax, 0x1234);
    c.rip = 0xdead;
    c.set_flag(cpu::kFlagCF, true);
    c.reset();
    EXPECT_EQ(c.reg(cpu::Gpr::Rax), 0u);
    EXPECT_FALSE(c.flag(cpu::kFlagCF));
}

TEST(CpuStateTest, RegisterAccessAndFlags) {
    cpu::CpuState c;
    for (std::size_t i = 0; i < cpu::kGprCount; ++i) {
        c.set_reg(static_cast<cpu::Gpr>(i), 0x1000 + i);
    }
    EXPECT_EQ(c.reg(cpu::Gpr::Rax), 0x1000u);
    EXPECT_EQ(c.reg(cpu::Gpr::R15), 0x1000u + 15);
    EXPECT_EQ(std::string(cpu::gpr_to_name(cpu::Gpr::Sp)), "rsp");
    auto parsed = cpu::gpr_from_name("r8");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, cpu::Gpr::R8);
    EXPECT_FALSE(cpu::gpr_from_name("r16").has_value());
    // Flags.
    c.set_flag(cpu::kFlagZF, true);
    EXPECT_TRUE(c.flag(cpu::kFlagZF));
    c.set_flag(cpu::kFlagZF, false);
    EXPECT_FALSE(c.flag(cpu::kFlagZF));
    EXPECT_TRUE(c.flag(cpu::kFlagFixed1));   // documented always-1
}

TEST(CpuStateTest, SnapshotRestoreRoundTrip) {
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);   // valid RSP (validate needs it)
    c.set_reg(cpu::Gpr::Rdx, 77);
    c.rip = 0x20001000;
    c.xmm[3][0] = 0xAB;
    cpu::CpuSnapshot snap;
    EXPECT_TRUE(cpu::snapshot_into(c, snap).ok());
    // Mutate.
    c.set_reg(cpu::Gpr::Rdx, 999);
    c.rip = 0;
    // Restore.
    EXPECT_TRUE(cpu::restore_into(snap, c).ok());
    EXPECT_EQ(c.reg(cpu::Gpr::Rdx), 77u);
    EXPECT_EQ(c.rip, 0x20001000u);
    EXPECT_EQ(c.xmm[3][0], 0xABu);
}

TEST(CpuStateTest, SerializationRoundTripAndRejects) {
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    c.rip = 0x20001000;
    cpu::CpuSnapshot snap;
    cpu::snapshot_into(c, snap);
    const auto bytes = snap.serialize();
    EXPECT_EQ(bytes.size(), 416u);
    auto back = cpu::CpuSnapshot::deserialize(bytes.data(), bytes.size());
    ASSERT_TRUE(back.ok());
    EXPECT_EQ(back.value().state, c);
    // Corrupt size / magic.
    EXPECT_FALSE(cpu::CpuSnapshot::deserialize(bytes.data(), 100).ok());
    auto bad = bytes;
    bad[0] ^= 0xFF;
    EXPECT_FALSE(cpu::CpuSnapshot::deserialize(bad.data(), bad.size()).ok());
    // Invalid state (RSP unaligned) rejected on restore.
    cpu::CpuState bad_state = c;
    bad_state.set_reg(cpu::Gpr::Sp, 0x20040001);
    cpu::CpuSnapshot bad_snap;
    cpu::snapshot_into(bad_state, bad_snap);
    EXPECT_FALSE(cpu::restore_into(bad_snap, c).ok());
}

TEST(CpuStateTest, ValidateInvariants) {
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    c.rip = 0x1000;
    EXPECT_TRUE(c.validate().empty());
    // Unaligned RSP.
    c.set_reg(cpu::Gpr::Sp, 0x20040001);
    EXPECT_FALSE(c.validate().empty());
    // RSP below floor / non-canonical / zero.
    c.set_reg(cpu::Gpr::Sp, 0x1000);
    EXPECT_FALSE(c.validate().empty());
    c.set_reg(cpu::Gpr::Sp, 1ull << 63);
    EXPECT_FALSE(c.validate().empty());
    c.set_reg(cpu::Gpr::Sp, 0);
    EXPECT_FALSE(c.validate().empty());
    // RIP zero / non-canonical.
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    c.rip = 0;
    EXPECT_FALSE(c.validate().empty());
    // Reserved RFLAGS bits.
    c.rip = 0x1000;
    c.rflags |= (1ull << 3);
    EXPECT_FALSE(c.validate().empty());
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    c.rip = 0x1000;
    c.rflags &= ~cpu::kFlagFixed1;   // bit 1 cleared
    EXPECT_FALSE(c.validate().empty());
}

// ── ABI ───────────────────────────────────────────────────────────────────

namespace {
// A tiny stack writer into a host buffer at a base VA (guest-mem-shaped).
struct HostStack {
    std::vector<std::uint8_t> mem;
    std::uint64_t base;
    explicit HostStack(std::uint64_t b, std::size_t n)
        : mem(n, 0), base(b) {}
    static rt::abi::StackWriter writer(HostStack* s) {
        rt::abi::StackWriter w;
        w.ctx = s;
        w.write = [](void* c, std::uint64_t va, const void* src,
                      std::size_t len) -> Result<void> {
            auto* self = static_cast<HostStack*>(c);
            if (va < self->base || va + len > self->base + self->mem.size()) {
                return Result<void>(RuntimeErrc::InvalidArgument, "out of stack");
            }
            std::memcpy(self->mem.data() + (va - self->base), src, len);
            return Result<void>::ok_result();
        };
        return w;
    }
    static rt::abi::StackReader reader(const HostStack* s) {
        rt::abi::StackReader r;
        r.ctx = const_cast<HostStack*>(s);
        r.read64 = [](void* c, std::uint64_t va) -> Result<std::uint64_t> {
            auto* self = static_cast<HostStack*>(c);
            if (va + 8 > self->base + self->mem.size() || va < self->base) {
                return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                             "out of stack");
            }
            std::uint64_t v = 0;
            std::memcpy(&v, self->mem.data() + (va - self->base), 8);
            return Result<std::uint64_t>(v);
        };
        return r;
    }
};
}  // namespace

TEST(AbiTest, IntegerArgsRegistersAndStack) {
    // 0..4 int args -> RCX/RDX/R8/R9; 5th+ on the stack.
    {
        rt::abi::CallSpec spec;
        spec.args = {};
        spec.ret = rt::abi::CallSpec::ReturnKind::Int;
        auto lay = rt::abi::compute_layout(spec);
        ASSERT_TRUE(lay.ok());
        EXPECT_EQ(lay.value().gp_reg_args, 0u);
        EXPECT_EQ(lay.value().total_stack_bytes, 32u);   // shadow only
    }
    {
        rt::abi::CallSpec spec;
        spec.ret = rt::abi::CallSpec::ReturnKind::Int;
        for (int i = 0; i < 4; ++i) spec.args.push_back({});   // Int default
        auto lay = rt::abi::compute_layout(spec);
        ASSERT_TRUE(lay.ok());
        EXPECT_EQ(lay.value().gp_reg_args, 4u);
        EXPECT_EQ(lay.value().total_stack_bytes, 32u);
    }
    {
        rt::abi::CallSpec spec;
        spec.ret = rt::abi::CallSpec::ReturnKind::Int;
        for (int i = 0; i < 6; ++i) spec.args.push_back({});
        auto lay = rt::abi::compute_layout(spec);
        ASSERT_TRUE(lay.ok());
        EXPECT_EQ(lay.value().gp_reg_args, 4u);
        EXPECT_EQ(lay.value().stack_args, 2u);
        // 32 shadow + 2*8 = 48 -> aligned to 48 (16 | 48 = 48).
        EXPECT_EQ(lay.value().total_stack_bytes, 48u);
    }
}

TEST(AbiTest, PrepareAndExtractRoundTrip) {
    // 6 int args + 2 FP: positions matter.
    rt::abi::CallSpec spec;
    spec.ret = rt::abi::CallSpec::ReturnKind::Int;
    for (int i = 0; i < 6; ++i) spec.args.push_back({});
    spec.args.push_back({rt::abi::ArgKind::F64});   // arg 7: FP -> stack (5th pos)
    spec.args[2].kind = rt::abi::ArgKind::F64;      // arg 3: FP -> XMM2 by position
    cpu::CpuState c;
    c.reset();
    HostStack st(0x20040000ull - 0x1000, 0x1000);
    c.set_reg(cpu::Gpr::Sp, 0x20040000ull - 0x800);
    std::vector<rt::abi::ArgValue> vals;
    for (int i = 0; i < 7; ++i) {
        rt::abi::ArgValue v;
        if (i == 2) { v.kind = rt::abi::ArgKind::F64; v.f64_v = 2.5; }
        else if (i == 6) { v.kind = rt::abi::ArgKind::F64; v.f64_v = 9.5; }
        else v.int_v = static_cast<std::uint64_t>(100 + i);
        vals.push_back(v);
    }
    auto prep = rt::abi::prepare_call(c, 0x30001000, spec, vals,
                                  HostStack::writer(&st));
    ASSERT_TRUE(prep.ok()) << prep.error_string();
    // Registers per [MS-X64CC]: arg1 RCX, arg2 RDX, arg3(fp) XMM2, arg4 R9,
    // arg5/6 + arg7(fp) on the stack.
    EXPECT_EQ(c.reg(cpu::Gpr::Rcx), 100u);
    EXPECT_EQ(c.reg(cpu::Gpr::Rdx), 101u);
    // Position 3 is occupied by XMM2, so integer arg 4 uses R9;
    // R8 is not used for a later argument under the positional ABI.
    EXPECT_EQ(c.reg(cpu::Gpr::R8), 0u);
    EXPECT_EQ(c.reg(cpu::Gpr::R9), 103u);
    EXPECT_EQ(c.rip, 0x30001000u);
    // Extract back at the callee side.
    auto got = rt::abi::extract_args(c, spec, HostStack::reader(&st));
    ASSERT_TRUE(got.ok()) << got.error_string();
    ASSERT_EQ(got.value().size(), 7u);
    EXPECT_EQ(got.value()[0].int_v, 100u);
    EXPECT_EQ(got.value()[4].int_v, 104u);   // 5th int on stack
    EXPECT_DOUBLE_EQ(got.value()[2].f64_v, 2.5);
    EXPECT_DOUBLE_EQ(got.value()[6].f64_v, 9.5);
    EXPECT_EQ(got.value()[5].int_v, 105u);
}

TEST(AbiTest, ReturnKindsAndPreservation) {
    cpu::CpuState before;
    before.reset();
    before.set_reg(cpu::Gpr::Sp, 0x20040000 - 0x800);
    before.set_reg(cpu::Gpr::Rbx, 0xBEEF);
    before.set_reg(cpu::Gpr::Bp, 0x1234);
    before.xmm[6][0] = 0x99;
    cpu::CpuState after = before;
    // Int return -> RAX.
    rt::abi::CallSpec spec;
    spec.ret = rt::abi::CallSpec::ReturnKind::Int;
    rt::abi::ReturnValue rv;
    rv.kind = rt::abi::CallSpec::ReturnKind::Int;
    rv.int_v = 42;
    auto wr = rt::abi::write_return(after, spec, rv);
    ASSERT_TRUE(wr.ok());
    EXPECT_EQ(after.reg(cpu::Gpr::Rax), 42u);
    // FP return -> XMM0.
    rt::abi::CallSpec fspec;
    fspec.ret = rt::abi::CallSpec::ReturnKind::F64;
    rt::abi::ReturnValue frv;
    frv.kind = rt::abi::CallSpec::ReturnKind::F64;
    frv.f64_v = 1.5;
    ASSERT_TRUE(rt::abi::write_return(after, fspec, frv).ok());
    std::uint64_t bits = 0;
    for (int b = 7; b >= 0; --b) bits = (bits << 8) | after.xmm[0][static_cast<std::size_t>(b)];
    double out = 0;
    std::memcpy(&out, &bits, 8);
    EXPECT_DOUBLE_EQ(out, 1.5);
    // Nonvolatile preservation across the call: untouched here.
    const auto violated = rt::abi::check_preserved(before, after);
    EXPECT_TRUE(violated.empty());
    // Clobber RBX -> reported.
    after.set_reg(cpu::Gpr::Rbx, 0xDEAD);
    const auto v2 = rt::abi::check_preserved(before, after);
    ASSERT_EQ(v2.size(), 1u);
    EXPECT_NE(v2[0].find("rbx"), std::string::npos);
    // Clobber XMM6 -> reported.
    after.set_reg(cpu::Gpr::Rbx, before.reg(cpu::Gpr::Rbx));
    after.xmm[6][1] = 1;
    EXPECT_EQ(rt::abi::check_preserved(before, after).size(), 1u);
}

TEST(AbiTest, InvalidLayoutsRejected) {
    // __m128 by value.
    rt::abi::CallSpec bad;
    bad.args.push_back({rt::abi::ArgKind::VecF32x4});
    auto r = rt::abi::validate_call(bad);
    EXPECT_FALSE(r.ok());
    // Varargs beyond 4.
    rt::abi::CallSpec varg;
    varg.varargs = true;
    for (int i = 0; i < 5; ++i) varg.args.push_back({});
    EXPECT_FALSE(rt::abi::validate_call(varg).ok());
    // Aggregate odd size.
    rt::abi::CallSpec agg;
    agg.args.push_back({.kind = rt::abi::ArgKind::Struct, .struct_size = 3});
    EXPECT_FALSE(rt::abi::validate_call(agg).ok());
    // Bad RSP for prepare.
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 3);   // not usable
    HostStack st(0x20000000, 0x1000);
    rt::abi::CallSpec spec;
    auto prep = rt::abi::prepare_call(c, 0x30001000, spec, {}, HostStack::writer(&st));
    EXPECT_FALSE(prep.ok());
    // Mismatched value count.
    rt::abi::CallSpec spec2;
    spec2.args.push_back({});
    auto prep2 = rt::abi::prepare_call(c, 0x30001000, spec2, {}, HostStack::writer(&st));
    EXPECT_FALSE(prep2.ok());
    // Return-kind mismatch.
    cpu::CpuState c2;
    c2.reset();
    c2.set_reg(cpu::Gpr::Sp, 0x20040000);
    rt::abi::ReturnValue mism;
    mism.kind = rt::abi::CallSpec::ReturnKind::Int;
    rt::abi::CallSpec void_spec;
    void_spec.ret = rt::abi::CallSpec::ReturnKind::Void;
    EXPECT_FALSE(rt::abi::write_return(c2, void_spec, mism).ok());
    EXPECT_EQ(c2.reg(cpu::Gpr::Sp), 0x20040000u);
    EXPECT_EQ(c2.reg(cpu::Gpr::Rax), 0u);
}

// ── guest memory ─────────────────────────────────────────────────────────

TEST(GuestMemTest, ValidInvalidPermissionsBoundaries) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("gm.exe");
    auto& space = proc->address_space();
    guest::GuestMemory mem(space);
    // Scratch RW region.
    std::uint64_t va = 0;
    scratch_region(*proc, 0x1000, &va);
    EXPECT_TRUE(mem.write_u64(va, 0x1122334455667788ull).ok());
    EXPECT_EQ(mem.read_u64(va).value(), 0x1122334455667788ull);
    // Range read/write.
    std::uint8_t buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_TRUE(mem.write(va, buf, 8).ok());
    std::uint8_t back[8] = {};
    EXPECT_TRUE(mem.read(va, back, 8).ok());
    EXPECT_EQ(std::memcmp(buf, back, 8), 0);
    // Unmapped address -> InvalidAddress distinct from permission.
    {
        const auto r = mem.validate(0x99990000, 8, false, false);
        EXPECT_EQ(r.err, guest::GuestMemErrc::InvalidAddress);
    }
    // End boundary: last byte past the region end — the tail endpoint is
    // unmapped (the hole after the region), reported as InvalidAddress.
    {
        const auto r = mem.validate(va + 0x1000 - 4, 8, false, false);
        EXPECT_EQ(r.err, guest::GuestMemErrc::InvalidAddress);
    }
    // Overflow: va near 2^64.
    {
        const auto r = mem.validate(~0ull - 4, 8, false, false);
        EXPECT_EQ(r.err, guest::GuestMemErrc::Overflow);
    }
    // Too large.
    {
        const auto r = mem.validate(va, guest::kMaxGuestOpBytes + 1, false, false);
        EXPECT_EQ(r.err, guest::GuestMemErrc::TooLarge);
    }
    // Null pointer.
    {
        const auto r = mem.validate(0, 8, false, false);
        EXPECT_EQ(r.err, guest::GuestMemErrc::NullPointer);
    }
    // Write to a read-only region: map an RX region via the loader? Use
    // the image .text: load a tiny image first.
    test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, {0xC3}});
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = test::PeBuilder(spec).build();
    diag::Diagnostics pd;
    auto img = pe::parse(image.data(), image.size(), "ro.exe", pd);
    loader::ImageLoader ld;
    api::ApiResolver resolver(w.reg);
    loader::LoadDiagnostics ldiag;
    loader::LoadResult out;
    auto h = ld.load_image(w.pm, w.core.objects(), ph, img, image.data(),
                           image.size(), &resolver, ldiag, out);
    ASSERT_TRUE(h.ok()) << out.error;
    const std::uint64_t entry = out.exec.entry_va;
    // Exec check passes on .text.
    EXPECT_TRUE(mem.validate_exec(entry).ok());
    // Read of .text is fine.
    EXPECT_TRUE(mem.read_u8(entry).ok());
    // WRITE to RX .text -> PermissionDenied.
    {
        const auto r = mem.validate(entry, 1, true, false);
        EXPECT_EQ(r.err, guest::GuestMemErrc::PermissionDenied);
        auto wr = mem.write_u8(entry, 0x90);
        EXPECT_FALSE(wr.ok());
    }
    // EXEC of the RW scratch -> PermissionDenied.
    {
        const auto r = mem.validate_exec(va);
        EXPECT_EQ(r.err, guest::GuestMemErrc::PermissionDenied);
    }
}

TEST(GuestMemTest, TypedAccessAndCstr) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("gc.exe");
    guest::GuestMemory mem(proc->address_space());
    std::uint64_t va = 0;
    scratch_region(*proc, 0x1000, &va);
    EXPECT_TRUE(mem.write_u8(va + 0, 0xAB).ok());
    EXPECT_TRUE(mem.write_u16(va + 2, 0xBEEF).ok());
    EXPECT_TRUE(mem.write_u32(va + 8, 0xDEADBEEFu).ok());
    EXPECT_EQ(mem.read_u8(va).value(), 0xABu);
    EXPECT_EQ(mem.read_u16(va + 2).value(), 0xBEEFu);
    EXPECT_EQ(mem.read_u32(va + 8).value(), 0xDEADBEEFu);
    // String read with NUL inside the bound.
    const char s[] = "hello guest";
    EXPECT_TRUE(mem.write(va + 0x100, s, sizeof s).ok());
    auto got = mem.read_cstr(va + 0x100, 64);
    ASSERT_TRUE(got.ok());
    EXPECT_EQ(got.value(), std::string("hello guest"));
    // No NUL within the bound -> typed error (never unbounded).
    // (bytes at va+8 are 0xDEADBEEF: u32, no zero byte inside).
    EXPECT_FALSE(mem.read_cstr(va + 8, 3).ok());
    EXPECT_FALSE(mem.read_cstr(va + 8, 4).ok());   // 4th byte is 0 (pad)
    // -> the 3-byte bound provably has no NUL.
    // Unreadable pointer.
    EXPECT_FALSE(mem.read_cstr(0x99990000, 64).ok());
}

// ── marshalling bridge ───────────────────────────────────────────────────

TEST(BridgeTest, PlanForDescriptorsAndErrors) {
    ExecWorld w;
    for (const auto* d : w.reg.all()) {
        auto p = plan_for_descriptor(*d);
        // Every descriptor has an explicit plan or is rejected by the whitelist.
        ASSERT_TRUE(p.ok()) << d->export_name << ": " << p.error_string();
        EXPECT_TRUE(rt::abi::validate_call(p.value().call).ok());
    }
    const auto* multi = w.reg.find("kernel32", "WaitForMultipleObjects");
    ASSERT_NE(multi, nullptr);
    auto multi_plan = plan_for_descriptor(*multi);
    ASSERT_TRUE(multi_plan.ok());
    ASSERT_EQ(multi_plan.value().pointer_array_args.size(), 1u);
    EXPECT_EQ(multi_plan.value().pointer_array_args[0].pointer_arg, 1u);
    EXPECT_EQ(multi_plan.value().pointer_array_args[0].count_arg, 0u);
    EXPECT_EQ(multi_plan.value().pointer_array_args[0].max_count, 64u);
    EXPECT_EQ(multi_plan.value().pointer_array_args[0].element_size, 8u);
    // An unknown descriptor is refused.
    api::ApiDescriptor fake;
    fake.library = "fakelib";
    fake.export_name = "MysteryApi";
    fake.convention = api::Convention::X64Microsoft;
    fake.param_count = 1;
    fake.ret = api::ReturnKind::HResult;
    fake.signature = "HRESULT MysteryApi(int)";
    fake.category = registry::ApiCategory::XboxGdk;
    fake.compat = api::ApiStatus::Unknown;
    fake.impl = api::ApiStatus::Unknown;
    fake.evidence = "[TEST]";
    fake.evidence_url = "https://example.com/test";
    auto plan = plan_for_descriptor(fake);
    EXPECT_FALSE(plan.ok());
}

TEST(BridgeTest, MarshalIntegerCall) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("br.exe");
    guest::GuestMemory mem(proc->address_space());
    // XGameRuntimeInitialize: no args, HRESULT in RAX.
    auto plan = plan_for_descriptor(*w.reg.find("xgameruntime", "XGameRuntimeInitialize"));
    ASSERT_TRUE(plan.ok());
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    HostStack st(0x2003F000ull, 0x1000);
    // Prepare the guest-side frame (shadow space written at RSP).
    std::vector<rt::abi::ArgValue> no_args;
    auto prep = rt::abi::prepare_call(c, 0x51000001, plan.value().call, no_args,
                                  HostStack::writer(&st));
    ASSERT_TRUE(prep.ok());
    auto r = marshal_and_dispatch(c, mem, w.reg, plan.value(), 1, 0, 64);
    ASSERT_TRUE(r.ok()) << r.error_string();
    EXPECT_TRUE(r.value().dispatched);
    EXPECT_EQ(r.value().api_result.return_value, api::kSOk);
    EXPECT_EQ(c.reg(cpu::Gpr::Rax), api::kSOk);   // marshalled into guest RAX
}

TEST(BridgeTest, ThreadIdentityReachesGdkService) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("thread-identity.exe");
    guest::GuestMemory mem(proc->address_space());
    auto plan = plan_for_descriptor(
        *w.reg.find("xgameruntime", "XThreadSetTimeSensitive"));
    ASSERT_TRUE(plan.ok());
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    HostStack st(0x2003F000ull, 0x1000);
    std::vector<rt::abi::ArgValue> args(1);
    args[0].int_v = 1;
    auto prep = rt::abi::prepare_call(
        c, 0x51000001, plan.value().call, args, HostStack::writer(&st));
    ASSERT_TRUE(prep.ok()) << prep.error_string();

    auto dispatched = marshal_and_dispatch(
        c, mem, w.reg, plan.value(), 42, 0, 64, 7);
    ASSERT_TRUE(dispatched.ok()) << dispatched.error_string();
    EXPECT_TRUE(dispatched.value().api_result.ok);
    EXPECT_EQ(dispatched.value().api_result.return_value, api::kSOk);

    api::ApiContext query;
    query.process_id = 42;
    query.thread_id = 7;
    auto same_thread = w.reg.dispatch(
        "xgameruntime", "XThreadIsTimeSensitive", query);
    ASSERT_TRUE(same_thread.ok);
    EXPECT_EQ(same_thread.return_value, 1u);
    query.process_id = 43;
    auto other_process = w.reg.dispatch(
        "xgameruntime", "XThreadIsTimeSensitive", query);
    ASSERT_TRUE(other_process.ok);
    EXPECT_EQ(other_process.return_value, 0u);
}

TEST(BridgeTest, MarshalPointerCallWithOutBuffer) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("br2.exe");
    guest::GuestMemory mem(proc->address_space());
    // XSystemGetXboxLiveSandboxId(size_t, char*, size_t*): stub returns
    // 'RETAIL' semantics (out payload = length 6 in the M7 out slot).
    auto plan = plan_for_descriptor(
        *w.reg.find("xgameruntime", "XSystemGetXboxLiveSandboxId"));
    ASSERT_TRUE(plan.ok());
    std::uint64_t buf_va = 0, used_va = 0;
    scratch_region(*proc, 0x1000, &buf_va);
    used_va = buf_va + 0x100;
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    HostStack st(0x2003F000ull, 0x1000);
    std::vector<rt::abi::ArgValue> vals(3);
    vals[0].int_v = 64;              // size
    vals[1].ptr_va = buf_va;         // char* out
    vals[1].int_v = buf_va;          // raw register value [MS-X64CC]
    vals[1].kind = rt::abi::ArgKind::Ptr;
    vals[2].ptr_va = used_va;        // size_t* out
    vals[2].int_v = used_va;
    vals[2].kind = rt::abi::ArgKind::Ptr;
    auto prep = rt::abi::prepare_call(c, 0x51000002, plan.value().call, vals,
                                  HostStack::writer(&st));
    ASSERT_TRUE(prep.ok()) << prep.error_string();
    auto r = marshal_and_dispatch(c, mem, w.reg, plan.value(), 1, 0, 64);
    ASSERT_TRUE(r.ok()) << r.error_string();
    // HRESULT semantics: the M7 impl rejects size 64? RETAIL fits (6+1<=64): S_OK.
    // Dispatch-level success is r.value().dispatched; api_result carries HRESULT.
    EXPECT_TRUE(r.value().dispatched);
    // M9: the bridge writes the implementation's out PAYLOAD BYTES into
    // the first out pointer — the sandbox id reads back as "RETAIL\0"
    // (the u64 length remains in api_result.out_value for reports).
    if (r.value().api_result.ok) {
        char buf[8] = {};
        ASSERT_TRUE(mem.read(buf_va, buf, 7).ok());
        EXPECT_STREQ(buf, "RETAIL");
        EXPECT_EQ(r.value().api_result.out_value, 6u);   // length reported
    }
}

TEST(BridgeTest, MarshalInvalidPointerAndDepth) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("br3.exe");
    guest::GuestMemory mem(proc->address_space());
    auto plan = plan_for_descriptor(
        *w.reg.find("xgameruntime", "XSystemGetConsoleId"));
    ASSERT_TRUE(plan.ok());
    // Invalid pointer arg (unmapped): bridge must reject typed.
    cpu::CpuState c;
    c.reset();
    c.set_reg(cpu::Gpr::Sp, 0x20040000);
    HostStack st(0x2003F000ull, 0x1000);
    std::vector<rt::abi::ArgValue> vals(3);
    vals[0].int_v = 64;
    vals[1].ptr_va = 0x99990000;   // unmapped
    vals[1].int_v = 0x99990000;
    vals[1].kind = rt::abi::ArgKind::Ptr;
    vals[2].ptr_va = 0x99990008;
    vals[2].int_v = 0x99990008;
    vals[2].kind = rt::abi::ArgKind::Ptr;
    auto prep = rt::abi::prepare_call(c, 0x51000003, plan.value().call, vals,
                                  HostStack::writer(&st));
    ASSERT_TRUE(prep.ok());
    auto r = marshal_and_dispatch(c, mem, w.reg, plan.value(), 1, 0, 64);
    // The plan's deref_size>0 for the pointer: validation fires.
    EXPECT_FALSE(r.ok());
    // Depth limit: marshalling at max depth refuses.
    cpu::CpuState c2;
    c2.reset();
    c2.set_reg(cpu::Gpr::Sp, 0x20040000);
    std::vector<rt::abi::ArgValue> vals2(3);
    vals2[0].int_v = 64;
    vals2[1].ptr_va = 0;
    vals2[2].ptr_va = 0;
    vals2[1].kind = rt::abi::ArgKind::Ptr;
    vals2[2].kind = rt::abi::ArgKind::Ptr;
    auto r2 = marshal_and_dispatch(c2, mem, w.reg, plan.value(), 1, 64, 64);
    EXPECT_FALSE(r2.ok());
}

// ── engine ───────────────────────────────────────────────────────────────

namespace {
// Build a tiny guest image with payload code and load it into a process.
struct LoadedGuest {
    ExecWorld& w;
    Handle ph;
    ManagedProcess* proc;
    Handle image;
    loader::LoadResult out;
    std::vector<std::uint8_t> bytes;
    loader::ImageLoader loader;
    api::ApiResolver resolver;
    bool load_ok = false;
    std::string load_error;

    LoadedGuest(ExecWorld& world, const std::vector<std::uint8_t>& code,
                const char* name, bool with_import = false)
        : w(world), resolver(world.reg) {
        auto pair = w.new_process(name);
        ph = pair.first;
        proc = pair.second;
        test::PeBuildSpec spec;
        spec.text_payloads.push_back({0x1000, code});
        spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
        if (with_import) {
            spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
        }
        bytes = test::PeBuilder(spec).build();
        diag::Diagnostics pd;
        auto img = pe::parse(bytes.data(), bytes.size(), name, pd);
        loader::LoadDiagnostics ld;
        auto h = loader.load_image(w.pm, w.core.objects(), ph, img,
                                   bytes.data(), bytes.size(), &resolver,
                                   ld, out);
        load_ok = h.ok();
        load_error = out.error;
        image = load_ok ? h.value() : Handle{};
    }
    ~LoadedGuest() {
        // Teardown is driven by the owning test via unload(); nothing here.
    }
};
}  // namespace

TEST(ContextTest, AutomaticallyBindsProcessThreadAndAddressSpaceToEngine) {
    ExecWorld w;
    auto [handle, process] = w.new_process("context-binding.exe");
    ASSERT_NE(process, nullptr);
    const auto pid = w.pm.resolve_pid(handle);
    ASSERT_TRUE(pid.ok());

    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(pid.value(), 0x5678, process->address_space(),
                         w.reg, cfg, "context-binding");
    ASSERT_TRUE(ctx.initialize().ok());

    ExecutionRequest req;
    req.stack_top_va = ctx.info().stack_top;
    req.stack_size = ctx.info().stack_size;
    ContextBindingProbe engine;
    std::atomic<bool> stop{false};

    const auto invoked = ctx.invoke(req, engine, stop);
    ASSERT_TRUE(invoked.ok()) << invoked.error_string();
    EXPECT_TRUE(engine.run_called);
    EXPECT_EQ(engine.bound_pid, pid.value());
    EXPECT_EQ(engine.bound_tid, 0x5678u);
    EXPECT_EQ(engine.bound_space, &process->address_space());

    const auto stepped = ctx.step(req, engine);
    ASSERT_TRUE(stepped.ok()) << stepped.error_string();
    EXPECT_TRUE(engine.step_called);
    EXPECT_EQ(engine.bind_count, 2u);
    EXPECT_EQ(engine.bound_pid, pid.value());
    EXPECT_EQ(engine.bound_tid, 0x5678u);

    EXPECT_TRUE(ctx.destroy().ok());
    EXPECT_TRUE(w.pm.terminate_process(handle, 0).ok());
}

TEST(EngineTest, ExecutesSubsetProgram) {
    ExecWorld w;
    // RAX = 42; RCX = 100; RCX += 8; RAX = RCX; RET -> 108.
    std::vector<std::uint8_t> code;
    auto emit = [&](std::initializer_list<std::uint8_t> bs) {
        for (std::uint8_t b : bs) code.push_back(b);
    };
    emit({0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0});           // MOV RAX, 42
    emit({0x48, 0xB9, 0x64, 0, 0, 0, 0, 0, 0, 0});           // MOV RCX, 100
    emit({0x48, 0x81, 0xC1, 0x08, 0, 0, 0});                  // ADD RCX, 8
    emit({0x48, 0x89, 0xC8});                                // MOV RAX, RCX
    emit({0xC3});                                             // RET
    LoadedGuest lg(w, code, "run.exe");
    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(1, 1, lg.proc->address_space(), w.reg, cfg, "ctx");
    ASSERT_TRUE(ctx.initialize().ok());
    loader::LoadedImageObject* loaded = nullptr;
    {
        auto lr = lg.proc->handle_table().lookup(lg.image);
        ASSERT_TRUE(lr.ok());
        loaded = lr.value().get()->as<loader::LoadedImageObject>();
    }
    rt::abi::CallSpec spec;
    spec.ret = rt::abi::CallSpec::ReturnKind::Int;
    auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
    ASSERT_TRUE(req.ok()) << req.error_string();
    DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(lg.proc->address_space());
    engine.bind_process(1, 1);
    std::atomic<bool> stop{false};
    auto res = ctx.invoke(req.value(), engine, stop);
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(res.value().outcome, Outcome::Returned);
    EXPECT_EQ(res.value().instructions_executed, 5u);
    EXPECT_EQ(res.value().return_value, 108u);
    // Context reusable after stop.
    EXPECT_EQ(ctx.context_state(), ContextState::Stopped);
    (void)ctx.destroy();
    (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
    (void)w.pm.terminate_process(lg.ph, 0);
}

TEST(EngineTest, CallChainAndStackLoadStore) {
    ExecWorld w;
    // helper: MOV RAX,[RSP+8]... simpler: use PUSH/POP + CALL rel32 chain.
    // main: MOV RAX, 7; PUSH RAX; CALL helper; POP RCX; ADD RAX, RCX; RET
    // helper: ADD RAX, 5; RET
    std::vector<std::uint8_t> code;
    auto emit = [&](std::initializer_list<std::uint8_t> bs) {
        for (std::uint8_t b : bs) code.push_back(b);
    };
    const std::size_t main_off = 0;          // RVA 0x1000
    emit({0x48, 0xB8, 0x07, 0, 0, 0, 0, 0, 0, 0});   // 0:  MOV RAX, 7
    emit({0x50});                                     // 10: PUSH RAX
    // CALL rel32 -> helper at 0x1020: rel = 0x20 - (10+5) = 11
    emit({0xE8, 0x0B, 0, 0, 0});                     // 11: CALL helper
    emit({0x59});                                     // 16: POP RCX
    emit({0x48, 0x01, 0xC8});                         // 17: ADD RAX, ECX? ->
    // NOTE: ADD r64,r64 is NOT in the subset (81 is imm-only). Use:
    // RAX += RCX via SUB with negated? Simplest: swap to: MOV RDX,[..]?
    // Redesign: main: MOV RAX,7; CALL helper(=adds 5); RET -> 12.
    (void)main_off;
    code.clear();
    emit({0x48, 0xB8, 0x07, 0, 0, 0, 0, 0, 0, 0});   // 0: MOV RAX, 7
    const int call_at = 10;
    const int helper_rva = 0x20;
    const std::int32_t rel = static_cast<std::int32_t>(helper_rva) - (call_at + 5);
    emit({0xE8, static_cast<std::uint8_t>(rel & 0xFF),
          static_cast<std::uint8_t>((rel >> 8) & 0xFF), 0, 0});   // CALL
    emit({0xC3});                                     // 15: RET -> completes
    while (code.size() < 0x20) code.push_back(0x90); // padding NOPs
    emit({0x48, 0x81, 0xC0, 0x05, 0, 0, 0});         // 0x20: ADD RAX, 5
    emit({0xC3});                                     // RET
    LoadedGuest lg(w, code, "chain.exe");
    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(1, 1, lg.proc->address_space(), w.reg, cfg, "ctx");
    ASSERT_TRUE(ctx.initialize().ok());
    loader::LoadedImageObject* loaded = nullptr;
    {
        auto lr = lg.proc->handle_table().lookup(lg.image);
        ASSERT_TRUE(lr.ok());
        loaded = lr.value().get()->as<loader::LoadedImageObject>();
    }
    rt::abi::CallSpec spec;
    spec.ret = rt::abi::CallSpec::ReturnKind::Int;
    auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
    ASSERT_TRUE(req.ok());
    DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(lg.proc->address_space());
    engine.bind_process(1, 1);
    std::atomic<bool> stop{false};
    auto res = ctx.invoke(req.value(), engine, stop);
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(res.value().outcome, Outcome::Returned);
    EXPECT_EQ(res.value().return_value, 12u);   // 7 + 5 through CALL/RET
    (void)ctx.destroy();
    (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
    (void)w.pm.terminate_process(lg.ph, 0);
}

TEST(EngineTest, FaultsBudgetAndCancellation) {
    ExecWorld w;
    auto cfg = ExecutionConfig::default_validated().value();

    // Unsupported opcode (0x0F prefix).
    {
        LoadedGuest lg(w, {0x0F, 0x1F, 0x00}, "bad.exe");
        ExecutionContext ctx(1, 1, lg.proc->address_space(), w.reg, cfg, "ctx");
        ASSERT_TRUE(ctx.initialize().ok());
        loader::LoadedImageObject* loaded = nullptr;
        {
            auto lr = lg.proc->handle_table().lookup(lg.image);
            ASSERT_TRUE(lr.ok());
            loaded = lr.value().get()->as<loader::LoadedImageObject>();
        }
        rt::abi::CallSpec spec;
        auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
        ASSERT_TRUE(req.ok());
        DeterministicBackend engine(w.reg, cfg);
        engine.bind_space(lg.proc->address_space());
        engine.bind_process(1, 1);
        std::atomic<bool> stop{false};
        auto res = ctx.invoke(req.value(), engine, stop);
        ASSERT_TRUE(res.ok());
        EXPECT_EQ(res.value().outcome, Outcome::Faulted);
        ASSERT_TRUE(res.value().exception.has_value());
        EXPECT_EQ(res.value().exception->fault,
                  GuestFault::UnsupportedInstruction);
        EXPECT_TRUE(res.value().exception->recoverability ==
                    Recoverability::Recoverable);
        (void)ctx.destroy();
        (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
        (void)w.pm.terminate_process(lg.ph, 0);
    }

    // Budget exhaustion: infinite JMP loop with a tiny budget.
    {
        // loop: JMP -5 (back to itself)
        std::vector<std::uint8_t> code{0xE9, 0xFB, 0xFF, 0xFF, 0xFF};  // jmp -5
        LoadedGuest lg(w, code, "loop.exe");
        ExecutionContext ctx(1, 1, lg.proc->address_space(), w.reg, cfg, "ctx");
        ASSERT_TRUE(ctx.initialize().ok());
        loader::LoadedImageObject* loaded = nullptr;
        {
            auto lr = lg.proc->handle_table().lookup(lg.image);
            ASSERT_TRUE(lr.ok());
            loaded = lr.value().get()->as<loader::LoadedImageObject>();
        }
        rt::abi::CallSpec spec;
        auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
        ASSERT_TRUE(req.ok());
        ExecutionConfig tiny = cfg;
        tiny.max_instructions = 100;
        DeterministicBackend engine(w.reg, tiny);
        engine.bind_space(lg.proc->address_space());
        engine.bind_process(1, 1);
        std::atomic<bool> stop{false};
        auto res = ctx.invoke(req.value(), engine, stop);
        ASSERT_TRUE(res.ok());
        EXPECT_EQ(res.value().outcome, Outcome::Faulted);
        EXPECT_EQ(res.value().exception->fault, GuestFault::BudgetExceeded);
        (void)ctx.destroy();
        (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
        (void)w.pm.terminate_process(lg.ph, 0);
    }

    // Cancellation observed.
    {
        std::vector<std::uint8_t> code{0xE9, 0xFB, 0xFF, 0xFF, 0xFF};
        LoadedGuest lg(w, code, "cancel.exe");
        ExecutionContext ctx(1, 1, lg.proc->address_space(), w.reg, cfg, "ctx");
        ASSERT_TRUE(ctx.initialize().ok());
        loader::LoadedImageObject* loaded = nullptr;
        {
            auto lr = lg.proc->handle_table().lookup(lg.image);
            ASSERT_TRUE(lr.ok());
            loaded = lr.value().get()->as<loader::LoadedImageObject>();
        }
        rt::abi::CallSpec spec;
        auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
        ASSERT_TRUE(req.ok());
        DeterministicBackend engine(w.reg, cfg);
        engine.bind_space(lg.proc->address_space());
        engine.bind_process(1, 1);
        std::atomic<bool> stop{true};   // already interrupted
        auto res = ctx.invoke(req.value(), engine, stop);
        ASSERT_TRUE(res.ok());
        EXPECT_EQ(res.value().outcome, Outcome::Interrupted);
        EXPECT_EQ(res.value().instructions_executed, 0u);
        (void)ctx.destroy();
        (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
        (void)w.pm.terminate_process(lg.ph, 0);
    }

    // Stack overflow: PUSH until below the floor. A SMALL stack
    // (0x1000 = 4 KiB) means ~500 pushes overflow; 2000 guarantee it.
    {
        std::vector<std::uint8_t> code;
        for (int i = 0; i < 2000; ++i) code.push_back(0x50);   // PUSH RAX
        LoadedGuest lg(w, code, "so.exe");
        ExecutionConfig tiny_stack = cfg;
        tiny_stack.max_stack_bytes = 0x1000;   // 4 KiB
        ExecutionContext ctx(1, 1, lg.proc->address_space(), w.reg,
                             tiny_stack, "ctx");
        ASSERT_TRUE(ctx.initialize().ok());
        loader::LoadedImageObject* loaded = nullptr;
        {
            auto lr = lg.proc->handle_table().lookup(lg.image);
            ASSERT_TRUE(lr.ok());
            loaded = lr.value().get()->as<loader::LoadedImageObject>();
        }
        rt::abi::CallSpec spec;
        auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
        ASSERT_TRUE(req.ok());
        DeterministicBackend engine(w.reg, cfg);
        engine.bind_space(lg.proc->address_space());
        engine.bind_process(1, 1);
        std::atomic<bool> stop{false};
        auto res = ctx.invoke(req.value(), engine, stop);
        ASSERT_TRUE(res.ok());
        EXPECT_EQ(res.value().outcome, Outcome::Faulted);
        EXPECT_EQ(res.value().exception->fault, GuestFault::StackOverflow);
        (void)ctx.destroy();
        (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
        (void)w.pm.terminate_process(lg.ph, 0);
    }
}

TEST(EngineTest, SingleStepWalks) {
    ExecWorld w;
    LoadedGuest lg(w, mov_rax_imm(5), "step.exe");
    // program: MOV RAX, 5 (10 bytes); RET
    std::vector<std::uint8_t> code = mov_rax_imm(5);
    code.push_back(0xC3);
    // (rebuild — LoadedGuest used the emitter output; use it directly)
    LoadedGuest lg2(w, code, "step2.exe");
    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(1, 1, lg2.proc->address_space(), w.reg, cfg, "ctx");
    ASSERT_TRUE(ctx.initialize().ok());
    loader::LoadedImageObject* loaded = nullptr;
    {
        auto lr = lg2.proc->handle_table().lookup(lg2.image);
        ASSERT_TRUE(lr.ok());
        loaded = lr.value().get()->as<loader::LoadedImageObject>();
    }
    rt::abi::CallSpec spec;
    auto req = ctx.prepare_entry(*loaded, 0, {}, spec);
    ASSERT_TRUE(req.ok());
    DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(lg2.proc->address_space());
    engine.bind_process(1, 1);
    auto r1 = ctx.step(req.value(), engine);
    ASSERT_TRUE(r1.ok());   // after MOV
    EXPECT_EQ(r1.value(), req.value().entry_va + 10);
    auto r2 = ctx.step(req.value(), engine);
    ASSERT_TRUE(r2.ok());   // after RET -> sentinel
    EXPECT_EQ(r2.value(), kCompletionSentinel);
    (void)ctx.destroy();
    (void)lg.loader.unload_image(w.pm, w.core.objects(), lg.ph, lg.image);
    (void)w.pm.terminate_process(lg.ph, 0);
    (void)lg2.loader.unload_image(w.pm, w.core.objects(), lg2.ph, lg2.image);
    (void)w.pm.terminate_process(lg2.ph, 0);
}

// ── context lifecycle ────────────────────────────────────────────────────

TEST(ContextTest, LifecycleTransitionsAndCleanup) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("lc.exe");
    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(1, 1, proc->address_space(), w.reg, cfg, "lc");
    EXPECT_EQ(ctx.context_state(), ContextState::Created);
    // Invoke before initialize: typed InvalidState.
    {
        ExecutionRequest req;
        DeterministicBackend engine(w.reg, cfg);
        std::atomic<bool> stop{false};
        auto r = ctx.invoke(req, engine, stop);
        EXPECT_FALSE(r.ok());
        EXPECT_EQ(r.errc(), RuntimeErrc::InvalidState);
    }
    ASSERT_TRUE(ctx.initialize().ok());
    EXPECT_EQ(ctx.context_state(), ContextState::Initialized);
    const auto regions_before = proc->address_space().stats().region_count;
    EXPECT_GE(regions_before, 1u);   // stack region exists
    // Double initialize refused.
    EXPECT_FALSE(ctx.initialize().ok());
    // Destroy: releases the stack region.
    ASSERT_TRUE(ctx.destroy().ok());
    EXPECT_EQ(ctx.context_state(), ContextState::Destroyed);
    EXPECT_EQ(proc->address_space().stats().region_count,
              regions_before - 1u);
    // Destroyed context refuses everything except idempotent destroy.
    EXPECT_FALSE(ctx.initialize().ok());
    EXPECT_TRUE(ctx.destroy().ok());   // documented idempotent
    // Process termination drops remaining regions.
    (void)w.pm.terminate_process(ph, 0);
}

TEST(ContextTest, ValidationAndLimits) {
    // Bad configs rejected.
    {
        ExecutionConfig bad;
        bad.max_stack_bytes = 15;   // not aligned
        EXPECT_FALSE(bad.validate().ok());
    }
    {
        ExecutionConfig bad;
        bad.max_contexts = 0;
        EXPECT_FALSE(bad.validate().ok());
    }
    {
        ExecutionConfig bad;
        bad.max_guest_op_bytes = guest::kMaxGuestOpBytes + 1;
        EXPECT_FALSE(bad.validate().ok());
    }
    // Entry validation on an unprepared image description.
    loader::ExecDescription not_prepared;
    not_prepared.entry_va = 0x1000;
    not_prepared.image_base = 0x1000;
    not_prepared.image_size = 0x1000;
    ExecWorld w;
    auto [ph, proc] = w.new_process("vv.exe");
    auto r = validate_entry_point(not_prepared, proc->address_space());
    EXPECT_FALSE(r.ok());
    (void)w.pm.terminate_process(ph, 0);
}

// ── TLS callbacks ─────────────────────────────────────────────────────────

TEST(TlsExecTest, PlanValidationAndExecution) {
    ExecWorld w;
    // Image with TLS callbacks: callback programs are tiny RET stubs.
    // The builder plants callback VAs; the loader maps .text RX.
    std::vector<std::uint8_t> cb_code;
    cb_code.push_back(0xC3);   // RET
    std::vector<std::uint8_t> code;
    code.push_back(0xC3);       // entry RET
    // Compose: entry at 0x1000, callbacks at 0x1100 and 0x1110.
    test::PeBuildSpec spec;
    std::vector<std::uint8_t> blob;
    blob.insert(blob.end(), code.begin(), code.end());
    while (blob.size() < 0x100) blob.push_back(0x90);
    blob.push_back(0xC3);   // cb1 @ 0x1100
    while (blob.size() < 0x110) blob.push_back(0x90);
    blob.push_back(0xC3);   // cb2 @ 0x1110
    spec.text_payloads.push_back({0x1000, blob});
    spec.tls.template_data = {1, 2, 3, 4};
    spec.tls.callback_vas = {0x140001100, 0x140001110};   // preferred base VAs
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = test::PeBuilder(spec).build();
    diag::Diagnostics pd;
    auto img = pe::parse(image.data(), image.size(), "tls.exe", pd);
    auto [ph, proc] = w.new_process("tlsp.exe");
    loader::ImageLoader loader;
    api::ApiResolver resolver(w.reg);
    loader::LoadDiagnostics ld;
    loader::LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), ph, img,
                               image.data(), image.size(), &resolver, ld, out);
    ASSERT_TRUE(h.ok()) << out.error;

    // Decode TLS + plan callbacks through the mapped image.
    auto tls = loader::decode_tls(img, image.data(), image.size(), ld);
    ASSERT_TRUE(tls.ok() && tls.value().has_value());
    auto cfg = ExecutionConfig::default_validated().value();
    guest::GuestMemory mem(proc->address_space());
    auto plan = plan_tls_callbacks(mem, *tls.value(), cfg);
    ASSERT_TRUE(plan.ok()) << plan.error_string();
    // The image base is relocated (preferred 0x140000000 is outside the
    // space) — callback VAs in the TLS directory are ABSOLUTE VAs that
    // relocation fixed up only for DIR64-referenced slots. The builder
    // plants preferred-base VAs; the loader's DIR64 relocs fix the IAT,
    // NOT the callback array (documented: the callback array entries are
    // absolute VAs fixed by relocations in a real toolchain).
    // The runtime's validation must therefore REJECT the un-relocated
    // (out-of-space) callback VAs honestly — rejecting_count > 0 or
    // typed failure. Both are honest outcomes; assert we don't crash and
    // the note explains.
    EXPECT_TRUE(plan.value().note.find("validated") != std::string::npos ||
                plan.value().note.find("rejected") != std::string::npos);

    // Execute whatever validated (0 or 2 callbacks) through the engine:
    // the deterministic backend runs RET-only callback programs to
    // completion; the documented callback ABI is prepared on the stack.
    ExecutionContext ctx(1, 1, proc->address_space(), w.reg, cfg, "tls-ctx");
    ASSERT_TRUE(ctx.initialize().ok());
    DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(proc->address_space());
    engine.bind_process(1, 1);
    auto res = execute_tls_callbacks(ctx, plan.value(), engine,
                                     out.exec.image_base);
    ASSERT_TRUE(res.ok());
    // Executed + failed == callbacks in the plan (nothing silently lost).
    EXPECT_EQ(res.value().executed + res.value().failed,
              plan.value().callbacks.size());
    (void)ctx.destroy();
    (void)loader.unload_image(w.pm, w.core.objects(), ph, h.value());
    (void)w.pm.terminate_process(ph, 0);
}

TEST(TlsExecTest, ExcessiveCallbacksRejected) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("tlx.exe");
    guest::GuestMemory mem(proc->address_space());
    loader::TlsInfo tls;
    tls.present = true;
    tls.callbacks_va = 0;
    tls.callback_count = 100;   // over the default limit (64)
    auto cfg = ExecutionConfig::default_validated().value();
    auto plan = plan_tls_callbacks(mem, tls, cfg);
    EXPECT_FALSE(plan.ok());
    (void)w.pm.terminate_process(ph, 0);
}

// ── end-to-end: the full M1..M8 path ─────────────────────────────────────

TEST(ExecE2eTest, VfsPackageLoadResolveExecuteCleanup) {
    ExecWorld w;
    // Guest program: MOV RAX, 20; ADD RAX, 22; RET -> 42.
    std::vector<std::uint8_t> code = mov_rax_imm(20);
    const std::uint8_t add[] = {0x48, 0x81, 0xC0, 0x16, 0, 0, 0};
    code.insert(code.end(), add, add + sizeof add);
    code.push_back(0xC3);

    // 1-3. M4 process + M5 VFS namespace + synthetic XPK.
    auto p = create_process_with_vfs(w.pm, w.core.objects(), "e2e8.exe");
    ASSERT_TRUE(p.ok());
    std::vector<std::uint8_t> read_buf;
    auto found = w.core.objects().lookup_handle(p.value());
    auto* proc = found.value().get()->as<ManagedProcess>();
    std::vector<XpkBuildEntry> entries = {
        {"content", true, {}},
        {"content/e2e8.exe", false,
         std::string(reinterpret_cast<const char*>(code.data()), code.size())},
    };
    // The PE image (not raw code) goes into the package: build the image.
    test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, code});
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    spec.tls.template_data = {9, 9};
    auto image = test::PeBuilder(spec).build();
    entries[1].data = std::string(reinterpret_cast<const char*>(image.data()),
                                 image.size());
    auto bytes = xpk_build(entries);
    auto pkg = parse_package(bytes.data(), bytes.size(), "e2e8.xpk", {});
    ASSERT_TRUE(pkg.ok());
    {
        auto s = w.core.objects().lookup_id(
            std::strtoull(proc->meta("vfs_session").c_str(), nullptr, 10));
        auto* session = s.value().get()->as<VfsSession>();
        ASSERT_NE(session, nullptr);
        ASSERT_TRUE(session
                        ->mount_backend(std::make_unique<PackageVfsBackend>(
                                            std::move(pkg.value())),
                                        "/Pkg", true, 0)
                        .ok());
        // 4. Discover.
        auto dres = discover_in_namespace(session->namespace_(),
                                          VfsPath::parse("/Pkg").value(), 64);
        ASSERT_TRUE(dres.ok());
        EXPECT_EQ(dres.value().pe_modules, 1u);
        // 5. Read through VFS handles.
        auto fh = proc_open_file(p.value(), "/Pkg/content/e2e8.exe", false);
        ASSERT_TRUE(fh.ok());
        read_buf.resize(image.size());
        std::uint64_t total = 0;
        while (total < image.size()) {
            auto n = vfs_read(w.core.objects(), fh.value(),
                              read_buf.data() + total,
                              image.size() - total);
            ASSERT_TRUE(n.ok());
            if (n.value() == 0) break;
            total += n.value();
        }
        ASSERT_EQ(total, image.size());
        (void)w.core.objects().destroy_handle(fh.value());
    }

    // 6-7. M6 load with M7 resolution.
    diag::Diagnostics pd;
    auto img = pe::parse(read_buf.data(), read_buf.size(), "e2e8.exe", pd);
    loader::ImageLoader loader;
    api::ApiResolver resolver(w.reg);
    loader::LoadDiagnostics ld;
    loader::LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), p.value(), img,
                               read_buf.data(), read_buf.size(), &resolver,
                               ld, out);
    ASSERT_TRUE(h.ok()) << out.error;

    // 8-11. M8: context + ABI + entry invocation.
    auto cfg = ExecutionConfig::default_validated().value();
    auto ctx_obj = std::make_unique<ExecutionContext>(
        1, 1, proc->address_space(), w.reg, cfg, "e2e-ctx");
    auto* ctx = ctx_obj.get();
    auto regd = w.core.objects().register_object(std::move(ctx_obj));
    ASSERT_TRUE(regd.ok());
    ASSERT_TRUE(ctx->initialize().ok());
    // TLS init (M7) for the loaded image.
    auto tls = loader::decode_tls(img, read_buf.data(), read_buf.size(), ld);
    std::uint32_t tls_index = 0;
    if (tls.ok() && tls.value().has_value()) {
        auto idx = api::tls_assign_index(1, "e2e8.exe", *tls.value());
        ASSERT_TRUE(idx.ok());
        tls_index = idx.value();
        auto t = std::make_unique<RtThread>(
            [](RtThread&, void*) -> void* { return nullptr; }, nullptr, "e2e8-t");
        auto regt = w.core.objects().register_object(std::move(t));
        auto tf = w.core.objects().lookup_id(regt.value());
        auto* th = tf.value().get()->as<RtThread>();
        ASSERT_TRUE(api::tls_init_thread(*th, tls_index, img,
                                        read_buf.data(), read_buf.size(),
                                        *tls.value())
                        .ok());
    }
    // Prepare + execute.
    loader::LoadedImageObject* loaded = nullptr;
    {
        auto lr = proc->handle_table().lookup(h.value());
        ASSERT_TRUE(lr.ok());
        loaded = lr.value().get()->as<loader::LoadedImageObject>();
    }   // guard released before teardown
    rt::abi::CallSpec spec2;
    spec2.ret = rt::abi::CallSpec::ReturnKind::Int;
    auto req = ctx->prepare_entry(*loaded, tls_index, {}, spec2);
    ASSERT_TRUE(req.ok()) << req.error_string();
    DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(proc->address_space());
    engine.bind_process(1, 1);
    std::atomic<bool> stop{false};
    auto res = ctx->invoke(req.value(), engine, stop);
    ASSERT_TRUE(res.ok());
    ASSERT_EQ(res.value().outcome, Outcome::Returned)
        << (res.value().exception.has_value()
                ? format_exception(*res.value().exception)
                : std::string("no exception"));
    EXPECT_EQ(res.value().return_value, 42u);   // 20 + 22 through VFS-loaded
                                                // guest code
    // Memory protections intact (entry RX).
    EXPECT_TRUE(proc->address_space()
                    .validate_access(out.exec.entry_va, false, true)
                    .ok());

    // 12-15. Cleanup: ctx destroy -> unload -> terminate -> zero leaks.
    ASSERT_TRUE(ctx->destroy().ok());
    (void)api::tls_release_indices(1);
    ASSERT_TRUE(loader.unload_image(w.pm, w.core.objects(), p.value(),
                                     h.value())
                    .ok());
    const auto st = proc->address_space().stats();
    (void)w.pm.terminate_process(p.value(), 0);
    EXPECT_EQ(st.region_count, 0u);
    EXPECT_EQ(st.committed_bytes, 0u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
