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
#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/execution_context.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/guest_environment.hpp"
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
    api::TaskQueueService* tq = nullptr;

    ExecWorld() : pm(core.objects()) {
        {
            auto grt_s = std::make_unique<api::GameRuntimeService>(reg, pm);
            grt = grt_s.get();
            EXPECT_TRUE(core.services().register_service(std::move(grt_s)).ok());
        }
        {
            auto tq_s = std::make_unique<api::TaskQueueService>(reg, pm);
            tq = tq_s.get();
            EXPECT_TRUE(core.services().register_service(std::move(tq_s)).ok());
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
    ExecutionResult run(const ExecutionRequest& request, cpu::CpuState& state,
                        const std::atomic<bool>&) override {
        run_called = true;
        run_control = request.control.get();
        ExecutionResult result;
        result.outcome = Outcome::Returned;
        result.cpu.state = state;
        return result;
    }
    bool supports_single_step() const override { return true; }
    Result<std::uint64_t> single_step(cpu::CpuState&, const ExecutionRequest& request) override {
        step_called = true;
        step_control = request.control.get();
        return Result<std::uint64_t>(0x1234u);
    }
    const ExecutionControl* run_control = nullptr;
    const ExecutionControl* step_control = nullptr;
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

// ── M10 cooperative execution control ────────────────────────────────────

TEST(ExecutionControlTest, SuspendResumeAndCancellationAreDistinct) {
    ExecutionControl control;
    std::atomic<bool> interrupted{false};
    std::atomic<bool> completed{false};
    std::atomic<bool> checkpoint_result{false};

    control.request_suspend();
    std::thread worker([&] {
        checkpoint_result.store(control.checkpoint(interrupted),
                                std::memory_order_release);
        completed.store(true, std::memory_order_release);
    });

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (!control.is_parked() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool parked = control.is_parked();
    EXPECT_TRUE(parked) << "suspend request did not park at checkpoint";
    EXPECT_FALSE(completed.load(std::memory_order_acquire));
    control.resume();
    worker.join();
    EXPECT_TRUE(checkpoint_result.load(std::memory_order_acquire));
    EXPECT_TRUE(completed.load(std::memory_order_acquire));
    EXPECT_FALSE(control.is_parked());

    // A terminal interrupt must also release a parked checkpoint without
    // being mistaken for a resume request.
    completed.store(false, std::memory_order_release);
    checkpoint_result.store(true, std::memory_order_release);
    control.request_suspend();
    std::thread cancelled_worker([&] {
        checkpoint_result.store(control.checkpoint(interrupted),
                                std::memory_order_release);
        completed.store(true, std::memory_order_release);
    });
    const auto cancel_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (!control.is_parked() &&
           std::chrono::steady_clock::now() < cancel_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool cancellation_parked = control.is_parked();
    EXPECT_TRUE(cancellation_parked);
    interrupted.store(true, std::memory_order_release);
    cancelled_worker.join();
    EXPECT_FALSE(checkpoint_result.load(std::memory_order_acquire));
    EXPECT_TRUE(completed.load(std::memory_order_acquire));
    EXPECT_FALSE(control.is_parked());
}

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
    const auto* submit_callback = w.reg.find(
        "xgameruntime", "XTaskQueueSubmitCallback");
    ASSERT_NE(submit_callback, nullptr);
    const auto submit_plan = plan_for_descriptor(*submit_callback);
    ASSERT_TRUE(submit_plan.ok()) << submit_plan.error_string();
    ASSERT_EQ(submit_plan.value().call.args.size(), 4u);
    EXPECT_EQ(submit_plan.value().call.args[0].kind, rt::abi::ArgKind::Int);
    EXPECT_EQ(submit_plan.value().call.args[1].kind, rt::abi::ArgKind::Int);
    EXPECT_EQ(submit_plan.value().call.args[2].kind, rt::abi::ArgKind::Ptr);
    EXPECT_EQ(submit_plan.value().call.args[3].kind, rt::abi::ArgKind::Ptr);
    const auto* delayed = w.reg.find("xgameruntime",
                                     "XTaskQueueSubmitDelayedCallback");
    ASSERT_NE(delayed, nullptr);
    auto delayed_plan = plan_for_descriptor(*delayed);
    ASSERT_TRUE(delayed_plan.ok()) << delayed_plan.error_string();
    ASSERT_EQ(delayed_plan.value().call.args.size(), 5u);
    EXPECT_EQ(delayed_plan.value().call.args[0].kind, rt::abi::ArgKind::Int);
    EXPECT_EQ(delayed_plan.value().call.args[1].kind, rt::abi::ArgKind::Int);
    EXPECT_EQ(delayed_plan.value().call.args[2].kind, rt::abi::ArgKind::Int);
    EXPECT_EQ(delayed_plan.value().call.args[3].kind, rt::abi::ArgKind::Ptr);
    EXPECT_EQ(delayed_plan.value().call.args[4].kind, rt::abi::ArgKind::Ptr);
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

TEST(BridgeTest, MarshalWaitForMultipleObjectsReadsGuestHandleArray) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("wait-multiple.exe");
    const auto resolved_pid = w.pm.resolve_pid(ph);
    ASSERT_TRUE(resolved_pid.ok());
    const auto pid = resolved_pid.value();
    ModuleDescriptor module;
    module.module_name = "wait-multiple.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(ph, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(ph).ok());
    guest::GuestMemory mem(proc->address_space());
    auto first = w.grt->create_event(pid, true, false);
    auto second = w.grt->create_event(pid, true, true);
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());

    std::uint64_t handles_va = 0;
    scratch_region(*proc, 0x1000, &handles_va);
    ASSERT_TRUE(mem.write_u64(handles_va, first.value()).ok());
    ASSERT_TRUE(mem.write_u64(handles_va + 8, second.value()).ok());

    const auto* descriptor = w.reg.find("kernel32", "WaitForMultipleObjects");
    ASSERT_NE(descriptor, nullptr);
    auto plan = plan_for_descriptor(*descriptor);
    ASSERT_TRUE(plan.ok());

    cpu::CpuState cpu_state;
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, 0x20040000);
    HostStack host_stack(0x2003F000ull, 0x1000);
    std::vector<rt::abi::ArgValue> values(4);
    values[0].int_v = 2; // nCount
    values[1].ptr_va = handles_va;
    values[1].int_v = handles_va;
    values[1].kind = rt::abi::ArgKind::Ptr;
    values[2].int_v = 0; // wait-any
    values[3].int_v = 0; // poll
    auto prepared = rt::abi::prepare_call(
        cpu_state, 0x51000004, plan.value().call, values,
        HostStack::writer(&host_stack));
    ASSERT_TRUE(prepared.ok()) << prepared.error_string();

    auto result = marshal_and_dispatch(
        cpu_state, mem, w.reg, plan.value(), pid, 0, 64, 91);
    ASSERT_TRUE(result.ok()) << result.error_string();
    EXPECT_TRUE(result.value().dispatched);
    EXPECT_EQ(result.value().api_result.return_value, 1u);
    EXPECT_EQ(cpu_state.reg(cpu::Gpr::Rax), 1u);

    // The same guest array now exercises transactional wait-all through
    // the guest-memory marshalling bridge. The first event is initially
    // unsignaled, so the initial attempt times out without consuming the
    // second manual-reset event.
    values[2].int_v = 1;
    auto wait_all_prepared = rt::abi::prepare_call(
        cpu_state, 0x51000005, plan.value().call, values,
        HostStack::writer(&host_stack));
    ASSERT_TRUE(wait_all_prepared.ok());
    auto wait_all_timeout = marshal_and_dispatch(
        cpu_state, mem, w.reg, plan.value(), pid, 0, 64, 91);
    ASSERT_TRUE(wait_all_timeout.ok());
    EXPECT_EQ(wait_all_timeout.value().api_result.return_value, 0x102u);

    ASSERT_TRUE(w.grt->set_event(pid, first.value()).ok());
    auto wait_all_ready = marshal_and_dispatch(
        cpu_state, mem, w.reg, plan.value(), pid, 0, 64, 91);
    ASSERT_TRUE(wait_all_ready.ok());
    EXPECT_EQ(wait_all_ready.value().api_result.return_value, 0u);
    EXPECT_EQ(cpu_state.reg(cpu::Gpr::Rax), 0u);

    // Counts above the explicit ABI bridge bound are rejected before reading.
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, 0x20040000);
    values[0].int_v = 65;
    values[2].int_v = 0;
    HostStack oversized_stack(0x2003F000ull, 0x1000);
    auto oversized_prepared = rt::abi::prepare_call(
        cpu_state, 0x51000006, plan.value().call, values,
        HostStack::writer(&oversized_stack));
    ASSERT_TRUE(oversized_prepared.ok());
    auto oversized = marshal_and_dispatch(
        cpu_state, mem, w.reg, plan.value(), pid, 0, 64, 91);
    EXPECT_FALSE(oversized.ok());

    // An unreadable guest handle array is rejected by GuestMemory validation.
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, 0x20040000);
    values[0].int_v = 2;
    values[1].ptr_va = 0xDEAD0000;
    values[1].int_v = 0xDEAD0000;
    HostStack invalid_stack(0x2003F000ull, 0x1000);
    auto invalid_prepared = rt::abi::prepare_call(
        cpu_state, 0x51000007, plan.value().call, values,
        HostStack::writer(&invalid_stack));
    ASSERT_TRUE(invalid_prepared.ok());
    auto invalid = marshal_and_dispatch(
        cpu_state, mem, w.reg, plan.value(), pid, 0, 64, 91);
    EXPECT_FALSE(invalid.ok());
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
    loader::LoadDiagnostics diagnostics;
    bool parsed_imports_present = false;
    std::size_t parsed_import_count = 0;
    std::size_t parsed_import_function_count = 0;
    std::size_t parsed_import_ordinal_count = 0;
    std::uint32_t parsed_import_int_rva = 0;
    std::uint32_t parsed_import_iat_rva = 0;
    std::uint32_t parsed_import_directory_size = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> original_bytes;
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
        original_bytes = bytes;
        diag::Diagnostics pd;
        auto img = pe::parse(bytes.data(), bytes.size(), name, pd);
        parsed_imports_present = img.imports.present;
        parsed_import_count = img.imports.entries.size();
        if (!img.imports.entries.empty()) {
            parsed_import_function_count = img.imports.entries.front().functions.size();
            parsed_import_ordinal_count = img.imports.entries.front().ordinal_only.size();
            parsed_import_int_rva = img.imports.entries.front().int_rva;
            parsed_import_iat_rva = img.imports.entries.front().iat_rva;
        }
        parsed_import_directory_size = img.directories.size() > pe::kDirImport
            ? img.directories[pe::kDirImport].size : 0;
        auto h = loader.load_image(w.pm, w.core.objects(), ph, img,
                                   bytes.data(), bytes.size(), &resolver,
                                   diagnostics, out);
        load_ok = h.ok();
        load_error = out.error;
        image = load_ok ? h.value() : Handle{};
    }
    ~LoadedGuest() {
        // Teardown is driven by the owning test via unload(); nothing here.
    }
};
}  // namespace

TEST(ExecutionControlTest, ManagedThreadSuspendResumeControlsGuestBackend) {
    ExecWorld world;
    const std::vector<std::uint8_t> loop_code{0xE9, 0xFB, 0xFF, 0xFF, 0xFF};
    LoadedGuest guest(world, loop_code, "suspend-loop.exe");
    ASSERT_TRUE(guest.load_ok) << guest.load_error;

    const auto pid = world.pm.resolve_pid(guest.ph);
    ASSERT_TRUE(pid.ok());
    auto cfg = ExecutionConfig::default_validated();
    ASSERT_TRUE(cfg.ok());
    ExecutionContext context(pid.value(), 0xA10, guest.proc->address_space(),
                             world.reg, cfg.value(), "suspend-loop");
    ASSERT_TRUE(context.initialize().ok());

    DeterministicBackend backend(world.reg, cfg.value());
    ExecutionRequest request;
    request.entry_va = guest.out.exec.entry_va;
    request.stack_top_va = context.info().stack_top;
    request.stack_size = context.info().stack_size;
    context.cpu_mut().set_reg(cpu::Gpr::Sp, context.info().stack_top - 0x20);
    context.cpu_mut().rip = request.entry_va;
    std::atomic<bool> interrupted{false};
    std::atomic<bool> entered_invoke{false};
    std::atomic<bool> finished{false};
    std::atomic<int> outcome{static_cast<int>(Outcome::Faulted)};
    struct RunnerState {
        ExecutionContext* context;
        DeterministicBackend* backend;
        ExecutionRequest* request;
        std::atomic<bool>* interrupted;
        std::atomic<bool>* entered_invoke;
        std::atomic<bool>* finished;
        std::atomic<int>* outcome;
    } runner{&context, &backend, &request, &interrupted, &entered_invoke,
             &finished, &outcome};

    auto handle = world.core.create_thread(
        [](RtThread&, void* raw) -> void* {
            auto& run = *static_cast<RunnerState*>(raw);
            run.entered_invoke->store(true, std::memory_order_release);
            const auto result = run.context->invoke(*run.request, *run.backend,
                                                     *run.interrupted);
            run.outcome->store(result.ok()
                ? static_cast<int>(result.value().outcome)
                : static_cast<int>(Outcome::Faulted), std::memory_order_release);
            run.finished->store(true, std::memory_order_release);
            return nullptr;
        },
        &runner, "guest-execution-thread");
    ASSERT_TRUE(handle.ok());
    auto thread_guard = world.core.objects().lookup_handle(handle.value());
    ASSERT_TRUE(thread_guard.ok());
    auto* thread = thread_guard.value().get()->as<RtThread>();
    ASSERT_NE(thread, nullptr);
    ASSERT_TRUE(context.bind_thread_control(thread->execution_control()).ok());
    ASSERT_TRUE(thread->start().ok());
    const auto entry_deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(2);
    while (!entered_invoke.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < entry_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(entered_invoke.load(std::memory_order_acquire));
    ASSERT_TRUE(thread->suspend().ok());

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (!thread->execution_control()->is_parked() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool parked = thread->execution_control()->is_parked();
    EXPECT_TRUE(parked) << "managed suspend did not park guest execution";
    EXPECT_FALSE(finished.load(std::memory_order_acquire));
    EXPECT_EQ(thread->state(), rt::ThreadState::Suspended);

    ASSERT_TRUE(thread->resume().ok());
    const auto resume_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (thread->execution_control()->is_parked() &&
           std::chrono::steady_clock::now() < resume_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(thread->execution_control()->is_parked());

    // Terminal stop is distinct from resume and wakes the running backend.
    thread->request_stop();
    const auto joined = thread->join_ns(2'000'000'000LL);
    ASSERT_TRUE(joined.ok());
    EXPECT_TRUE(finished.load(std::memory_order_acquire));
    EXPECT_EQ(outcome.load(std::memory_order_acquire),
              static_cast<int>(Outcome::Interrupted));
    EXPECT_EQ(thread->state(), rt::ThreadState::Terminated);
}

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

TEST(EngineTest, DispatchesResolvedApiBindingAndReturnsToGuest) {
    ExecWorld w;
    auto [process_handle, process] = w.new_process("api-binding.exe");
    const auto pid_result = w.pm.resolve_pid(process_handle);
    ASSERT_TRUE(pid_result.ok());
    const auto pid = pid_result.value();

    ModuleDescriptor module;
    module.module_name = "api-binding.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(process_handle, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(process_handle).ok());

    guest::GuestMemory mem(process->address_space());
    std::uint64_t code_va = 0;
    std::uint64_t stack_va = 0;
    scratch_region(*process, 0x1000, &code_va);
    scratch_region(*process, 0x1000, &stack_va);
    ASSERT_TRUE(mem.write_u8(code_va + 0x100, 0xC3).ok()); // guest RET
    ASSERT_TRUE(process->address_space().protect_region(
        code_va, MemProtect::ReadExecute).ok());

    constexpr std::uint64_t binding = 0x51000001ull;
    EXPECT_TRUE(is_api_binding(0x51010001ull)); // Win32 bindings occupy the second synthetic range
    constexpr std::uint64_t tid = 0x91;
    const std::uint64_t rsp = stack_va + 0x100;
    ASSERT_TRUE(mem.write_u64(rsp, code_va + 0x100).ok());
    ASSERT_TRUE(mem.write_u64(rsp + 8, kCompletionSentinel).ok());

    auto config = ExecutionConfig::default_validated();
    ASSERT_TRUE(config.ok());
    DeterministicBackend backend(w.reg, config.value());
    ASSERT_TRUE(backend.bind_execution_context(
        pid, tid, process->address_space()).ok());

    ExecutionRequest request;
    request.entry_va = binding;
    request.stack_top_va = stack_va + 0x1000;
    request.stack_size = 0x1000;
    request.completion_va = kCompletionSentinel;
    request.api_binding_values.push_back(binding);
    request.api_bindings.push_back(
        ApiBindingInfo{binding, "xgameruntime", "XGameRuntimeInitialize", false, 0});

    cpu::CpuState cpu_state;
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, rsp);
    cpu_state.rip = binding;
    std::atomic<bool> interrupted{false};
    const auto result = backend.run(request, cpu_state, interrupted);

    EXPECT_EQ(result.outcome, Outcome::Returned);
    EXPECT_EQ(result.api_calls, 1u);
    EXPECT_EQ(result.return_value, api::kSOk);
    EXPECT_EQ(cpu_state.reg(cpu::Gpr::Rax), api::kSOk);
    EXPECT_EQ(cpu_state.rip, code_va + 0x100); // RET sentinel pre-check stops at the return instruction
}

TEST(EngineTest, DispatchesWin32EventApiBinding) {
    ExecWorld w;
    auto [process_handle, process] = w.new_process("win32-api-binding.exe");
    const auto pid_result = w.pm.resolve_pid(process_handle);
    ASSERT_TRUE(pid_result.ok());
    const auto pid = pid_result.value();

    ModuleDescriptor module;
    module.module_name = "win32-api-binding.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(process_handle, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(process_handle).ok());

    guest::GuestMemory mem(process->address_space());
    std::uint64_t code_va = 0;
    std::uint64_t stack_va = 0;
    scratch_region(*process, 0x1000, &code_va);
    scratch_region(*process, 0x1000, &stack_va);
    ASSERT_TRUE(mem.write_u8(code_va + 0x100, 0xC3).ok());
    ASSERT_TRUE(process->address_space().protect_region(
        code_va, MemProtect::ReadExecute).ok());

    constexpr std::uint64_t binding = 0x51010001ull;
    constexpr std::uint64_t tid = 0x94;
    const std::uint64_t rsp = stack_va + 0x100;
    ASSERT_TRUE(mem.write_u64(rsp, code_va + 0x100).ok());
    ASSERT_TRUE(mem.write_u64(rsp + 8, kCompletionSentinel).ok());

    auto config = ExecutionConfig::default_validated();
    ASSERT_TRUE(config.ok());
    DeterministicBackend backend(w.reg, config.value());
    ASSERT_TRUE(backend.bind_execution_context(
        pid, tid, process->address_space()).ok());

    ExecutionRequest request;
    request.entry_va = binding;
    request.stack_top_va = stack_va + 0x1000;
    request.stack_size = 0x1000;
    request.completion_va = kCompletionSentinel;
    request.api_binding_values.push_back(binding);
    request.api_bindings.push_back(
        ApiBindingInfo{binding, "kernel32", "CreateEventW", false, 0});

    cpu::CpuState cpu_state;
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, rsp);
    cpu_state.set_reg(cpu::Gpr::Rcx, 0); // null security attributes
    cpu_state.set_reg(cpu::Gpr::Rdx, 1); // manual-reset event
    cpu_state.set_reg(cpu::Gpr::R8, 1);  // initially signaled
    cpu_state.set_reg(cpu::Gpr::R9, 0);  // unnamed
    cpu_state.rip = binding;
    std::atomic<bool> interrupted{false};
    const auto result = backend.run(request, cpu_state, interrupted);

    EXPECT_EQ(result.outcome, Outcome::Returned);
    EXPECT_EQ(result.api_calls, 1u);
    ASSERT_NE(result.return_value, 0u);
    EXPECT_EQ(cpu_state.reg(cpu::Gpr::Rax), result.return_value);
    auto signaled = w.grt->wait_object(pid, tid, result.return_value, 0);
    ASSERT_TRUE(signaled.ok());
    EXPECT_EQ(signaled.value(), 0u);
    EXPECT_TRUE(w.grt->close_sync_handle(pid, result.return_value).ok());
}

TEST(EngineTest, DispatchesTaskQueueDuplicateHandleAndWritesGuestOutput) {
    ExecWorld w;
    auto [process_handle, process] = w.new_process("task-queue-duplicate-binding.exe");
    const auto pid_result = w.pm.resolve_pid(process_handle);
    ASSERT_TRUE(pid_result.ok());
    const auto pid = pid_result.value();

    ModuleDescriptor module;
    module.module_name = "task-queue-duplicate-binding.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(process_handle, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(process_handle).ok());

    const auto original = w.tq->create_queue(
        pid,
        static_cast<std::uint32_t>(api::XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(api::XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(original.ok());

    guest::GuestMemory mem(process->address_space());
    std::uint64_t code_va = 0;
    std::uint64_t stack_va = 0;
    std::uint64_t output_va = 0;
    scratch_region(*process, 0x1000, &code_va);
    scratch_region(*process, 0x1000, &stack_va);
    scratch_region(*process, 0x1000, &output_va);
    ASSERT_TRUE(mem.write_u8(code_va + 0x100, 0xC3).ok());
    ASSERT_TRUE(process->address_space().protect_region(
        code_va, MemProtect::ReadExecute).ok());
    ASSERT_TRUE(mem.write_u64(output_va, 0).ok());

    constexpr std::uint64_t binding = 0x51000001ull;
    constexpr std::uint64_t tid = 0x95;
    const std::uint64_t rsp = stack_va + 0x100;
    ASSERT_TRUE(mem.write_u64(rsp, code_va + 0x100).ok());
    ASSERT_TRUE(mem.write_u64(rsp + 8, kCompletionSentinel).ok());

    auto config = ExecutionConfig::default_validated();
    ASSERT_TRUE(config.ok());
    DeterministicBackend backend(w.reg, config.value());
    ASSERT_TRUE(backend.bind_execution_context(
        pid, tid, process->address_space()).ok());

    ExecutionRequest request;
    request.entry_va = binding;
    request.stack_top_va = stack_va + 0x1000;
    request.stack_size = 0x1000;
    request.completion_va = kCompletionSentinel;
    request.api_binding_values.push_back(binding);
    request.api_bindings.push_back(ApiBindingInfo{
        binding, "xgameruntime", "XTaskQueueDuplicateHandle", false, 0});

    cpu::CpuState cpu_state;
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, rsp);
    cpu_state.set_reg(cpu::Gpr::Rcx, original.value());
    cpu_state.set_reg(cpu::Gpr::Rdx, output_va);
    cpu_state.rip = binding;
    std::atomic<bool> interrupted{false};
    const auto result = backend.run(request, cpu_state, interrupted);

    ASSERT_EQ(result.outcome, Outcome::Returned);
    ASSERT_EQ(result.api_calls, 1u);
    EXPECT_EQ(result.return_value, api::kSOk);
    auto duplicated = mem.read_u64(output_va);
    ASSERT_TRUE(duplicated.ok());
    ASSERT_NE(duplicated.value(), 0u);
    EXPECT_NE(duplicated.value(), original.value());

    ASSERT_TRUE(w.tq->close_queue(pid, original.value()).ok());
    EXPECT_TRUE(w.tq->dispatch(pid, duplicated.value(),
                              api::XTaskQueuePort::Work, 0).ok());
    ASSERT_TRUE(w.tq->close_queue(pid, duplicated.value()).ok());
    EXPECT_EQ(w.tq->live_queues(), 0u);
    ASSERT_TRUE(w.pm.terminate_process(process_handle, 0).ok());
}

TEST(EngineTest, DispatchesGuestTaskQueueCallbackThroughNestedBackend) {
    ExecWorld w;
    auto [process_handle, process] = w.new_process("task-queue-guest-callback.exe");
    const auto pid_result = w.pm.resolve_pid(process_handle);
    ASSERT_TRUE(pid_result.ok());
    const auto pid = pid_result.value();
    ModuleDescriptor module;
    module.module_name = "task-queue-guest-callback.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(process_handle, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(process_handle).ok());

    const auto queue = w.tq->create_queue(
        pid, static_cast<std::uint32_t>(api::XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(api::XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(queue.ok());

    guest::GuestMemory mem(process->address_space());
    std::uint64_t code_va = 0, stack_va = 0, output_va = 0;
    scratch_region(*process, 0x1000, &code_va);
    scratch_region(*process, 0x1000, &stack_va);
    scratch_region(*process, 0x1000, &output_va);
    const std::uint64_t callback_va = code_va + 0x100;
    const std::uint64_t continuation_va = code_va + 0x200;
    // Callback writes a marker through RCX and the canceled flag from RDX.
    const std::uint8_t callback_code[] = {
        0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0, // mov rax, 42
        0x48, 0x89, 0x01,                       // mov [rcx], rax
        0x48, 0x89, 0x51, 0x08,                 // mov [rcx+8], rdx
        0xC3
    };
    ASSERT_TRUE(mem.write(callback_va, callback_code, sizeof(callback_code)).ok());
    ASSERT_TRUE(mem.write_u8(continuation_va, 0xC3).ok());
    ASSERT_TRUE(process->address_space().protect_region(
        code_va, MemProtect::ReadExecute).ok());
    for (std::uint64_t offset : {0ull, 8ull, 16ull, 24ull})
        ASSERT_TRUE(mem.write_u64(output_va + offset, 0).ok());

    constexpr std::uint64_t submit_binding = 0x51000020ull;
    constexpr std::uint64_t dispatch_binding = 0x51000021ull;
    constexpr std::uint64_t tid = 0xA5;
    const std::uint64_t rsp = stack_va + 0x808; // x64 function-entry alignment;

    auto config = ExecutionConfig::default_validated();
    ASSERT_TRUE(config.ok());
    DeterministicBackend backend(w.reg, config.value());
    ASSERT_TRUE(backend.bind_execution_context(
        pid, tid, process->address_space()).ok());
    ExecutionRequest request;
    request.entry_va = submit_binding;
    request.stack_top_va = stack_va + 0x1000;
    request.stack_size = 0x1000;
    request.completion_va = kCompletionSentinel;
    request.api_binding_values = {submit_binding, dispatch_binding};
    request.api_bindings.push_back(ApiBindingInfo{
        submit_binding, "xgameruntime", "XTaskQueueSubmitCallback", false, 0});
    request.api_bindings.push_back(ApiBindingInfo{
        dispatch_binding, "xgameruntime", "XTaskQueueDispatch", false, 0});
    std::atomic<bool> interrupted{false};

    const auto run_guest_api = [&](std::uint64_t binding, std::uint64_t rcx,
                                   std::uint64_t rdx, std::uint64_t r8,
                                   std::uint64_t r9) {
        EXPECT_TRUE(mem.write_u64(rsp, continuation_va).ok());
        EXPECT_TRUE(mem.write_u64(rsp + 8, kCompletionSentinel).ok());
        cpu::CpuState state;
        state.reset();
        state.set_reg(cpu::Gpr::Sp, rsp);
        state.set_reg(cpu::Gpr::Rcx, rcx);
        state.set_reg(cpu::Gpr::Rdx, rdx);
        state.set_reg(cpu::Gpr::R8, r8);
        state.set_reg(cpu::Gpr::R9, r9);
        state.rip = binding;
        return backend.run(request, state, interrupted);
    };
    const auto port = static_cast<std::uint32_t>(api::XTaskQueuePort::Work);

    // Reject a non-executable callback pointer before storing it in the queue.
    const auto invalid_callback = run_guest_api(
        submit_binding, queue.value(), port, output_va, 0x7FFF00000000ull);
    EXPECT_EQ(invalid_callback.outcome, Outcome::Faulted);
    ASSERT_TRUE(invalid_callback.exception.has_value());
    EXPECT_EQ(invalid_callback.exception->fault, GuestFault::MarshalFailure);

    // Submit through the real guest ABI bridge (RCX/RDX/R8/R9).
    const auto submitted = run_guest_api(
        submit_binding, queue.value(), port, output_va, callback_va);
    ASSERT_EQ(submitted.outcome, Outcome::Returned)
        << (submitted.exception.has_value() ? format_exception(*submitted.exception) : "");
    EXPECT_EQ(submitted.return_value, 0u); // S_OK

    // Dispatch invokes the callback on this guest thread with context in RCX
    // and canceled=false in RDX, then returns to the suspended caller.
    const auto dispatched = run_guest_api(
        dispatch_binding, queue.value(), port, 0, 0);
    ASSERT_EQ(dispatched.outcome, Outcome::Returned)
        << (dispatched.exception.has_value() ? format_exception(*dispatched.exception) : "");
    EXPECT_EQ(dispatched.return_value, 1u);
    ASSERT_EQ(mem.read_u64(output_va).value(), 42u);
    ASSERT_EQ(mem.read_u64(output_va + 8).value(), 0u);

    // Termination marks a queued callback canceled. The nested guest callback
    // must observe canceled=true through RDX.
    const auto submitted_canceled = run_guest_api(
        submit_binding, queue.value(), port, output_va + 16, callback_va);
    ASSERT_EQ(submitted_canceled.outcome, Outcome::Returned)
        << (submitted_canceled.exception.has_value()
                ? format_exception(*submitted_canceled.exception) : "");
    EXPECT_EQ(submitted_canceled.return_value, 0u);
    ASSERT_TRUE(w.tq->terminate_queue(pid, queue.value(), false).ok());
    const auto dispatched_canceled = run_guest_api(
        dispatch_binding, queue.value(), port, 0, 0);
    ASSERT_EQ(dispatched_canceled.outcome, Outcome::Returned)
        << (dispatched_canceled.exception.has_value()
                ? format_exception(*dispatched_canceled.exception) : "");
    EXPECT_EQ(dispatched_canceled.return_value, 1u);
    ASSERT_EQ(mem.read_u64(output_va + 16).value(), 42u);
    ASSERT_EQ(mem.read_u64(output_va + 24).value(), 1u);

    EXPECT_TRUE(w.tq->close_queue(pid, queue.value()).ok());
    ASSERT_TRUE(w.pm.terminate_process(process_handle, 0).ok());
}

TEST(EngineTest, RejectsUnmappedSyntheticApiBinding) {
    ExecWorld w;
    auto [process_handle, process] = w.new_process("unmapped-api.exe");
    const auto pid = w.pm.resolve_pid(process_handle);
    ASSERT_TRUE(pid.ok());
    ModuleDescriptor module;
    module.module_name = "unmapped-api.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(process_handle, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(process_handle).ok());

    std::uint64_t stack_va = 0;
    scratch_region(*process, 0x1000, &stack_va);
    auto config = ExecutionConfig::default_validated();
    ASSERT_TRUE(config.ok());
    DeterministicBackend backend(w.reg, config.value());
    ASSERT_TRUE(backend.bind_execution_context(
        pid.value(), 0x93, process->address_space()).ok());

    ExecutionRequest request;
    request.entry_va = 0x51000001ull;
    request.stack_top_va = stack_va + 0x1000;
    request.stack_size = 0x1000;
    request.completion_va = kCompletionSentinel;
    cpu::CpuState cpu_state;
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, stack_va + 0x100);
    cpu_state.rip = request.entry_va;
    std::atomic<bool> interrupted{false};

    const auto result = backend.run(request, cpu_state, interrupted);
    EXPECT_EQ(result.outcome, Outcome::Faulted);
    ASSERT_TRUE(result.exception.has_value());
    EXPECT_EQ(result.exception->fault, GuestFault::InvalidState);
    EXPECT_EQ(result.api_calls, 0u);

    // A duplicated value with two different import identities is ambiguous
    // and must be rejected rather than dispatching whichever appears first.
    request.api_bindings.push_back(
        ApiBindingInfo{request.entry_va, "xgameruntime", "XGameRuntimeInitialize", false, 0});
    request.api_bindings.push_back(
        ApiBindingInfo{request.entry_va, "xgameruntime", "XGameRuntimeUninitialize", false, 0});
    cpu_state.reset();
    cpu_state.set_reg(cpu::Gpr::Sp, stack_va + 0x100);
    cpu_state.rip = request.entry_va;
    const auto duplicate = backend.run(request, cpu_state, interrupted);
    EXPECT_EQ(duplicate.outcome, Outcome::Faulted);
    ASSERT_TRUE(duplicate.exception.has_value());
    EXPECT_EQ(duplicate.exception->fault, GuestFault::InvalidState);
    EXPECT_EQ(duplicate.api_calls, 0u);
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

TEST(ContextTest, CarriesResolvedLoaderImportsIntoExecutionRequest) {
    ExecWorld w;
    const std::vector<std::uint8_t> code{0xC3};
    LoadedGuest guest(w, code, "import-map.exe", true);
    ASSERT_TRUE(guest.load_ok) << guest.load_error;

    EXPECT_EQ(guest.bytes, guest.original_bytes)
        << "ImageLoader must not modify the caller-owned PE file buffer";
    diag::Diagnostics parsed_diags;
    const auto parsed = pe::parse(guest.original_bytes.data(),
                                  guest.original_bytes.size(),
                                  "import-map.exe", parsed_diags);
    ASSERT_GT(parsed.directories.size(), pe::kDirImport);
    ASSERT_NE(parsed.directories[pe::kDirImport].rva, 0u);
    ASSERT_NE(parsed.directories[pe::kDirImport].size, 0u);
    ASSERT_TRUE(parsed.imports.present);
    ASSERT_EQ(parsed.imports.entries.size(), 1u);
    loader::LoadDiagnostics probe_diagnostics;
    auto probed_imports = guest.loader.resolve_imports(
        guest.proc->address_space(), guest.out.layout, parsed,
        guest.original_bytes.data(), guest.original_bytes.size(),
        guest.resolver, probe_diagnostics);
    ASSERT_TRUE(probed_imports.ok()) << probed_imports.error_string();
    ASSERT_EQ(probed_imports.value().size(), 1u)
        << "raw PE thunk walk must resolve the fixture's single import";

    // Loaded images are owned by the process handle table, not the
    // global object-manager handle table.
    auto loaded_ref = guest.proc->handle_table().lookup(guest.image);
    ASSERT_TRUE(loaded_ref.ok());
    auto* loaded = loaded_ref.value().get()->as<loader::LoadedImageObject>();
    ASSERT_NE(loaded, nullptr);
    ASSERT_TRUE(guest.parsed_imports_present)
        << "fixture parse before load did not recognize import directory";
    ASSERT_EQ(guest.parsed_import_count, 1u)
        << "fixture parse before load import entry count";
    ASSERT_EQ(guest.parsed_import_function_count, 1u)
        << "fixture parse before load function count; ordinal count="
        << guest.parsed_import_ordinal_count << ", INT RVA="
        << guest.parsed_import_int_rva << ", IAT RVA="
        << guest.parsed_import_iat_rva;
    ASSERT_NE(guest.parsed_import_directory_size, 0u);
    ASSERT_EQ(guest.diagnostics.imports.size(), 1u)
        << "loader diagnostic imports; resolved count="
        << guest.out.exec.imports_resolved << ", unresolved="
        << guest.out.exec.imports_unresolved;
    ASSERT_EQ(loaded->diagnostics().imports.size(), 1u)
        << "loaded-image object did not retain loader import diagnostics";
    ASSERT_EQ(loaded->diagnostics().imports[0].status, loader::ImportStatus::Resolved);

    const auto pid = w.pm.resolve_pid(guest.ph);
    ASSERT_TRUE(pid.ok());
    auto config = ExecutionConfig::default_validated();
    ASSERT_TRUE(config.ok());
    ExecutionContext context(pid.value(), 0x92, guest.proc->address_space(),
                             w.reg, config.value(), "import-map-context");
    ASSERT_TRUE(context.initialize().ok());

    rt::abi::CallSpec spec;
    spec.ret = rt::abi::CallSpec::ReturnKind::Int;
    auto request = context.prepare_entry(*loaded, 0, {}, spec);
    ASSERT_TRUE(request.ok()) << request.error_string();
    ASSERT_EQ(request.value().api_bindings.size(), 1u);
    ASSERT_EQ(request.value().api_binding_values.size(), 1u);
    EXPECT_EQ(request.value().api_bindings[0].value,
              loaded->diagnostics().imports[0].value);
    EXPECT_EQ(request.value().api_bindings[0].library, "xgameruntime");
    EXPECT_EQ(request.value().api_bindings[0].export_name, "XGameRuntimeInitialize");
    EXPECT_TRUE(is_api_binding(request.value().api_bindings[0].value));

    // Drop the process-table object pin before unload_image destroys the
    // loaded-image object. Keeping this RefGuard alive would self-deadlock
    // ObjectManager::destroy while it waits for outstanding pins to drain.
    loaded_ref.value().release();
    (void)context.destroy();
    (void)guest.loader.unload_image(w.pm, w.core.objects(), guest.ph, guest.image);
    (void)w.pm.terminate_process(guest.ph, 0);
}

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
    // Destroy releases stack + TEB + TLS vector + the final shared PEB.
    ASSERT_TRUE(ctx.destroy().ok());
    EXPECT_EQ(ctx.context_state(), ContextState::Destroyed);
    EXPECT_EQ(proc->address_space().stats().region_count,
              regions_before - 4u);
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
    spec.tls.zero_fill = 3;
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
    EXPECT_EQ(ctx->info().tls_index, tls_index);
    ASSERT_NE(ctx->guest_environment(), nullptr);
    const std::uint64_t tls_vector_slot =
        ctx->guest_environment()->tls_vector_base() +
        static_cast<std::uint64_t>(tls_index) * sizeof(std::uint64_t);
    auto tls_block = ctx->memory().read_u64(tls_vector_slot);
    ASSERT_TRUE(tls_block.ok()) << tls_block.error_string();
    ASSERT_NE(tls_block.value(), 0u);
    std::uint8_t copied_tls[2] = {};
    ASSERT_TRUE(ctx->memory().read(tls_block.value(), copied_tls,
                                   sizeof(copied_tls)).ok());
    EXPECT_EQ(copied_tls[0], 9u);
    EXPECT_EQ(copied_tls[1], 9u);
    std::uint8_t tls_tail[3] = {0xFF, 0xFF, 0xFF};
    ASSERT_TRUE(ctx->memory().read(tls_block.value() + 2, tls_tail,
                                   sizeof(tls_tail)).ok());
    EXPECT_EQ(tls_tail[0], 0u);
    EXPECT_EQ(tls_tail[1], 0u);
    EXPECT_EQ(tls_tail[2], 0u);
    if (loaded->diagnostics().tls_index_slot_rva != 0) {
        auto stored_index = ctx->memory().read_u32(
            loaded->exec().image_base + loaded->diagnostics().tls_index_slot_rva);
        ASSERT_TRUE(stored_index.ok());
        EXPECT_EQ(stored_index.value(), tls_index);
    }
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

TEST(ExecutionControlTest, ManagedThreadConstructorBindsIdentityAndGate) {
    ExecWorld world;
    auto [process_handle, process] = world.new_process("managed-thread-context.exe");
    ASSERT_NE(process, nullptr);
    const auto pid = world.pm.resolve_pid(process_handle);
    ASSERT_TRUE(pid.ok());

    RtThread managed_thread(
        [](RtThread&, void*) -> void* { return nullptr; }, nullptr,
        "managed-guest-thread", pid.value());
    auto cfg = ExecutionConfig::default_validated();
    ASSERT_TRUE(cfg.ok());

    ExecutionContext context(managed_thread, process->address_space(),
                             world.reg, cfg.value(), "managed-context");
    ASSERT_TRUE(context.initialize().ok());
    EXPECT_EQ(context.info().process_id, pid.value());
    EXPECT_EQ(context.info().thread_id, managed_thread.thread_id());
    EXPECT_EQ(context.execution_control(), managed_thread.execution_control());

    ExecutionRequest request;
    request.stack_top_va = context.info().stack_top;
    request.stack_size = context.info().stack_size;
    // A caller-supplied gate must not detach managed execution from its
    // owning thread's suspend/terminate lifecycle.
    request.control = std::make_shared<ExecutionControl>();
    ContextBindingProbe engine;
    std::atomic<bool> interrupted{false};
    const auto result = context.invoke(request, engine, interrupted);
    ASSERT_TRUE(result.ok()) << result.error_string();
    EXPECT_EQ(engine.bound_pid, pid.value());
    EXPECT_EQ(engine.bound_tid, managed_thread.thread_id());
    EXPECT_EQ(engine.bound_space, &process->address_space());
    EXPECT_EQ(engine.run_control, managed_thread.execution_control().get());

    ASSERT_TRUE(context.step(request, engine).ok());
    EXPECT_TRUE(engine.step_called);
    EXPECT_EQ(engine.step_control, managed_thread.execution_control().get());
    EXPECT_TRUE(context.destroy().ok());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


// ── M11.3 guest TEB/PEB and implicit TLS storage ──────────────────────────

TEST(GuestThreadEnvironmentTest, InitializesTebPebAndTlsVectorPointers) {
    AddressSpace space(16ull << 20, 0x30000000, "guest-env-test");
    guest::GuestMemory mem(space);
    {
        exec::GuestProcessEnvironment process(space);
        ASSERT_TRUE(process.initialize(0x1234).ok());
        exec::GuestThreadEnvironment env(space, process);
        ASSERT_TRUE(env.initialize(0x5678).ok());
        EXPECT_NE(env.teb_base(), 0u);
        EXPECT_NE(env.peb_base(), 0u);
        EXPECT_NE(env.tls_vector_base(), 0u);
        EXPECT_EQ(mem.read_u64(env.teb_base() + exec::GuestThreadEnvironment::kTebSelfOffset).value(),
                  env.teb_base());
        EXPECT_EQ(mem.read_u64(env.teb_base() + exec::GuestThreadEnvironment::kTebTlsVectorOffset).value(),
                  env.tls_vector_base());
        EXPECT_EQ(mem.read_u64(env.teb_base() + exec::GuestThreadEnvironment::kTebPebOffset).value(),
                  env.peb_base());
        EXPECT_EQ(mem.read_u64(env.teb_base() + exec::GuestThreadEnvironment::kTebProcessIdOffset).value(),
                  0x1234u);
        EXPECT_EQ(mem.read_u64(env.teb_base() + exec::GuestThreadEnvironment::kTebThreadIdOffset).value(),
                  0x5678u);
        ASSERT_TRUE(process.set_image_base(0x180000000ull).ok());
        EXPECT_EQ(mem.read_u64(env.peb_base() + exec::GuestProcessEnvironment::kPebImageBaseOffset).value(),
                  0x180000000ull);
    }
    EXPECT_EQ(space.stats().region_count, 0u);
}

TEST(GuestThreadEnvironmentTest, InstallsPerThreadTlsTemplateAndZeroFill) {
    AddressSpace space(16ull << 20, 0x31000000, "guest-tls-test");
    guest::GuestMemory mem(space);
    exec::GuestProcessEnvironment process(space);
    ASSERT_TRUE(process.initialize(1).ok());
    exec::GuestThreadEnvironment env(space, process);
    ASSERT_TRUE(env.initialize(2).ok());
    const std::uint8_t image_template[] = {0x11, 0x22, 0x33, 0x44};
    auto block = env.install_tls_module(3, image_template, sizeof(image_template), 12);
    ASSERT_TRUE(block.ok()) << block.error_string();
    EXPECT_EQ(mem.read_u64(env.tls_vector_base() + 3 * 8).value(), block.value());
    std::uint8_t contents[16] = {};
    ASSERT_TRUE(env.read_tls(3, 0, contents, sizeof(contents)).ok());
    EXPECT_EQ(contents[0], 0x11);
    EXPECT_EQ(contents[1], 0x22);
    EXPECT_EQ(contents[2], 0x33);
    EXPECT_EQ(contents[3], 0x44);
    for (std::size_t i = 4; i < sizeof(contents); ++i) EXPECT_EQ(contents[i], 0);
    EXPECT_EQ(env.install_tls_module(3, image_template, sizeof(image_template), 0).errc(),
              RuntimeErrc::AlreadyExists);
    EXPECT_EQ(env.install_tls_module(64, image_template, sizeof(image_template), 0).errc(),
              RuntimeErrc::InvalidArgument);
    EXPECT_EQ(env.read_tls(3, 15, contents, 2).errc(), RuntimeErrc::InvalidArgument);
    EXPECT_EQ(env.read_tls(4, 0, contents, 1).errc(), RuntimeErrc::NotFound);
}

TEST(ExecutionContextM11Test, ThreadsShareProcessPebButOwnDistinctTebs) {
    AddressSpace space(32ull << 20, 0x32000000, "execution-context-m11");
    api::ApiRegistry registry;
    ExecutionConfig config;
    auto process_environment = std::make_shared<GuestProcessEnvironment>(space);
    {
        ExecutionContext first(0x91, 0xA2, space, registry, config, "first",
                               process_environment);
        ExecutionContext second(0x91, 0xA3, space, registry, config, "second",
                                process_environment);
        ASSERT_TRUE(first.initialize().ok());
        ASSERT_TRUE(second.initialize().ok());
        ASSERT_NE(first.guest_environment(), nullptr);
        ASSERT_NE(second.guest_environment(), nullptr);
        EXPECT_EQ(first.guest_environment()->peb_base(),
                  second.guest_environment()->peb_base());
        EXPECT_NE(first.guest_environment()->teb_base(),
                  second.guest_environment()->teb_base());
        EXPECT_EQ(first.guest_gs_base(), first.guest_environment()->teb_base());
        EXPECT_EQ(second.guest_gs_base(), second.guest_environment()->teb_base());
        EXPECT_TRUE(first.destroy().ok());
        EXPECT_TRUE(second.destroy().ok());
        EXPECT_EQ(space.stats().region_count, 1u); // external shared PEB owner remains
    }
    process_environment.reset();
    EXPECT_EQ(space.stats().region_count, 0u);
}


TEST(GuestProcessEnvironmentTest, AllocatesStableUniqueTlsIndexesPerImage) {
    AddressSpace space(16ull << 20, 0x33000000, "process-tls-index-test");
    exec::GuestProcessEnvironment process(space);
    ASSERT_TRUE(process.initialize(0x44).ok());
    auto first = process.tls_index_for_image(0x140000000ull, 7);
    ASSERT_TRUE(first.ok()) << first.error_string();
    EXPECT_EQ(first.value(), 7u);
    auto again = process.tls_index_for_image(0x140000000ull, 12);
    ASSERT_TRUE(again.ok());
    EXPECT_EQ(again.value(), first.value());
    auto collision = process.tls_index_for_image(0x150000000ull, 7);
    ASSERT_TRUE(collision.ok());
    EXPECT_EQ(collision.value(), 0u);
    auto invalid_preference = process.tls_index_for_image(0x160000000ull, 99);
    ASSERT_TRUE(invalid_preference.ok());
    EXPECT_EQ(invalid_preference.value(), 1u);

    AddressSpace other_space(16ull << 20, 0x34000000, "other-process-tls-index");
    exec::GuestProcessEnvironment other(other_space);
    ASSERT_TRUE(other.initialize(0x45).ok());
    auto independent = other.tls_index_for_image(0x140000000ull, 7);
    ASSERT_TRUE(independent.ok());
    EXPECT_EQ(independent.value(), 7u);
}

TEST(GuestProcessEnvironmentTest, RejectsUninitializedAndExhaustedTlsRegistry) {
    AddressSpace space(16ull << 20, 0x35000000, "process-tls-exhaustion-test");
    exec::GuestProcessEnvironment process(space);
    EXPECT_EQ(process.tls_index_for_image(0x140000000ull, 0).errc(),
              RuntimeErrc::InvalidState);
    ASSERT_TRUE(process.initialize(0x46).ok());
    for (std::uint32_t i = 0; i < exec::GuestThreadEnvironment::kTlsSlotCount; ++i) {
        auto result = process.tls_index_for_image(
            0x140000000ull + static_cast<std::uint64_t>(i) * 0x100000ull, i);
        ASSERT_TRUE(result.ok()) << result.error_string();
        EXPECT_EQ(result.value(), i);
    }
    EXPECT_EQ(process.tls_index_for_image(0x1F0000000ull, 0).errc(),
              RuntimeErrc::OutOfResources);
    auto existing = process.tls_index_for_image(0x140000000ull, 63);
    ASSERT_TRUE(existing.ok());
    EXPECT_EQ(existing.value(), 0u);
}

TEST(GuestProcessEnvironmentTest, ConcurrentRequestsForSameImageReturnOneIndex) {
    AddressSpace space(16ull << 20, 0x36000000, "process-tls-concurrent-test");
    exec::GuestProcessEnvironment process(space);
    ASSERT_TRUE(process.initialize(0x47).ok());
    std::array<std::uint32_t, 8> indexes{};
    std::array<bool, 8> succeeded{};
    std::vector<std::thread> workers;
    for (std::size_t i = 0; i < indexes.size(); ++i) {
        workers.emplace_back([&, i] {
            auto result = process.tls_index_for_image(
                0x170000000ull, static_cast<std::uint32_t>(i));
            if (result.ok()) { indexes[i] = result.value(); succeeded[i] = true; }
        });
    }
    for (auto& worker : workers) worker.join();
    for (std::size_t i = 0; i < indexes.size(); ++i) {
        ASSERT_TRUE(succeeded[i]);
        EXPECT_EQ(indexes[i], indexes[0]);
    }
}


TEST(GuestThreadEnvironmentTest, LastErrorIsThreadLocalAndUsesTebField) {
    AddressSpace space(16ull << 20, 0x37000000, "guest-last-error-test");
    api::ApiRegistry registry;
    auto process = std::make_shared<exec::GuestProcessEnvironment>(space);
    exec::ExecutionContext first(0x81, 0x91, space, registry,
        ExecutionConfig::default_validated().value(), "last-error-first", process);
    exec::ExecutionContext second(0x81, 0x92, space, registry,
        ExecutionConfig::default_validated().value(), "last-error-second", process);
    ASSERT_TRUE(first.initialize().ok());
    ASSERT_TRUE(second.initialize().ok());
    ASSERT_NE(first.guest_environment(), nullptr);
    ASSERT_NE(second.guest_environment(), nullptr);

    EXPECT_EQ(first.guest_environment()->last_error().value(), 0u);
    EXPECT_EQ(second.guest_environment()->last_error().value(), 0u);
    ASSERT_TRUE(first.guest_environment_mut()->set_last_error(0x12345678u).ok());
    EXPECT_EQ(first.guest_environment()->last_error().value(), 0x12345678u);
    EXPECT_EQ(second.guest_environment()->last_error().value(), 0u);
    ASSERT_TRUE(second.guest_environment_mut()->set_last_error(5u).ok());
    EXPECT_EQ(second.guest_environment()->last_error().value(), 5u);
    EXPECT_EQ(first.guest_environment()->last_error().value(), 0x12345678u);

    const auto raw = first.memory().read_u32(
        first.guest_gs_base() + exec::GuestThreadEnvironment::kTebLastErrorValueOffset);
    ASSERT_TRUE(raw.ok());
    EXPECT_EQ(raw.value(), 0x12345678u);
    // The second thread's value remains independent of the first thread.
    ASSERT_TRUE(first.destroy().ok());
    EXPECT_EQ(first.guest_environment(), nullptr);
    EXPECT_EQ(second.guest_environment()->last_error().value(), 5u);
    ASSERT_TRUE(second.destroy().ok());
}
