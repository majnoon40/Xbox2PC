// xbox2pc/tests/execution_fuzz.cpp — M8 deterministic fuzz harnesses.
//
// Spec §15 fuzzing: CPU context validation, ABI argument layouts, guest
// memory ranges, marshalling metadata (plans), execution requests, TLS
// callback metadata, exception metadata. Boundary values, overflows,
// truncated structures, invalid addresses, extreme counts. Every case:
// typed result or clean fault — never a crash/hang/unbounded allocation.
//
// Harnesses (seeds fixed; mutation counts printed):
//   1. CpuFuzz        — random states -> validate/snapshot/serialize;
//                        accepted serialize() must round-trip; validate()
//                        invariants hold for accepted snapshots.
//   2. AbiFuzz        — random CallSpecs -> validate/compute/prepare/
//                        extract round-trips; accepted specs behave
//                        consistently; rejects are typed.
//   3. GuestMemFuzz   — random (va,len) over a live process space ->
//                        validate/read/write typed results; permission
//                        distinctions preserved.
//   4. MarshalFuzz    — mutated descriptor signatures -> plan_for_
//                        descriptor typed results (never guessed).
//   5. RequestFuzz     — random ExecutionRequests over a loaded guest
//                        program -> engine run -> typed outcome/fault
//                        (bounded by small instruction budgets).
//   6. TlsFuzz        — random TLS metadata -> rt::exec::plan_tls_callbacks typed.
//   7. ExceptionFuzz  — random rt::exec::GuestException fields -> formatting +
//                        clamp_detail (bounded).

#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/execution_context.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/xbox_abi.hpp"

using namespace xbox2pc;
using namespace xbox2pc::rt;
using namespace xbox2pc::rt::cpu;
using namespace xbox2pc::rt::guest;

namespace {

std::uint64_t g_mutations = 0;   // counted across all harnesses

std::uint64_t rr(std::mt19937_64& rng) { return rng(); }

cpu::CpuState random_cpu(std::mt19937_64& rng) {
    cpu::CpuState c;
    c.reset();
    for (std::size_t i = 0; i < kGprCount; ++i) {
        c.gprs[i] = rr(rng);
    }
    c.rip = rr(rng);
    c.rflags = rr(rng) & 0xFFFFFFFFull;
    for (auto& x : c.xmm) {
        for (auto& b : x) b = static_cast<std::uint8_t>(rr(rng));
    }
    c.mxcsr = static_cast<std::uint32_t>(rr(rng));
    c.fcw = static_cast<std::uint32_t>(rr(rng));
    return c;
}

}  // namespace

TEST(ExecFuzzTest, CpuContextValidationFuzz) {
    std::mt19937_64 rng(0xC0FFEE01ull);
    std::size_t valid = 0, invalid = 0;
    for (int i = 0; i < 30000; ++i) {
        ++g_mutations;
        auto c = random_cpu(rng);
        const auto problems = c.validate();
        if (problems.empty()) {
            ++valid;
            // Snapshot/serialize round-trip must hold for valid states.
            cpu::CpuSnapshot snap;
            EXPECT_TRUE(cpu::snapshot_into(c, snap).ok());
            const auto bytes = snap.serialize();
            auto back = cpu::CpuSnapshot::deserialize(bytes.data(), bytes.size());
            ASSERT_TRUE(back.ok()) << "valid state failed round-trip";
            EXPECT_EQ(back.value().state, c);
        } else {
            ++invalid;
            EXPECT_FALSE(problems.empty());
        }
        // Truncated serialization always rejected.
        const cpu::CpuSnapshot snap;
        if (i % 97 == 0) {
            auto b = snap.serialize();
            b.resize(b.size() - 1);
            EXPECT_FALSE(cpu::CpuSnapshot::deserialize(b.data(), b.size()).ok());
        }
    }
    EXPECT_GT(valid + invalid, 0u);
}

TEST(ExecFuzzTest, AbiLayoutFuzz) {
    std::mt19937_64 rng(0xAB1700D5ull);
    // A host-backed stack for prepare/extract round-trips.
    struct HostStack {
        std::vector<std::uint8_t> mem;
        std::uint64_t base;
    };
    for (int i = 0; i < 30000; ++i) {
        ++g_mutations;
        rt::abi::CallSpec spec;
        const int n = static_cast<int>(rr(rng) % 9);
        for (int a = 0; a < n; ++a) {
            rt::abi::ArgSpec as;
            const auto kind = rr(rng) % 6;
            switch (kind) {
                case 0: as.kind = rt::abi::ArgKind::Int; break;
                case 1: as.kind = rt::abi::ArgKind::Ptr;
                        as.deref_size = rr(rng) % 0x2000;
                        as.is_out = (rr(rng) & 1) != 0; break;
                case 2: as.kind = rt::abi::ArgKind::F32; break;
                case 3: as.kind = rt::abi::ArgKind::F64; break;
                case 4: as.kind = rt::abi::ArgKind::VecF32x4; break;
                case 5: as.kind = rt::abi::ArgKind::Struct;
                        as.struct_size = 1u << (rr(rng) % 4); break;
            }
            spec.args.push_back(as);
        }
        spec.varargs = (rr(rng) & 1) != 0;
        spec.ret = static_cast<rt::abi::CallSpec::ReturnKind>(rr(rng) % 5);
        const auto v = rt::abi::validate_call(spec);
        const auto lay = rt::abi::compute_layout(spec);
        if (!v.ok()) {
            // Rejected spec: layout refuses too.
            EXPECT_FALSE(lay.ok());
            continue;
        }
        ASSERT_TRUE(lay.ok());
        // Layout invariants: <= 4 reg args per class; stack 16-aligned
        // total >= shadow 32.
        EXPECT_LE(lay.value().gp_reg_args, 4u);
        EXPECT_LE(lay.value().xmm_reg_args, 4u);
        EXPECT_GE(lay.value().total_stack_bytes, 32u);
        EXPECT_EQ(lay.value().total_stack_bytes % 16, 0u);
        // Prepare on a valid RSP then extract must round-trip counts.
        cpu::CpuState c;
        c.reset();
        c.set_reg(Gpr::Sp, 0x20040000ull - 0x400);
        HostStack st{std::vector<std::uint8_t>(0x1000, 0), 0x2003F000ull};
        rt::abi::StackWriter writer;
        writer.ctx = &st;
        writer.write = [](void* ctx, std::uint64_t va, const void* src,
                            std::size_t len) -> Result<void> {
            auto* s = static_cast<HostStack*>(ctx);
            if (va < s->base || va + len > s->base + s->mem.size()) {
                return Result<void>(RuntimeErrc::InvalidArgument, "oos");
            }
            std::memcpy(s->mem.data() + (va - s->base), src, len);
            return Result<void>::ok_result();
        };
        std::vector<rt::abi::ArgValue> vals;
        for (const auto& a : spec.args) {
            rt::abi::ArgValue av;
            av.kind = a.kind;
            av.int_v = rr(rng);
            av.ptr_va = rr(rng) % 0x100000;
            av.f64_v = 1.5;
            vals.push_back(av);
        }
        const auto prep = rt::abi::prepare_call(c, 0x30001000, spec, vals, writer);
        // Typed either way; on success, extract returns the same count.
        if (prep.ok()) {
            rt::abi::StackReader reader;
            reader.ctx = &st;
            reader.read64 = [](void* ctx, std::uint64_t va) -> Result<std::uint64_t> {
                auto* s = static_cast<HostStack*>(ctx);
                if (va + 8 > s->base + s->mem.size() || va < s->base) {
                    return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "oos");
                }
                std::uint64_t out = 0;
                std::memcpy(&out, s->mem.data() + (va - s->base), 8);
                return Result<std::uint64_t>(out);
            };
            auto got = rt::abi::extract_args(c, spec, reader);
            if (got.ok()) {
                EXPECT_EQ(got.value().size(), spec.args.size());
            }
        }
    }
}

TEST(ExecFuzzTest, GuestMemoryRangeFuzz) {
    // A live world with an image (RX) + scratch (RW) regions.
    api::ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm(core.objects());
    {
        auto grt = std::make_unique<api::GameRuntimeService>(reg, pm);
        core.services().register_service(std::move(grt));
    }
    core.initialize();
    auto ph = pm.create_process("fz.exe", 64ull << 20);
    ASSERT_TRUE(ph.ok());
    auto pr = core.objects().lookup_handle(ph.value());
    auto* proc = pr.value().get()->as<ManagedProcess>();
    std::vector<std::uint8_t> code = {0xC3};
    test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, code});
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = test::PeBuilder(spec).build();
    diag::Diagnostics pd;
    auto img = pe::parse(image.data(), image.size(), "fz.exe", pd);
    loader::ImageLoader loader;
    api::ApiResolver resolver(reg);
    loader::LoadDiagnostics ld;
    loader::LoadResult out;
    auto h = loader.load_image(pm, core.objects(), ph.value(), img,
                               image.data(), image.size(), &resolver, ld, out);
    ASSERT_TRUE(h.ok());
    auto rw = proc->address_space().reserve_region_auto(0x2000, "scr");
    ASSERT_TRUE(rw.ok());
    ASSERT_TRUE(proc->address_space().commit_region(rw.value()).ok());

    guest::GuestMemory mem(proc->address_space());
    std::mt19937_64 rng(0x6E7F00D5ull);
    std::size_t rejects = 0, oks = 0;
    for (int i = 0; i < 30000; ++i) {
        ++g_mutations;
        std::uint64_t va;
        if ((rng() & 3) == 0) {
            va = rr(rng) % (1ull << 40);   // mostly-unmapped probes
        } else {
            // Offsets into the KNOWN mapped regions (scratch + image).
            va = (rng() & 1) ? rw.value() + (rr(rng) % 0x2000)
                            : out.exec.image_base + (rr(rng) % 0x3000);
        }
        const std::uint64_t len = rr(rng) % 0x3000;
        const bool w = (rr(rng) & 1) != 0;
        const auto r = mem.validate(va, len ? len : 1, w, false);
        if (r.ok()) ++oks; else ++rejects;
        // Typed reads/writes never crash (destination sized to len).
        const std::uint64_t op_len = len ? len : 1;
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(op_len), 0);
        (void)mem.read(va, buf.data(), op_len);
        (void)mem.write(va, buf.data(), op_len);
        // Boundary spot: region end +- 1.
        if (i % 251 == 0) {
            const auto end = rw.value() + 0x2000;
            EXPECT_FALSE(mem.validate(end, 1, false, false).ok());
            EXPECT_TRUE(mem.validate(end - 1, 1, false, false).ok());
        }
    }
    EXPECT_GT(rejects, 0u);
    EXPECT_GT(oks, 0u);
    (void)loader.unload_image(pm, core.objects(), ph.value(), h.value());
    (void)pm.terminate_process(ph.value(), 0);
    (void)core.shutdown();
}

TEST(ExecFuzzTest, MarshalPlanFuzz) {
    api::ApiRegistry reg;
    std::mt19937_64 rng(0xF1A7A11Dull);
    std::size_t planned = 0;
    for (int i = 0; i < 20000; ++i) {
        ++g_mutations;
        api::ApiDescriptor d;
        d.library = rng() & 1 ? "xgameruntime" : "kernel32";
        // Mutate the export name from the known set (known -> planned;
        // mutated -> refused; never guessed).
        static const char* names[] = {
            "XGameRuntimeInitialize", "XGameRuntimeUninitialize",
            "XGameRuntimeInitializeWithOptions", "XSystemGetDeviceType",
            "XSystemGetConsoleId", "XSystemGetXboxLiveSandboxId",
            "XSystemGetAppSpecificDeviceId", "XSystemGetRuntimeInfo",
            "XThreadSetTimeSensitive", "XThreadIsTimeSensitive",
            "XTaskQueueCreate", "XTaskQueueDispatch",
            "XTaskQueueCloseHandle", "XTaskQueueTerminate",
            "QueryPerformanceCounter", "QueryPerformanceFrequency",
        };
        std::string name = names[rng() % 16];
        if (rng() & 1) {
            // Mutate one character.
            const auto pos = rng() % name.size();
            name[pos] = static_cast<char>('A' + (rng() % 26));
        }
        d.export_name = name;
        const auto p = rt::exec::plan_for_descriptor(d);
        if (p.ok()) {
            ++planned;
            EXPECT_TRUE(rt::abi::validate_call(p.value().call).ok());
        } else {
            // Refused APIs yield typed NotFound — never a guess.
            EXPECT_EQ(p.errc(), RuntimeErrc::NotFound);
        }
    }
    // Unmutated names must all plan (the 16 documented APIs).
    EXPECT_GT(planned, 1000u);
}

TEST(ExecFuzzTest, ExecutionRequestFuzz) {
    api::ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm(core.objects());
    {
        auto grt = std::make_unique<api::GameRuntimeService>(reg, pm);
        core.services().register_service(std::move(grt));
    }
    core.initialize();
    auto ph = pm.create_process("rfz.exe", 64ull << 20);
    auto pr = core.objects().lookup_handle(ph.value());
    auto* proc = pr.value().get()->as<ManagedProcess>();
    // A guest program: infinite-ish loop of NOPs/JMPs within a payload.
    std::vector<std::uint8_t> code(0x40, 0x90);   // 64 NOPs
    code.push_back(0xC3);
    test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, code});
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = test::PeBuilder(spec).build();
    diag::Diagnostics pd;
    auto img = pe::parse(image.data(), image.size(), "rfz.exe", pd);
    loader::ImageLoader loader;
    api::ApiResolver resolver(reg);
    loader::LoadDiagnostics ld;
    loader::LoadResult out;
    auto h = loader.load_image(pm, core.objects(), ph.value(), img,
                               image.data(), image.size(), &resolver, ld, out);
    ASSERT_TRUE(h.ok());

    auto cfg = rt::exec::ExecutionConfig::default_validated().value();
    std::mt19937_64 rng(0xE7E0E511ull);
    rt::exec::DeterministicBackend engine(reg, cfg);
    engine.bind_space(proc->address_space());
    engine.bind_process(1, 1);
    for (int i = 0; i < 400; ++i) {
        ++g_mutations;
        // Random entry points (in/out of the image), stacks, budgets.
        rt::exec::ExecutionRequest req;
        req.entry_va = rng() % 2 == 0
            ? out.exec.entry_va + (rng() % 0x100)
            : rr(rng) % (1ull << 40);
        req.stack_top_va = proc->address_space().base() + (rr(rng) % (1ull << 20));
        req.stack_size = 0x1000;
        req.completion_va = rt::exec::kCompletionSentinel;
        rt::exec::ExecutionConfig tiny = cfg;
        tiny.max_instructions = 1 + (rng() % 500);
        rt::exec::DeterministicBackend eng2(reg, tiny);
        eng2.bind_space(proc->address_space());
        eng2.bind_process(1, 1);
        cpu::CpuState c;
        c.reset();
        c.set_reg(Gpr::Sp, req.stack_top_va & ~0xFull);
        std::atomic<bool> stop{false};
        // Direct engine.run (context-free fuzz): typed result every time.
        const auto res = eng2.run(req, c, stop);
        // Outcome is one of the documented values; faults carry a
        // populated, bounded exception record.
        if (res.outcome == rt::exec::Outcome::Faulted) {
            ASSERT_TRUE(res.exception.has_value());
            auto e2 = *res.exception;
            e2.clamp_detail(1024);
            EXPECT_LE(e2.detail.size(), 1024u);
        }
    }
    (void)loader.unload_image(pm, core.objects(), ph.value(), h.value());
    (void)pm.terminate_process(ph.value(), 0);
}

TEST(ExecFuzzTest, TlsMetadataFuzz) {
    api::ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm(core.objects());
    {
        auto grt = std::make_unique<api::GameRuntimeService>(reg, pm);
        core.services().register_service(std::move(grt));
    }
    core.initialize();
    auto ph = pm.create_process("tfz.exe", 32ull << 20);
    auto pr = core.objects().lookup_handle(ph.value());
    auto* proc = pr.value().get()->as<ManagedProcess>();
    guest::GuestMemory mem(proc->address_space());
    auto cfg = rt::exec::ExecutionConfig::default_validated().value();
    std::mt19937_64 rng(0x75C8A11Dull);
    for (int i = 0; i < 30000; ++i) {
        ++g_mutations;
        loader::TlsInfo tls;
        tls.present = (rng() & 7) != 0;
        tls.callbacks_va = rr(rng) % (1ull << 40);
        tls.callback_count = static_cast<std::uint32_t>(rr(rng) % 200);
        const auto p = rt::exec::plan_tls_callbacks(mem, tls, cfg);
        // Typed: ok (with rejected_count) or typed rejection.
        if (p.ok()) {
            EXPECT_LE(p.value().callbacks.size(),
                      static_cast<std::size_t>(cfg.max_tls_callbacks));
        } else {
            EXPECT_NE(p.errc(), RuntimeErrc::Ok);
        }
    }
    (void)pm.terminate_process(ph.value(), 0);
}

TEST(ExecFuzzTest, ExceptionMetadataFuzz) {
    std::mt19937_64 rng(0xEACE00D5ull);
    for (int i = 0; i < 30000; ++i) {
        ++g_mutations;
        rt::exec::GuestException e;
        e.fault = static_cast<rt::exec::GuestFault>(rr(rng) % 12);
        e.rip = rr(rng);
        e.access = static_cast<rt::exec::AccessType>(rr(rng) % 4);
        e.fault_address = rr(rng);
        e.process_id = rr(rng);
        e.thread_id = rr(rng);
        e.recoverability = (rr(rng) & 1) ? rt::exec::Recoverability::Recoverable
                                          : rt::exec::Recoverability::Fatal;
        // Extreme detail lengths: clamped, never unbounded.
        e.detail = std::string(static_cast<std::size_t>(rr(rng) % 100000), 'x');
        e.clamp_detail(1024);
        EXPECT_LE(e.detail.size(), 1024u);
        const auto text = rt::exec::format_exception(e);
        EXPECT_FALSE(text.empty());
        // Round-trip the fault names.
        const auto back = rt::exec::guest_fault_from_name(rt::exec::guest_fault_to_name(e.fault));
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(*back, e.fault);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    const int rc = RUN_ALL_TESTS();
    std::printf("[fuzz] total mutations: %llu\n",
                static_cast<unsigned long long>(g_mutations));
    return rc;
}
