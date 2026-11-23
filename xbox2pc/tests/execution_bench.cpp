// xbox2pc/tests/execution_bench.cpp — M8 execution benchmarks (spec §16).
//
// Measures: CPU context creation/destruction (snapshot alloc), snapshot/
// restore, ABI argument preparation, guest memory reads/writes, API
// marshalling (bridge), dispatch through the bridge, execution-context
// creation (full lifecycle: stack region + CPU init), deterministic
// backend execution, exception reporting.
//
// Methodology: Release build (-O3), steady_clock, explicit iteration
// counts printed per benchmark, warm-up loops before each measurement
// (one full run of the measured operation), means over N iterations.
// Allocation overhead IS included where noted (snapshots and contexts
// allocate); pure compute paths (ABI prepare, engine execute) exclude
// process setup by measuring only the operation.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

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

namespace {
using Clock = std::chrono::steady_clock;
double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0)
        .count();
}
constexpr int kWarmup = 100;
}  // namespace

int main() {
    std::printf("M8 execution benchmarks (Release -O3, steady_clock, "
                "means over N ops, warm-up %d)\n", kWarmup);

    // ── CPU snapshot/restore (includes allocation) ──
    {
        cpu::CpuState c;
        c.reset();
        c.set_reg(cpu::Gpr::Sp, 0x20040000);
        for (int w = 0; w < kWarmup; ++w) {
            cpu::CpuSnapshot s;
            cpu::snapshot_into(c, s);
            cpu::restore_into(s, c);
        }
        const int N = 50000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            cpu::CpuSnapshot s;
            cpu::snapshot_into(c, s);
            cpu::restore_into(s, c);
        }
        std::printf("snapshot+restore:      %8.3f us/op (alloc incl.)\n",
                    ms_since(t0) * 1000.0 / N);
    }

    // ── serialization (diagnostics path) ──
    {
        cpu::CpuState c;
        c.reset();
        cpu::CpuSnapshot s;
        cpu::snapshot_into(c, s);
        for (int w = 0; w < kWarmup; ++w) (void)s.serialize();
        const int N = 20000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) (void)s.serialize();
        std::printf("snapshot serialize:     %8.3f us/op (416 B)\n",
                    ms_since(t0) * 1000.0 / N);
    }

    // World for the rest.
    api::ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm(core.objects());
    {
        auto grt = std::make_unique<api::GameRuntimeService>(reg);
        auto tq = std::make_unique<api::TaskQueueService>(reg, pm);
        auto tim = std::make_unique<api::TimingService>(reg);
        (void)core.services().register_service(std::move(grt));
        (void)core.services().register_service(std::move(tq));
        (void)core.services().register_service(std::move(tim));
    }
    core.initialize();

    // ── ABI argument preparation (host-backed stack) ──
    {
        struct HostStack {
            std::vector<std::uint8_t> mem;
            std::uint64_t base;
        };
        HostStack st{std::vector<std::uint8_t>(0x2000, 0), 0x2003E000ull};
        abi::CallSpec spec;
        spec.ret = abi::CallSpec::ReturnKind::Int;
        for (int i = 0; i < 6; ++i) spec.args.push_back({});
        std::vector<abi::ArgValue> vals(6);
        for (int i = 0; i < 6; ++i) vals[static_cast<std::size_t>(i)].int_v =
                static_cast<std::uint64_t>(0x100 + i);
        abi::StackWriter writer;
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
        for (int w = 0; w < kWarmup; ++w) {
            cpu::CpuState c;
            c.reset();
            c.set_reg(cpu::Gpr::Sp, 0x20040000ull - 0x100);
            (void)abi::prepare_call(c, 0x30001000, spec, vals, writer);
        }
        const int N = 100000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            cpu::CpuState c;
            c.reset();
            c.set_reg(cpu::Gpr::Sp, 0x20040000ull - 0x100);
            (void)abi::prepare_call(c, 0x30001000, spec, vals, writer);
        }
        std::printf("abi prepare (6 args):   %8.3f us/op\n",
                    ms_since(t0) * 1000.0 / N);
    }

    // ── guest memory reads/writes ──
    {
        auto ph = pm.create_process("bench-mem.exe", 32ull << 20);
        auto pr = core.objects().lookup_handle(ph.value());
        auto* proc = pr.value().get()->as<ManagedProcess>();
        auto r = proc->address_space().reserve_region_auto(0x1000, "bench");
        (void)proc->address_space().commit_region(r.value());
        guest::GuestMemory mem(proc->address_space());
        for (int w = 0; w < kWarmup; ++w) {
            (void)mem.write_u64(r.value(), 0x1234);
            (void)mem.read_u64(r.value());
        }
        const int N = 200000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) (void)mem.write_u64(r.value(), 0x1234);
        const double w_ms = ms_since(t0);
        const auto t1 = Clock::now();
        for (int i = 0; i < N; ++i) (void)mem.read_u64(r.value());
        std::printf("guest mem u64 write:     %8.3f ns/op\n",
                    w_ms * 1e6 / N);
        std::printf("guest mem u64 read:     %8.3f ns/op\n",
                    ms_since(t1) * 1e6 / N);
        (void)pm.terminate_process(ph.value(), 0);
    }

    // ── API marshalling + dispatch through the bridge ──
    {
        auto ph = pm.create_process("bench-br.exe", 32ull << 20);
        auto pr = core.objects().lookup_handle(ph.value());
        auto* proc = pr.value().get()->as<ManagedProcess>();
        guest::GuestMemory mem(proc->address_space());
        auto plan = exec::plan_for_descriptor(
            *reg.find("xgameruntime", "XGameRuntimeInitialize"));
        if (!plan.ok()) { std::printf("plan FAILED\n"); return 1; }
        for (int w = 0; w < kWarmup; ++w) {
            cpu::CpuState c;
            c.reset();
            c.set_reg(cpu::Gpr::Sp, 0x20040000);
            (void)exec::marshal_and_dispatch(c, mem, reg, plan.value(), 1, 0, 64);
        }
        const int N = 50000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            cpu::CpuState c;
            c.reset();
            c.set_reg(cpu::Gpr::Sp, 0x20040000);
            (void)exec::marshal_and_dispatch(c, mem, reg, plan.value(), 1, 0, 64);
        }
        std::printf("bridge marshal+dispatch:%8.3f us/op (0-arg HRESULT)\n",
                    ms_since(t0) * 1000.0 / N);
        (void)pm.terminate_process(ph.value(), 0);
    }

    // ── execution-context lifecycle + engine execution ──
    {
        // Guest program: MOV RAX,1..30 (10B each is slow; use ADDs):
        // MOV RAX, 7; ADD RAX, imm32 x20; RET -> measures ~22 instructions.
        std::vector<std::uint8_t> code{0x48, 0xB8, 7, 0, 0, 0, 0, 0, 0, 0};
        for (int i = 0; i < 20; ++i) {
            const std::uint8_t add[] = {0x48, 0x81, 0xC0, 0x01, 0, 0, 0};
            code.insert(code.end(), add, add + sizeof add);
        }
        code.push_back(0xC3);
        test::PeBuildSpec spec;
        spec.text_payloads.push_back({0x1000, code});
        spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
        auto image = test::PeBuilder(spec).build();
        diag::Diagnostics pd;
        auto img = pe::parse(image.data(), image.size(), "bench.exe", pd);
        loader::ImageLoader loader;
        api::ApiResolver resolver(reg);
        auto cfg = exec::ExecutionConfig::default_validated().value();

        // Context creation benchmark (per process: load + context + init).
        {
            for (int w = 0; w < 3; ++w) {
                auto ph = pm.create_process("bench-ctx.exe", 32ull << 20);
                loader::LoadDiagnostics ld;
                loader::LoadResult out;
                auto h = loader.load_image(pm, core.objects(), ph.value(), img,
                                           image.data(), image.size(),
                                           &resolver, ld, out);
                exec::ExecutionContext ctx(1, 1,
                                            [&]() -> AddressSpace& {
                                                auto pr = core.objects().lookup_handle(ph.value());
                                                return pr.value().get()->as<ManagedProcess>()->address_space();
                                            }(), reg, cfg, "bench");
                (void)ctx.initialize();
                (void)ctx.destroy();
                (void)loader.unload_image(pm, core.objects(), ph.value(), h.value());
                (void)pm.terminate_process(ph.value(), 0);
            }
            const int N = 100;
            const auto t0 = Clock::now();
            for (int i = 0; i < N; ++i) {
                auto ph = pm.create_process("bench-ctx.exe", 32ull << 20);
                loader::LoadDiagnostics ld;
                loader::LoadResult out;
                auto h = loader.load_image(pm, core.objects(), ph.value(), img,
                                           image.data(), image.size(),
                                           &resolver, ld, out);
                auto pr = core.objects().lookup_handle(ph.value());
                auto* proc = pr.value().get()->as<ManagedProcess>();
                exec::ExecutionContext ctx(1, 1, proc->address_space(), reg,
                                            cfg, "bench");
                (void)ctx.initialize();
                (void)ctx.destroy();
                (void)loader.unload_image(pm, core.objects(), ph.value(), h.value());
                (void)pm.terminate_process(ph.value(), 0);
            }
            std::printf("ctx full lifecycle:     %8.3f ms/op (proc+load+ctx+teardown)\n",
                        ms_since(t0) / N);
        }

        // Engine execution benchmark (reused context; includes the
        // completion check + faults machinery per run).
        {
            auto ph = pm.create_process("bench-run.exe", 64ull << 20);
            loader::LoadDiagnostics ld;
            loader::LoadResult out;
            auto h = loader.load_image(pm, core.objects(), ph.value(), img,
                                       image.data(), image.size(),
                                       &resolver, ld, out);
            auto pr = core.objects().lookup_handle(ph.value());
            auto* proc = pr.value().get()->as<ManagedProcess>();
            exec::ExecutionContext ctx(1, 1, proc->address_space(), reg, cfg,
                                        "bench");
            (void)ctx.initialize();
            loader::LoadedImageObject* loaded = nullptr;
            {
                auto lr = proc->handle_table().lookup(h.value());
                loaded = lr.value().get()->as<loader::LoadedImageObject>();
            }
            abi::CallSpec spec2;
            spec2.ret = abi::CallSpec::ReturnKind::Int;
            auto req = ctx.prepare_entry(*loaded, 0, {}, spec2);
            exec::DeterministicBackend engine(reg, cfg);
            engine.bind_space(proc->address_space());
            engine.bind_process(1, 1);
            std::atomic<bool> stop{false};
            for (int w = 0; w < kWarmup; ++w) {
                // Reset CPU state per run through prepare_entry.
                auto req2 = ctx.prepare_entry(*loaded, 0, {}, spec2);
                (void)ctx.invoke(req2.value(), engine, stop);
            }
            const int N = 10000;
            const auto t0 = Clock::now();
            for (int i = 0; i < N; ++i) {
                auto req2 = ctx.prepare_entry(*loaded, 0, {}, spec2);
                (void)ctx.invoke(req2.value(), engine, stop);
            }
            std::printf("backend execute:        %8.3f us/op (22 insns: MOV+20xADD+RET)\n",
                        ms_since(t0) * 1000.0 / N);
            (void)ctx.destroy();
            (void)loader.unload_image(pm, core.objects(), ph.value(), h.value());
            (void)pm.terminate_process(ph.value(), 0);
        }
    }

    // ── exception reporting ──
    {
        for (int w = 0; w < kWarmup; ++w) {
            exec::GuestException e;
            e.fault = exec::GuestFault::InvalidAccess;
            e.detail = "x";
            (void)exec::format_exception(e);
        }
        const int N = 200000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            exec::GuestException e;
            e.fault = exec::GuestFault::InvalidAccess;
            e.detail = "x";
            (void)exec::format_exception(e);
        }
        std::printf("exception report:       %8.3f ns/op (format+alloc)\n",
                    ms_since(t0) * 1e6 / N);
    }

    (void)core.shutdown();
    std::printf("done.\n");
    return 0;
}
