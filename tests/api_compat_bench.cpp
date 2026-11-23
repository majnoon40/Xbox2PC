// xbox2pc/tests/api_compat_bench.cpp — M7 API-path benchmarks (spec §16).
//
// Measures: API registration, lookup, dispatch, normal import resolution
// (ApiResolver), delay-load resolution, TLS initialization, compatibility
// reporting, concurrent API calls. Timings: steady_clock; the container
// environment and methodology are printed. Correctness beats throughput.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/compat_report.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/runtime_core.hpp"

using namespace xbox2pc::rt::api;
using xbox2pc::diag::Diagnostics;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

namespace {
using Clock = std::chrono::steady_clock;
double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0)
        .count();
}
}  // namespace

int main() {
    ApiRegistry reg;
    xbox2pc::rt::RuntimeCore core;
    xbox2pc::rt::ProcessManager pm(core.objects());
    {
        auto grt = std::make_unique<GameRuntimeService>(reg, pm);
        auto tq = std::make_unique<TaskQueueService>(reg, pm);
        auto tim = std::make_unique<TimingService>(reg);
        (void)core.services().register_service(std::move(grt));
        (void)core.services().register_service(std::move(tq));
        (void)core.services().register_service(std::move(tim));
    }
    (void)core.initialize();
    std::printf("M7 benchmarks (container CPU, Release build, "
                "steady_clock, mean over N ops)\n");

    // ── API registration (16 built-ins re-registered into a fresh table) ──
    {
        const int N = 500;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            ApiRegistry fresh;
        }
        std::printf("descriptor table load:   %8.3f ms/op (16 descriptors)\n",
                    ms_since(t0) / N);
    }

    // ── API lookup ──
    {
        const int N = 200000;
        const auto t0 = Clock::now();
        std::size_t hits = 0;
        for (int i = 0; i < N; ++i) {
            if (reg.find("xgameruntime", "XSystemGetDeviceType") != nullptr) ++hits;
        }
        std::printf("api lookup:              %8.3f ns/op (%llu hits)\n",
                    ms_since(t0) * 1e6 / N,
                    static_cast<unsigned long long>(hits));
    }

    // ── API dispatch ──
    {
        const int N = 50000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            ApiContext ctx;
            (void)reg.dispatch("xgameruntime", "XSystemGetDeviceType", ctx);
        }
        std::printf("api dispatch:             %8.3f us/op\n",
                    ms_since(t0) * 1000.0 / N);
    }

    // ── concurrent API calls ──
    {
        const int T = 4;
        const int N = 20000;
        std::atomic<std::size_t> ok{0};
        const auto t0 = Clock::now();
        std::vector<std::thread> threads;
        for (int t = 0; t < T; ++t) {
            threads.emplace_back([&] {
                for (int i = 0; i < N; ++i) {
                    ApiContext ctx;
                    if (reg.dispatch("xgameruntime", "XSystemGetDeviceType", ctx).ok) {
                        ++ok;
                    }
                }
            });
        }
        for (auto& t : threads) t.join();
        const double total_ops = static_cast<double>(T) * N;
        std::printf("concurrent dispatch:      %8.3f us/op/op (%llu ok, %d threads)\n",
                    ms_since(t0) * 1000.0 / total_ops,
                    static_cast<unsigned long long>(ok.load()), T);
    }

    // ── import resolution (ApiResolver over imports) ──
    {
        PeBuildSpec spec;
        spec.imports = {
            {"xgameruntime", {{"XGameRuntimeInitialize", 1}, {"XSystemGetDeviceType", 2}}},
            {"kernel32", {{"QueryPerformanceCounter", 1}}},
        };
        auto image = PeBuilder(spec).build();
        Diagnostics pd;
        auto img = xbox2pc::pe::parse(image.data(), image.size(), "b.exe", pd);
        ApiResolver resolver(reg);
        const int N = 20000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            xbox2pc::rt::loader::ImportLookup look;
            look.dll = "xgameruntime";
            look.symbol = "XGameRuntimeInitialize";
            (void)resolver.resolve(look);
        }
        std::printf("import resolve:           %8.3f us/op\n",
                    ms_since(t0) * 1000.0 / N);
    }

    // ── delay-load resolution (full mapped-image pass) ──
    {
        PeBuildSpec spec;
        spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
        spec.delay_imports = {{"xgameruntime", {{"XSystemGetDeviceType", 1}}}};
        spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
        auto image = PeBuilder(spec).build();
        Diagnostics pd;
        auto img = xbox2pc::pe::parse(image.data(), image.size(), "b.exe", pd);
        xbox2pc::rt::loader::ImageLoader loader;
        const int N = 300;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            auto p = pm.create_process("bench-delay.exe", 32ull << 20);
            if (!p.ok()) continue;
            auto found = core.objects().lookup_handle(p.value());
            auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
            xbox2pc::rt::loader::LoadDiagnostics ld;
            auto lay = loader.map_image(proc->address_space(), img,
                                        image.data(), image.size(), 0, ld);
            if (lay.ok()) {
                (void)resolve_delay_imports(proc->address_space(), lay.value(),
                                            img, image.data(), image.size(),
                                            reg, false);
            }
            (void)pm.terminate_process(p.value(), 0);
        }
        std::printf("delay-load pass:          %8.3f ms/op (map+resolve+term)\n",
                    ms_since(t0) / N);
    }

    // ── TLS initialization ──
    {
        PeBuildSpec spec;
        spec.tls.template_data = {1, 2, 3, 4, 5, 6, 7, 8};
        spec.tls.zero_fill = 32;
        auto image = PeBuilder(spec).build();
        Diagnostics pd;
        auto img = xbox2pc::pe::parse(image.data(), image.size(), "b.exe", pd);
        xbox2pc::rt::loader::LoadDiagnostics ld;
        auto tls = xbox2pc::rt::loader::decode_tls(img, image.data(),
                                                   image.size(), ld);
        const int N = 20000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            auto idx = tls_assign_index(9500, "b.exe", *tls.value());
            xbox2pc::rt::RtThread t(
                [](xbox2pc::rt::RtThread&, void*) -> void* { return nullptr; },
                nullptr, "b");
            (void)tls_init_thread(t, idx.value(), img, image.data(),
                                  image.size(), *tls.value());
        }
        std::printf("tls init (assign+copy):   %8.3f us/op\n",
                    ms_since(t0) * 1000.0 / N);
    }

    // ── compatibility report ──
    {
        PeBuildSpec spec;
        spec.imports = {
            {"xgameruntime", {{"XGameRuntimeInitialize", 1}}},
            {"kernel32", {{"QueryPerformanceCounter", 1}}},
            {"mystery.dll", {{"Unknown", 1}}},
        };
        auto image = PeBuilder(spec).build();
        Diagnostics pd;
        auto img = xbox2pc::pe::parse(image.data(), image.size(), "b.exe", pd);
        Diagnostics dd;
        const int N = 2000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            auto dep = xbox2pc::deps::analyze(img, dd);
            (void)build_compat_report(img, dep, reg, nullptr);
        }
        std::printf("compat report:            %8.3f us/op (3 rows)\n",
                    ms_since(t0) * 1000.0 / N);
    }

    (void)core.shutdown();
    std::printf("done.\n");
    return 0;
}
