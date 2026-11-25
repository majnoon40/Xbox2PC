// src/run_cli.cpp — M11 Phase 9 `xbox2pc run <file>` implementation.
//
// Shared by the xbox2pc CLI tool and the m11_run_test integration
// suite. See include/xbox2pc/run_cli.hpp for the contract.

#include "xbox2pc/run_cli.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/execution_context.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/json_writer.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/runtime_core.hpp"

namespace xbox2pc::cli {
namespace {

using xbox2pc::json::Json;
using rt::ManagedProcess;
using rt::RuntimeCore;
using rt::ProcessManager;
using rt::api::ApiRegistry;
using rt::api::ApiResolver;
using rt::exec::DeterministicBackend;
using rt::exec::ExecutionContext;
using rt::exec::ExecutionConfig;
using rt::exec::Outcome;
using rt::loader::ImageLoader;
using rt::loader::LoadDiagnostics;
using rt::loader::LoadResult;

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

// Minimal service world for the run path (mirrors the CLI's M8World).
struct RunWorld {
    ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    RunWorld() : pm(core.objects()) {
        {
            auto grt = std::make_unique<rt::api::GameRuntimeService>(reg, pm);
            (void)core.services().register_service(std::move(grt));
        }
        (void)core.initialize();
    }
    ~RunWorld() { (void)core.shutdown(); }
};

}  // namespace

int run_file(const std::string& file, const std::optional<std::string>& json_out) {
    std::ifstream in(file, std::ios::binary);
    if (!in.good()) {
        std::fprintf(stderr, "error: cannot open %s\n", file.c_str());
        return 2;
    }
    std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
    if (image.empty()) {
        std::fprintf(stderr, "error: %s is empty\n", file.c_str());
        return 2;
    }
    std::string base = file;
    const auto slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    diag::Diagnostics pd;
    auto img = pe::parse(image.data(), image.size(), base, pd);
    if (pd.has_errors()) {
        std::fprintf(stderr, "error: %s is not a parseable PE32+ image\n", file.c_str());
        return 2;
    }

    RunWorld w;
    auto ph = w.pm.create_process("run-guest.exe", 64ull << 20);
    if (!ph.ok()) {
        std::fprintf(stderr, "error: process creation failed\n");
        return 1;
    }
    auto pr = w.core.objects().lookup_handle(ph.value());
    auto* proc = pr.value().get()->as<ManagedProcess>();
    ImageLoader loader;
    ApiResolver resolver(w.reg);
    LoadDiagnostics ld;
    LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), ph.value(), img,
                               image.data(), image.size(), &resolver, ld, out);
    if (!h.ok()) {
        std::fprintf(stderr, "error: load failed: %s\n", out.error.c_str());
        return 1;
    }
    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(1, 1, proc->address_space(), w.reg, cfg, "cli-run");
    auto ini = ctx.initialize();
    if (!ini.ok()) {
        std::fprintf(stderr, "error: execution context failed\n");
        return 1;
    }
    rt::loader::LoadedImageObject* loaded = nullptr;
    {
        auto lr = proc->handle_table().lookup(h.value());
        loaded = lr.value().get()->as<rt::loader::LoadedImageObject>();
    }  // guard released before teardown (pin-drain contract)
    rt::abi::CallSpec cspec;
    cspec.ret = rt::abi::CallSpec::ReturnKind::Int;
    auto req = ctx.prepare_entry(*loaded, 0, {}, cspec);
    if (!req.ok()) {
        std::fprintf(stderr, "error: prepare failed: %s\n",
                     req.error_string().c_str());
        return 1;
    }
    DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(proc->address_space());
    engine.bind_process(1, 1);
    std::atomic<bool> stop{false};
    auto res = ctx.invoke(req.value(), engine, stop);
    const bool ok = res.ok() && res.value().outcome == Outcome::Returned;
    const auto rax = res.ok() ? res.value().return_value : 0;
    (void)ctx.destroy();
    (void)loader.unload_image(w.pm, w.core.objects(), ph.value(), h.value());
    (void)w.pm.terminate_process(ph.value(), rax & 0xFFu);
    // Snapshot AFTER termination so the reported region count reflects
    // completed teardown (the field name promises post-terminate state).
    const auto st = proc->address_space().stats();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", file);
        j.set("backend", "deterministic-run");
        j.set("outcome", res.ok() ? rt::exec::outcome_to_name(res.value().outcome) : "error");
        j.set("instructions", res.ok() ? res.value().instructions_executed : 0);
        j.set("return_value", rax);
        j.set("exit_code", rax & 0xFFu);
        j.set("api_calls", res.ok() ? res.value().api_calls : 0);
        j.set("regions_after_terminate", static_cast<std::uint64_t>(st.region_count));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return ok ? 0 : 1;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc run %s\n", file.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    if (res.ok()) {
        std::printf("  outcome:     %s  instructions=%llu  RAX=%llu\n",
                    rt::exec::outcome_to_name(res.value().outcome),
                    (unsigned long long)res.value().instructions_executed,
                    (unsigned long long)rax);
        std::printf("  exit code:   %llu (RAX & 0xFF)\n",
                    (unsigned long long)(rax & 0xFFu));
        std::printf("  api calls:   %llu\n",
                    (unsigned long long)res.value().api_calls);
    } else {
        std::printf("  outcome:     error: %s\n", res.error_string().c_str());
    }
    std::printf("  teardown:    regions after terminate = %u\n", st.region_count);
    std::printf("  NOTE: subset interpreter execution — NOT a general emulator,\n");
    std::printf("        NOT a claim of Xbox-title compatibility.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return ok ? 0 : 1;
}

}  // namespace xbox2pc::cli
