// src/run_cli.cpp — `xbox2pc run <file>`: the M11 Phase 9 entry point,
// extended in M12 P0 with a report on every outcome and the
// --unimplemented policy.
//
// Shared by the xbox2pc CLI tool and the m11/m12 run integration suites.
// See include/xbox2pc/run_cli.hpp for the contract.

#include "xbox2pc/run_cli.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
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

constexpr unsigned long long u64(std::uint64_t v) { return static_cast<unsigned long long>(v); }

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

// The service world of the run path: every service the repository has, the
// same three as the CLI's M7World. Until M12 P0 it registered only
// GameRuntimeService, so our own compiler-built M11 sample could not load
// here (docs/m12-what-broke.md, entry 3).
struct RunWorld {
    ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    RunWorld() : pm(core.objects()) {
        (void)core.services().register_service(
            std::make_unique<rt::api::GameRuntimeService>(reg, pm));
        (void)core.services().register_service(
            std::make_unique<rt::api::TaskQueueService>(reg, pm));
        (void)core.services().register_service(
            std::make_unique<rt::api::TimingService>(reg));
        (void)core.initialize();
    }
    ~RunWorld() { (void)core.shutdown(); }
};

// One IAT slot as the report shows it.
struct ReportedImport {
    std::string dll;
    std::string name;       // empty for an ordinal import
    std::uint32_t ordinal = 0;
    std::string status;     // resolved | unimplemented | unresolved | unsupported | invalid
    std::string note;
};

// The run report. Written on every outcome once the input path is known, so
// a caller never has to parse stderr to learn why nothing ran.
struct Report {
    std::string file;
    std::string backend = "none";       // none | deterministic-run | native-run
    std::string unimplemented;          // the policy name
    std::string outcome;
    std::string stage;
    std::string error;                  // why a stage failed (empty when nothing did)
    std::string detail;                 // the formatted guest exception, if any
    bool ran = false;                   // a backend executed guest code
    std::uint64_t exit_code = 0;        // the guest's process-style code (RAX & 0xFF)
    std::uint64_t return_value = 0;
    std::uint64_t instructions = 0;
    std::uint32_t api_calls = 0;
    std::uint32_t unimplemented_calls = 0;
    std::string first_unimplemented;    // dll!name of the first stub reached
    std::uint64_t regions_after_terminate = 0;
    std::vector<ReportedImport> imports;  // every IAT slot, in image order
};

std::uint64_t count_imports(const Report& r, const char* status) {
    std::uint64_t n = 0;
    for (const auto& imported : r.imports) {
        if (imported.status == status) ++n;
    }
    return n;
}

Json report_json(const Report& r) {
    Json j = Json::object();
    j.set("file", r.file);
    j.set("backend", r.backend);
    j.set("unimplemented", r.unimplemented);
    j.set("outcome", r.outcome);
    j.set("stage", r.stage);
    j.set("error", r.error);
    j.set("detail", r.detail);
    j.set("ran", r.ran);
    j.set("exit_code", r.exit_code);
    j.set("return_value", r.return_value);
    j.set("instructions", r.instructions);
    j.set("api_calls", r.api_calls);
    j.set("unimplemented_calls", r.unimplemented_calls);
    j.set("first_unimplemented", r.first_unimplemented);
    j.set("regions_after_terminate", r.regions_after_terminate);
    Json imports = Json::object();
    imports.set("total", static_cast<std::uint64_t>(r.imports.size()));
    imports.set("resolved", count_imports(r, "resolved"));
    imports.set("unimplemented", count_imports(r, "unimplemented"));
    imports.set("unresolved", count_imports(r, "unresolved"));
    imports.set("unsupported", count_imports(r, "unsupported"));
    imports.set("invalid", count_imports(r, "invalid"));
    j.set("imports", std::move(imports));
    Json missing = Json::array();
    for (const auto& imported : r.imports) {
        if (imported.status == "resolved") continue;
        Json e = Json::object();
        e.set("dll", imported.dll);
        e.set("name", imported.name);
        e.set("ordinal", imported.ordinal);
        e.set("status", imported.status);
        e.set("note", imported.note);
        missing.push_back(std::move(e));
    }
    j.set("missing", std::move(missing));
    return j;
}

void print_report(const Report& r) {
    const std::string rule(64, '=');
    std::printf("%s\nxbox2pc run %s\n%s\n", rule.c_str(), r.file.c_str(), rule.c_str());
    std::printf("  outcome:     %s  (stage: %s)\n", r.outcome.c_str(), r.stage.c_str());
    std::printf("  backend:     %s   unimplemented: %s\n",
                r.backend.c_str(), r.unimplemented.c_str());
    std::printf("  imports:     %zu total: %llu resolved, %llu unimplemented, "
                "%llu unresolved, %llu unsupported, %llu invalid\n",
                r.imports.size(), u64(count_imports(r, "resolved")),
                u64(count_imports(r, "unimplemented")), u64(count_imports(r, "unresolved")),
                u64(count_imports(r, "unsupported")), u64(count_imports(r, "invalid")));
    for (const auto& imported : r.imports) {
        if (imported.status == "resolved") continue;
        const std::string symbol = imported.name.empty()
            ? "#" + std::to_string(imported.ordinal) : imported.name;
        std::printf("  missing:     %s!%s (%s)\n", imported.dll.c_str(), symbol.c_str(),
                    imported.status.c_str());
    }
    if (r.ran) {
        std::printf("  exit code:   %llu (RAX & 0xFF)\n", u64(r.exit_code));
        std::printf("  instructions: %llu   api calls: %u   unimplemented calls: %u\n",
                    u64(r.instructions), r.api_calls, r.unimplemented_calls);
        if (!r.first_unimplemented.empty())
            std::printf("  first unimplemented import reached: %s\n",
                        r.first_unimplemented.c_str());
        std::printf("  teardown:    regions after terminate = %llu\n",
                    u64(r.regions_after_terminate));
    }
    if (!r.detail.empty()) std::printf("  detail:      %s\n", r.detail.c_str());
    if (!r.error.empty()) std::printf("  error:       %s\n", r.error.c_str());
    std::printf("  NOTE: subset interpreter execution — NOT a general emulator,\n");
    std::printf("        NOT a claim of Xbox-title compatibility.\n");
    std::printf("%s\n", rule.c_str());
}

void collect_imports(Report& report, const LoadDiagnostics& ld) {
    for (const auto& imported : ld.imports) {
        ReportedImport e;
        e.dll = imported.lookup.dll;
        e.name = imported.lookup.symbol;
        e.ordinal = imported.lookup.ordinal;
        e.status = imported.unimplemented
            ? "unimplemented"
            : rt::loader::import_status_to_name(imported.status);
        e.note = imported.note;
        report.imports.push_back(std::move(e));
    }
}

}  // namespace

int run_file(const std::string& file, const std::optional<std::string>& json_out,
             const std::string& backend, const rt::api::UnimplementedPolicy unimplemented) {
    Report report;
    report.file = file;
    report.unimplemented = rt::api::unimplemented_policy_to_name(unimplemented);

    // A usage error is the caller's mistake, not a property of the program:
    // stderr only, no report file.
    if (backend != "deterministic" && backend != "native") {
        std::fprintf(stderr, "error: unknown backend '%s' (deterministic | native)\n",
                     backend.c_str());
        return 2;
    }
    bool native_available = false;
#if XBOX2PC_NATIVE_EXECUTION_ENABLED
    native_available = true;
#endif
    if (backend == "native" && !native_available) {
        std::fprintf(stderr,
                     "error: --backend=native requires a build with "
                     "-DXBOX2PC_NATIVE_EXECUTION=ON\n");
        return 2;
    }

    const auto finish = [&](int code) -> int {
        if (json_out.has_value()) {
            if (!write_file(*json_out, report_json(report).serialize() + "\n")) return 1;
            std::printf("wrote %s\n", json_out->c_str());
        } else {
            print_report(report);
        }
        return code;
    };

    report.stage = "read";
    std::ifstream in(file, std::ios::binary);
    if (!in.good()) {
        report.outcome = "cannot_open";
        report.error = "cannot open " + file;
        std::fprintf(stderr, "error: %s\n", report.error.c_str());
        return finish(2);
    }
    std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
    if (image.empty()) {
        report.outcome = "cannot_open";
        report.error = file + " is empty";
        std::fprintf(stderr, "error: %s\n", report.error.c_str());
        return finish(2);
    }
    std::string base = file;
    const auto slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);

    report.stage = "parse";
    diag::Diagnostics pd;
    pe::PeImage img;
    try {
        img = pe::parse(image.data(), image.size(), base, pd);
    } catch (const pe::ParseError& error) {
        report.outcome = "not_pe";
        report.error = std::string("not a parseable PE32+ image: ") + error.what();
        std::fprintf(stderr, "error: %s\n", report.error.c_str());
        return finish(2);
    }
    if (pd.has_errors()) {
        report.outcome = "not_pe";
        report.error = "not a parseable PE32+ image";
        std::fprintf(stderr, "error: %s: %s\n", file.c_str(), report.error.c_str());
        return finish(2);
    }

    report.stage = "process";
    RunWorld w;
    auto ph = w.pm.create_process("run-guest.exe", 64ull << 20);
    if (!ph.ok()) {
        report.outcome = "error";
        report.error = "process creation failed: " + ph.error_string();
        std::fprintf(stderr, "error: %s\n", report.error.c_str());
        return finish(1);
    }
    // The Win32 process and memory APIs (VirtualAlloc, CreateEvent, ...) act
    // only on a process in the Running state. The M11 run path created the
    // process and loaded the image without initializing or starting it, so
    // every such call failed and the compiler-built M11 sample took its
    // "VirtualAlloc returned NULL" branch (docs/m12-what-broke.md, entry 12).
    // Do what the execution tests do: initialize with the module, then start.
    rt::ModuleDescriptor module;
    module.module_name = base;
    module.is_valid_pe = true;
    auto initialized = w.pm.initialize_process(ph.value(), module, rt::RuntimeConfig{});
    if (!initialized.ok()) {
        report.outcome = "error";
        report.error = "process initialization failed: " + initialized.error_string();
        std::fprintf(stderr, "error: %s\n", report.error.c_str());
        return finish(1);
    }
    auto started = w.pm.start_process(ph.value());
    if (!started.ok()) {
        report.outcome = "error";
        report.error = "process start failed: " + started.error_string();
        std::fprintf(stderr, "error: %s\n", report.error.c_str());
        return finish(1);
    }
    auto pr = w.core.objects().lookup_handle(ph.value());
    auto* proc = pr.value().get()->as<ManagedProcess>();

    report.stage = "load";
    ImageLoader loader;
    ApiResolver resolver(w.reg, unimplemented);
    LoadDiagnostics ld;
    LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), ph.value(), img,
                               image.data(), image.size(), &resolver, ld, out);
    // The resolver's verdict on every IAT slot is part of the report even
    // (especially) when the load fails.
    collect_imports(report, ld);
    if (!h.ok()) {
        report.outcome = "load_failed";
        report.error = out.error;
        (void)w.pm.terminate_process(ph.value(), 0);
        std::fprintf(stderr, "error: load failed: %s\n", out.error.c_str());
        return finish(1);
    }

    // Everything after a successful load shares one teardown.
    const auto abandon = [&](const std::string& outcome, const std::string& error) -> int {
        report.outcome = outcome;
        report.error = error;
        (void)loader.unload_image(w.pm, w.core.objects(), ph.value(), h.value());
        (void)w.pm.terminate_process(ph.value(), 0);
        std::fprintf(stderr, "error: %s\n", error.c_str());
        return finish(1);
    };

    report.stage = "prepare";
    auto cfg = ExecutionConfig::default_validated().value();
    ExecutionContext ctx(1, 1, proc->address_space(), w.reg, cfg, "cli-run");
    auto ini = ctx.initialize();
    if (!ini.ok()) {
        (void)ctx.destroy();
        return abandon("prepare_failed", "execution context failed: " + ini.error_string());
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
        (void)ctx.destroy();
        return abandon("prepare_failed", "prepare failed: " + req.error_string());
    }
    // M11 Phase 6: bind the raw image bytes so RaiseException dispatch can
    // search .pdata/.xdata (RVAs resolve through the file's section table).
    req.value().unwind.unwind_image = image;
    req.value().unwind.image_base = loaded->layout().actual_base;
    req.value().unwind.image_size = loaded->layout().mapped_size;
    // M11 Phase 5: IAT VAs for the native import ring (same order as the
    // loader-reported bindings).
    for (const auto& imported : ld.imports) {
        if (imported.status == rt::loader::ImportStatus::Resolved && imported.value != 0)
            req.value().api_iat_vas.push_back(imported.iat_va);
    }
    if (ctx.guest_environment() != nullptr)
        req.value().guest_teb_va = ctx.guest_gs_base();

    report.stage = "execute";
    std::atomic<bool> stop{false};
    rt::Result<rt::exec::ExecutionResult> res_holder =
        rt::Result<rt::exec::ExecutionResult>(
            rt::RuntimeErrc::InvalidState, "no backend ran");
    const char* used_backend = "deterministic-run";
#if XBOX2PC_NATIVE_EXECUTION_ENABLED
    if (backend == "native") {
        rt::exec::NativeExecutionBackend engine(w.reg, std::chrono::milliseconds(5000));
        engine.bind_execution_context(1, 1, proc->address_space());
        res_holder = ctx.invoke(req.value(), engine, stop);
        used_backend = "native-run";
    } else
#endif
    {
        DeterministicBackend engine(w.reg, cfg);
        engine.bind_space(proc->address_space());
        engine.bind_process(1, 1);
        res_holder = ctx.invoke(req.value(), engine, stop);
        used_backend = "deterministic-run";
    }

    report.stage = "teardown";
    const auto& res = res_holder;
    const bool ok = res.ok() && res.value().outcome == Outcome::Returned;
    const auto rax = res.ok() ? res.value().return_value : 0;
    (void)ctx.destroy();
    (void)loader.unload_image(w.pm, w.core.objects(), ph.value(), h.value());
    (void)w.pm.terminate_process(ph.value(), rax & 0xFFu);
    // Snapshot AFTER termination so the reported region count reflects
    // completed teardown (the field name promises post-terminate state).
    const auto st = proc->address_space().stats();

    report.ran = true;
    report.backend = used_backend;
    report.outcome = res.ok() ? rt::exec::outcome_to_name(res.value().outcome) : "error";
    report.error = res.ok() ? std::string() : res.error_string();
    report.exit_code = rax & 0xFFu;
    report.return_value = rax;
    report.instructions = res.ok() ? res.value().instructions_executed : 0;
    report.api_calls = res.ok() ? res.value().api_calls : 0;
    report.unimplemented_calls = res.ok() ? res.value().unimplemented_calls : 0;
    report.first_unimplemented = res.ok() ? res.value().first_unimplemented : std::string();
    if (res.ok() && res.value().exception.has_value())
        report.detail = rt::exec::format_exception(*res.value().exception);
    report.regions_after_terminate = st.region_count;
    return finish(ok ? 0 : 1);
}

}  // namespace xbox2pc::cli
