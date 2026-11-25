// xbox2pc CLI — M1 inspect + M2 dependencies/graph/classify.
//
// Commands:
//   xbox2pc inspect <file> [--quiet]
//   xbox2pc dependencies <file> [--json <out>]   (default prints text)
//   xbox2pc graph <file> [--json <out>]
//   xbox2pc classify <file>
//
// Exit codes: 0 success (warnings allowed), 1 parse error, 2 usage error.
// Structured output on stdout; diagnostics to stderr.

#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/api_registry.hpp"
#include "xbox2pc/compat_db.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/dep_graph.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/json_writer.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/run_cli.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/package_vfs.hpp"
#include "xbox2pc/packages.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/vfs_backends.hpp"
#include "xbox2pc/vfs_process.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/service_registry.hpp"
#include "xbox2pc/thread_model.hpp"
#include "xbox2pc/m9_cli.hpp"

using xbox2pc::compat::CompatibilityDb;
using xbox2pc::deps::DependencyReport;
using xbox2pc::graph::DependencyGraph;
using xbox2pc::json::Json;
using xbox2pc::pe::PeImage;
using xbox2pc::registry::ApiRegistry;
using Diagnostics = xbox2pc::diag::Diagnostics;

namespace {

std::string hex(std::uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(v));
    return b;
}

std::string human_size(std::uint64_t bytes) {
    char b[48];
    if (bytes >= 1024 * 1024) {
        std::snprintf(b, sizeof(b), "%.2f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        std::snprintf(b, sizeof(b), "%.2f KiB", static_cast<double>(bytes) / 1024.0);
    } else {
        std::snprintf(b, sizeof(b), "%llu B", static_cast<unsigned long long>(bytes));
    }
    return b;
}

void usage() {
    std::fprintf(stderr,
                 "usage: xbox2pc inspect <pe-file> [--quiet]\n"
                 "       xbox2pc dependencies <pe-file> [--json <out>]\n"
                 "       xbox2pc graph <pe-file> [--json <out>]\n"
                 "       xbox2pc classify <pe-file>\n"
                 "       xbox2pc runtime-info [--json <out>]\n"
                 "       xbox2pc runtime-objects [--json <out>]\n"
                 "       xbox2pc runtime-services [--json <out>]\n"
                 "       xbox2pc memory-info [--json <out>]\n"
                 "       xbox2pc memory-regions [--json <out>]\n"
                 "       xbox2pc process-info [--json <out>]\n"
                 "       xbox2pc thread-info [--json <out>]\n"
                 "       xbox2pc handle-info [--json <out>]\n"
                 "       xbox2pc resource-info [--json <out>]\n"
                 "       xbox2pc mount\n"
                 "       xbox2pc unmount\n"
                 "       xbox2pc list <path> [--json <out>]\n"
                 "       xbox2pc stat <path> [--json <out>]\n"
                 "       xbox2pc read <path> [--limit N] [--json <out>]\n"
                 "       xbox2pc packages [--json <out>]\n"
                 "       xbox2pc discover [path] [--json <out>]\n"
                 "       xbox2pc validate-pe <pe-file> [--json <out>]\n"
                 "       xbox2pc map-image <pe-file> [--base 0xVA] [--json <out>]\n"
                 "       xbox2pc relocations <pe-file> [--json <out>]\n"
                 "       xbox2pc imports <pe-file> [--json <out>]\n"
                 "       xbox2pc load-image <pe-file> [--json <out>]\n"
                 "       xbox2pc unload-image <pe-file>\n"
                 "       xbox2pc image-info <pe-file> [--json <out>]\n"
                 "       xbox2pc cpu-state [--json <out>]\n"
                 "       xbox2pc abi-info [--json <out>]\n"
                 "       xbox2pc execution-info [--json <out>]\n"
                 "       xbox2pc tls-info [--json <out>]\n"
                 "       xbox2pc execute-test [--json <out>]\n"
                 "       xbox2pc api-list [--json <out>]\n"
                 "       xbox2pc api-info <library!name> [--json <out>]\n"
                 "       xbox2pc api-status [--json <out>]\n"
                 "       xbox2pc dispatch-test <library!name> [--json <out>]\n"
                 "       xbox2pc compat-report <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-analyze <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-info <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-sections <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-imports <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-relocations <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-tls <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-instructions <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-compat <pe-file> [--json <out>]\n"
                 "       xbox2pc binary-report <pe-file> [--json <out>]\n"
                 "       xbox2pc interpreter-info [--json <out>]\n"
                 "       xbox2pc interpreter-test [--json <out>]\n"
                 "       xbox2pc gdk-services [--json <out>]\n"
                 "       xbox2pc gameos-services [--json <out>]\n"
                 "       xbox2pc --version\n");
}

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

int load_and_run(const std::string& path,
                 const std::function<int(const PeImage&, const Diagnostics&)>& run) {
    Diagnostics diags;
    try {
        const PeImage img = xbox2pc::pe::parse_file(path, diags);
        return run(img, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s", e.what());
        if (e.has_offset()) std::fprintf(stderr, " at offset %s", hex(e.offset()).c_str());
        std::fprintf(stderr, "\n");
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}

// ── M1: inspect report (unchanged output) ─────────────────────────────────

void print_report(const PeImage& img, const Diagnostics& diags) {
    using namespace xbox2pc::pe;

    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc PE inspection report\n");
    std::printf("source: %s\n", img.source_name.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());

    std::printf("architecture:  %s\n", img.machine_name().c_str());
    std::printf("pe_format:     %s\n",
                img.opt.is_pe32plus ? "PE32+ (x86-64, 64-bit addresses)"
                                    : (img.opt.is_pe32 ? "PE32 (32-bit)" : "unknown"));
    std::printf("entry_point:   RVA %s", hex(img.opt.address_of_entry_point).c_str());
    if (const auto va = img.entry_point_va()) {
        std::printf(" (VA %s)", hex(*va).c_str());
    }
    std::printf("\n");
    std::printf("image_base:    %s\n", hex(img.opt.image_base).c_str());
    std::printf("subsystem:     %u (%s)\n", img.opt.subsystem, img.subsystem_name().c_str());
    std::printf("size_of_image: %s\n", hex(img.opt.size_of_image).c_str());
    std::printf("timestamp:     %u (0x%X)\n", img.coff.time_date_stamp, img.coff.time_date_stamp);
    std::printf("linker:        %u.%u\n", img.opt.major_linker_version,
                img.opt.minor_linker_version);
    std::printf("dll_characteristics: 0x%04X\n", img.opt.dll_characteristics);
    if (img.coff.characteristics & 0x2000) std::printf("image_type:    DLL\n");
    else if (img.coff.characteristics & 0x0002) std::printf("image_type:    executable\n");
    else std::printf("image_type:    object\n");

    std::printf("\nsections (%u):\n", static_cast<unsigned>(img.sections.size()));
    std::printf("  %-8s %-10s %-10s %-10s %-10s\n", "name", "vsize", "vaddr", "rawsz", "raw@");
    for (const auto& s : img.sections) {
        const bool readable = (s.characteristics & sect_flags::kReadable) != 0;
        std::printf("  %-8s %-10s %-10s %-10s %-10s %s%s%s%s%s\n",
                    s.name.c_str(),
                    hex(s.virtual_size).c_str(),
                    hex(s.virtual_address).c_str(),
                    hex(s.size_of_raw_data).c_str(),
                    hex(s.raw_data_offset).c_str(),
                    human_size(s.size_of_raw_data).c_str(),
                    readable ? " r" : "",
                    (s.characteristics & sect_flags::kCode) != 0 ? " code" : "",
                    (s.characteristics & sect_flags::kWritable) != 0 ? " w" : "",
                    s.has_raw_data ? "" : " [no raw data]");
    }

    std::printf("\ndata_directories:\n");
    bool any_dir = false;
    for (std::uint16_t i = 0; i < img.directories.size(); ++i) {
        const auto& d = img.directories[i];
        if (d.rva == 0 && d.size == 0) continue;
        any_dir = true;
        std::printf("  %-14s rva %s  size %s\n", d.name.c_str(), hex(d.rva).c_str(),
                    hex(d.size).c_str());
    }
    if (!any_dir) std::printf("  (none)\n");

    std::printf("\nimports:\n");
    if (!img.imports.present || img.imports.entries.empty()) {
        std::printf("  (none)\n");
    } else {
        std::size_t total_fn = 0;
        for (const auto& e : img.imports.entries) {
            total_fn += e.functions.size() + e.ordinal_only.size();
        }
        std::printf("  %zu DLL(s), %zu function(s)\n", img.imports.entries.size(), total_fn);
        for (const auto& e : img.imports.entries) {
            std::printf("  %s\n", e.dll_name.c_str());
            for (const auto& fn : e.functions) std::printf("      %s\n", fn.c_str());
            for (std::uint32_t ord : e.ordinal_only) {
                std::printf("      #%u (ordinal only)\n", ord);
            }
        }
    }

    std::printf("\nexports:\n");
    if (!img.exports.present || img.exports.functions.empty()) {
        std::printf("  (none)\n");
    } else {
        std::printf("  name: %s  (ordinal base %u, %zu functions, %zu named)\n",
                    img.exports.dll_name.empty() ? "(unnamed)" : img.exports.dll_name.c_str(),
                    img.exports.ordinal_base, img.exports.functions.size(),
                    img.exports.name_rvas.size());
        for (const auto& f : img.exports.functions) {
            const std::string fwd = f.forwarder.empty() ? ""
                : " -> forwarded to " + f.forwarder;
            std::printf("  #%-6u %-12s %s%s\n", f.ordinal, hex(f.rva).c_str(),
                        f.name.empty() ? "(unnamed)" : f.name.c_str(), fwd.c_str());
        }
    }

    std::printf("\ndiagnostics:\n");
    const auto& es = diags.entries();
    if (es.empty()) {
        std::printf("  (no warnings or errors)\n");
    } else {
        for (const auto& l : diags.lines()) std::printf("  %s\n", l.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
}

// ── M2: JSON dependency report ────────────────────────────────────────────

Json report_to_json(const DependencyReport& rep) {
    Json root = Json::object();
    root.set("tool", "xbox2pc");
    root.set("version", "0.2.0");
    root.set("source", rep.source);

    Json dlls = Json::array();
    for (const auto& d : rep.dependencies) {
        Json j = Json::object();
        j.set("dll", d.dll_name);
        j.set("category", d.category_name);
        j.set("classified", d.classified);
        j.set("regular_import", d.regular_import);
        j.set("delay_import", d.delay_import);
        j.set("duplicate", d.duplicate);
        j.set("function_count", static_cast<std::uint64_t>(d.function_count));
        Json sources = Json::array();
        for (const auto& s : d.import_sources) sources.push_back(s);
        j.set("import_sources", std::move(sources));
        if (d.timestamp != 0) j.set("bound_timestamp", d.timestamp);
        if (d.iat_rva != 0) j.set("iat_rva", d.iat_rva);
        if (d.int_rva != 0) j.set("int_rva", d.int_rva);
        Json fns = Json::array();
        for (const auto& f : d.functions) {
            Json fj = Json::object();
            fj.set("name", f.name);
            if (f.by_ordinal) {
                fj.set("ordinal", f.ordinal);
                fj.set("by_ordinal", true);
            } else if (f.ordinal != 0) {
                fj.set("hint_ordinal", f.ordinal);
            }
            fj.set("delay_load", f.delay_load);
            fj.set("unresolved", f.unresolved);
            fns.push_back(std::move(fj));
        }
        j.set("functions", std::move(fns));
        Json comp = Json::object();
        comp.set("status", xbox2pc::compat::status_to_name(d.compat_status));
        comp.set("known", d.compat_known);
        if (!d.compat_note.empty()) comp.set("windows_equivalent", d.compat_note);
        j.set("compatibility", std::move(comp));
        dlls.push_back(std::move(j));
    }
    root.set("dependencies", std::move(dlls));

    Json fwd = Json::array();
    for (const auto& f : rep.forwarded_exports) {
        Json fj = Json::object();
        fj.set("export", f.export_name);
        fj.set("forwarder", f.forwarder);
        fj.set("target_dll", f.target_dll);
        fj.set("target_api", f.target_api);
        fwd.push_back(std::move(fj));
    }
    root.set("forwarded_exports", std::move(fwd));

    root.set("distinct_dll_count", static_cast<std::uint64_t>(rep.distinct_dll_count()));
    root.set("total_function_imports", static_cast<std::uint64_t>(rep.total_function_imports()));
    root.set("duplicate_dependencies", static_cast<std::uint64_t>(rep.duplicate_count));
    root.set("unresolved_functions", static_cast<std::uint64_t>(rep.unresolved_function_count));
    root.set("unresolved_dlls", static_cast<std::uint64_t>(rep.unresolved_dll_count));
    root.set("has_delay_imports", rep.has_delay_imports);
    return root;
}

// ── M2: text dependency report ────────────────────────────────────────────

void print_dependencies(const DependencyReport& rep, const Diagnostics& diags) {
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc dependency analysis\n");
    std::printf("source: %s\n", rep.source.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());

    std::printf("\nimported DLLs (%zu distinct, %zu function imports):\n",
                rep.distinct_dll_count(), rep.total_function_imports());
    if (rep.dependencies.empty()) std::printf("  (none)\n");
    for (const auto& d : rep.dependencies) {
        std::printf("  %s  [%s]\n", d.dll_name.c_str(), d.category_name.c_str());
        if (d.regular_import && d.delay_import) {
            std::printf("      imported via: regular + delay-load\n");
        } else if (d.delay_import) {
            std::printf("      imported via: delay-load\n");
        }
        if (d.duplicate) std::printf("      duplicate dependency\n");
        if (d.compat_known) {
            std::printf("      compatibility: %s\n",
                        xbox2pc::compat::status_to_name(d.compat_status));
            if (!d.compat_note.empty()) {
                std::printf("        windows equivalent: %s\n", d.compat_note.c_str());
            }
        }
        for (const auto& f : d.functions) {
            if (f.by_ordinal) {
                std::printf("      #%u (ordinal%s)\n", f.ordinal,
                            f.delay_load ? ", delay" : "");
            } else {
                std::printf("      %s%s%s\n", f.name.c_str(), f.delay_load ? " (delay)" : "",
                            f.unresolved ? " [unresolved]" : "");
            }
        }
    }

    if (!rep.forwarded_exports.empty()) {
        std::printf("\nforwarded exports (%zu):\n", rep.forwarded_exports.size());
        for (const auto& f : rep.forwarded_exports) {
            std::printf("  %s -> %s (target %s!%s)\n", f.export_name.c_str(),
                        f.forwarder.c_str(), f.target_dll.c_str(), f.target_api.c_str());
        }
    }

    std::printf("\nsummary:\n");
    std::printf("  distinct DLLs:          %zu\n", rep.distinct_dll_count());
    std::printf("  function imports:      %zu\n", rep.total_function_imports());
    std::printf("  duplicates:            %zu\n", rep.duplicate_count);
    std::printf("  unresolved functions:  %zu\n", rep.unresolved_function_count);
    std::printf("  unresolved DLLs:       %zu\n", rep.unresolved_dll_count);
    std::printf("  delay-load DLLs:       %s\n", rep.has_delay_imports ? "yes" : "no");

    std::printf("\ndiagnostics:\n");
    if (diags.entries().empty()) {
        std::printf("  (no warnings or errors)\n");
    } else {
        for (const auto& l : diags.lines()) std::printf("  %s\n", l.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
}

// ── M2: graph command ─────────────────────────────────────────────────────

void print_graph(const DependencyGraph& g) {
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc dependency graph\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("\nnodes (%zu):\n", g.node_count());
    for (const auto& kv : g.nodes()) {
        std::printf("  %-34s %-22s%s%s\n", kv.second.id.c_str(), kv.second.category_name.c_str(),
                    kv.second.is_root ? " [root]" : "",
                    kv.second.missing ? " [missing]" : "");
    }
    std::printf("\nedges (%zu):\n", g.edge_count());
    for (const auto& e : g.edges()) {
        std::printf("  %s -> %s  (%zu function(s)%s)\n", e.from.c_str(), e.to.c_str(),
                    e.functions.size(), e.delay_load ? ", delay-load" : "");
    }
    const auto cycles = g.detect_cycles();
    std::printf("\ncircular dependencies: %zu\n", cycles.size());
    for (const auto& c : cycles) {
        std::string path;
        for (std::size_t i = 0; i < c.nodes.size(); ++i) {
            path += c.nodes[i];
            if (i + 1 < c.nodes.size()) path += " -> ";
        }
        std::printf("  %s\n", path.c_str());
    }
    const auto missing = g.missing_dependencies();
    std::printf("\nmissing dependencies: %zu\n", missing.size());
    for (const auto& m : missing) {
        std::printf("  %s -> %s\n", m.from.c_str(), m.to.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
}

// ── M2: classify command ──────────────────────────────────────────────────

void print_classify(const DependencyReport& rep, const PeImage& img) {
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc API classification\n");
    std::printf("source: %s\n", rep.source.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());

    const ApiRegistry reg;
    const CompatibilityDb db;
    std::size_t known = 0, unknown = 0;

    for (const auto& d : rep.dependencies) {
        const bool cls = d.classified;
        if (cls) ++known; else ++unknown;
        std::printf("\n%s [%s]\n", d.dll_name.c_str(), d.category_name.c_str());
        if (!cls) {
            std::printf("  classification: Unknown (no evidence-based record)\n");
            continue;
        }
        if (const auto rec = reg.classify_library(d.dll_name)) {
            std::printf("  evidence: %s\n", rec->source.c_str());
            std::printf("  note:     %s\n", rec->note.c_str());
        }
        if (const auto cr = db.lookup(d.dll_name, "")) {
            std::printf("  compatibility: %s\n", xbox2pc::compat::status_to_name(cr->status));
            if (!cr->windows_equivalent.empty()) {
                std::printf("    windows equivalent: %s\n", cr->windows_equivalent.c_str());
            }
        }
        for (const auto& f : d.functions) {
            if (f.name.empty()) continue;
            const auto frec = reg.classify_api(d.dll_name, f.name);
            const auto fdb = db.lookup(d.dll_name, f.name);
            if (!frec.has_value() && !fdb.has_value()) continue;
            std::printf("    %s: %s", f.name.c_str(),
                        frec.has_value()
                            ? xbox2pc::registry::category_to_name(frec->category)
                            : "Unknown");
            if (fdb.has_value()) {
                std::printf(" | %s", xbox2pc::compat::status_to_name(fdb->status));
            }
            std::printf("\n");
        }
    }

    std::printf("\nsummary: %zu classified, %zu unknown DLL(s)\n", known, unknown);
    std::printf("export name: %s (%zu exported function(s))\n",
                img.exports.dll_name.empty() ? "(none)" : img.exports.dll_name.c_str(),
                img.exports.functions.size());
    std::printf("%s\n", std::string(64, '=').c_str());
}

// ── command entry points ──────────────────────────────────────────────────

int cmd_inspect(const std::string& path, bool quiet) {
    return load_and_run(path, [quiet](const PeImage& img, const Diagnostics& diags) {
        print_report(img, diags);
        if (!quiet && diags.has_warnings()) {
            std::fprintf(stderr, "note: %zu warning(s) during parse\n",
                         static_cast<std::size_t>(
                             diags.count(xbox2pc::diag::Severity::Warning)));
        }
        return 0;
    });
}

int cmd_dependencies(const std::string& path, const std::optional<std::string>& json_out) {
    return load_and_run(path, [json_out](const PeImage& img, const Diagnostics&) {
        Diagnostics diags;
        const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
        if (json_out.has_value()) {
            const std::string out = report_to_json(rep).serialize();
            if (!write_file(*json_out, out + "\n")) {
                std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
                return 1;
            }
            std::printf("wrote %s\n", json_out->c_str());
            return 0;
        }
        print_dependencies(rep, diags);
        return 0;
    });
}

int cmd_graph(const std::string& path, const std::optional<std::string>& json_out) {
    return load_and_run(path, [json_out](const PeImage& img, const Diagnostics&) {
        Diagnostics diags;
        const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
        DependencyGraph g;
        g.build_from_report(rep, img, diags);
        // Single-file mode: every import is a "missing" dependency (the DLL
        // files themselves are not provided to the tool).
        for (const auto& d : rep.dependencies) {
            g.mark_missing(d.dll_name);
        }
        if (json_out.has_value()) {
            const std::string out = g.to_json().serialize();
            if (!write_file(*json_out, out + "\n")) {
                std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
                return 1;
            }
            std::printf("wrote %s\n", json_out->c_str());
            return 0;
        }
        print_graph(g);
        return 0;
    });
}

int cmd_classify(const std::string& path) {
    return load_and_run(path, [](const PeImage& img, const Diagnostics&) {
        Diagnostics diags;
        const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
        print_classify(rep, img);
        return 0;
    });
}

// ── M3: runtime architecture inspection ──────────────────────────────────
//
// Each command boots a REAL RuntimeCore (initialize + create a few live
// objects so the architecture is exercised, not an empty shell) and reports
// actual state. Nothing here emulates Xbox OS behavior — the runtime is the
// xbox2pc architecture itself, and the output says so.

namespace {

Json runtime_info_json(const xbox2pc::rt::RuntimeCore& core) {
    const auto s = core.summary();
    Json j = Json::object();
    j.set("tool", "xbox2pc");
    j.set("version", "0.3.0");
    j.set("runtime_state", s.state);
    j.set("pal_backend", s.pal_backend);
    j.set("pal_clock", s.pal_clock);
    j.set("page_size", static_cast<std::uint64_t>(s.page_size));
    j.set("object_count", static_cast<std::uint64_t>(s.object_count));
    j.set("service_count", static_cast<std::uint64_t>(s.service_count));
    j.set("handle_count", static_cast<std::uint64_t>(s.handle_count));
    j.set("services_initialized", s.services_initialized);
    j.set("layers", Json::array());  // filled by caller if needed
    return j;
}

Json runtime_objects_json(const xbox2pc::rt::RuntimeCore& core) {
    Json arr = Json::array();
    for (const auto& o : core.objects().list_objects()) {
        Json j = Json::object();
        j.set("id", static_cast<std::uint64_t>(o.id));
        j.set("type", o.type_name);
        j.set("name", o.name);
        j.set("state", xbox2pc::rt::object_state_to_name(o.state));
        j.set("pins", static_cast<std::uint64_t>(o.pins));
        arr.push_back(std::move(j));
    }
    return arr;
}

Json runtime_services_json(const xbox2pc::rt::RuntimeCore& core) {
    Json arr = Json::array();
    for (const auto& s : core.services().list_services()) {
        Json j = Json::object();
        j.set("name", s.name);
        j.set("object_id", static_cast<std::uint64_t>(s.object_id));
        j.set("state", xbox2pc::rt::service_state_to_name(s.state));
        Json deps = Json::array();
        for (const auto& d : s.dependencies) deps.push_back(d);
        j.set("dependencies", std::move(deps));
        if (!s.last_error.empty()) j.set("last_error", s.last_error);
        arr.push_back(std::move(j));
    }
    return arr;
}


// ── M4: management diagnostics commands ──────────────────────────────────
//
// Every command boots a REAL runtime, creates a small deterministic
// scenario (one process with region + thread via the ProcessManager) and
// reports ACTUAL state; nothing is fabricated. The scenario is labeled.

namespace {

// Builds the demo scenario used by the M4 commands: one process, one
// committed region, one finished worker thread (joined, so listings show
// a Terminated thread), plus resource accounting through the manager.
struct DemoRuntime {
    xbox2pc::rt::RuntimeCore core;
    xbox2pc::rt::ProcessManager pm;
    xbox2pc::rt::Handle process;
    std::uint64_t region_va = 0;

    DemoRuntime() : pm(core.objects()) {
        if (!core.initialize().ok()) return;
        auto p = pm.create_process("demo-m4.exe");
        if (!p.ok()) return;
        process = p.value();
        xbox2pc::rt::ModuleDescriptor mod;
        mod.module_name = "demo-m4.exe";
        mod.is_valid_pe = true;
        (void)pm.initialize_process(process, mod, xbox2pc::rt::RuntimeConfig{});
        (void)pm.start_process(process);
        auto r = pm.reserve_region(process, 2 * 4096, "demo-region");
        if (r.ok()) {
            region_va = r.value();
            (void)pm.commit_region(process, r.value());
        }
        auto th = pm.spawn_thread(
            process,
            [](xbox2pc::rt::RtThread&, void*) -> void* { return nullptr; },
            nullptr, "demo-worker");
        if (th.ok()) {
            // Join so the thread list shows a completed thread.
            auto g = core.objects().lookup_handle(th.value());
            if (g.ok() && g.value().get() != nullptr) {
                if (auto* t = g.value().get()->as<xbox2pc::rt::RtThread>()) {
                    (void)t->join_ns(xbox2pc::pal::kInfiniteTimeout);
                }
            }
        }
    }
};

Json stats_json(const xbox2pc::rt::ResourceStats& s) {
    Json j = Json::object();
    j.set("reserved_bytes", static_cast<std::uint64_t>(s.reserved_bytes));
    j.set("committed_bytes", static_cast<std::uint64_t>(s.committed_bytes));
    j.set("region_count", static_cast<std::uint64_t>(s.region_count));
    j.set("thread_count", static_cast<std::uint64_t>(s.thread_count));
    j.set("handle_count", static_cast<std::uint64_t>(s.handle_count));
    j.set("object_count", static_cast<std::uint64_t>(s.object_count));
    j.set("module_count", static_cast<std::uint64_t>(s.module_count));
    j.set("process_count", static_cast<std::uint64_t>(s.process_count));
    j.set("address_space_count", static_cast<std::uint64_t>(s.address_space_count));
    return j;
}

}  // namespace

int cmd_memory_info(const std::optional<std::string>& json_out);
int cmd_memory_regions(const std::optional<std::string>& json_out);
int cmd_process_info(const std::optional<std::string>& json_out);
int cmd_thread_info(const std::optional<std::string>& json_out);
int cmd_handle_info(const std::optional<std::string>& json_out);
int cmd_resource_info(const std::optional<std::string>& json_out);

int cmd_memory_info(const std::optional<std::string>& json_out) {
    DemoRuntime demo;
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("tool", "xbox2pc");
        j.set("version", "0.4.0");
        j.set("host_page_size", static_cast<std::uint64_t>(xbox2pc::pal::host_page_size()));
        j.set("wx_allowed_by_default", false);
        j.set("global", stats_json(demo.pm.global_stats()));
        const std::string out = j.serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    const auto g = demo.pm.global_stats();
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc memory info (live runtime, demo scenario)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("host_page_size:     %llu\n",
                static_cast<unsigned long long>(xbox2pc::pal::host_page_size()));
    std::printf("wx_allowed_by_default: no (W^X discipline; opt-in per call)\n");
    std::printf("reserved_bytes:    %llu\n", static_cast<unsigned long long>(g.reserved_bytes));
    std::printf("committed_bytes:   %llu\n", static_cast<unsigned long long>(g.committed_bytes));
    std::printf("region_count:      %u\n", g.region_count);
    std::printf("process_count:     %u\n", g.process_count);
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_memory_regions(const std::optional<std::string>& json_out) {
    DemoRuntime demo;
    const auto regions = demo.pm.list_regions(demo.process);
    if (json_out.has_value()) {
        Json arr = Json::array();
        for (const auto& r : regions) {
            Json j = Json::object();
            j.set("xbox_va", static_cast<std::uint64_t>(r.xbox_va));
            j.set("size", static_cast<std::uint64_t>(r.size));
            j.set("state", xbox2pc::rt::region_state_to_name(r.state));
            j.set("protection", xbox2pc::rt::mem_protect_to_name(r.protection));
            j.set("name", r.name);
            arr.push_back(std::move(j));
        }
        const std::string out = arr.serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc memory regions (demo process, live)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("%zu region(s):\n", regions.size());
    std::printf("  %-12s %-10s %-12s %-12s %s\n", "xbox_va", "size", "state",
                "protection", "name");
    for (const auto& r : regions) {
        std::printf("  %-12llx %-10llu %-12s %-12s %s\n",
                    static_cast<unsigned long long>(r.xbox_va),
                    static_cast<unsigned long long>(r.size),
                    xbox2pc::rt::region_state_to_name(r.state),
                    xbox2pc::rt::mem_protect_to_name(r.protection),
                    r.name.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_process_info(const std::optional<std::string>& json_out) {
    DemoRuntime demo;
    const auto procs = demo.pm.list_processes();
    if (json_out.has_value()) {
        Json arr = Json::array();
        for (const auto& p : procs) {
            Json j = Json::object();
            j.set("pid", static_cast<std::uint64_t>(p.pid));
            j.set("image_name", p.image_name);
            j.set("state", xbox2pc::rt::process_state_to_name(p.state));
            j.set("exit_code", static_cast<std::uint64_t>(p.exit_code));
            j.set("stats", stats_json(p.stats));
            arr.push_back(std::move(j));
        }
        const std::string out = arr.serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc process info (live runtime, demo scenario)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("%zu process(es):\n", procs.size());
    std::printf("  %-6s %-16s %-12s %-8s %-8s %s\n", "pid", "image", "state",
                "threads", "regions", "committed");
    for (const auto& p : procs) {
        std::printf("  %-6llu %-16s %-12s %-8u %-8u %llu\n",
                    static_cast<unsigned long long>(p.pid), p.image_name.c_str(),
                    xbox2pc::rt::process_state_to_name(p.state),
                    p.stats.thread_count, p.stats.region_count,
                    static_cast<unsigned long long>(p.stats.committed_bytes));
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_thread_info(const std::optional<std::string>& json_out) {
    DemoRuntime demo;
    const auto objs = demo.core.objects().list_objects();
    if (json_out.has_value()) {
        Json arr = Json::array();
        for (const auto& o : objs) {
            if (o.type != xbox2pc::rt::TypeId::Thread) continue;
            auto g = demo.core.objects().lookup_id(o.id);
            if (!g.ok() || g.value().get() == nullptr) continue;
            auto* t = g.value().get()->as<xbox2pc::rt::RtThread>();
            if (t == nullptr) continue;
            Json j = Json::object();
            j.set("thread_id", static_cast<std::uint64_t>(t->thread_id()));
            j.set("name", t->name());
            j.set("state", xbox2pc::rt::thread_state_to_name(t->state()));
            j.set("priority",
                  xbox2pc::rt::thread_priority_to_name(t->priority()));
            j.set("exit_code", static_cast<std::uint64_t>(t->exit_code()));
            arr.push_back(std::move(j));
        }
        const std::string out = arr.serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc thread info (live runtime, demo scenario)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::size_t count = 0;
    for (const auto& o : objs) {
        if (o.type != xbox2pc::rt::TypeId::Thread) continue;
        auto g = demo.core.objects().lookup_id(o.id);
        if (!g.ok() || g.value().get() == nullptr) continue;
        auto* t = g.value().get()->as<xbox2pc::rt::RtThread>();
        if (t == nullptr) continue;
        ++count;
        std::printf("  thread %-6llu %-16s state=%-10s prio=%s exit=%llu\n",
                    static_cast<unsigned long long>(t->thread_id()),
                    t->name().c_str(),
                    xbox2pc::rt::thread_state_to_name(t->state()),
                    xbox2pc::rt::thread_priority_to_name(t->priority()),
                    static_cast<unsigned long long>(t->exit_code()));
    }
    std::printf("%zu thread object(s)\n", count);
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_handle_info(const std::optional<std::string>& json_out) {
    DemoRuntime demo;
    const auto handles = demo.core.objects().table().list_handles();
    if (json_out.has_value()) {
        Json arr = Json::array();
        for (const auto& h : handles) {
            Json j = Json::object();
            j.set("raw", [&] {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "0x%llx",
                              static_cast<unsigned long long>(h.handle.raw()));
                return std::string(buf);
            }());
            j.set("table_id", static_cast<std::uint64_t>(h.handle.table_id()));
            j.set("index", static_cast<std::uint64_t>(h.handle.index()));
            j.set("object_id", static_cast<std::uint64_t>(h.object_id));
            j.set("type", xbox2pc::rt::ObjectTypeRegistry::instance().name(
                              static_cast<xbox2pc::rt::TypeId>(h.type)));
            j.set("rights", xbox2pc::rt::access_rights_to_name(h.rights));
            j.set("inheritable", h.inheritable);
            arr.push_back(std::move(j));
        }
        const std::string out = arr.serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc handle info (runtime table, live)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("%zu live handle(s):\n", handles.size());
    std::printf("  %-18s %-6s %-8s %-16s %-10s %s\n", "raw", "table", "obj-id",
                "type", "rights", "inheritable");
    for (const auto& h : handles) {
        std::printf("  0x%-16llx %-6u %-8llu %-16s %-10s %s\n",
                    static_cast<unsigned long long>(h.handle.raw()),
                    static_cast<unsigned>(h.handle.table_id()),
                    static_cast<unsigned long long>(h.object_id),
                    xbox2pc::rt::ObjectTypeRegistry::instance().name(
                        static_cast<xbox2pc::rt::TypeId>(h.type)).c_str(),
                    xbox2pc::rt::access_rights_to_name(h.rights),
                    h.inheritable ? "yes" : "no");
    }
    std::printf("\nNOTE: handles encode table id + slot + generation + type;\n");
    std::printf("no raw addresses are ever exposed.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_resource_info(const std::optional<std::string>& json_out) {
    DemoRuntime demo;
    const auto g = demo.pm.global_stats();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("tool", "xbox2pc");
        j.set("version", "0.4.0");
        j.set("global", stats_json(g));
        const std::string out = j.serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc resource accounting (live runtime)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("processes:         %u\n", g.process_count);
    std::printf("address spaces:    %llu\n",
                static_cast<unsigned long long>(g.address_space_count));
    std::printf("reserved_bytes:    %llu\n", static_cast<unsigned long long>(g.reserved_bytes));
    std::printf("committed_bytes:   %llu\n", static_cast<unsigned long long>(g.committed_bytes));
    std::printf("regions:           %u\n", g.region_count);
    std::printf("threads:           %u\n", g.thread_count);
    std::printf("handles:           %u\n", g.handle_count);
    std::printf("objects:           %u\n", g.object_count);
    std::printf("module descriptors:%u\n", g.module_count);
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

}  // namespace

int cmd_runtime_info(const std::optional<std::string>& json_out) {
    xbox2pc::rt::RuntimeCore core;
    if (const auto r = core.initialize(); !r.ok()) {
        std::fprintf(stderr, "error: runtime init failed: %s\n",
                     r.error_string().c_str());
        return 1;
    }
    if (json_out.has_value()) {
        const std::string out = runtime_info_json(core).serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    const auto s = core.summary();
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc runtime architecture info\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("runtime_state:     %s\n", s.state.c_str());
    std::printf("pal_backend:       %s\n", s.pal_backend.c_str());
    std::printf("pal_clock:         %s\n", s.pal_clock.c_str());
    std::printf("page_size:         %llu\n",
                static_cast<unsigned long long>(s.page_size));
    std::printf("objects:           %zu\n", s.object_count);
    std::printf("services:          %zu\n", s.service_count);
    std::printf("handles:           %zu\n", s.handle_count);
    std::printf("services_initialized: %s\n", s.services_initialized ? "yes" : "no");
    std::printf("\nlayers (bottom-up):\n");
    std::printf("  1. runtime error model + type ids\n");
    std::printf("  2. platform abstraction (Linux backend)\n");
    std::printf("  3. object manager + object type registry\n");
    std::printf("  4. handle management (generation-protected)\n");
    std::printf("  5. sync / thread / process / io object models\n");
    std::printf("  6. runtime service registry\n");
    std::printf("  7. RuntimeCore facade (init/shutdown sequencing)\n");
    std::printf("\nNOTE: this is the xbox2pc runtime architecture itself; no Xbox\n");
    std::printf("OS emulation is claimed or performed.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_runtime_objects(const std::optional<std::string>& json_out) {
    xbox2pc::rt::RuntimeCore core;
    if (const auto r = core.initialize(); !r.ok()) {
        std::fprintf(stderr, "error: runtime init failed: %s\n",
                     r.error_string().c_str());
        return 1;
    }
    // Create a few representative objects so the listing shows a living
    // architecture (event, mutex, semaphore, memory region, process).
    (void)core.create_event(true, false, "demo-event");
    (void)core.create_mutex("demo-mutex");
    (void)core.create_semaphore(1, 4, "demo-semaphore");
    (void)core.create_memory_region(4096, true, "demo-region");
    (void)core.create_process("demo-image.exe");

    if (json_out.has_value()) {
        const std::string out = runtime_objects_json(core).serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc runtime objects (live instance)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    const auto objs = core.objects().list_objects();
    std::printf("%zu live object(s):\n", objs.size());
    std::printf("  %-6s %-16s %-20s %-12s %s\n", "id", "type", "name", "state",
                "pins");
    for (const auto& o : objs) {
        std::printf("  %-6llu %-16s %-20s %-12s %llu\n",
                    static_cast<unsigned long long>(o.id), o.type_name.c_str(),
                    o.name.c_str(),
                    xbox2pc::rt::object_state_to_name(o.state),
                    static_cast<unsigned long long>(o.pins));
    }
    std::printf("\nNOTE: demo objects created by this command in a fresh\n");
    std::printf("runtime; no Xbox runtime objects are fabricated.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_runtime_services(const std::optional<std::string>& json_out) {
    xbox2pc::rt::RuntimeCore core;
    if (const auto r = core.initialize(); !r.ok()) {
        std::fprintf(stderr, "error: runtime init failed: %s\n",
                     r.error_string().c_str());
        return 1;
    }
    if (json_out.has_value()) {
        const std::string out = runtime_services_json(core).serialize();
        if (!write_file(*json_out, out + "\n")) {
            std::fprintf(stderr, "error: cannot write JSON to %s\n", json_out->c_str());
            return 1;
        }
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc runtime services (live instance)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    const auto svcs = core.services().list_services();
    std::printf("%zu registered service(s):\n", svcs.size());
    std::printf("  %-16s %-12s %-12s %s\n", "name", "state", "object", "deps");
    for (const auto& s : svcs) {
        std::string deps;
        for (std::size_t i = 0; i < s.dependencies.size(); ++i) {
            deps += s.dependencies[i];
            if (i + 1 < s.dependencies.size()) deps += ", ";
        }
        std::printf("  %-16s %-12s %-12llu %s\n", s.name.c_str(),
                    xbox2pc::rt::service_state_to_name(s.state),
                    static_cast<unsigned long long>(s.object_id),
                    deps.empty() ? "-" : deps.c_str());
    }
    std::printf("\nNOTE: only the built-in platform_info service exists in M3;\n");
    std::printf("graphics/audio/input/... register in later milestones.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}


// ── M5: filesystem/package CLI commands ────────────────────────────────────
//
// Every M5 command boots a live runtime and a demo process with a VFS
// session; mount state lives within the single command invocation
// (documented: the CLI is stateless across runs). For `list`/`stat`/`read`
// the target tree is either --host <dir> (host backend) or a built-in
// synthetic package fixture (clearly labeled). No fabricated data.

namespace {

// Builds the demo M5 world: process + session with (a) a synthetic XPK
// package mounted at /Packages (read-only) and (b) nothing else. The
// package contains: game.xex-like name (NOT executed — M5 exclusion),
// a PNG-signed asset, an unknown file, and a directory.
struct DemoVfs {
    xbox2pc::rt::RuntimeCore core;
    xbox2pc::rt::ProcessManager pm;
    xbox2pc::rt::Handle process;

    DemoVfs() : pm(core.objects()) {
        if (!core.initialize().ok()) return;
        auto p = xbox2pc::rt::create_process_with_vfs(pm, core.objects(),
                                                       "m5-cli.exe");
        if (p.ok()) process = p.value();
    }
    ~DemoVfs() {
        (void)core.shutdown();
    }

    bool ok() const { return !process.is_null(); }

    // Build + mount the synthetic package (labeled).
    xbox2pc::rt::Result<std::uint64_t> mount_demo_package() {
        using xbox2pc::rt::Result;
        using xbox2pc::rt::XpkBuildEntry;
        using xbox2pc::rt::xpk_build;
        using xbox2pc::rt::parse_package;
        using xbox2pc::rt::PackageVfsBackend;
        // Fixture entries (SYNTHETIC — not Xbox content).
        std::vector<XpkBuildEntry> entries = {
            {"content", true},
            {"content/README.txt", false, "xbox2pc synthetic package fixture\n"},
            {"content/asset.png",
             false,
             std::string("\x89PNG\r\n\x1a\n", 8) + std::string(64, '\0')},
            {"content/blob.bin", false, std::string(128, 'x')},
        };
        auto bytes = xpk_build(entries);
        auto pkg = parse_package(bytes.data(), bytes.size(),
                                 "m5-demo.xpk", {});
        if (!pkg.ok()) {
            return Result<std::uint64_t>(pkg.errc(), pkg.context());
        }
        auto backend = std::make_unique<PackageVfsBackend>(std::move(pkg.value()));
        return mount_backend(core, process, std::move(backend), "/Packages");
    }

    static xbox2pc::rt::Result<std::uint64_t> mount_backend(
        xbox2pc::rt::RuntimeCore& core, xbox2pc::rt::Handle process,
        std::unique_ptr<xbox2pc::rt::IVfsBackend> backend,
        const std::string& mount_path) {
        using xbox2pc::rt::ManagedProcess;
        using xbox2pc::rt::VfsSession;
        using xbox2pc::rt::RuntimeErrc;
        using xbox2pc::rt::Result;
        // Register the backend object + mount via the session.
        auto found = core.objects().lookup_handle(process);
        if (!found.ok()) {
            return Result<std::uint64_t>(found.errc(), found.context());
        }
        auto* proc = found.value().get()->as<ManagedProcess>();
        const std::string sid = proc->meta("vfs_session");
        auto s = core.objects().lookup_id(
            std::strtoull(sid.c_str(), nullptr, 10));
        if (!s.ok() || s.value().get() == nullptr) {
            return Result<std::uint64_t>(RuntimeErrc::NotFound, "no session");
        }
        auto* session = s.value().get()->as<VfsSession>();
        return session->mount_backend(std::move(backend), mount_path,
                                      /*read_only=*/true, 0);
    }
};

}  // namespace

int cmd_mount(const std::optional<std::string>& json_out);
int cmd_unmount(const std::optional<std::string>& json_out);
int cmd_list(const std::string& path, const std::optional<std::string>& json_out);
int cmd_stat(const std::string& path, const std::optional<std::string>& json_out);
int cmd_read(const std::string& path, std::uint64_t limit,
             const std::optional<std::string>& json_out);
int cmd_packages(const std::optional<std::string>& json_out);
int cmd_discover(const std::string& root, const std::optional<std::string>& json_out);

int cmd_mount(const std::optional<std::string>& json_out) {
    DemoVfs demo;
    if (!demo.ok()) {
        std::fprintf(stderr, "error: runtime init failed\n");
        return 1;
    }
    auto m = demo.mount_demo_package();
    if (!m.ok()) {
        std::fprintf(stderr, "error: mount failed: %s\n",
                     m.error_string().c_str());
        return 1;
    }
    auto mounts = xbox2pc::rt::proc_mounts(demo.process);
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("mounted", true);
        j.set("mount_id", static_cast<std::uint64_t>(m.value()));
        Json arr = Json::array();
        for (const auto& mi : mounts.value()) {
            Json mj = Json::object();
            mj.set("mount_path", mi.mount_path);
            mj.set("backend", mi.backend_name);
            mj.set("read_only", mi.read_only);
            mj.set("precedence", static_cast<std::int64_t>(mi.precedence));
            mj.set("mount_id", static_cast<std::uint64_t>(mi.mount_id));
            arr.push_back(std::move(mj));
        }
        j.set("mounts", std::move(arr));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc mount (demo: synthetic XPK package -> /Packages)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& mi : mounts.value()) {
        std::printf("  %-12s backend=%-10s ro=%d prec=%lld id=%llu\n",
                    mi.mount_path.c_str(), mi.backend_name.c_str(),
                    mi.read_only ? 1 : 0,
                    static_cast<long long>(mi.precedence),
                    static_cast<unsigned long long>(mi.mount_id));
    }
    std::printf("NOTE: XPK is xbox2pc's SYNTHETIC format (not an Xbox format).\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_unmount(const std::optional<std::string>& json_out) {
    (void)json_out;
    DemoVfs demo;
    if (!demo.ok()) return 1;
    auto m = demo.mount_demo_package();
    if (!m.ok()) return 1;
    auto u = xbox2pc::rt::proc_unmount(demo.process, m.value());
    if (!u.ok()) {
        std::fprintf(stderr, "error: unmount failed: %s\n",
                     u.error_string().c_str());
        return 1;
    }
    auto mounts = xbox2pc::rt::proc_mounts(demo.process);
    std::printf("unmounted %llu; remaining mounts: %zu\n",
                static_cast<unsigned long long>(m.value()),
                mounts.value().size());
    return 0;
}

int cmd_list(const std::string& path, const std::optional<std::string>& json_out) {
    DemoVfs demo;
    if (!demo.ok()) return 1;
    auto m = demo.mount_demo_package();
    if (!m.ok()) return 1;
    auto ls = xbox2pc::rt::proc_list(demo.process, path);
    if (!ls.ok()) {
        std::fprintf(stderr, "error: list '%s' failed: %s\n", path.c_str(),
                     ls.error_string().c_str());
        return 1;
    }
    if (json_out.has_value()) {
        Json arr = Json::array();
        for (const auto& e : ls.value()) {
            Json ej = Json::object();
            ej.set("name", e.name);
            ej.set("kind", e.is_directory ? "directory" : "file");
            ej.set("size", static_cast<std::uint64_t>(e.size));
            arr.push_back(std::move(ej));
        }
        if (!write_file(*json_out, arr.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc list %s (live VFS)\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& e : ls.value()) {
        std::printf("  %-10s %-24s %8llu bytes\n",
                    e.is_directory ? "[dir]" : "[file]", e.name.c_str(),
                    static_cast<unsigned long long>(e.size));
    }
    std::printf("%zu entr%s\n", ls.value().size(),
                ls.value().size() == 1 ? "y" : "ies");
    return 0;
}

int cmd_stat(const std::string& path, const std::optional<std::string>& json_out) {
    DemoVfs demo;
    if (!demo.ok()) return 1;
    auto m = demo.mount_demo_package();
    if (!m.ok()) return 1;
    auto st = xbox2pc::rt::proc_stat(demo.process, path);
    if (!st.ok()) {
        std::fprintf(stderr, "error: stat '%s' failed: %s\n", path.c_str(),
                     st.error_string().c_str());
        return 1;
    }
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("path", path);
        j.set("exists", st.value().exists);
        j.set("kind", st.value().is_directory ? "directory" : "file");
        j.set("size", static_cast<std::uint64_t>(st.value().size));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s: exists=%d kind=%s size=%llu\n", path.c_str(),
                st.value().exists ? 1 : 0,
                st.value().is_directory ? "directory" : "file",
                static_cast<unsigned long long>(st.value().size));
    return 0;
}

int cmd_read(const std::string& path, std::uint64_t limit,
             const std::optional<std::string>& json_out) {
    DemoVfs demo;
    if (!demo.ok()) return 1;
    auto m = demo.mount_demo_package();
    if (!m.ok()) return 1;
    auto h = xbox2pc::rt::proc_open_file(demo.process, path, false);
    if (!h.ok()) {
        std::fprintf(stderr, "error: open '%s' failed: %s\n", path.c_str(),
                     h.error_string().c_str());
        return 1;
    }
    // Read bounded bytes.
    std::vector<std::uint8_t> buf(limit);
    auto got = xbox2pc::rt::vfs_read(demo.core.objects(), h.value(),
                                     buf.data(), limit);
    if (!got.ok()) {
        std::fprintf(stderr, "error: read failed: %s\n",
                     got.error_string().c_str());
        return 1;
    }
    buf.resize(got.value());
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("path", path);
        j.set("length", static_cast<std::uint64_t>(buf.size()));
        // Safe text preview (printable subset only).
        std::string preview;
        for (std::uint8_t b : buf) {
            const char c = static_cast<char>(b);
            preview.push_back(c >= 0x20 && c != 0x7F ? c : '.');
        }
        j.set("preview", preview);
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc read %s (%llu bytes, printable preview)\n", path.c_str(),
                static_cast<unsigned long long>(buf.size()));
    std::printf("%s\n", std::string(64, '=').c_str());
    for (std::uint8_t b : buf) {
        const char c = static_cast<char>(b);
        std::putchar(c >= 0x20 && c != 0x7F ? c : '.');
    }
    std::putchar('\n');
    return 0;
}

int cmd_packages(const std::optional<std::string>& json_out) {
    DemoVfs demo;
    if (!demo.ok()) return 1;
    auto m = demo.mount_demo_package();
    if (!m.ok()) return 1;
    // The mounted backend IS the parsed package: enumerate entries.
    auto found = demo.core.objects().lookup_handle(demo.process);
    auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
    const std::string sid = proc->meta("vfs_session");
    auto s = demo.core.objects().lookup_id(std::strtoull(sid.c_str(), nullptr, 10));
    auto* session = s.value().get()->as<xbox2pc::rt::VfsSession>();
    // Walk mounts to find the package backend.
    const auto mounts = session->namespace_().list_mounts();
    const auto& info = [&]() -> const xbox2pc::rt::PackageInfo& {
        for (const auto& mi : mounts) {
            // Resolve the backend object by entry (backends registered as objects).
        }
        static xbox2pc::rt::PackageInfo empty{};
        return empty;
    }();
    (void)info;
    // Simpler: re-parse the built fixture for metadata display (identical
    // to what is mounted).
    std::vector<xbox2pc::rt::XpkBuildEntry> entries = {
        {"content", true},
        {"content/README.txt", false, "xbox2pc synthetic package fixture\n"},
        {"content/asset.png", false,
         std::string("\x89PNG\r\n\x1a\n", 8) + std::string(64, '\0')},
        {"content/blob.bin", false, std::string(128, 'x')},
    };
    auto bytes = xbox2pc::rt::xpk_build(entries);
    auto pkg = xbox2pc::rt::parse_package(bytes.data(), bytes.size(),
                                          "m5-demo.xpk", {});
    if (!pkg.ok()) return 1;
    const auto& pi = pkg.value()->info();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("format", pi.format_name);
        j.set("synthetic", pi.synthetic);
        j.set("version", static_cast<std::uint64_t>(pi.version));
        j.set("entry_count", static_cast<std::uint64_t>(pi.entry_count));
        Json arr = Json::array();
        for (const auto& e : pi.entries) {
            Json ej = Json::object();
            std::string full;
            for (const auto& p : e.path) {
                full.append(p);
                full.push_back('/');
            }
            full.append(e.name);
            ej.set("path", full);
            ej.set("kind", e.is_directory ? "directory" : "file");
            ej.set("size", static_cast<std::uint64_t>(e.size));
            arr.push_back(std::move(ej));
        }
        j.set("entries", std::move(arr));
        // Unsupported formats: classify by extension (evidence notes).
        Json un = Json::object();
        for (const char* ext : {".xvc", ".xvd", ".msixvc"}) {
            auto cls = xbox2pc::rt::classify_bytes(
                reinterpret_cast<const std::uint8_t*>("X"), 1,
                std::string("demo") + ext);
            Json cj = Json::object();
            cj.set("label", cls.label);
            cj.set("parseable", cls.parseable);
            cj.set("evidence", cls.evidence_note);
            un.set(ext, std::move(cj));
        }
        j.set("unsupported_formats", std::move(un));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc packages (synthetic XPK fixture; live parse)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("format=%s (version %u) entries=%llu SYNTHETIC=%d\n",
                pi.format_name.c_str(), pi.version,
                static_cast<unsigned long long>(pi.entry_count),
                pi.synthetic ? 1 : 0);
    for (const auto& e : pi.entries) {
        std::string full;
        for (const auto& p : e.path) {
            full.append(p);
            full.push_back('/');
        }
        full.append(e.name);
        std::printf("  %-10s %-32s %8llu\n",
                    e.is_directory ? "[dir]" : "[file]", full.c_str(),
                    static_cast<unsigned long long>(e.size));
    }
    std::printf("\nXbox formats (classified, NOT parsed):\n");
    for (const char* ext : {".xvc", ".xvd"}) {
        auto cls = xbox2pc::rt::classify_bytes(
            reinterpret_cast<const std::uint8_t*>("X"), 1,
            std::string("demo") + ext);
        std::printf("  %-8s label=%s parseable=%d\n    %s\n", ext,
                    cls.label.c_str(), cls.parseable ? 1 : 0,
                    cls.evidence_note.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_discover(const std::string& root,
                 const std::optional<std::string>& json_out) {
    DemoVfs demo;
    if (!demo.ok()) return 1;
    auto m = demo.mount_demo_package();
    if (!m.ok()) return 1;
    // Discovery runs on the process's session namespace.
    auto found = demo.core.objects().lookup_handle(demo.process);
    auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
    const std::string sid = proc->meta("vfs_session");
    auto s = demo.core.objects().lookup_id(std::strtoull(sid.c_str(), nullptr, 10));
    auto* session = s.value().get()->as<xbox2pc::rt::VfsSession>();
    auto rootp = xbox2pc::rt::VfsPath::parse(root);
    if (!rootp.ok()) {
        std::fprintf(stderr, "error: bad root path\n");
        return 1;
    }
    auto res = xbox2pc::rt::discover_in_namespace(session->namespace_(),
                                                  rootp.value(), 4096);
    if (!res.ok()) {
        std::fprintf(stderr, "error: discovery failed: %s\n",
                     res.error_string().c_str());
        return 1;
    }
    const auto& d = res.value();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("root", root);
        j.set("files", [&] {
            Json arr = Json::array();
            for (const auto& f : d.files) {
                Json fj = Json::object();
                fj.set("path", f.path);
                fj.set("kind", xbox2pc::rt::discovered_kind_to_name(f.kind));
                fj.set("size", static_cast<std::uint64_t>(f.size));
                if (f.kind == xbox2pc::rt::DiscoveredKind::PeModule) {
                    fj.set("module_name", f.module_name);
                    fj.set("size_of_image",
                           static_cast<std::uint64_t>(f.size_of_image));
                    Json imps = Json::array();
                    for (const auto& i : f.imports) imps.push_back(i);
                    fj.set("unresolved_imports", std::move(imps));
                } else if (f.kind == xbox2pc::rt::DiscoveredKind::InvalidPe) {
                    fj.set("parse_error", f.pe_note);
                } else if (!f.pe_note.empty()) {
                    fj.set("signature", f.pe_note);
                }
                arr.push_back(std::move(fj));
            }
            return arr;
        }());
        j.set("pe_modules", static_cast<std::uint64_t>(d.pe_modules));
        j.set("invalid_pe", static_cast<std::uint64_t>(d.invalid_pe));
        j.set("known_assets", static_cast<std::uint64_t>(d.known_assets));
        j.set("unknown_files", static_cast<std::uint64_t>(d.unknown_files));
        j.set("directories", static_cast<std::uint64_t>(d.directories));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc discover %s (live VFS; classification by CONTENT)\n",
                root.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& f : d.files) {
        std::printf("  %-10s %-36s %8llu\n",
                    xbox2pc::rt::discovered_kind_to_name(f.kind), f.path.c_str(),
                    static_cast<unsigned long long>(f.size));
    }
    std::printf("\nsummary: %u dirs, %u PE, %u invalid-PE, %u known assets,\n"
                "          %u unknown (never guessed by extension)\n",
                d.directories, d.pe_modules, d.invalid_pe, d.known_assets,
                d.unknown_files);
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

}  // namespace


// ── M6: executable loader CLI commands ─────────────────────────────────────
//
// Every M6 command loads the PE file (bytes + M1 parse), then exercises
// the loader against a LIVE runtime: a managed process with its own
// address space. `load-image`/`map-image` show the complete lifecycle;
// `validate-pe`/`relocations`/`imports` are inspection-only (no process
// needed for validate; the mapping ones use a scratch process).
// State is per-invocation (documented: the CLI is stateless across runs).

namespace {

// Read a whole file into a byte vector (bounded by fstream).
std::optional<std::vector<std::uint8_t>> read_pe_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::vector<std::uint8_t> bytes;
    char buf[4096];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        bytes.insert(bytes.end(), buf, buf + in.gcount());
    }
    return bytes;
}

using namespace xbox2pc::rt::loader;

// Shared world for the mapping-bearing commands: runtime + process.
struct LoaderWorld {
    xbox2pc::rt::RuntimeCore core;
    xbox2pc::rt::ProcessManager pm;
    xbox2pc::rt::Handle process;
    xbox2pc::rt::loader::ImageLoader loader;

    // Scratch process for the mapping-bearing commands. The address space
    // must hold the image being mapped: real Xbox titles ship images far
    // larger than the old fixed 64 MB demo space (e.g. 176 MB), which made
    // map/load fail with OutOfResources on files that validate perfectly.
    // Size the space to the image (rounded up, with the old 64 MB floor).
    explicit LoaderWorld(std::uint64_t image_bytes) : pm(core.objects()) {
        if (!core.initialize().ok()) return;
        constexpr std::uint64_t kFloor = 64ull << 20;          // previous default
        constexpr std::uint64_t kRound = 16ull << 20;          // 16 MiB granularity
        std::uint64_t capacity = kFloor;
        if (image_bytes > kFloor) {
            capacity = ((image_bytes + kRound - 1) / kRound) * kRound;
        }
        auto p = pm.create_process("m6-cli.exe", capacity);
        if (p.ok()) process = p.value();
    }
    ~LoaderWorld() { (void)core.shutdown(); }
    bool ok() const { return !process.is_null(); }
};

// Resolve the ManagedProcess for the world handle.
xbox2pc::rt::ManagedProcess* world_process(LoaderWorld& w) {
    auto found = w.core.objects().lookup_handle(w.process);
    return found.ok() ? found.value().get()->as<xbox2pc::rt::ManagedProcess>()
                      : nullptr;
}

std::string prot_name(xbox2pc::rt::MemProtect p) {
    return xbox2pc::rt::mem_protect_to_name(p);
}

}  // namespace

int cmd_validate_pe(const std::string& path,
                    const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        if (json_out.has_value()) {
            Json j = Json::object();
            j.set("file", path);
            j.set("valid", false);
            j.set("error", e.what());
            if (!write_file(*json_out, j.serialize() + "\n")) return 1;
            std::printf("wrote %s\n", json_out->c_str());
            return 0;
        }
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    const auto rep = xbox2pc::rt::loader::validate_image(img, bytes->data(),
                                                        bytes->size());
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", path);
        j.set("valid", rep.valid);
        j.set("size_of_image", rep.size_of_image);
        j.set("size_of_headers", rep.size_of_headers);
        j.set("preferred_base", rep.preferred_base);
        j.set("entry_rva", static_cast<std::uint64_t>(rep.entry_rva));
        j.set("needs_relocation", rep.needs_relocation);
        j.set("has_tls_directory", rep.has_tls_directory);
        Json arr = Json::array();
        for (const auto& i : rep.issues) {
            Json ij = Json::object();
            ij.set("code", i.code);
            ij.set("message", i.message);
            arr.push_back(std::move(ij));
        }
        j.set("issues", std::move(arr));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc validate-pe %s\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("valid=%d SizeOfImage=%s SizeOfHeaders=%s\n",
                rep.valid ? 1 : 0, hex(rep.size_of_image).c_str(),
                hex(rep.size_of_headers).c_str());
    std::printf("preferred-base=%s entry-rva=%s relocs=%d tls-dir=%d\n",
                hex(rep.preferred_base).c_str(), hex(rep.entry_rva).c_str(),
                rep.needs_relocation ? 1 : 0, rep.has_tls_directory ? 1 : 0);
    if (!rep.issues.empty()) std::printf("issues:\n");
    for (const auto& i : rep.issues) {
        std::printf("  [%s] %s\n", i.code.c_str(), i.message.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return rep.valid ? 0 : 1;
}

int cmd_relocations(const std::string& path,
                     const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    auto blocks = xbox2pc::rt::loader::decode_relocations(
        img, bytes->data(), bytes->size(), 1u << 20);
    if (!blocks.ok()) {
        std::fprintf(stderr, "error: %s\n", blocks.error_string().c_str());
        return 1;
    }
    std::uint64_t total = 0;
    for (const auto& b : blocks.value()) total += b.entries.size();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", path);
        j.set("blocks", static_cast<std::uint64_t>(blocks.value().size()));
        j.set("entries", total);
        Json arr = Json::array();
        for (const auto& b : blocks.value()) {
            Json bj = Json::object();
            bj.set("page_rva", b.page_rva);
            bj.set("block_size", static_cast<std::uint64_t>(b.block_size));
            Json es = Json::array();
            for (const auto& e : b.entries) {
                Json ej = Json::object();
                ej.set("type", static_cast<std::uint64_t>(e.type));
                ej.set("type_name", xbox2pc::rt::loader::reloc_type_to_name(e.type));
                ej.set("target_rva", e.target_rva);
                es.push_back(std::move(ej));
            }
            bj.set("entries", std::move(es));
            arr.push_back(std::move(bj));
        }
        j.set("detail", std::move(arr));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc relocations %s (decoded, not applied)\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& b : blocks.value()) {
        std::printf("block page-rva=%s size=%u entries=%zu\n",
                    hex(b.page_rva).c_str(), b.block_size, b.entries.size());
        for (const auto& e : b.entries) {
            std::printf("  %-9s target-rva=%s\n",
                        xbox2pc::rt::loader::reloc_type_to_name(e.type),
                        hex(e.target_rva).c_str());
        }
    }
    std::printf("%llu blocks, %llu entries\n",
                static_cast<unsigned long long>(blocks.value().size()),
                static_cast<unsigned long long>(total));
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_imports(const std::string& path,
                const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    // Enumerate import bindings with the NullResolver: statuses then are
    // Unsupported (module unknown) — showing exactly what WOULD need a
    // resolver. For by-name listing we mirror M1's decoded view instead.
    LoaderWorld w(img.opt.size_of_image);
    if (!w.ok()) {
        std::fprintf(stderr, "error: runtime init failed\n");
        return 1;
    }
    auto* proc = world_process(w);
    LoadDiagnostics diag;
    xbox2pc::rt::loader::NullResolver null_res;
    auto layout = w.loader.map_image(proc->address_space(), img,
                                      bytes->data(), bytes->size(), 0, diag);
    if (!layout.ok()) {
        std::fprintf(stderr, "error: map for import inspection failed: %s\n",
                     layout.error_string().c_str());
        return 1;
    }
    auto bindings = w.loader.resolve_imports(proc->address_space(), layout.value(),
                                            img, bytes->data(), bytes->size(),
                                            null_res, diag);
    if (!bindings.ok()) {
        std::fprintf(stderr, "error: import walk failed: %s\n",
                     bindings.error_string().c_str());
        return 1;
    }
    std::uint64_t by_name = 0, by_ord = 0;
    for (const auto& b : bindings.value()) {
        if (b.lookup.by_ordinal) ++by_ord; else ++by_name;
    }
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", path);
        j.set("count", static_cast<std::uint64_t>(bindings.value().size()));
        Json arr = Json::array();
        for (const auto& b : bindings.value()) {
            Json bj = Json::object();
            bj.set("dll", b.lookup.dll);
            if (b.lookup.by_ordinal) {
                bj.set("ordinal", static_cast<std::uint64_t>(b.lookup.ordinal));
            } else {
                bj.set("symbol", b.lookup.symbol);
            }
            bj.set("by_ordinal", b.lookup.by_ordinal);
            // Null-resolver statuses: what a real resolver must cover.
            bj.set("requires_resolver", true);
            arr.push_back(std::move(bj));
        }
        j.set("imports", std::move(arr));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc imports %s (resolver-required view)\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& b : bindings.value()) {
        if (b.lookup.by_ordinal) {
            std::printf("  %-24s #%u\n", b.lookup.dll.c_str(), b.lookup.ordinal);
        } else {
            std::printf("  %-24s %s\n", b.lookup.dll.c_str(),
                        b.lookup.symbol.c_str());
        }
    }
    std::printf("%llu imports (%llu by-name, %llu by-ordinal); NONE are "
                "bound (no resolver in inspection mode)\n",
                static_cast<unsigned long long>(bindings.value().size()),
                static_cast<unsigned long long>(by_name),
                static_cast<unsigned long long>(by_ord));
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_map_image(const std::string& path, std::uint64_t want_base,
                  const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    const auto rep = xbox2pc::rt::loader::validate_image(img, bytes->data(),
                                                         bytes->size());
    if (!rep.valid) {
        std::fprintf(stderr, "error: image fails validation:\n");
        for (const auto& i : rep.issues)
            std::fprintf(stderr, "  [%s] %s\n", i.code.c_str(), i.message.c_str());
        return 1;
    }
    LoaderWorld w(img.opt.size_of_image);
    if (!w.ok()) {
        std::fprintf(stderr, "error: runtime init failed\n");
        return 1;
    }
    auto* proc = world_process(w);
    LoadDiagnostics diag;
    auto layout = w.loader.map_image(proc->address_space(), img,
                                     bytes->data(), bytes->size(), want_base,
                                     diag);
    if (!layout.ok()) {
        std::fprintf(stderr, "error: map failed: %s\n",
                     layout.error_string().c_str());
        return 1;
    }
    const auto& lay = layout.value();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", path);
        j.set("preferred_base", lay.preferred_base);
        j.set("actual_base", lay.actual_base);
        j.set("mapped_size", lay.mapped_size);
        j.set("relocated", lay.relocated);
        j.set("delta", lay.delta);
        j.set("entry_rva", static_cast<std::uint64_t>(lay.entry_rva));
        j.set("entry_va", lay.entry_va);
        Json secs = Json::array();
        for (const auto& s : lay.sections) {
            Json sj = Json::object();
            sj.set("name", s.name);
            sj.set("rva", static_cast<std::uint64_t>(s.rva));
            sj.set("virtual_size", static_cast<std::uint64_t>(s.virtual_size));
            sj.set("mapped_base", s.mapped_base);
            sj.set("mapped_size", s.mapped_size);
            sj.set("protection", prot_name(s.protection));
            sj.set("file_backed", s.file_backed);
            secs.push_back(std::move(sj));
        }
        j.set("sections", std::move(secs));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc map-image %s (live M4 address space)\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("preferred=%s actual=%s %s (delta %s)\n",
                hex(lay.preferred_base).c_str(), hex(lay.actual_base).c_str(),
                lay.relocated ? "RELOCATED" : "at-preferred",
                hex(lay.delta).c_str());
    std::printf("mapped=%s entry-va=%s\n", hex(lay.mapped_size).c_str(),
                hex(lay.entry_va).c_str());
    std::printf("headers-region=%s+%s\n",
                hex(lay.headers_region_xbox_va).c_str(),
                hex(lay.headers_region_size).c_str());
    std::printf("sections (%zu):\n", lay.sections.size());
    for (const auto& s : lay.sections) {
        std::printf("  %-8s rva=%-6s vsz=%-6s map=%s+%s %s%s\n",
                    s.name.c_str(), hex(s.rva).c_str(),
                    hex(s.virtual_size).c_str(), hex(s.mapped_base).c_str(),
                    hex(s.mapped_size).c_str(), prot_name(s.protection).c_str(),
                    s.file_backed ? "" : " (zero-fill)");
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_load_image(const std::string& path,
                   const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    LoaderWorld w(img.opt.size_of_image);
    if (!w.ok()) {
        std::fprintf(stderr, "error: runtime init failed\n");
        return 1;
    }
    // Controlled resolver: registers exactly the DLLs the image imports
    // (CLI demo policy — clearly labeled; NOTHING binds to host functions).
    xbox2pc::rt::loader::StaticResolver res;
    for (const auto& e : img.imports.entries) {
        res.add_module(e.dll_name, e.functions);
    }
    LoadDiagnostics diag;
    LoadResult out;
    auto h = w.loader.load_image(w.pm, w.core.objects(), w.process, img,
                                 bytes->data(), bytes->size(), &res, diag, out);
    if (!h.ok()) {
        if (json_out.has_value()) {
            Json j = Json::object();
            j.set("file", path);
            j.set("loaded", false);
            j.set("state", load_state_to_name(out.final_state));
            j.set("error", out.error);
            if (!write_file(*json_out, j.serialize() + "\n")) return 1;
            std::printf("wrote %s\n", json_out->c_str());
            return 0;
        }
        std::fprintf(stderr, "error: load failed at %s: %s\n",
                     load_state_to_name(out.final_state), out.error.c_str());
        return 1;
    }
    const auto& e = out.exec;
    const bool fully_resolved = e.imports_resolved_all;
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", path);
        j.set("loaded", true);
        j.set("validated", e.validated);
        j.set("mapped", e.mapped);
        j.set("relocated", e.relocated);
        j.set("imports_resolved", e.imports_resolved);
        j.set("imports_unresolved", e.imports_unresolved);
        j.set("imports_resolved_all", fully_resolved);
        j.set("prepared", e.prepared);
        j.set("actual_base", out.layout.actual_base);
        j.set("entry_va", e.entry_va);
        j.set("image_size", e.image_size);
        j.set("relocations_applied", e.relocations_applied);
        j.set("tls_present", e.tls_present);
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc load-image %s (full lifecycle, live runtime)\n",
                path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  validated:  %s\n", e.validated ? "yes" : "NO");
    std::printf("  mapped:     %s (base %s, size %s)\n",
                e.mapped ? "yes" : "NO", hex(out.layout.actual_base).c_str(),
                hex(e.image_size).c_str());
    std::printf("  relocated:  %s (%llu DIR64 entries)\n",
                e.relocated ? "yes" : "NO",
                static_cast<unsigned long long>(e.relocations_applied));
    std::printf("  imports:    %llu resolved, %llu unresolved (resolver: "
                "controlled static test resolver)\n",
                static_cast<unsigned long long>(e.imports_resolved),
                static_cast<unsigned long long>(e.imports_unresolved));
    std::printf("  prepared:  %s (entry-va %s)\n", e.prepared ? "yes" : "NO",
                hex(e.entry_va).c_str());
    std::printf("NOTE: reaching Prepared is NOT execution. No entry point "
                "is started.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_unload_image(const std::string& path) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    LoaderWorld w(img.opt.size_of_image);
    if (!w.ok()) return 1;
    xbox2pc::rt::loader::StaticResolver res;
    for (const auto& e : img.imports.entries) res.add_module(e.dll_name, e.functions);
    LoadDiagnostics diag;
    LoadResult out;
    auto h = w.loader.load_image(w.pm, w.core.objects(), w.process, img,
                                  bytes->data(), bytes->size(), &res, diag, out);
    if (!h.ok()) {
        std::fprintf(stderr, "error: load for unload failed: %s\n",
                     out.error.c_str());
        return 1;
    }
    auto un = w.loader.unload_image(w.pm, w.core.objects(), w.process, h.value());
    if (!un.ok()) {
        std::fprintf(stderr, "error: unload failed: %s\n",
                     un.error_string().c_str());
        return 1;
    }
    auto list = w.loader.list_images(w.pm, w.core.objects(), w.process);
    auto& space = world_process(w)->address_space();
    std::printf("loaded then unloaded %s\n", path.c_str());
    std::printf("remaining images: %zu; remaining regions: %u\n",
                list.ok() ? list.value().size() : 0u,
                space.stats().region_count);
    return 0;
}

int cmd_image_info(const std::string& path,
                   const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    LoaderWorld w(img.opt.size_of_image);
    if (!w.ok()) return 1;
    xbox2pc::rt::loader::StaticResolver res;
    for (const auto& e : img.imports.entries) res.add_module(e.dll_name, e.functions);
    LoadDiagnostics diag;
    LoadResult out;
    auto h = w.loader.load_image(w.pm, w.core.objects(), w.process, img,
                                  bytes->data(), bytes->size(), &res, diag, out);
    if (!h.ok()) {
        std::fprintf(stderr, "error: load failed: %s\n", out.error.c_str());
        return 1;
    }
    auto list = w.loader.list_images(w.pm, w.core.objects(), w.process);
    if (!list.ok() || list.value().empty()) {
        std::fprintf(stderr, "error: no loaded image info\n");
        return 1;
    }
    const auto& info = list.value().front();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("file", path);
        j.set("name", info.name);
        j.set("state", load_state_to_name(info.state));
        j.set("actual_base", info.layout.actual_base);
        j.set("preferred_base", info.layout.preferred_base);
        j.set("mapped_size", info.layout.mapped_size);
        j.set("entry_va", info.layout.entry_va);
        j.set("imports_resolved", info.imports_resolved);
        j.set("imports_unresolved", info.imports_unresolved);
        j.set("relocations_applied", diag.relocations_applied);
        j.set("tls_present", diag.has_tls);
        Json secs = Json::array();
        for (const auto& s : info.layout.sections) {
            Json sj = Json::object();
            sj.set("name", s.name);
            sj.set("protection", prot_name(s.protection));
            sj.set("mapped_base", s.mapped_base);
            sj.set("mapped_size", s.mapped_size);
            secs.push_back(std::move(sj));
        }
        j.set("sections", std::move(secs));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc image-info %s (loaded image view)\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("state=%s name=%s\n", load_state_to_name(info.state),
                info.name.c_str());
    std::printf("base: preferred=%s actual=%s size=%s\n",
                hex(info.layout.preferred_base).c_str(),
                hex(info.layout.actual_base).c_str(),
                hex(info.layout.mapped_size).c_str());
    std::printf("entry-va=%s imports: %llu resolved / %llu unresolved\n",
                hex(info.layout.entry_va).c_str(),
                static_cast<unsigned long long>(info.imports_resolved),
                static_cast<unsigned long long>(info.imports_unresolved));
    std::printf("relocations applied: %llu; TLS present: %d\n",
                static_cast<unsigned long long>(diag.relocations_applied),
                diag.has_tls ? 1 : 0);
    for (const auto& s : info.layout.sections) {
        std::printf("  %-8s %s %s+%s\n", s.name.c_str(),
                    prot_name(s.protection).c_str(),
                    hex(s.mapped_base).c_str(), hex(s.mapped_size).c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}


// ── M7: API compatibility CLI commands ─────────────────────────────────────
//
// Every command boots a LIVE runtime with the three M7 services
// initialized (GameRuntime/TaskQueue/Timing registered before
// core.initialize() so initialize_all covers them). Outputs report
// evidence, statuses, and limitations honestly; nothing is faked.

#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/compat_report.hpp"
#include "xbox2pc/dep_analyzer.hpp"

// A live world with M7 services (declared so the registry outlives core).
namespace {
struct M7World {
    xbox2pc::rt::api::ApiRegistry reg;
    xbox2pc::rt::RuntimeCore core;
    xbox2pc::rt::ProcessManager pm;
    xbox2pc::rt::api::GameRuntimeService* grt = nullptr;
    xbox2pc::rt::api::TaskQueueService* tq = nullptr;
    xbox2pc::rt::api::TimingService* tim = nullptr;

    M7World() : pm(core.objects()) {
        {
            auto grt_s = std::make_unique<xbox2pc::rt::api::GameRuntimeService>(reg, pm);
            auto tq_s = std::make_unique<xbox2pc::rt::api::TaskQueueService>(reg, pm);
            auto tim_s = std::make_unique<xbox2pc::rt::api::TimingService>(reg);
            grt = grt_s.get();
            tq = tq_s.get();
            tim = tim_s.get();
            (void)core.services().register_service(std::move(grt_s));
            (void)core.services().register_service(std::move(tq_s));
            (void)core.services().register_service(std::move(tim_s));
        }
        if (!core.initialize().ok()) return;
    }
    ~M7World() { (void)core.shutdown(); }
};
}  // namespace

int cmd_api_list(const std::optional<std::string>& json_out) {
    M7World w;
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("descriptors", static_cast<std::uint64_t>(w.reg.descriptor_count()));
        j.set("implementations", static_cast<std::uint64_t>(w.reg.implementation_count()));
        Json arr = Json::array();
        for (const auto* d : w.reg.all()) {
            Json dj = Json::object();
            dj.set("library", d->library);
            dj.set("export", d->export_name);
            dj.set("signature", d->signature);
            dj.set("convention", xbox2pc::rt::api::convention_to_name(d->convention));
            dj.set("params", static_cast<std::uint64_t>(d->param_count));
            dj.set("return", xbox2pc::rt::api::return_kind_to_name(d->ret));
            dj.set("compat", xbox2pc::rt::api::api_status_to_name(d->compat));
            dj.set("impl", xbox2pc::rt::api::api_status_to_name(d->impl));
            dj.set("evidence", d->evidence + " " + d->evidence_url);
            dj.set("implemented", w.reg.has_implementation(d->library, d->export_name));
            arr.push_back(std::move(dj));
        }
        j.set("apis", std::move(arr));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc api-list (%zu descriptors, %zu implementations)\n",
                w.reg.descriptor_count(), w.reg.implementation_count());
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto* d : w.reg.all()) {
        const bool has_impl = w.reg.has_implementation(d->library, d->export_name);
        std::printf("  %-24s %-34s %s/%s%s\n",
                    (d->library + "!" + d->export_name).c_str(),
                    d->signature.c_str(),
                    xbox2pc::rt::api::api_status_to_name(d->compat),
                    xbox2pc::rt::api::api_status_to_name(d->impl),
                    has_impl ? "" : " [no impl]");
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_api_info(const std::string& api,
                 const std::optional<std::string>& json_out) {
    M7World w;
    // api is "library!export" (or just "export" -> search all).
    std::string lib, name;
    const auto sep = api.find('!');
    if (sep != std::string::npos) {
        lib = api.substr(0, sep);
        name = api.substr(sep + 1);
    } else {
        name = api;
    }
    const xbox2pc::rt::api::ApiDescriptor* d =
        lib.empty() ? nullptr : w.reg.find(lib, name);
    if (d == nullptr) {
        // Search by export name across libraries.
        for (const auto* cand : w.reg.all()) {
            if (cand->export_name == name) {
                d = cand;
                break;
            }
        }
    }
    if (d == nullptr) {
        std::fprintf(stderr, "error: no verified descriptor for '%s'\n",
                     api.c_str());
        return 1;
    }
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("library", d->library);
        j.set("export", d->export_name);
        j.set("signature", d->signature);
        j.set("convention", xbox2pc::rt::api::convention_to_name(d->convention));
        j.set("params", static_cast<std::uint64_t>(d->param_count));
        j.set("return", xbox2pc::rt::api::return_kind_to_name(d->ret));
        j.set("compat", xbox2pc::rt::api::api_status_to_name(d->compat));
        j.set("impl", xbox2pc::rt::api::api_status_to_name(d->impl));
        j.set("evidence", d->evidence);
        j.set("url", d->evidence_url);
        j.set("notes", d->notes);
        j.set("implemented", w.reg.has_implementation(d->library, d->export_name));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc api-info %s!%s\n", d->library.c_str(),
                d->export_name.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("signature:  %s\n", d->signature.c_str());
    std::printf("convention: %s (%u documented params, return %s)\n",
                xbox2pc::rt::api::convention_to_name(d->convention), d->param_count,
                xbox2pc::rt::api::return_kind_to_name(d->ret));
    std::printf("status:     compat=%s impl=%s registered=%s\n",
                xbox2pc::rt::api::api_status_to_name(d->compat),
                xbox2pc::rt::api::api_status_to_name(d->impl),
                w.reg.has_implementation(d->library, d->export_name) ? "yes" : "NO");
    std::printf("evidence:   %s\n              %s\n", d->evidence.c_str(),
                d->evidence_url.c_str());
    std::printf("notes:      %s\n", d->notes.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_api_status(const std::optional<std::string>& json_out) {
    M7World w;
    std::uint64_t by_status[6] = {0};
    for (const auto* d : w.reg.all()) {
        by_status[static_cast<std::size_t>(d->compat)]++;
    }
    const char* names[6] = {"native-equivalent", "fully-implemented",
                            "partially-implemented", "stubbed",
                            "unsupported", "unknown"};
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("descriptors", static_cast<std::uint64_t>(w.reg.descriptor_count()));
        j.set("implementations", static_cast<std::uint64_t>(w.reg.implementation_count()));
        Json st = Json::object();
        for (int i = 0; i < 6; ++i) {
            st.set(names[i], by_status[static_cast<std::size_t>(i)]);
        }
        j.set("by_status", std::move(st));
        Json regs = Json::array();
        for (const auto& r : w.reg.registrations()) {
            Json rj = Json::object();
            rj.set("library", r.library);
            rj.set("export", r.export_name);
            rj.set("owner", r.owner);
            rj.set("test_only", r.test_only);
            rj.set("implementation", r.describe);
            regs.push_back(std::move(rj));
        }
        j.set("registrations", std::move(regs));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc api-status (live registry)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    for (int i = 0; i < 6; ++i) {
        std::printf("  %-22s %llu\n", names[i],
                    static_cast<unsigned long long>(by_status[static_cast<std::size_t>(i)]));
    }
    std::printf("implementations: %zu of %zu descriptors\n",
                w.reg.implementation_count(), w.reg.descriptor_count());
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_dispatch_test(const std::string& api,
                      const std::optional<std::string>& json_out) {
    M7World w;
    std::string lib, name;
    const auto sep = api.find('!');
    if (sep != std::string::npos) {
        lib = api.substr(0, sep);
        name = api.substr(sep + 1);
    } else {
        name = api;
        for (const auto* cand : w.reg.all()) {
            if (cand->export_name == name) {
                lib = cand->library;
                break;
            }
        }
    }
    if (lib.empty()) {
        std::fprintf(stderr, "error: unknown api '%s' (use library!name)\n",
                     api.c_str());
        return 1;
    }
    // Zero-arg dispatch (the controlled interface: no guest code runs).
    xbox2pc::rt::api::ApiContext ctx;
    const auto* d = w.reg.find(lib, name);
    if (d != nullptr && d->param_count != 0) {
        // Arguments default to zero-filled slots matching the documented
        // count (e.g. size=0 probes the validation path honestly).
        ctx.arg_count = d->param_count;
    }
    const auto r = w.reg.dispatch(lib, name, ctx);
    const bool ok = r.ok;
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("api", lib + "!" + name);
        j.set("dispatched", ok);
        j.set("return_value", r.return_value);
        j.set("error", r.error);
        j.set("note", r.note);
        j.set("has_out", r.has_out);
        j.set("out_value", r.out_value);
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return ok ? 0 : 1;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc dispatch-test %s!%s (controlled interface; no guest code)\n",
                lib.c_str(), name.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  dispatched: %s\n", ok ? "yes" : "NO");
    std::printf("  return:    %s (0x%llX)\n",
                ok ? "success" : "error",
                static_cast<unsigned long long>(r.return_value));
    if (!r.error.empty()) std::printf("  error:     %s\n", r.error.c_str());
    if (!r.note.empty()) std::printf("  note:      %s\n", r.note.c_str());
    if (r.has_out) {
        std::printf("  out:       %llu (0x%llX)\n",
                    static_cast<unsigned long long>(r.out_value),
                    static_cast<unsigned long long>(r.out_value));
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    return ok ? 0 : 1;
}

int cmd_gdk_services(const std::optional<std::string>& json_out) {
    M7World w;
    auto list = w.core.services().list_services();
    if (json_out.has_value()) {
        Json j = Json::object();
        Json arr = Json::array();
        for (const auto& s : list) {
            Json sj = Json::object();
            sj.set("name", s.name);
            sj.set("state", xbox2pc::rt::service_state_to_name(s.state));
            sj.set("dependencies", static_cast<std::uint64_t>(s.dependencies.size()));
            sj.set("last_error", s.last_error);
            arr.push_back(std::move(sj));
        }
        j.set("services", std::move(arr));
        j.set("implementations", static_cast<std::uint64_t>(w.reg.implementation_count()));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc gdk-services (live service registry)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& s : list) {
        std::printf("  %-22s %-12s deps=%zu%s\n", s.name.c_str(),
                    xbox2pc::rt::service_state_to_name(s.state),
                    s.dependencies.size(),
                    s.last_error.empty() ? "" : (" err=" + s.last_error).c_str());
    }
    std::printf("API implementations registered: %zu\n",
                w.reg.implementation_count());
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_gameos_services(const std::optional<std::string>& json_out) {
    // The Game OS surface in M7 is the M4-backed runtime surface exposed
    // through the GameRuntimeService (per-process lifecycle state) plus
    // the timing/taskqueue services: report them as the honest Game OS
    // compatibility foundation.
    M7World w;
    auto p = w.pm.create_process("gameos-probe.exe", 16ull << 20);
    std::string pid_note;
    if (p.ok()) {
        auto r1 = w.grt->grt_initialize(1);
        pid_note = r1.ok() ? "per-process GRT state tracked" : "init refused";
        (void)w.pm.terminate_process(p.value(), 0);
    }
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("surface", "game-os foundation via M4-backed services");
        j.set("lifecycle_state", pid_note);
        j.set("services", static_cast<std::uint64_t>(w.core.services().service_count()));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc gameos-services (M4-backed Game OS foundation)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  surface:    process lifecycle, threads, sync, memory,\n"
                "              handles, VFS, loader — all M3..M6 subsystems\n"
                "              exposed through documented GDK-facing APIs\n");
    std::printf("  lifecycle: %s\n", pid_note.c_str());
    std::printf("  services:  %zu registered, %zu API implementations\n",
                w.core.services().service_count(),
                w.reg.implementation_count());
    std::printf("NOTE: this is the COMPATIBILITY FOUNDATION, not a Game OS\n"
                "implementation. No kernel emulation is claimed.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_compat_report(const std::string& path,
                      const std::optional<std::string>& json_out) {
    auto bytes = read_pe_bytes(path);
    if (!bytes.has_value()) {
        std::fprintf(stderr, "error: cannot read '%s'\n", path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diags;
    xbox2pc::pe::PeImage img;
    try {
        img = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diags);
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    M7World w;
    // Delay-load resolution into a scratch mapped image (best effort;
    // unresolved entries are reported, never hidden).
    std::optional<xbox2pc::rt::api::DelayLoadReport> delay;
    {
        auto p = w.pm.create_process("compat-probe.exe", 32ull << 20);
        if (p.ok()) {
            auto found = w.core.objects().lookup_handle(p.value());
            auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
            xbox2pc::rt::loader::ImageLoader loader;
            xbox2pc::rt::loader::LoadDiagnostics ld;
            auto lay = loader.map_image(proc->address_space(), img,
                                        bytes->data(), bytes->size(), 0, ld);
            if (lay.ok()) {
                auto d = xbox2pc::rt::api::resolve_delay_imports(
                    proc->address_space(), lay.value(), img, bytes->data(),
                    bytes->size(), w.reg, false);
                if (d.ok()) delay = d.value();
            }
            (void)w.pm.terminate_process(p.value(), 0);
        }
    }
    xbox2pc::diag::Diagnostics dd;
    auto dep = xbox2pc::deps::analyze(img, dd);
    auto rep = xbox2pc::rt::api::build_compat_report(
        img, dep, w.reg, delay.has_value() ? &delay.value() : nullptr);
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("source", rep.source);
        Json arr = Json::array();
        for (const auto& row : rep.rows) {
            Json rj = Json::object();
            rj.set("dll", row.dll);
            rj.set("name", row.name);
            rj.set("by_ordinal", row.by_ordinal);
            rj.set("delay_load", row.delay_load);
            rj.set("code", xbox2pc::rt::api::compat_code_to_name(row.code));
            rj.set("verified", row.verified);
            rj.set("compat", xbox2pc::rt::api::api_status_to_name(row.compat));
            rj.set("evidence", row.evidence);
            rj.set("signature", row.signature);
            rj.set("note", row.note);
            arr.push_back(std::move(rj));
        }
        j.set("imports", std::move(arr));
        Json summary = Json::object();
        summary.set("total", static_cast<std::uint64_t>(rep.rows.size()));
        std::uint64_t verified_count = 0;
        for (const auto& row : rep.rows) if (row.verified) ++verified_count;
        summary.set("verified", verified_count);
        for (std::size_t i = 0; i < 11; ++i) {
            const auto code = static_cast<xbox2pc::rt::api::CompatCode>(i);
            summary.set(xbox2pc::rt::api::compat_code_to_name(code),
                        static_cast<std::uint64_t>(rep.counts[i]));
        }
        j.set("summary", std::move(summary));
        j.set("delay_entries", static_cast<std::uint64_t>(rep.delay_entries));
        j.set("delay_resolved", static_cast<std::uint64_t>(rep.delay_resolved));
        j.set("verdict", rep.verdict);
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc compat-report %s\n", path.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());
    for (const auto& row : rep.rows) {
        std::printf("  %-16s %s!%s%s\n",
                    xbox2pc::rt::api::compat_code_to_name(row.code),
                    row.dll.c_str(), row.name.c_str(),
                    row.delay_load ? " [delay]" : "");
        if (row.verified) {
            std::printf("      %s\n      evidence: %s\n",
                        row.signature.c_str(), row.evidence.c_str());
        } else if (!row.note.empty()) {
            std::printf("      %s\n", row.note.c_str());
        }
    }
    std::size_t verified_count = 0;
    for (const auto& row : rep.rows) if (row.verified) ++verified_count;
    std::printf("summary: %zu imports, %zu verified descriptors\n",
                rep.rows.size(), verified_count);
    for (std::size_t i = 0; i < 11; ++i) {
        const auto code = static_cast<xbox2pc::rt::api::CompatCode>(i);
        std::printf("  %-22s %zu\n",
                    xbox2pc::rt::api::compat_code_to_name(code), rep.counts[i]);
    }
    std::printf("delay-load: %zu entries, %zu resolved\n", rep.delay_entries,
                rep.delay_resolved);
    std::printf("verdict: %s\n", rep.verdict.c_str());
    std::printf("NOTE: import coverage is NOT game compatibility.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}


// ── M8: execution CLI commands ──────────────────────────────────────────────

#include "xbox2pc/execution_context.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/xbox_abi.hpp"

namespace {
struct M8World {
    xbox2pc::rt::api::ApiRegistry reg;
    xbox2pc::rt::RuntimeCore core;
    xbox2pc::rt::ProcessManager pm;
    M8World() : pm(core.objects()) {
        {
            auto grt = std::make_unique<xbox2pc::rt::api::GameRuntimeService>(reg, pm);
            (void)core.services().register_service(std::move(grt));
        }
        (void)core.initialize();
    }
    ~M8World() { (void)core.shutdown(); }
};
}  // namespace

int cmd_cpu_state(const std::optional<std::string>& json_out) {
    xbox2pc::rt::cpu::CpuState c;
    c.reset();
    // A representative initialized state.
    c.set_reg(xbox2pc::rt::cpu::Gpr::Sp, 0x20040000);
    c.set_reg(xbox2pc::rt::cpu::Gpr::Rax, 0x42);
    c.rip = 0x20001000;
    xbox2pc::rt::cpu::CpuSnapshot snap;
    (void)xbox2pc::rt::cpu::snapshot_into(c, snap);
    const auto bytes = snap.serialize();
    if (json_out.has_value()) {
        Json j = Json::object();
        Json g = Json::object();
        const char* names[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                 "r8","r9","r10","r11","r12","r13","r14","r15"};
        for (int i = 0; i < 16; ++i) g.set(names[i], c.gprs[i]);
        j.set("gprs", std::move(g));
        j.set("rip", c.rip);
        j.set("rflags", c.rflags);
        j.set("rflags_hex", "0x" + [&] { char b[20]; std::snprintf(b, sizeof b, "%llx",
                (unsigned long long)c.rflags); return std::string(b); }());
        j.set("mxcsr", static_cast<std::uint64_t>(c.mxcsr));
        j.set("fcw", static_cast<std::uint64_t>(c.fcw));
        j.set("xmm_count", 16u);
        j.set("validate_problems", static_cast<std::uint64_t>(c.validate().size()));
        j.set("snapshot_bytes", static_cast<std::uint64_t>(bytes.size()));
        j.set("roundtrip", xbox2pc::rt::cpu::CpuSnapshot::deserialize(bytes.data(), bytes.size()).ok());
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc cpu-state (deterministic model; NO instruction-set claim)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    const char* names[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                             "r8","r9","r10","r11","r12","r13","r14","r15"};
    for (int i = 0; i < 16; ++i) {
        std::printf("  %-4s 0x%016llx\n", names[i],
                    (unsigned long long)c.gprs[i]);
    }
    std::printf("  rip  0x%016llx\n  rflags 0x%llx (bit1 fixed, IF=1)\n",
                (unsigned long long)c.rip, (unsigned long long)c.rflags);
    std::printf("  mxcsr 0x%x (documented 0x1F80)  fcw 0x%x (documented 0x027F)\n",
                c.mxcsr, c.fcw);
    std::printf("  xmm0-15: 128-bit storage (YMM/ZMM deliberately NOT modeled)\n");
    std::printf("  validate: %zu problems; snapshot %zu bytes; roundtrip %s\n",
                c.validate().size(), bytes.size(),
                xbox2pc::rt::cpu::CpuSnapshot::deserialize(bytes.data(), bytes.size()).ok() ? "ok" : "FAIL");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_abi_info(const std::optional<std::string>& json_out) {
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("convention", "x64-microsoft");
        j.set("doc", xbox2pc::rt::abi::abi_doc_summary());
        j.set("shadow_space_bytes", 32u);
        j.set("stack_alignment", 16u);
        Json gp = Json::array();
        for (const char* r : {"rcx","rdx","r8","r9"}) gp.push_back(std::string(r));
        j.set("gp_arg_regs", std::move(gp));
        Json fp = Json::array();
        for (const char* r : {"xmm0","xmm1","xmm2","xmm3"}) fp.push_back(std::string(r));
        j.set("fp_arg_regs", std::move(fp));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc abi-info (Microsoft x64; evidence [MS-X64CC][MS-X64STACK])\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  %s\n", xbox2pc::rt::abi::abi_doc_summary());
    std::printf("  int/ptr args 1-4: RCX RDX R8 R9; 5+ on stack (8B slots)\n");
    std::printf("  fp args 1-4:    XMM0-3 by POSITION; 5+ on stack\n");
    std::printf("  shadow space:  32 bytes always reserved by the caller\n");
    std::printf("  alignment:     16-byte; return address at [RSP] on entry\n");
    std::printf("  returns:       scalars<=64b in RAX; fp/__m128 in XMM0;\n");
    std::printf("                 aggregates>64b: hidden ptr in RCX, ret in RAX\n");
    std::printf("  volatile:      RAX RCX RDX R8-R11 XMM0-5\n");
    std::printf("  nonvolatile:   RBX RBP RDI RSI R12-R15 XMM6-15\n");
    std::printf("  varargs:       fp values duplicated into GP registers\n");
    std::printf("  unsupported (typed rejects): __m128 by value, varargs>4,\n");
    std::printf("                 aggregates not in {1,2,4,8} bytes\n");
    std::printf("  Xbox-specific deviations: none documented; none invented\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_execution_info(const std::optional<std::string>& json_out) {
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("interface", "IExecutionEngine");
        j.set("backend", "deterministic-test");
        j.set("backend_desc",
              "bounded-subset x86-64 interpreter (test backend; NOT a general emulator)");
        Json sup = Json::array();
        const char* insns[] = {"mov r64,imm64","mov r64,r64","mov r64,[r64+disp8]",
                               "mov [r64+disp8],r64","add r64,imm32","sub r64,imm32",
                               "xor r64,r64","cmp r64,imm32","push r64","pop r64",
                               "call rel32","jmp rel32","ret","nop"};
        for (const char* i : insns) sup.push_back(std::string(i));
        j.set("supported_instructions", std::move(sup));
        j.set("single_step", true);
        Json outs = Json::array();
        for (const char* o : {"completed","returned","interrupted","terminated","faulted"}) {
            outs.push_back(std::string(o));
        }
        j.set("outcomes", std::move(outs));
        Json fl = Json::array();
        for (int i = 0; i < 12; ++i) {
            fl.push_back(std::string(xbox2pc::rt::exec::guest_fault_to_name(
                static_cast<xbox2pc::rt::exec::GuestFault>(i))));
        }
        j.set("faults", std::move(fl));
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc execution-info (interface + backend HONESTLY labeled)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  engine kind: deterministic-test\n");
    std::printf("  %s\n",
                "bounded-subset x86-64 interpreter (test backend; NOT a general emulator)");
    std::printf("  subset: MOV r64,imm64/r64/mem(disp8) (both forms), ADD/SUB/\n");
    std::printf("          CMP r64,imm32 (flags), XOR r64,r64, PUSH/POP r64,\n");
    std::printf("          CALL/JMP rel32, RET, NOP\n");
    std::printf("  single-step: yes (budget==1 is the step itself)\n");
    std::printf("  outcomes: completed returned interrupted terminated faulted\n");
    std::printf("  faults:   invalid-access permission-r/w/x invalid-instruction\n");
    std::printf("            unsupported-instruction stack-overflow invalid-state\n");
    std::printf("            marshal-failure guest-terminated budget-exceeded internal\n");
    std::printf("  Imported APIs land in the marshalling bridge (M7 registry).\n");
    std::printf("  Execution of arbitrary Xbox titles is NOT claimed.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_tls_info(const std::optional<std::string>& json_out) {
    auto cfg = xbox2pc::rt::exec::ExecutionConfig::default_validated().value();
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("max_callbacks", static_cast<std::uint64_t>(cfg.max_tls_callbacks));
        j.set("callback_abi", "RCX=DllHandle RDX=Reason(DLL_PROCESS_ATTACH=1) R8=Reserved");
        j.set("execution", "through IExecutionEngine only (never host pointers)");
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return 0;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc tls-info (M7 init + M8 callback scheduling)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  template copy + SizeOfZeroFill: M7 (bounded 1 MiB)\n");
    std::printf("  callbacks: validated (mapped RX VAs, array bounds, order),\n");
    std::printf("             limit %u, executed through the ENGINE only\n",
                cfg.max_tls_callbacks);
    std::printf("  callback ABI: RCX=DllHandle RDX=Reason R8=Reserved\n");
    std::printf("  failures REPORTED; partial-init cleanup completes\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return 0;
}

int cmd_execute_test(const std::optional<std::string>& json_out) {
    // Full in-runtime test: M4 process -> M6 load (M7 resolver) -> M8
    // context -> prepare -> deterministic-backend execution. The guest
    // program is REAL x64 subset code: RAX = 20; RAX += 22; RET -> 42.
    M8World w;
    std::vector<std::uint8_t> code;
    std::vector<std::uint8_t> mov{0x48, 0xB8, 20, 0, 0, 0, 0, 0, 0, 0};
    code.insert(code.end(), mov.begin(), mov.end());
    const std::uint8_t add[] = {0x48, 0x81, 0xC0, 0x16, 0, 0, 0};
    code.insert(code.end(), add, add + sizeof add);
    code.push_back(0xC3);
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, code});
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = xbox2pc::test::PeBuilder(spec).build();
    xbox2pc::diag::Diagnostics pd;
    auto img = xbox2pc::pe::parse(image.data(), image.size(), "exec-demo.exe", pd);
    auto ph = w.pm.create_process("exec-host.exe", 64ull << 20);
    if (!ph.ok()) return 1;
    auto pr = w.core.objects().lookup_handle(ph.value());
    auto* proc = pr.value().get()->as<xbox2pc::rt::ManagedProcess>();
    xbox2pc::rt::loader::ImageLoader loader;
    xbox2pc::rt::api::ApiResolver resolver(w.reg);
    xbox2pc::rt::loader::LoadDiagnostics ld;
    xbox2pc::rt::loader::LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), ph.value(), img,
                               image.data(), image.size(), &resolver, ld, out);
    if (!h.ok()) {
        std::fprintf(stderr, "error: load failed: %s\n", out.error.c_str());
        return 1;
    }
    auto cfg = xbox2pc::rt::exec::ExecutionConfig::default_validated().value();
    xbox2pc::rt::exec::ExecutionContext ctx(1, 1, proc->address_space(), w.reg, cfg,
                                "cli-exec");
    auto ini = ctx.initialize();
    if (!ini.ok()) return 1;
    xbox2pc::rt::loader::LoadedImageObject* loaded = nullptr;
    {
        auto lr = proc->handle_table().lookup(h.value());
        loaded = lr.value().get()->as<xbox2pc::rt::loader::LoadedImageObject>();
    }   // guard released before teardown (pin-drain contract)
    xbox2pc::rt::abi::CallSpec cspec;
    cspec.ret = xbox2pc::rt::abi::CallSpec::ReturnKind::Int;
    auto req = ctx.prepare_entry(*loaded, 0, {}, cspec);
    if (!req.ok()) {
        std::fprintf(stderr, "error: prepare failed: %s\n",
                     req.error_string().c_str());
        return 1;
    }
    xbox2pc::rt::exec::DeterministicBackend engine(w.reg, cfg);
    engine.bind_space(proc->address_space());
    engine.bind_process(1, 1);
    std::atomic<bool> stop{false};
    auto res = ctx.invoke(req.value(), engine, stop);
    const bool ok = res.ok() && res.value().outcome == xbox2pc::rt::exec::Outcome::Returned;
    const auto st = proc->address_space().stats();
    (void)ctx.destroy();
    (void)loader.unload_image(w.pm, w.core.objects(), ph.value(), h.value());
    (void)w.pm.terminate_process(ph.value(), 0);
    if (json_out.has_value()) {
        Json j = Json::object();
        j.set("backend", "deterministic-test");
        j.set("outcome", ok ? "returned" : "other");
        j.set("instructions", res.ok() ? res.value().instructions_executed : 0);
        j.set("return_value", res.ok() ? res.value().return_value : 0);
        j.set("expected", 42u);
        j.set("regions_after_terminate", static_cast<std::uint64_t>(st.region_count));
        j.set("api_calls", res.ok() ? res.value().api_calls : 0);
        if (!write_file(*json_out, j.serialize() + "\n")) return 1;
        std::printf("wrote %s\n", json_out->c_str());
        return ok ? 0 : 1;
    }
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc execute-test (DETERMINISTIC TEST BACKEND; real subset insns)\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("  program: MOV RAX,20; ADD RAX,22; RET\n");
    std::printf("  load:    %s (M6+M7 resolver)\n", "ok");
    std::printf("  context: %s\n", "initialized");
    if (res.ok()) {
        std::printf("  outcome: %s  instructions=%llu  RAX=%llu (expect 42)\n",
                    xbox2pc::rt::exec::outcome_to_name(res.value().outcome),
                    (unsigned long long)res.value().instructions_executed,
                    (unsigned long long)res.value().return_value);
    }
    std::printf("  teardown: regions after terminate = %u\n", st.region_count);
    std::printf("  NOTE: subset interpreter execution — NOT a general emulator,\n");
    std::printf("        NOT a claim of Xbox-title compatibility.\n");
    std::printf("%s\n", std::string(64, '=').c_str());
    return ok ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc >= 2 && (std::strcmp(argv[1], "--version") == 0 || std::strcmp(argv[1], "-v") == 0)) {
        std::printf("xbox2pc 0.3.0 (M1: PE32+ inspection; M2: dependency "
                    "intelligence; M3: runtime architecture)\n");
        return 0;
    }
    const int m9_binary_result = xbox2pc::cli::run_m9_binary_cli(argc, argv);
    if (m9_binary_result >= 0) return m9_binary_result;
    if (argc >= 2 && std::strcmp(argv[1], "run") == 0) {
        if (argc < 3) {
            std::fprintf(stderr, "usage: xbox2pc run <file> [--backend deterministic|native] [--json <out>]\n");
            return 2;
        }
        std::optional<std::string> json_out;
        std::string backend = "deterministic";
        int file_arg = 2;
        for (int i = 3; i < argc; ++i) {
            if (std::strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
                backend = argv[++i];
            } else if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
                json_out = argv[++i];
            } else {
                std::fprintf(stderr, "error: invalid run arguments\n");
                return 2;
            }
        }
        (void)file_arg;
        return xbox2pc::cli::run_file(argv[2], json_out, backend);
    }
    if (argc >= 2 && std::strcmp(argv[1], "interpreter-info") == 0) {
        std::optional<std::string> json_out;
        if (argc == 4 && std::strcmp(argv[2], "--json") == 0) json_out = argv[3];
        else if (argc != 2) { std::fprintf(stderr, "error: invalid interpreter-info arguments\\n"); return 2; }
        return cmd_execution_info(json_out);
    }
    if (argc >= 2 && std::strcmp(argv[1], "interpreter-test") == 0) {
        std::optional<std::string> json_out;
        if (argc == 4 && std::strcmp(argv[2], "--json") == 0) json_out = argv[3];
        else if (argc != 2) { std::fprintf(stderr, "error: invalid interpreter-test arguments\\n"); return 2; }
        return cmd_execute_test(json_out);
    }
    // Runtime-architecture commands take NO file argument (unlike the PE
    // analysis commands); they are valid at argc == 2.
    if (argc >= 2) {
        const std::string early_cmd = argv[1];
        const bool m4_cmd = early_cmd == "memory-info" || early_cmd == "memory-regions" ||
                            early_cmd == "process-info" || early_cmd == "thread-info" ||
                            early_cmd == "handle-info" || early_cmd == "resource-info";
        const bool m5_cmd = early_cmd == "mount" || early_cmd == "unmount" ||
                            early_cmd == "list" || early_cmd == "stat" ||
                            early_cmd == "read" || early_cmd == "packages" ||
                            early_cmd == "discover";
        const bool m6_cmd = early_cmd == "validate-pe" || early_cmd == "map-image" ||
                            early_cmd == "relocations" || early_cmd == "imports" ||
                            early_cmd == "load-image" || early_cmd == "unload-image" ||
                            early_cmd == "image-info";
        if (m6_cmd) {
            // M6 syntax: <cmd> <pe-file> [--base 0xVA (map-image)] [--json <out>]
            std::string file;
            std::optional<std::string> json_out;
            std::uint64_t want_base = 0;
            bool have_file = false;
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "--json") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --json requires an output path\n");
                        return 2;
                    }
                    json_out = argv[i + 1];
                    ++i;
                } else if (std::strcmp(argv[i], "--base") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --base requires a value\n");
                        return 2;
                    }
                    want_base = std::strtoull(argv[i + 1], nullptr, 0);
                    ++i;
                } else if (!have_file) {
                    file = argv[i];
                    have_file = true;
                } else {
                    std::fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                    return 2;
                }
            }
            if (!have_file) {
                std::fprintf(stderr, "error: %s requires a PE file\n", early_cmd.c_str());
                return 2;
            }
            if (early_cmd == "validate-pe") return cmd_validate_pe(file, json_out);
            if (early_cmd == "map-image") return cmd_map_image(file, want_base, json_out);
            if (early_cmd == "relocations") return cmd_relocations(file, json_out);
            if (early_cmd == "imports") return cmd_imports(file, json_out);
            if (early_cmd == "load-image") return cmd_load_image(file, json_out);
            if (early_cmd == "unload-image") return cmd_unload_image(file);
            return cmd_image_info(file, json_out);
        }
        const bool m8_noarg = early_cmd == "cpu-state" || early_cmd == "abi-info" ||
                              early_cmd == "execution-info" || early_cmd == "tls-info" ||
                              early_cmd == "execute-test";
        if (m8_noarg) {
            std::optional<std::string> json_out;
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "--json") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --json requires an output path\n");
                        return 2;
                    }
                    json_out = argv[i + 1];
                    ++i;
                } else {
                    std::fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                    return 2;
                }
            }
            if (early_cmd == "cpu-state") return cmd_cpu_state(json_out);
            if (early_cmd == "abi-info") return cmd_abi_info(json_out);
            if (early_cmd == "execution-info") return cmd_execution_info(json_out);
            if (early_cmd == "tls-info") return cmd_tls_info(json_out);
            return cmd_execute_test(json_out);
        }
        const bool m7_noarg = early_cmd == "api-list" || early_cmd == "api-status" ||
                              early_cmd == "gdk-services" || early_cmd == "gameos-services";
        if (m7_noarg) {
            std::optional<std::string> json_out;
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "--json") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --json requires an output path\n");
                        return 2;
                    }
                    json_out = argv[i + 1];
                    ++i;
                } else {
                    std::fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                    return 2;
                }
            }
            if (early_cmd == "api-list") return cmd_api_list(json_out);
            if (early_cmd == "api-status") return cmd_api_status(json_out);
            if (early_cmd == "gdk-services") return cmd_gdk_services(json_out);
            return cmd_gameos_services(json_out);
        }
        const bool m7_arg = early_cmd == "api-info" || early_cmd == "dispatch-test" ||
                            early_cmd == "compat-report";
        if (m7_arg) {
            std::string arg;
            std::optional<std::string> json_out;
            bool have_arg = false;
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "--json") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --json requires an output path\n");
                        return 2;
                    }
                    json_out = argv[i + 1];
                    ++i;
                } else if (!have_arg) {
                    arg = argv[i];
                    have_arg = true;
                } else {
                    std::fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                    return 2;
                }
            }
            if (!have_arg) {
                std::fprintf(stderr, "error: %s requires an argument\n",
                             early_cmd.c_str());
                return 2;
            }
            if (early_cmd == "api-info") return cmd_api_info(arg, json_out);
            if (early_cmd == "dispatch-test") return cmd_dispatch_test(arg, json_out);
            return cmd_compat_report(arg, json_out);
        }
        if (early_cmd == "runtime-info" || early_cmd == "runtime-objects" ||
            early_cmd == "runtime-services" || m4_cmd) {
            std::optional<std::string> json_out;
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "--json") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --json requires an output path\n");
                        return 2;
                    }
                    json_out = argv[i + 1];
                    ++i;
                } else if (i == 2) {
                    continue;  // subcommand word
                } else {
                    std::fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
                    return 2;
                }
            }
            if (early_cmd == "runtime-info") return cmd_runtime_info(json_out);
            if (early_cmd == "runtime-objects") return cmd_runtime_objects(json_out);
            if (early_cmd == "runtime-services") return cmd_runtime_services(json_out);
            if (early_cmd == "memory-info") return cmd_memory_info(json_out);
            if (early_cmd == "memory-regions") return cmd_memory_regions(json_out);
            if (early_cmd == "process-info") return cmd_process_info(json_out);
            if (early_cmd == "thread-info") return cmd_thread_info(json_out);
            if (early_cmd == "handle-info") return cmd_handle_info(json_out);
            return cmd_resource_info(json_out);  // resource-info
        }
        if (m5_cmd) {
            // M5 syntax: <cmd> [path] [--json <out>] [--limit N (read)]
            std::string path;              // defaulted per command below
            std::optional<std::string> json_out;
            std::uint64_t read_limit = 256;
            bool have_path = false;
            for (int i = 2; i < argc; ++i) {
                if (std::strcmp(argv[i], "--json") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --json requires an output path\n");
                        return 2;
                    }
                    json_out = argv[i + 1];
                    ++i;
                } else if (std::strcmp(argv[i], "--limit") == 0) {
                    if (i + 1 >= argc) {
                        std::fprintf(stderr, "error: --limit requires a number\n");
                        return 2;
                    }
                    read_limit = std::strtoull(argv[i + 1], nullptr, 10);
                    ++i;
                } else if (!have_path) {
                    path = argv[i];
                    have_path = true;
                } else {
                    std::fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                    return 2;
                }
            }
            // Per-command defaults.
            if (early_cmd == "mount" || early_cmd == "unmount" ||
                early_cmd == "packages") {
                if (have_path) {
                    std::fprintf(stderr, "error: %s takes no path argument\n",
                                 early_cmd.c_str());
                    return 2;
                }
                if (early_cmd == "mount") return cmd_mount(json_out);
                if (early_cmd == "unmount") return cmd_unmount(json_out);
                return cmd_packages(json_out);
            }
            if (early_cmd == "discover" && !have_path) path = "/";
            if ((early_cmd == "list" || early_cmd == "stat" ||
                 early_cmd == "read" || early_cmd == "discover") && !have_path &&
                early_cmd != "discover") {
                std::fprintf(stderr, "error: %s requires a path\n", early_cmd.c_str());
                return 2;
            }
            if (early_cmd == "list") return cmd_list(path, json_out);
            if (early_cmd == "stat") return cmd_stat(path, json_out);
            if (early_cmd == "read") return cmd_read(path, read_limit, json_out);
            return cmd_discover(path, json_out);
        }
    }
    if (argc < 3) {
        usage();
        return 2;
    }
    const std::string cmd = argv[1];
    const std::string path = argv[2];

    if (cmd == "inspect") {
        bool quiet = false;
        for (int i = 3; i < argc; ++i) {
            if (std::strcmp(argv[i], "--quiet") == 0) quiet = true;
            else {
                std::fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }
        return cmd_inspect(path, quiet);
    }
    if (cmd == "dependencies" || cmd == "graph") {
        std::optional<std::string> json_out;
        for (int i = 3; i < argc; ++i) {
            if (std::strcmp(argv[i], "--json") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(stderr, "error: --json requires an output path\n");
                    return 2;
                }
                json_out = argv[i + 1];
                ++i;
            } else {
                std::fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }
        return cmd == "dependencies" ? cmd_dependencies(path, json_out)
                                     : cmd_graph(path, json_out);
    }
    if (cmd == "classify") {
        for (int i = 3; i < argc; ++i) {
            std::fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 2;
        }
        return cmd_classify(path);
    }
    usage();
    return 2;
}
