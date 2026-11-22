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
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/service_registry.hpp"

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
    if (img.coff.characteristics & 0x0002) std::printf("image_type:    DLL\n");
    else if (img.coff.characteristics & 0x0001) std::printf("image_type:    object\n");
    else std::printf("image_type:    executable\n");

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

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && (std::strcmp(argv[1], "--version") == 0 || std::strcmp(argv[1], "-v") == 0)) {
        std::printf("xbox2pc 0.3.0 (M1: PE32+ inspection; M2: dependency "
                    "intelligence; M3: runtime architecture)\n");
        return 0;
    }
    // Runtime-architecture commands take NO file argument (unlike the PE
    // analysis commands); they are valid at argc == 2.
    if (argc >= 2) {
        const std::string early_cmd = argv[1];
        if (early_cmd == "runtime-info" || early_cmd == "runtime-objects" ||
            early_cmd == "runtime-services") {
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
            return cmd_runtime_services(json_out);
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
