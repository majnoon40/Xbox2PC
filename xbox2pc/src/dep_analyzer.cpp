// xbox2pc/dep_analyzer.cpp — dependency analysis over a parsed PeImage.

#include "xbox2pc/dep_analyzer.hpp"

#include <algorithm>
#include <utility>

namespace xbox2pc::deps {
namespace {

// Case-insensitive module name equality (loader-equivalent, extension-aware).
bool same_module(const std::string& a, const std::string& b) {
    return registry::normalize_module_name(a) == registry::normalize_module_name(b);
}

std::string lower_copy(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

}  // namespace

void split_forwarder(const std::string& forwarder, std::string& dll, std::string& api) {
    const std::size_t dot = forwarder.find('.');
    if (dot == std::string::npos) {
        dll = forwarder;
        api.clear();
        return;
    }
    dll = forwarder.substr(0, dot);
    api = forwarder.substr(dot + 1);
}

std::size_t DependencyReport::total_function_imports() const {
    std::size_t total = 0;
    for (const auto& d : dependencies) total += d.function_count;
    return total;
}

DependencyReport analyze(const pe::PeImage& img, diag::Diagnostics& diags) {
    DependencyReport rep;
    rep.source = img.source_name;

    // ── 1. Enumerate imported DLLs (regular + delay) ──
    // Merge by normalized module name; keep first-seen spelling.
    const registry::ApiRegistry reg;
    const compat::CompatibilityDb compat_db;

    std::vector<std::string> keys;       // normalized names, index-aligned with rep.dependencies

    auto find_edge = [&](const std::string& dll) -> int {
        const std::string norm = registry::normalize_module_name(dll);
        for (std::size_t i = 0; i < keys.size(); ++i) {
            if (keys[i] == norm) return static_cast<int>(i);
        }
        return -1;
    };

    // Returns the index of the (new or existing) edge for `dll`. Indices stay
    // valid across vector growth — never store pointers into the vector.
    auto ensure_edge = [&](const std::string& dll, bool delay) -> std::size_t {
        const int found = find_edge(dll);
        if (found >= 0) {
            DependencyEdge& e = rep.dependencies[static_cast<std::size_t>(found)];
            if (delay) {
                e.delay_import = true;
                e.import_sources.push_back("delay");
            } else {
                e.regular_import = true;
                e.import_sources.push_back("regular");
            }
            return static_cast<std::size_t>(found);
        }
        DependencyEdge e;
        e.dll_name = dll;
        if (delay) {
            e.delay_import = true;
            e.import_sources.push_back("delay");
        } else {
            e.regular_import = true;
            e.import_sources.push_back("regular");
        }
        rep.dependencies.push_back(std::move(e));
        keys.push_back(registry::normalize_module_name(dll));
        return rep.dependencies.size() - 1;
    };

    // Regular import table: entries carry functions + ordinals in order, but
    // the by-name/ordinal split loses the interleaved order; the FunctionImport
    // list preserves both kinds, by-name first then ordinals (documented).
    for (const auto& entry : img.imports.entries) {
        const std::size_t ei = ensure_edge(entry.dll_name, false);
        DependencyEdge& e = rep.dependencies[ei];
        e.timestamp = entry.timestamp;
        e.iat_rva = entry.iat_rva;
        e.int_rva = entry.int_rva;
        if (entry.bound) {
            diags.warning("import from '" + entry.dll_name + "' is bound (TimeDateStamp != 0)");
        }
        for (std::size_t i = 0; i < entry.functions.size(); ++i) {
            FunctionImport f;
            f.name = entry.functions[i];
            f.ordinal = i < entry.by_name_ordinals.size() ? entry.by_name_ordinals[i] : 0;
            f.delay_load = false;
            f.unresolved = entry.functions[i].rfind("<unresolved", 0) == 0 ||
                            entry.functions[i].rfind("<empty", 0) == 0;
            e.functions.push_back(std::move(f));
        }
        for (std::uint32_t ord : entry.ordinal_only) {
            FunctionImport f;
            f.name.clear();
            f.ordinal = ord;
            f.by_ordinal = true;
            f.delay_load = false;
            e.functions.push_back(std::move(f));
        }
    }

    // Delay-load table: separate descriptors, same merge logic.
    for (const auto& entry : img.delay_imports.entries) {
        const std::size_t ei = ensure_edge(entry.dll_name, true);
        DependencyEdge& e = rep.dependencies[ei];
        rep.has_delay_imports = true;
        for (const auto& fn : entry.functions) {
            FunctionImport f;
            f.name = fn;
            f.delay_load = true;
            f.unresolved = fn.rfind("<unresolved", 0) == 0 || fn.rfind("<empty", 0) == 0;
            e.functions.push_back(std::move(f));
        }
        for (std::uint32_t ord : entry.ordinal_only) {
            FunctionImport f;
            f.name.clear();
            f.ordinal = ord;
            f.by_ordinal = true;
            f.delay_load = true;
            e.functions.push_back(std::move(f));
        }
    }

    // ── 2. Classify + attach compatibility, detect duplicates ──
    rep.duplicate_count = 0;
    for (auto& e : rep.dependencies) {
        e.function_count = e.functions.size();
        // Duplicate = DLL appears more than once across the raw tables.
        // Count occurrences by normalized name over both tables.
        std::size_t occurrences = 0;
        for (const auto& entry : img.imports.entries) {
            if (same_module(entry.dll_name, e.dll_name)) ++occurrences;
        }
        for (const auto& entry : img.delay_imports.entries) {
            if (same_module(entry.dll_name, e.dll_name)) ++occurrences;
        }
        e.duplicate = occurrences > 1;
        if (e.duplicate) {
            ++rep.duplicate_count;
            diags.warning("duplicate dependency on '" + e.dll_name + "' (" +
                          std::to_string(occurrences) + " import descriptors)");
        }

        // Classification (evidence-based; fallback Unknown is explicit).
        if (const auto rec = reg.classify_library(e.dll_name)) {
            e.category = rec->category;
            e.category_name = registry::category_to_name(rec->category);
            e.classified = true;
        } else {
            e.category = registry::ApiCategory::Unknown;
            e.category_name = "Unknown";
            e.classified = false;
        }

        // Compatibility (library-level).
        if (const auto rec = compat_db.lookup(e.dll_name, "")) {
            e.compat_status = rec->status;
            e.compat_note = rec->windows_equivalent;
            e.compat_known = true;
        }
    }

    // ── 3. Unresolved imports count ──
    rep.unresolved_function_count = 0;
    rep.unresolved_dll_count = 0;
    for (const auto& e : rep.dependencies) {
        if (e.dll_name.rfind("<unresolved", 0) == 0 || e.dll_name.rfind("<empty", 0) == 0) {
            ++rep.unresolved_dll_count;
            continue;
        }
        for (const auto& f : e.functions) {
            if (f.unresolved) ++rep.unresolved_function_count;
        }
    }
    if (rep.unresolved_dll_count != 0) {
        diags.warning("unresolved DLL name in " + std::to_string(rep.unresolved_dll_count) +
                      " import descriptor(s)");
    }
    if (rep.unresolved_function_count != 0) {
        diags.warning("unresolved imported function names: " +
                      std::to_string(rep.unresolved_function_count));
    }

    // ── 4. Forwarded exports of the image ──
    for (const auto& f : img.exports.functions) {
        if (f.forwarder.empty()) continue;
        ForwardedExport fe;
        fe.export_name = f.name;
        fe.forwarder = f.forwarder;
        split_forwarder(f.forwarder, fe.target_dll, fe.target_api);
        rep.forwarded_exports.push_back(std::move(fe));
    }
    if (!rep.forwarded_exports.empty()) {
        diags.info(std::to_string(rep.forwarded_exports.size()) +
                   " forwarded export(s) — implicit dependencies on the forward targets");
    }

    return rep;
}

}  // namespace xbox2pc::deps
