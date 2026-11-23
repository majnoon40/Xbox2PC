#pragma once
// xbox2pc/dep_analyzer.hpp — dependency intelligence engine (M2).
//
// Consumes a parsed PeImage and produces the analyzed view the CLI and the
// dependency graph consume:
//   - enumerated DLL imports (regular + delay-load) with per-function records
//   - duplicate dependency detection (same DLL imported more than once,
//     including cross-regular/delay)
//   - unresolved imports (unmappable name/thunk RVAs recorded by the parser)
//   - forwarded export detection (the image's own exports that forward)
//   - per-DLL classification via the evidence-based ApiRegistry
//   - per-DLL compatibility via CompatibilityDb
//
// Design notes:
//   1. Pure data transformation: no re-reading of the file, no execution.
//   2. Duplicate detection is case-insensitive (module names are, too).
//   3. Everything the analyzer computes is exposed in one `DependencyReport`
//      so tests and the CLI see identical data.

#include <cstdint>
#include <string>
#include <vector>

#include "xbox2pc/api_registry.hpp"
#include "xbox2pc/compat_db.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::deps {

// One imported function record (name or ordinal, from either table).
struct FunctionImport {
    std::string name;        // empty for ordinal-only
    std::uint32_t ordinal = 0;   // 0 when by-name without hint info
    bool by_ordinal = false;
    bool delay_load = false;     // came from the delay-import table
    bool unresolved = false;     // parser could not resolve its name RVA
};

// One dependency edge to one DLL (deduplicated view entry).
struct DependencyEdge {
    std::string dll_name;         // name as imported (byte-exact)
    registry::ApiCategory category = registry::ApiCategory::Unknown;
    std::string category_name;    // precomputed for printing/JSON
    bool classified = false;      // registry had any record

    std::vector<FunctionImport> functions;
    std::size_t function_count = 0;

    bool regular_import = false;  // appears in the standard import table
    bool delay_import = false;     // appears in the delay-load table
    std::uint32_t timestamp = 0;
    std::uint32_t iat_rva = 0;
    std::uint32_t int_rva = 0;

    bool duplicate = false;       // DLL appears more than once in the tables
    std::vector<std::string> import_sources;  // "regular"/"delay" per occurrence

    // Compatibility lookup result (library-level).
    compat::Status compat_status = compat::Status::Unknown;
    std::string compat_note;      // windows_equivalent / evidence summary
    bool compat_known = false;
};

// The image's own forwarded exports (dependency-relevant: a forwarder is an
// implicit runtime dependency on the target DLL).
struct ForwardedExport {
    std::string export_name;
    std::string forwarder;       // "DLL.Function" string
    std::string target_dll;      // parsed forwarder DLL part
    std::string target_api;      // parsed forwarder function part
};

// ── Report ───────────────────────────────────────────────────────────────

struct DependencyReport {
    std::string source;
    std::vector<DependencyEdge> dependencies;     // one per distinct DLL
    std::vector<ForwardedExport> forwarded_exports;
    std::size_t duplicate_count = 0;
    std::size_t unresolved_function_count = 0;
    std::size_t unresolved_dll_count = 0;         // DLL names unmappable
    bool has_delay_imports = false;

    // Summary counts.
    std::size_t total_function_imports() const;
    std::size_t distinct_dll_count() const { return dependencies.size(); }
};

// Run the full analysis. `diags` collects analyzer-level warnings (duplicate
// dependencies, unresolved names, forwarded-export targets).
DependencyReport analyze(const pe::PeImage& img, diag::Diagnostics& diags);

// Split a forwarder string "DLL.Function" (also "DLL.#ordinal").
void split_forwarder(const std::string& forwarder, std::string& dll, std::string& api);

}  // namespace xbox2pc::deps
