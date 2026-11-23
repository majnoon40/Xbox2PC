#pragma once
// xbox2pc/compat_report.hpp — M7 compatibility reporting model.
//
// build_compat_report joins: M1 parse (image), M2 DependencyReport
// (imports incl. delay-load + unresolved markers), the M7 ApiRegistry
// (verified descriptors + registered implementations), and the delay-load
// resolution report. Output: one row per imported function with a STABLE
// machine-readable code, evidence citation, and honest status. The
// verdict never claims game compatibility from import recognition.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::rt::api {

// Stable, machine-readable verdict codes (CLI/JSON/tests match on these).
enum class CompatCode : std::uint8_t {
    OkImplemented,     // verified + implemented
    OkStubbed,         // verified + deterministic stub (documented defaults)
    OkNative,          // verified + host-native equivalent
    Partial,           // verified + partial implementation (cited limits)
    StubMissing,       // verified descriptor, NO implementation registered
    UnsupportedApi,    // module known, export has no verified descriptor
    UnsupportedModule, // module not in the evidence base
    UnknownImport,     // no evidence either way
    UnresolvedDelay,   // delay-load entry unresolved
    InvalidImport,     // malformed import metadata
    MissingService,    // required runtime service missing
};
const char* compat_code_to_name(CompatCode c);

struct ImportCompat {
    std::string dll;
    std::string name;            // or ordinal text when by_ordinal
    std::uint32_t ordinal = 0;
    bool by_ordinal = false;
    bool delay_load = false;
    bool verified = false;       // a verified descriptor exists
    ApiStatus compat = ApiStatus::Unknown;
    std::string evidence;        // citation tag + URL
    std::string signature;      // documented signature (verbatim)
    CompatCode code = CompatCode::UnknownImport;
    std::string note;            // limitation detail
    ImportCompat() = default;
};

struct CompatReport {
    std::string source;
    std::vector<ImportCompat> rows;
    std::size_t delay_entries = 0;
    std::size_t delay_resolved = 0;
    // counts[kCode] aggregated over rows (built by build_compat_report).
    std::size_t counts[11] = {0};
    std::string verdict;         // human summary line (honest)
};

// Build the report. `delay` is optional (pass the DelayLoadReport from
// resolve_delay_imports to include delay-load verdicts).
CompatReport build_compat_report(const pe::PeImage& img,
                                 const deps::DependencyReport& dep,
                                 ApiRegistry& reg,
                                 const DelayLoadReport* delay);

}  // namespace xbox2pc::rt::api
