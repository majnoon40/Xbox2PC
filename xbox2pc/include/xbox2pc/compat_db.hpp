#pragma once
// xbox2pc/compat_db.hpp — API compatibility status database (M2).
//
// Tracks what is known about running Xbox-class binaries against a Windows
// PC host. Every entry must cite evidence; entries without evidence get the
// status Unknown — the database never claims compatibility it cannot back.
//
// Status vocabulary (exactly the five required):
//   Compatible            — documented to behave equivalently on Windows PC
//   Partially compatible  — works with documented caveats/limits
//   Unsupported           — documented to not exist on Windows PC
//   Unknown               — no evidence either way
//   NotApplicable         — not a compatibility question (e.g. the analysis
//                            tool itself, ordinal-only imports with no name)
//
// Evidence discipline:
//   - Stock Win32 DLLs (kernel32 etc.): every Windows install provides them
//     [MS-SEARCH documents the loader/known-DLL machinery]; status
//     Compatible for the library, Unknown per-function beyond curated rows.
//   - combase.dll (WinRT): present on Windows 8+ [MS-ROAPI]; Compatible.
//   - d3d11/d3d12/dxgi: stock Windows Direct3D [GDK-SUBVAL contrast];
//     Compatible on a PC host.
//   - d3d12_x.dll / d3d12_xs.dll: Xbox console graphics stacks [GDK-SUBVAL];
//     Unsupported on a PC — the whole point of the Xbox2PC layer is to
//     substitute these.
//   - kernelx.dll: Xbox One OS kernel [XVALKYRIE]; Unsupported on a PC.
//   - xgameruntime.dll / GDK extension libs: GRTS is installed by Gaming
//     Services on Windows PCs [GDK-CUSTOM]; Partially compatible — depends
//     on Gaming Services being present and the game being packaged.
//   - api-* contracts: resolved by the Windows loader [MS-APTSETS]; Compatible.
//
// Implementation status vocabulary: NotPlanned / Planned / InProgress /
// Stub / Implemented. Nothing is marked Implemented unless the M2 CLI exposes
// working functionality for it.

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "xbox2pc/api_registry.hpp"

namespace xbox2pc::compat {

enum class Status {
    Compatible,
    PartiallyCompatible,
    Unsupported,
    Unknown,
    NotApplicable,
};

const char* status_to_name(Status s);
std::optional<Status> status_from_name(const std::string& name);

enum class ImplementationStatus {
    NotPlanned,
    Planned,
    InProgress,
    Stub,
    Implemented,
};

const char* impl_to_name(ImplementationStatus s);

// One compatibility record. `platform` names the platform the API is native
// to (e.g. "Windows PC", "Xbox One", "Series X|S", "GDK (PC/console)").
struct CompatibilityRecord {
    std::string api_name;        // function name or "" for library-level
    std::string library;
    std::string platform;
    std::string signature;       // where documented; empty when unknown
    std::string windows_equivalent;  // where documented; empty otherwise
    Status status = Status::Unknown;
    std::string evidence;         // source tag + URL
    std::string evidence_url;
    ImplementationStatus impl = ImplementationStatus::NotPlanned;
};

// Database: library-level + function-level records; case-insensitive.
class CompatibilityDb {
public:
    CompatibilityDb();  // built-in evidence table

    // Lookup by (library, function). Function "" -> library-level record.
    std::optional<CompatibilityRecord> lookup(const std::string& library,
                                               const std::string& function) const;

    // Records for a library at any level (library-level first).
    std::vector<CompatibilityRecord> records_for(const std::string& library) const;

    // All records (CLI `classify --db` and tests).
    std::vector<CompatibilityRecord> all_records() const;

    // Validation for tests:
    //  - no record may claim Compatible/PartiallyCompatible/Unsupported
    //    without a non-empty evidence URL
    //  - api_name non-empty implies signature documented-or-empty is fine,
    //    but a Windows-equivalent string may only appear with evidence
    std::vector<std::string> validate() const;

    std::size_t size() const { return by_key_.size(); }

private:
    std::string key(const std::string& lib, const std::string& fn) const;
    void add(CompatibilityRecord rec);

    std::unordered_map<std::string, CompatibilityRecord> by_key_;
};

}  // namespace xbox2pc::compat
