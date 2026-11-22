#pragma once
// xbox2pc/api_registry.hpp — modular, evidence-based API classification DB.
//
// Design rules for this component:
//   1. Classification is by (library, api-name) pair — never by a similar
//      function name alone. A DLL the binary imports plus the function it
//      imports from it is evidence; the name alone is not.
//   2. Every record carries an evidence source (URL / spec citation) and an
//      evidence kind (DocumentedDLL, DocumentedExport, DocumentedAPISet,
//      CommunityReverse). Records without evidence cannot exist.
//   3. Case-insensitive matching: Windows DLL names and API names are
//      case-insensitive on the platform, so lookups normalize to lower-case.
//      Comparison ignores the ".dll" extension exactly like the OS loader
//      treats module names (a bare "KERNEL32" matches "kernel32.dll").
//   4. The registry is data-driven: a separate module record table (kept in
//      api_registry.cpp) can be extended without touching the lookup logic.
//
// Evidence sources embedded in the shipped records (all URLs verified):
//   [GDK-SUBVAL]  Microsoft GDK Submission Validator messages
//                https://learn.microsoft.com/en-us/gaming/gdk/docs/features/common/packaging/subval/submissionvalidator-messages
//                (d3d12_x.dll = Xbox One graphics stack; d3d12_xs.dll =
//                 Scarlett graphics stack)
//   [GDK-CUSTOM]  GDK custom-engine integration docs
//                https://learn.microsoft.com/en-us/gaming/gdk/docs/gdk-dev/pc-dev/tutorials/get-started-with-custom-engine/gc-get-started-with-custom-engine-pc
//                (xgameruntime.dll GRTS; Microsoft.Xbox.Services.GDK.C.Thunks.dll,
//                 XCurl.dll, libHttpClient.GDK.dll = GDK extension libs)
//   [XVALKYRIE]   sammwyy/xvalkyrie project (import-table platform detection)
//                https://github.com/sammwyy/xvalkyrie
//                (kernelx.dll = Xbox One OS kernel module; d3d12_x.dll +
//                 kernelx.dll => Durango; d3d12_xs.dll => Series X|S)
//   [MS-ROAPI]    RoGetActivationFactory function reference
//                https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-rogetactivationfactory
//                (combase.dll hosts Windows Runtime activation)
//   [MS-APTSETS]  Windows API sets overview
//                https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
//                (api-/ext- module names are loader contracts)
//   [MS-SEARCH]   Dynamic-link library search order (known DLLs)
//                https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "xbox2pc/diagnostics.hpp"

namespace xbox2pc::registry {

// ── API categories (the classification vocabulary) ────────────────────────
//
// The category is a property of the *library*, with the API record deciding
// whether a specific function is an exception (e.g. a WinRT activation helper
// exported by combase.dll).
enum class ApiCategory {
    WindowsWin32,        // kernel32.dll and friends — classic Win32 surface
    WindowsRuntime,      // combase.dll, WinRT activation
    Direct3D,            // d3d11.dll / d3d12.dll — stock Windows Direct3D
    XboxGdk,             // xgameruntime.dll, GDK extension libraries
    XboxGameOs,          // kernelx.dll, Xbox OS system modules
    XboxGraphics,        // d3d12_x.dll / d3d12_xs.dll console graphics stacks
    Unknown,             // no evidence either way
};

const char* category_to_name(ApiCategory c);
std::optional<ApiCategory> category_from_name(const std::string& name);

// ── Evidence kinds ───────────────────────────────────────────────────────
enum class EvidenceKind {
    DocumentedDLL,       // the DLL's existence/role is documented by its owner
    DocumentedExport,   // the specific function is documented in that DLL
    DocumentedAPISet,   // api-*/ext-* contract name documented by the loader
    CommunityReverse,   // community tooling observed the mapping (cited)
};

const char* evidence_to_name(EvidenceKind k);

// One classification record: a (library, function) observation.
struct ApiRecord {
    std::string library;        // DLL name (any case, .dll optional)
    std::string api_name;       // function name ("" = library-level record)
    ApiCategory category = ApiCategory::Unknown;
    EvidenceKind evidence = EvidenceKind::DocumentedDLL;
    std::string source;         // short citation tag, e.g. "[GDK-SUBVAL]"
    std::string source_url;     // full URL, verified at authoring time
    std::string note;          // human note about what the evidence says
};

// ── The registry ──────────────────────────────────────────────────────────
//
// Built once from the static module tables; lookups are case-insensitive.
class ApiRegistry {
public:
    ApiRegistry();  // loads built-in module records

    // Library-level classification. Returns nullopt only when the library
    // is entirely unknown (no record at any level).
    std::optional<ApiRecord> classify_library(const std::string& dll_name) const;

    // Function-level classification: a record must exist for the exact
    // (library, function) pair — name similarity never plays a role.
    std::optional<ApiRecord> classify_api(const std::string& dll_name,
                                          const std::string& func_name) const;

    // True when the library has any record (including function records).
    bool known_library(const std::string& dll_name) const;

    // All library-level records (for `classify` CLI listing and tests).
    std::vector<ApiRecord> library_records() const;

    // Number of records loaded (library-level + function-level).
    std::size_t record_count() const { return records_.size() + library_records_.size(); }

    // Validation used at build time by tests: every record must have a
    // non-empty source, non-empty URL starting with http(s)://, and a
    // category other than Unknown. Returns violation descriptions.
    std::vector<std::string> validate() const;

private:
    // key = lowercased library name (extension stripped) + '\x1F' + lowercased
    // function name ('\x1F' cannot appear in either, so keys are unambiguous).
    std::unordered_map<std::string, ApiRecord> records_;
    std::unordered_map<std::string, ApiRecord> library_records_;
};

// Shared name normalization: lowercase; strip a trailing ".dll" if present.
std::string normalize_module_name(const std::string& name);

}  // namespace xbox2pc::registry
