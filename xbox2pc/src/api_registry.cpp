// xbox2pc/api_registry.cpp — evidence-based API classification records.
//
// IMPORTANT — why each record exists:
//   Every entry cites a source that was opened and read while authoring this
//   table. No record is derived from a "sounds like Xbox" name. When a real
//   import cannot be classified from evidence, it must stay Unknown — the
//   classifier explicitly reports that rather than guessing.
//
//   The table is split by category so adding a platform family means adding
//   a new section in kModuleRecords, not new lookup logic (modularity).

#include "xbox2pc/api_registry.hpp"

#include <cctype>
#include <utility>

namespace xbox2pc::registry {
namespace {

// ── per-category module record tables ────────────────────────────────────
//
// Fields: library, api_name, category, evidence, source tag, URL, note.
// The api_name "" marks the library-level classification record.

constexpr char kSubval[] =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/features/common/packaging/"
    "subval/submissionvalidator-messages";
constexpr char kGdkCustom[] =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/gdk-dev/pc-dev/tutorials/"
    "get-started-with-custom-engine/gc-get-started-with-custom-engine-pc";
constexpr char kValkyrie[] = "https://github.com/sammwyy/xvalkyrie";
constexpr char kRoapi[] =
    "https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-rogetactivationfactory";
constexpr char kApiSets[] =
    "https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets";
constexpr char kDllSearch[] =
    "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order";

struct RawRecord {
    const char* library;
    const char* api;
    ApiCategory cat;
    EvidenceKind ev;
    const char* tag;
    const char* url;
    const char* note;
};

// Windows Win32 — classic system DLLs. Evidence: these are the documented
// Windows system libraries; [MS-SEARCH] documents the DLL search/known-DLL
// machinery they participate in.
const RawRecord kWin32Modules[] = {
    {"kernel32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Windows kernel API host (process/thread/file/memory)"},
    {"user32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Windows user interface API host"},
    {"gdi32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Windows graphics device interface"},
    {"shell32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Windows shell API host"},
    {"advapi32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Windows advanced API (registry, security)"},
    {"ole32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "COM base"},
    {"oleaut32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "COM automation"},
    {"ws2_32", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Windows sockets 2"},
    {"msvcrt", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Visual C runtime (system copy)"},
    {"ucrtbase", "", ApiCategory::WindowsWin32, EvidenceKind::DocumentedDLL,
     "[MS-SEARCH]", kDllSearch, "Universal C runtime"},
    // Two function-level Win32 records used as fixture anchors in tests:
    {"kernel32", "CreateFileW", ApiCategory::WindowsWin32, EvidenceKind::DocumentedExport,
     "[MS-SEARCH]", kDllSearch, "Documented Win32 file API"},
    {"user32", "MessageBoxW", ApiCategory::WindowsWin32, EvidenceKind::DocumentedExport,
     "[MS-SEARCH]", kDllSearch, "Documented Win32 message box API"},
};

// Windows Runtime — combase.dll hosts RoGetActivationFactory [MS-ROAPI].
const RawRecord kWinRtModules[] = {
    {"combase", "", ApiCategory::WindowsRuntime, EvidenceKind::DocumentedDLL,
     "[MS-ROAPI]", kRoapi, "Windows Runtime activation host"},
    {"combase", "RoGetActivationFactory", ApiCategory::WindowsRuntime,
     EvidenceKind::DocumentedExport, "[MS-ROAPI]", kRoapi,
     "req.dll = Combase.dll on the function reference page"},
};

// Direct3D — stock Windows graphics. d3d11.dll/d3d12.dll are the documented
// Windows Direct3D DLLs; console stacks use their own _x/_xs names below,
// which is exactly the distinction the classifier must draw.
const RawRecord kD3dModules[] = {
    {"d3d11", "", ApiCategory::Direct3D, EvidenceKind::DocumentedDLL,
     "[GDK-SUBVAL]", kSubval, "Stock Windows Direct3D 11"},
    {"d3d12", "", ApiCategory::Direct3D, EvidenceKind::DocumentedDLL,
     "[GDK-SUBVAL]", kSubval, "Stock Windows Direct3D 12"},
    {"dxgi", "", ApiCategory::Direct3D, EvidenceKind::DocumentedDLL,
     "[GDK-SUBVAL]", kSubval, "DirectX graphics infrastructure"},
};

// Xbox GDK — Gaming Runtime Services and GDK extension libraries [GDK-CUSTOM].
const RawRecord kGdkModules[] = {
    {"xgameruntime", "", ApiCategory::XboxGdk, EvidenceKind::DocumentedDLL,
     "[GDK-CUSTOM]", kGdkCustom, "GRTS runtime DLL (XGameRuntimeInitialize etc.)"},
    {"microsoft.xbox.services.gdk.c.thunks", "", ApiCategory::XboxGdk,
     EvidenceKind::DocumentedDLL, "[GDK-CUSTOM]", kGdkCustom,
     "XSAPI thunk DLL shipped in the game package"},
    {"xcurl", "", ApiCategory::XboxGdk, EvidenceKind::DocumentedDLL,
     "[GDK-CUSTOM]", kGdkCustom, "GDK curl extension library"},
    {"libhttpclient.gdk", "", ApiCategory::XboxGdk, EvidenceKind::DocumentedDLL,
     "[GDK-CUSTOM]", kGdkCustom, "GDK libHttpClient extension library"},
};

// Xbox Game OS — kernelx.dll is the console OS kernel module [XVALKYRIE].
const RawRecord kGameOsModules[] = {
    {"kernelx", "", ApiCategory::XboxGameOs, EvidenceKind::CommunityReverse,
     "[XVALKYRIE]", kValkyrie, "Xbox One OS kernel module (community observation)"},
};

// Xbox-specific graphics — the console Direct3D stacks [GDK-SUBVAL].
const RawRecord kXboxGfxModules[] = {
    {"d3d12_x", "", ApiCategory::XboxGraphics, EvidenceKind::DocumentedDLL,
     "[GDK-SUBVAL]", kSubval, "Xbox One (Gen8) graphics stack"},
    {"d3d12_xs", "", ApiCategory::XboxGraphics, EvidenceKind::DocumentedDLL,
     "[GDK-SUBVAL]", kSubval, "Scarlett (Series X|S) graphics stack"},
};

// Windows API sets — api-*/ext-* module names are loader contracts, not
// files [MS-APTSETS]. They classify as Windows Win32 (the contracts route
// to Win32 host DLLs at load time).
bool is_api_set_module(const std::string& normalized) {
    return normalized.rfind("api-", 0) == 0 || normalized.rfind("ext-", 0) == 0;
}

const RawRecord* const kTables[] = {
    kWin32Modules, kWinRtModules, kD3dModules, kGdkModules, kGameOsModules, kXboxGfxModules,
};
constexpr std::size_t kTableSizes[] = {
    sizeof(kWin32Modules) / sizeof(kWin32Modules[0]),
    sizeof(kWinRtModules) / sizeof(kWinRtModules[0]),
    sizeof(kD3dModules) / sizeof(kD3dModules[0]),
    sizeof(kGdkModules) / sizeof(kGdkModules[0]),
    sizeof(kGameOsModules) / sizeof(kGameOsModules[0]),
    sizeof(kXboxGfxModules) / sizeof(kXboxGfxModules[0]),
};

}  // namespace

// ── name normalization ────────────────────────────────────────────────────

std::string normalize_module_name(const std::string& name) {
    std::string out;
    // Path components can appear in import names ("/api-ms-win-..." style);
    // keep only the basename for classification purposes.
    std::size_t start = name.find_last_of("/\\");
    start = start == std::string::npos ? 0 : start + 1;
    for (std::size_t i = start; i < name.size(); ++i) {
        const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(name[i])));
        out.push_back(c);
    }
    // Strip one trailing ".dll" (loader-equivalent module comparison).
    if (out.size() >= 4 && out.compare(out.size() - 4, 4, ".dll") == 0) {
        out.resize(out.size() - 4);
    }
    return out;
}

const char* category_to_name(ApiCategory c) {
    switch (c) {
        case ApiCategory::WindowsWin32: return "Windows Win32";
        case ApiCategory::WindowsRuntime: return "Windows Runtime";
        case ApiCategory::Direct3D: return "Direct3D";
        case ApiCategory::XboxGdk: return "Xbox GDK";
        case ApiCategory::XboxGameOs: return "Xbox Game OS";
        case ApiCategory::XboxGraphics: return "Xbox-specific graphics";
        case ApiCategory::Unknown: return "Unknown";
    }
    return "Unknown";
}

std::optional<ApiCategory> category_from_name(const std::string& name) {
    if (name == "Windows Win32") return ApiCategory::WindowsWin32;
    if (name == "Windows Runtime") return ApiCategory::WindowsRuntime;
    if (name == "Direct3D") return ApiCategory::Direct3D;
    if (name == "Xbox GDK") return ApiCategory::XboxGdk;
    if (name == "Xbox Game OS") return ApiCategory::XboxGameOs;
    if (name == "Xbox-specific graphics") return ApiCategory::XboxGraphics;
    if (name == "Unknown") return ApiCategory::Unknown;
    return std::nullopt;
}

const char* evidence_to_name(EvidenceKind k) {
    switch (k) {
        case EvidenceKind::DocumentedDLL: return "DocumentedDLL";
        case EvidenceKind::DocumentedExport: return "DocumentedExport";
        case EvidenceKind::DocumentedAPISet: return "DocumentedAPISet";
        case EvidenceKind::CommunityReverse: return "CommunityReverse";
    }
    return "?";
}

// ── registry construction ─────────────────────────────────────────────────

ApiRegistry::ApiRegistry() {
    for (std::size_t t = 0; t < sizeof(kTables) / sizeof(kTables[0]); ++t) {
        for (std::size_t i = 0; i < kTableSizes[t]; ++i) {
            const RawRecord& r = kTables[t][i];
            ApiRecord rec;
            rec.library = r.library;
            rec.api_name = r.api;
            rec.category = r.cat;
            rec.evidence = r.ev;
            rec.source = r.tag;
            rec.source_url = r.url;
            rec.note = r.note;
            if (r.api[0] == '\0') {
                library_records_.emplace(normalize_module_name(r.library), rec);
            } else {
                const std::string key = normalize_module_name(r.library) + '\x1F' +
                                        std::string(r.api);
                records_.emplace(key, std::move(rec));
            }
        }
    }
}

std::optional<ApiRecord> ApiRegistry::classify_library(const std::string& dll_name) const {
    const std::string lib = normalize_module_name(dll_name);
    // API-set contract names classify as Windows Win32 by documented loader
    // behaviour [MS-APTSETS].
    if (is_api_set_module(lib)) {
        ApiRecord rec;
        rec.library = dll_name;
        rec.category = ApiCategory::WindowsWin32;
        rec.evidence = EvidenceKind::DocumentedAPISet;
        rec.source = "[MS-APTSETS]";
        rec.source_url = kApiSets;
        rec.note = "api-/ext- contract names are loader contracts over Win32 hosts";
        return rec;
    }
    const auto it = library_records_.find(lib);
    if (it == library_records_.end()) return std::nullopt;
    return it->second;
}

std::optional<ApiRecord> ApiRegistry::classify_api(const std::string& dll_name,
                                                   const std::string& func_name) const {
    const std::string lib = normalize_module_name(dll_name);
    const std::string key = lib + '\x1F' + normalize_module_name(func_name);
    const auto it = records_.find(key);
    if (it != records_.end()) {
        ApiRecord out = it->second;
        out.library = dll_name;  // report the name as imported
        return out;
    }
    // No exact (library, function) record: fall back to the library-level
    // classification — still evidence-based (the DLL itself is documented),
    // never name-similarity.
    return classify_library(dll_name);
}

bool ApiRegistry::known_library(const std::string& dll_name) const {
    const std::string lib = normalize_module_name(dll_name);
    if (is_api_set_module(lib)) return true;
    if (library_records_.count(lib) != 0) return true;
    // Function-level records imply a known library too.
    for (const auto& kv : records_) {
        const std::size_t sep = kv.first.find('\x1F');
        if (kv.first.compare(0, sep, lib) == 0) return true;
    }
    return false;
}

std::vector<ApiRecord> ApiRegistry::library_records() const {
    std::vector<ApiRecord> out;
    out.reserve(library_records_.size());
    for (const auto& kv : library_records_) out.push_back(kv.second);
    return out;
}

std::vector<std::string> ApiRegistry::validate() const {
    std::vector<std::string> problems;
    auto check = [&](const ApiRecord& r) {
        if (r.source.empty()) problems.push_back("record without source: " + r.library);
        if (r.source_url.rfind("https://", 0) != 0) {
            problems.push_back("record without verified https URL: " + r.library);
        }
        if (r.category == ApiCategory::Unknown) {
            problems.push_back("record classified Unknown (must carry evidence): " + r.library);
        }
        if (r.library.empty()) problems.push_back("record with empty library name");
    };
    for (const auto& kv : library_records_) check(kv.second);
    for (const auto& kv : records_) check(kv.second);
    return problems;
}

}  // namespace xbox2pc::registry
