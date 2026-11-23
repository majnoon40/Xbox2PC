// xbox2pc/compat_db.cpp — compatibility database records.
//
// The evidence table below is derived from the SAME verified sources as the
// api_registry (see tags in api_registry.hpp). Where a real Windows
// equivalent exists and is documented, it is stated; otherwise the field
// stays empty and the status stays Unknown — never a guess.

#include "xbox2pc/compat_db.hpp"

#include <utility>

namespace xbox2pc::compat {
namespace {

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

struct Raw {
    const char* api;
    const char* lib;
    const char* platform;
    const char* sig;
    const char* win_equiv;
    Status status;
    const char* tag;
    const char* url;
    ImplementationStatus impl;
};

const Raw kRows[] = {
    // ── Windows Win32 (PC host) ──
    // kernel32 & friends are present on every Windows install: the DLL
    // search/known-DLL machinery [MS-SEARCH] guarantees the loader resolves
    // them; per-function coverage is curated, not blanket.
    {"", "kernel32.dll", "Windows PC", "",
     "same DLL on Windows PC (loader-resolved system library)",
     Status::Compatible, "[MS-SEARCH]",
     "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
     ImplementationStatus::NotPlanned},
    {"CreateFileW", "kernel32.dll", "Windows PC", "HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)",
     "identical export on Windows PC", Status::Compatible, "[MS-SEARCH]",
     "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew",
     ImplementationStatus::NotPlanned},
    {"", "user32.dll", "Windows PC", "",
     "same DLL on Windows PC (loader-resolved system library)",
     Status::Compatible, "[MS-SEARCH]",
     "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
     ImplementationStatus::NotPlanned},
    {"", "advapi32.dll", "Windows PC", "",
     "same DLL on Windows PC (loader-resolved system library)",
     Status::Compatible, "[MS-SEARCH]",
     "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
     ImplementationStatus::NotPlanned},
    {"", "ws2_32.dll", "Windows PC", "",
     "same DLL on Windows PC (loader-resolved system library)",
     Status::Compatible, "[MS-SEARCH]",
     "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
     ImplementationStatus::NotPlanned},
    // API-set contracts resolve through the loader schema [MS-APTSETS].
    {"", "api-ms-win-*.dll", "Windows PC", "",
     "loader resolves api-/ext- contracts to host DLLs",
     Status::Compatible, "[MS-APTSETS]", kApiSets, ImplementationStatus::NotPlanned},

    // ── Windows Runtime ──
    // combase.dll exists on Windows 8+; RoGetActivationFactory is documented
    // with req.dll Combase.dll [MS-ROAPI].
    {"", "combase.dll", "Windows PC", "",
     "same DLL on Windows PC", Status::Compatible, "[MS-ROAPI]", kRoapi,
     ImplementationStatus::NotPlanned},
    {"RoGetActivationFactory", "combase.dll", "Windows PC",
     "HRESULT RoGetActivationFactory(HSTRING activatableClassId, REFIID iid, void** factory)",
     "identical export on Windows PC", Status::Compatible, "[MS-ROAPI]", kRoapi,
     ImplementationStatus::NotPlanned},

    // ── Direct3D (stock Windows) ──
    // Stock Direct3D/DXGI are shipped with Windows and the GDK validator
    // message set treats them as the PC graphics path [GDK-SUBVAL].
    {"", "d3d11.dll", "Windows PC", "",
     "same DLL on Windows PC", Status::Compatible, "[GDK-SUBVAL]", kSubval,
     ImplementationStatus::NotPlanned},
    {"", "d3d12.dll", "Windows PC", "",
     "same DLL on Windows PC", Status::Compatible, "[GDK-SUBVAL]", kSubval,
     ImplementationStatus::NotPlanned},
    {"", "dxgi.dll", "Windows PC", "",
     "same DLL on Windows PC", Status::Compatible, "[GDK-SUBVAL]", kSubval,
     ImplementationStatus::NotPlanned},

    // ── Xbox graphics stacks ──
    // d3d12_x.dll is the Xbox One (Gen8) graphics stack, d3d12_xs.dll the
    // Scarlett stack [GDK-SUBVAL]. Neither exists on a PC; substituting them
    // is exactly what a compatibility layer must do.
    {"", "d3d12_x.dll", "Xbox One", "",
     "d3d12.dll on Windows PC (requires API surface translation — see note)",
     Status::Unsupported, "[GDK-SUBVAL]", kSubval, ImplementationStatus::Planned},
    {"", "d3d12_xs.dll", "Series X|S", "",
     "d3d12.dll on Windows PC (requires API surface translation — see note)",
     Status::Unsupported, "[GDK-SUBVAL]", kSubval, ImplementationStatus::Planned},

    // ── Xbox Game OS ──
    {"", "kernelx.dll", "Xbox One", "",
     "kernel32.dll + kernelbase.dll on Windows PC (OS-level: not a drop-in)",
     Status::Unsupported, "[XVALKYRIE]", kValkyrie, ImplementationStatus::Planned},

    // ── Xbox GDK ──
    // GRTS: xgameruntime.dll is installed by Gaming Services on Windows PCs
    // [GDK-CUSTOM]; function surface is PC-compatible but requires GRTS
    // present and the title packaged — hence Partially compatible.
    {"", "xgameruntime.dll", "GDK (PC/console)", "",
     "same DLL via Gaming Services on Windows PC",
     Status::PartiallyCompatible, "[GDK-CUSTOM]", kGdkCustom,
     ImplementationStatus::Planned},
    {"XGameRuntimeInitialize", "xgameruntime.dll", "GDK (PC/console)",
     "HRESULT XGameRuntimeInitialize()", "same export via Gaming Services",
     Status::PartiallyCompatible, "[GDK-CUSTOM]", kGdkCustom,
     ImplementationStatus::Planned},
    {"", "Microsoft.Xbox.Services.GDK.C.Thunks.dll", "GDK (PC/console)", "",
     "shipped in the game package on both platforms [GDK-CUSTOM]",
     Status::PartiallyCompatible, "[GDK-CUSTOM]", kGdkCustom,
     ImplementationStatus::Planned},
    {"", "XCurl.dll", "GDK (PC/console)", "",
     "GDK redist DLL, package-local", Status::PartiallyCompatible, "[GDK-CUSTOM]",
     kGdkCustom, ImplementationStatus::Planned},
    {"", "libHttpClient.GDK.dll", "GDK (PC/console)", "",
     "GDK redist DLL, package-local", Status::PartiallyCompatible, "[GDK-CUSTOM]",
     kGdkCustom, ImplementationStatus::Planned},
};

}  // namespace

const char* status_to_name(Status s) {
    switch (s) {
        case Status::Compatible: return "Compatible";
        case Status::PartiallyCompatible: return "Partially compatible";
        case Status::Unsupported: return "Unsupported";
        case Status::Unknown: return "Unknown";
        case Status::NotApplicable: return "Not applicable";
    }
    return "?";
}

std::optional<Status> status_from_name(const std::string& name) {
    if (name == "Compatible") return Status::Compatible;
    if (name == "Partially compatible") return Status::PartiallyCompatible;
    if (name == "Unsupported") return Status::Unsupported;
    if (name == "Unknown") return Status::Unknown;
    if (name == "Not applicable") return Status::NotApplicable;
    return std::nullopt;
}

const char* impl_to_name(ImplementationStatus s) {
    switch (s) {
        case ImplementationStatus::NotPlanned: return "NotPlanned";
        case ImplementationStatus::Planned: return "Planned";
        case ImplementationStatus::InProgress: return "InProgress";
        case ImplementationStatus::Stub: return "Stub";
        case ImplementationStatus::Implemented: return "Implemented";
    }
    return "?";
}

std::string CompatibilityDb::key(const std::string& lib, const std::string& fn) const {
    return registry::normalize_module_name(lib) + '\x1F' +
           registry::normalize_module_name(fn);
}

void CompatibilityDb::add(CompatibilityRecord rec) {
    by_key_[key(rec.library, rec.api_name)] = std::move(rec);
}

CompatibilityDb::CompatibilityDb() {
    for (const Raw& r : kRows) {
        CompatibilityRecord rec;
        rec.api_name = r.api;
        rec.library = r.lib;
        rec.platform = r.platform;
        rec.signature = r.sig;
        rec.windows_equivalent = r.win_equiv;
        rec.status = r.status;
        rec.evidence = r.tag;
        rec.evidence_url = r.url;
        rec.impl = r.impl;
        add(std::move(rec));
    }
}

std::optional<CompatibilityRecord> CompatibilityDb::lookup(const std::string& library,
                                                           const std::string& function) const {
    const auto it = by_key_.find(key(library, function));
    if (it != by_key_.end()) return it->second;
    return std::nullopt;
}

std::vector<CompatibilityRecord> CompatibilityDb::records_for(const std::string& library) const {
    const std::string lib_key = registry::normalize_module_name(library);
    std::vector<CompatibilityRecord> out;
    // Library-level record first.
    if (const auto it = by_key_.find(lib_key + '\x1F'); it != by_key_.end()) {
        out.push_back(it->second);
    }
    for (const auto& kv : by_key_) {
        const std::size_t sep = kv.first.find('\x1F');
        const std::string lib_part = kv.first.substr(0, sep);
        const std::string fn_part = kv.first.substr(sep + 1);
        if (lib_part == lib_key && !fn_part.empty()) out.push_back(kv.second);
    }
    return out;
}

std::vector<CompatibilityRecord> CompatibilityDb::all_records() const {
    std::vector<CompatibilityRecord> out;
    out.reserve(by_key_.size());
    for (const auto& kv : by_key_) out.push_back(kv.second);
    return out;
}

std::vector<std::string> CompatibilityDb::validate() const {
    std::vector<std::string> problems;
    for (const auto& kv : by_key_) {
        const CompatibilityRecord& r = kv.second;
        const std::string where = r.library + (r.api_name.empty() ? "" : ":" + r.api_name);
        if (r.status != Status::Unknown && r.status != Status::NotApplicable) {
            if (r.evidence_url.empty()) {
                problems.push_back("status claim without evidence URL: " + where);
            } else if (r.evidence_url.rfind("https://", 0) != 0) {
                problems.push_back("evidence URL not https: " + where);
            }
        }
        if (r.library.empty()) problems.push_back("record with empty library: " + where);
        if (!r.windows_equivalent.empty() && r.evidence_url.empty()) {
            problems.push_back("Windows equivalent stated without evidence: " + where);
        }
    }
    return problems;
}

}  // namespace xbox2pc::compat
