// xbox2pc/src/api_compat.cpp — M7 API compatibility foundation impl.
//
// Sections:
//   1. names/statuses/conventions
//   2. built-in descriptor table (evidence-cited, signatures verbatim)
//   3. ApiRegistry: descriptor add/lookup + implementation registration +
//      revoke + dispatch (validation: convention, param count, impl present)
//   4. ApiResolver (IImportResolver over the registry)
//   5. resolve_delay_imports (directory 13 walk + mapped-IAT writes)
//   6. per-thread TLS initialization (template copy + zero fill)
//   7. compatibility report builder (human + JSON-ready model)

#include "xbox2pc/api_compat.hpp"

#include <algorithm>
#include <cstring>

namespace xbox2pc::rt::api {

// ── 1. names ──────────────────────────────────────────────────────────────

const char* convention_to_name(Convention c) {
    switch (c) {
        case Convention::None: return "none";
        case Convention::X64Microsoft: return "x64-microsoft";
        case Convention::Unknown: return "unknown";
    }
    return "?";
}

const char* return_kind_to_name(ReturnKind r) {
    switch (r) {
        case ReturnKind::Void: return "void";
        case ReturnKind::HResult: return "HRESULT";
        case ReturnKind::Bool: return "BOOL";
        case ReturnKind::Uint32: return "uint32";
        case ReturnKind::Uint64: return "uint64";
        case ReturnKind::Uint32Enum: return "uint32-enum";
        case ReturnKind::Pointer: return "pointer-out";
        case ReturnKind::Unknown: return "unknown";
    }
    return "?";
}

const char* api_status_to_name(ApiStatus s) {
    switch (s) {
        case ApiStatus::NativeEquivalent: return "native-equivalent";
        case ApiStatus::FullyImplemented: return "fully-implemented";
        case ApiStatus::PartiallyImplemented: return "partially-implemented";
        case ApiStatus::Stubbed: return "stubbed";
        case ApiStatus::Unsupported: return "unsupported";
        case ApiStatus::Unknown: return "unknown";
    }
    return "?";
}

std::optional<ApiStatus> api_status_from_name(const std::string& name) {
    if (name == "native-equivalent") return ApiStatus::NativeEquivalent;
    if (name == "fully-implemented") return ApiStatus::FullyImplemented;
    if (name == "partially-implemented") return ApiStatus::PartiallyImplemented;
    if (name == "stubbed") return ApiStatus::Stubbed;
    if (name == "unsupported") return ApiStatus::Unsupported;
    if (name == "unknown") return ApiStatus::Unknown;
    return std::nullopt;
}

std::vector<std::string> ApiDescriptor::validate() const {
    std::vector<std::string> problems;
    if (library.empty()) problems.push_back("empty library");
    if (export_name.empty()) problems.push_back("empty export name");
    if (evidence.empty()) problems.push_back("missing evidence tag");
    if (evidence_url.rfind("https://", 0) != 0)
        problems.push_back("missing verified https evidence URL");
    if (category == registry::ApiCategory::Unknown && compat == ApiStatus::Unknown)
        problems.push_back("no category and no compatibility evidence");
    if (convention == Convention::Unknown)
        problems.push_back("calling convention not established (dispatch refuses)");
    return problems;
}

// ── 2. built-in descriptor table ──────────────────────────────────────────

namespace {

const char* kInitUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xgameruntimeinit/functions/xgameruntimeinitialize";
const char* kUninitUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xgameruntimeinit/functions/xgameruntimeuninitialize";
const char* kInitOptUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xgameruntimeinit/functions/xgameruntimeinitializewithoptions";
const char* kDevTypeUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xsystem/functions/xsystemgetdevicetype";
const char* kConsoleIdUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xsystem/functions/xsystemgetconsoleid";
const char* kSandboxIdUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xsystem/functions/xsystemgetxboxlivesandboxid";
const char* kAppDevIdUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xsystem/functions/xsystemgetappspecificdeviceid";
const char* kRuntimeInfoUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xsystem/functions/xsystemgetruntimeinfo";
const char* kThreadTsUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xthread/functions/xthreadsettimesensitive";
const char* kThreadIsTsUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xthread/functions/xthreadistimesensitive";
const char* kTqCreateUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xtaskqueue/functions/xtaskqueuecreate";
const char* kTqDispatchUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xtaskqueue/functions/xtaskqueuedispatch";
const char* kTqCloseUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xtaskqueue/functions/xtaskqueueclosehandle";
const char* kTqTermUrl =
    "https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/"
    "xtaskqueue/functions/xtaskqueueterminate";
const char* kQpcUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/profileapi/"
    "nf-profileapi-queryperformancecounter";
const char* kQpfUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/profileapi/"
    "nf-profileapi-queryperformancefrequency";
const char* kCurrentProcessIdUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/"
    "nf-processthreadsapi-getcurrentprocessid";
const char* kCurrentThreadIdUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/"
    "nf-processthreadsapi-getcurrentthreadid";
const char* kVirtualQueryUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/"
    "nf-memoryapi-virtualquery";
const char* kVirtualAllocUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc";
const char* kVirtualFreeUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree";
const char* kVirtualProtectUrl =
    "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect";
const char* kCreateEventWUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw";
const char* kSetEventUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setevent";
const char* kResetEventUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-resetevent";
const char* kWaitForSingleObjectUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject";
const char* kCloseHandleUrl = "https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle";
const char* kCreateMutexWUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw";
const char* kReleaseMutexUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-releasemutex";
const char* kCreateSemaphoreWUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createsemaphorew";
const char* kReleaseSemaphoreUrl = "https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-releasesemaphore";

std::vector<ApiDescriptor> builtin_descriptors() {
    std::vector<ApiDescriptor> d;
    auto add = [&](ApiDescriptor x) { d.push_back(std::move(x)); };

    // — XGameRuntimeInit.h (lifecycle) —
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XGameRuntimeInitialize";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::HResult;
        a.signature = "HRESULT XGameRuntimeInitialize()";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::FullyImplemented;
        a.impl = ApiStatus::FullyImplemented;
        a.evidence = "[GDK-INIT]";
        a.evidence_url = kInitUrl;
        a.notes = "S_OK; E_GAMERUNTIME_DLL_NOT_FOUND / "
                  "E_GAMERUNTIME_VERSION_MISMATCH documented";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XGameRuntimeUninitialize";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::Void;
        a.signature = "void XGameRuntimeUninitialize()";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::FullyImplemented;
        a.impl = ApiStatus::FullyImplemented;
        a.evidence = "[GDK-INIT]";
        a.evidence_url = kUninitUrl;
        a.notes = "last activity before exit; ref-count semantics documented";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XGameRuntimeInitializeWithOptions";
        a.convention = Convention::X64Microsoft;
        a.param_count = 1;
        a.ret = ReturnKind::HResult;
        a.signature =
            "HRESULT XGameRuntimeInitializeWithOptions(_In_ const "
            "XGameRuntimeOptions* options)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::Stubbed;
        a.impl = ApiStatus::Stubbed;
        a.evidence = "[GDK-INIT]";
        a.evidence_url = kInitOptUrl;
        a.notes = "options-mismatch (E_GAMERUNTIME_OPTIONS_MISMATCH) and "
                  "ref-count semantics documented; stub validates nothing";
        add(a);
    }

    // — XSystem.h —
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XSystemGetDeviceType";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::Uint32Enum;
        a.signature = "XSystemDeviceType XSystemGetDeviceType()";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::Stubbed;
        a.impl = ApiStatus::Stubbed;
        a.evidence = "[GDK-SYS]";
        a.evidence_url = kDevTypeUrl;
        a.notes = "returns Unknown when undeterminable; can be called "
                  "before initialize; enum values documented at "
                  "learn.microsoft.com/.../xsystemdevicetype "
                  "(Pc=0x01..XboxScarlettDevkit=0x08)";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XSystemGetConsoleId";
        a.convention = Convention::X64Microsoft;
        a.param_count = 3;
        a.ret = ReturnKind::HResult;
        a.signature =
            "HRESULT XSystemGetConsoleId(size_t consoleIdSize, char* "
            "consoleId, size_t* consoleIdUsed)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::Stubbed;
        a.impl = ApiStatus::Stubbed;
        a.evidence = "[GDK-SYS]";
        a.evidence_url = kConsoleIdUrl;
        a.notes = "consoleIdSize >= XSystemConsoleIdBytes else "
                  "HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER); PC default "
                  "all-zero id documented; not time-sensitive-safe";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XSystemGetXboxLiveSandboxId";
        a.convention = Convention::X64Microsoft;
        a.param_count = 3;
        a.ret = ReturnKind::HResult;
        a.signature =
            "HRESULT XSystemGetXboxLiveSandboxId(size_t sandboxIdSize, "
            "char* sandboxId, size_t* sandboxIdUsed)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::Stubbed;
        a.impl = ApiStatus::Stubbed;
        a.evidence = "[GDK-SYS]";
        a.evidence_url = kSandboxIdUrl;
        a.notes = "sandbox IDs case sensitive; 'RETAIL' default; "
                  "XSystemXboxLiveSandboxIdMaxBytes bound; not "
                  "time-sensitive-safe";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XSystemGetAppSpecificDeviceId";
        a.convention = Convention::X64Microsoft;
        a.param_count = 3;
        a.ret = ReturnKind::HResult;
        a.signature =
            "HRESULT XSystemGetAppSpecificDeviceId(size_t "
            "appSpecificDeviceIdSize, char* appSpecificDeviceId, size_t* "
            "appSpecificDeviceIdUsed)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::Stubbed;
        a.impl = ApiStatus::Stubbed;
        a.evidence = "[GDK-SYS]";
        a.evidence_url = kAppDevIdUrl;
        a.notes = "ERROR_INSUFFICIENT_BUFFER when size < "
                  "XSystemAppSpecificDeviceIdBytes; all-zero fallback string "
                  "documented; not time-sensitive-safe";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XSystemGetRuntimeInfo";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::Pointer;  // struct return by value slot
        a.signature = "XSystemRuntimeInfo XSystemGetRuntimeInfo()";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::Stubbed;
        a.impl = ApiStatus::Stubbed;
        a.evidence = "[GDK-SYS]";
        a.evidence_url = kRuntimeInfoUrl;
        a.notes = "callable before XGameRuntimeInitialize; struct contents "
                  "documented separately (version fields)";
        add(a);
    }

    // — XThread.h —
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XThreadSetTimeSensitive";
        a.convention = Convention::X64Microsoft;
        a.param_count = 1;
        a.ret = ReturnKind::HResult;
        a.signature = "HRESULT XThreadSetTimeSensitive(bool "
                      "isTimeSensitiveThread)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[GDK-THREAD]";
        a.evidence_url = kThreadTsUrl;
        a.notes = "sets a TLS bit on the CALLING thread; runtime maps to "
                  "M4 thread state for runtime-created threads only";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XThreadIsTimeSensitive";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::Bool;
        a.signature = "bool XThreadIsTimeSensitive()";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[GDK-THREAD]";
        a.evidence_url = kThreadIsTsUrl;
        a.notes = "TLS-bit query; same M4-mapping limitation as the setter";
        add(a);
    }

    // — XTaskQueue.h —
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XTaskQueueCreate";
        a.convention = Convention::X64Microsoft;
        a.param_count = 3;
        a.ret = ReturnKind::HResult;
        a.signature =
            "HRESULT XTaskQueueCreate(XTaskQueueDispatchMode "
            "workDispatchMode, XTaskQueueDispatchMode "
            "completionDispatchMode, XTaskQueueHandle* queue)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[GDK-TQ]";
        a.evidence_url = kTqCreateUrl;
        a.notes = "reference-counted queues; Manual/ThreadPool dispatch "
                  "modes documented — runtime models Manual only (M4 "
                  "threads), other modes reported unsupported";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XTaskQueueDispatch";
        a.convention = Convention::X64Microsoft;
        a.param_count = 3;
        a.ret = ReturnKind::Bool;
        a.signature =
            "bool XTaskQueueDispatch(XTaskQueueHandle queue, "
            "XTaskQueuePort port, uint32_t timeoutInMs)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[GDK-TQ]";
        a.evidence_url = kTqDispatchUrl;
        a.notes = "false when nothing dispatched / terminated; manual "
                  "ports only (ThreadPool ports auto-dispatch — modeled "
                  "unsupported)";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XTaskQueueCloseHandle";
        a.convention = Convention::X64Microsoft;
        a.param_count = 1;
        a.ret = ReturnKind::Void;
        a.signature = "void XTaskQueueCloseHandle(XTaskQueueHandle queue)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[GDK-TQ]";
        a.evidence_url = kTqCloseUrl;
        a.notes = "ref-count decrement documented; terminate() required "
                  "for controlled shutdown";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "xgameruntime";
        a.export_name = "XTaskQueueTerminate";
        a.convention = Convention::X64Microsoft;
        a.param_count = 4;
        a.ret = ReturnKind::HResult;
        a.signature =
            "HRESULT XTaskQueueTerminate(XTaskQueueHandle queue, bool wait, "
            "void* callbackContext, XTaskQueueTerminatedCallback* callback)";
        a.category = registry::ApiCategory::XboxGdk;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[GDK-TQ]";
        a.evidence_url = kTqTermUrl;
        a.notes = "cancel callbacks + E_ABORT submissions documented; "
                  "wait=true on a dispatching thread deadlocks (doc)";
        add(a);
    }

    // — kernel32 (Win32 timing; evidence: MS-QPC pages) —
    {
        ApiDescriptor a;
        a.library = "kernel32";
        a.export_name = "QueryPerformanceCounter";
        a.convention = Convention::X64Microsoft;
        a.param_count = 1;
        a.ret = ReturnKind::Bool;
        a.signature = "BOOL QueryPerformanceCounter(LARGE_INTEGER* "
                      "lpPerformanceCount)";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::NativeEquivalent;
        a.impl = ApiStatus::FullyImplemented;
        a.evidence = "[MS-QPC]";
        a.evidence_url = kQpcUrl;
        a.notes = "host CLOCK_MONOTONIC via PAL is the native equivalent; "
                  "out-param modeled through the ApiContext out slot";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "kernel32";
        a.export_name = "QueryPerformanceFrequency";
        a.convention = Convention::X64Microsoft;
        a.param_count = 1;
        a.ret = ReturnKind::Bool;
        a.signature = "BOOL QueryPerformanceFrequency(LARGE_INTEGER* "
                      "lpFrequency)";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::NativeEquivalent;
        a.impl = ApiStatus::FullyImplemented;
        a.evidence = "[MS-QPC]";
        a.evidence_url = kQpfUrl;
        a.notes = "PAL monotonic frequency; fixed at boot documented";
        add(a);
    }

    // — kernel32 (process/thread identity) —
    {
        ApiDescriptor a;
        a.library = "kernel32";
        a.export_name = "GetCurrentProcessId";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::Uint32;
        a.signature = "DWORD GetCurrentProcessId()";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::FullyImplemented;
        a.impl = ApiStatus::FullyImplemented;
        a.evidence = "[MS-PROCESS-THREAD-ID]";
        a.evidence_url = kCurrentProcessIdUrl;
        a.notes = "returns the calling guest process ID; fails when no guest process context exists";
        add(a);
    }
    {
        ApiDescriptor a;
        a.library = "kernel32";
        a.export_name = "GetCurrentThreadId";
        a.convention = Convention::None;
        a.param_count = 0;
        a.ret = ReturnKind::Uint32;
        a.signature = "DWORD GetCurrentThreadId()";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::PartiallyImplemented;
        a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[MS-PROCESS-THREAD-ID]";
        a.evidence_url = kCurrentThreadIdUrl;
        a.notes = "returns the calling guest thread ID when execution context supplies one; zero/unavailable context is rejected";
        add(a);
    }

    {
        ApiDescriptor a;
        a.library = "kernel32"; a.export_name = "VirtualQuery";
        a.convention = Convention::X64Microsoft; a.param_count = 3;
        a.ret = ReturnKind::Uint64;
        a.signature = "SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::PartiallyImplemented; a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[MS-VIRTUAL-QUERY]"; a.evidence_url = kVirtualQueryUrl;
        a.notes = "x64 MEMORY_BASIC_INFORMATION for tracked M4 regions; reports free gaps within the modeled reservation, retained allocation protection, and tracked MEM_PRIVATE/MEM_IMAGE types; mapped/shared memory and addresses outside the modeled reservation are unsupported";
        add(a);
    }
    {
        ApiDescriptor a; a.library = "kernel32"; a.export_name = "VirtualAlloc";
        a.convention = Convention::X64Microsoft; a.param_count = 4; a.ret = ReturnKind::Pointer;
        a.signature = "LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::PartiallyImplemented; a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[MS-VIRTUAL-ALLOC]"; a.evidence_url = kVirtualAllocUrl;
        a.notes = "automatic and fixed-address MEM_RESERVE and MEM_RESERVE|MEM_COMMIT; exact-region MEM_COMMIT at an existing reservation address; partial-range commit is unsupported";
        add(a);
    }
    {
        ApiDescriptor a; a.library = "kernel32"; a.export_name = "VirtualFree";
        a.convention = Convention::X64Microsoft; a.param_count = 3; a.ret = ReturnKind::Bool;
        a.signature = "BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::PartiallyImplemented; a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[MS-VIRTUAL-FREE]"; a.evidence_url = kVirtualFreeUrl;
        a.notes = "supports MEM_RELEASE with dwSize zero and exact-region MEM_DECOMMIT; partial-range decommit is unsupported";
        add(a);
    }
    {
        ApiDescriptor a; a.library = "kernel32"; a.export_name = "VirtualProtect";
        a.convention = Convention::X64Microsoft; a.param_count = 4; a.ret = ReturnKind::Bool;
        a.signature = "BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)";
        a.category = registry::ApiCategory::WindowsWin32;
        a.compat = ApiStatus::PartiallyImplemented; a.impl = ApiStatus::PartiallyImplemented;
        a.evidence = "[MS-VIRTUAL-PROTECT]"; a.evidence_url = kVirtualProtectUrl;
        a.notes = "whole tracked regions only; returns previous protection; unsupported protection constants fail closed";
        add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="CreateMutexW";
        a.convention=Convention::X64Microsoft; a.param_count=3; a.ret=ReturnKind::Pointer;
        a.signature="HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR)";
        a.category=registry::ApiCategory::WindowsWin32; a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-MUTEX]"; a.evidence_url=kCreateMutexWUrl;
        a.notes="unnamed mutexes only; null security attributes/name; ownership is keyed by guest thread id; recursive acquisition and abandoned-owner result modeled"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="ReleaseMutex";
        a.convention=Convention::X64Microsoft; a.param_count=1; a.ret=ReturnKind::Bool;
        a.signature="BOOL ReleaseMutex(HANDLE)";
        a.category=registry::ApiCategory::WindowsWin32; a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-MUTEX]"; a.evidence_url=kReleaseMutexUrl;
        a.notes="only the owning guest thread may release the mutex"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="CreateSemaphoreW";
        a.convention=Convention::X64Microsoft; a.param_count=4; a.ret=ReturnKind::Pointer;
        a.signature="HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR)";
        a.category=registry::ApiCategory::WindowsWin32; a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-SEMAPHORE]"; a.evidence_url=kCreateSemaphoreWUrl;
        a.notes="unnamed semaphores only; null security attributes/name; count bounds validated"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="ReleaseSemaphore";
        a.convention=Convention::X64Microsoft; a.param_count=3; a.ret=ReturnKind::Bool;
        a.signature="BOOL ReleaseSemaphore(HANDLE, LONG, LPLONG)";
        a.category=registry::ApiCategory::WindowsWin32; a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-SEMAPHORE]"; a.evidence_url=kReleaseSemaphoreUrl;
        a.notes="positive release count; optional lpPreviousCount output is written when non-null"; add(a);
    }
    // Partial Win32 event synchronization: no names/security descriptors,
    // duplicate handles, or non-event waitable objects are modeled.
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="CreateEventW";
        a.convention=Convention::X64Microsoft; a.param_count=4; a.ret=ReturnKind::Pointer;
        a.signature="HANDLE CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR)";
        a.category=registry::ApiCategory::WindowsWin32; a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-EVENT]"; a.evidence_url=kCreateEventWUrl;
        a.notes="unnamed events only; security attributes and name must be null; process-scoped opaque runtime token"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="SetEvent";
        a.convention=Convention::X64Microsoft; a.param_count=1; a.ret=ReturnKind::Bool;
        a.signature="BOOL SetEvent(HANDLE)"; a.category=registry::ApiCategory::WindowsWin32;
        a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-EVENT]"; a.evidence_url=kSetEventUrl; a.notes="event handles created by this process only"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="ResetEvent";
        a.convention=Convention::X64Microsoft; a.param_count=1; a.ret=ReturnKind::Bool;
        a.signature="BOOL ResetEvent(HANDLE)"; a.category=registry::ApiCategory::WindowsWin32;
        a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-EVENT]"; a.evidence_url=kResetEventUrl; a.notes="event handles created by this process only"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="WaitForSingleObject";
        a.convention=Convention::X64Microsoft; a.param_count=2; a.ret=ReturnKind::Uint32;
        a.signature="DWORD WaitForSingleObject(HANDLE, DWORD)";
        a.category=registry::ApiCategory::WindowsWin32; a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-EVENT]"; a.evidence_url=kWaitForSingleObjectUrl;
        a.notes="process-scoped event, guest mutex, and guest semaphore handles; supports WAIT_OBJECT_0, WAIT_ABANDONED_0 for mutexes, WAIT_TIMEOUT, cancellation, and finite/infinite waits; blocks host execution thread in short polling intervals"; add(a);
    }
    {
        ApiDescriptor a; a.library="kernel32"; a.export_name="CloseHandle";
        a.convention=Convention::X64Microsoft; a.param_count=1; a.ret=ReturnKind::Bool;
        a.signature="BOOL CloseHandle(HANDLE)"; a.category=registry::ApiCategory::WindowsWin32;
        a.compat=ApiStatus::PartiallyImplemented; a.impl=ApiStatus::PartiallyImplemented;
        a.evidence="[MS-SYNC-EVENT]"; a.evidence_url=kCloseHandleUrl;
        a.notes="closes event, guest mutex, and guest semaphore handles created by this service only"; add(a);
    }

    return d;
}

std::string desc_key(const std::string& lib, const std::string& name) {
    return registry::normalize_module_name(lib) + '\x1F' +
           [](std::string s) {
               std::transform(s.begin(), s.end(), s.begin(),
                              [](unsigned char c) { return std::tolower(c); });
               return s;
           }(name);
}

}  // namespace

// ── 3. ApiRegistry ────────────────────────────────────────────────────────

ApiRegistry::ApiRegistry() {
    for (auto& d : builtin_descriptors()) {
        (void)add_descriptor(std::move(d));
    }
}

ApiRegistry::~ApiRegistry() = default;

Result<void> ApiRegistry::add_descriptor(ApiDescriptor desc) {
    const auto problems = desc.validate();
    if (!problems.empty()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "invalid descriptor: " + problems.front());
    }
    std::lock_guard lock(lock_);
    const std::string key = desc_key(desc.library, desc.export_name);
    auto it = descriptors_.find(key);
    if (it != descriptors_.end()) {
        // Same identity: replacing with a DIFFERENT evidence/signature is a
        // conflict (protects against accidental divergence).
        const bool same = it->second.signature == desc.signature &&
                          it->second.evidence == desc.evidence;
        if (!same) {
            return Result<void>(RuntimeErrc::AlreadyExists,
                                "conflicting descriptor for " + key);
        }
        return Result<void>::ok_result();  // idempotent re-add
    }
    descriptors_.emplace(key, std::move(desc));
    return Result<void>::ok_result();
}

const ApiDescriptor* ApiRegistry::find(const std::string& library,
                                      const std::string& export_name) const {
    std::lock_guard lock(lock_);
    const auto it = descriptors_.find(desc_key(library, export_name));
    return it == descriptors_.end() ? nullptr : &it->second;
}

const ApiDescriptor* ApiRegistry::find_ordinal(const std::string& library,
                                               std::uint32_t ordinal) const {
    std::lock_guard lock(lock_);
    const std::string key = registry::normalize_module_name(library) +
                             "\x1F#" + std::to_string(ordinal);
    const auto it = ordinal_index_.find(key);
    return it == ordinal_index_.end() ? nullptr : it->second;
}

std::vector<const ApiDescriptor*> ApiRegistry::all() const {
    std::lock_guard lock(lock_);
    std::vector<const ApiDescriptor*> out;
    out.reserve(descriptors_.size());
    for (const auto& kv : descriptors_) out.push_back(&kv.second);
    return out;
}

Result<void> ApiRegistry::register_implementation(
    const std::string& library, const std::string& export_name,
    std::shared_ptr<IApiImplementation> impl, std::uint64_t owner) {
    if (impl == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument, "null implementation");
    }
    std::lock_guard lock(lock_);
    const std::string key = desc_key(library, export_name);
    if (descriptors_.find(key) == descriptors_.end()) {
        return Result<void>(RuntimeErrc::NotFound,
                            "no verified descriptor for " + library + "!" +
                                export_name +
                                " (register the descriptor with evidence "
                                "first)");
    }
    const auto it = impls_.find(key);
    if (it != impls_.end()) {
        if (it->second.owner != owner) {
            return Result<void>(RuntimeErrc::AlreadyExists,
                                "implementation already registered by owner " +
                                    std::to_string(it->second.owner));
        }
        // Same owner re-registering: replace (service re-init path).
        it->second.fn = std::move(impl);
        return Result<void>::ok_result();
    }
    impls_[key] = Impl{std::move(impl), owner};
    return Result<void>::ok_result();
}

Result<std::size_t> ApiRegistry::revoke_owner(std::uint64_t owner) {
    std::lock_guard lock(lock_);
    std::size_t removed = 0;
    for (auto it = impls_.begin(); it != impls_.end();) {
        if (it->second.owner == owner) {
            it = impls_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return Result<std::size_t>(removed);
}

ApiCallResult ApiRegistry::dispatch(const std::string& library,
                                    const std::string& export_name,
                                    const ApiContext& ctx) {
    const ApiDescriptor* d = find(library, export_name);
    if (d == nullptr) {
        ApiCallResult r;
        r.error = "no verified descriptor for " + library + "!" + export_name;
        return r;
    }
    // Argument count validation (documented param_count).
    if (ctx.arg_count != d->param_count) {
        ApiCallResult r;
        r.error = "argument count " + std::to_string(ctx.arg_count) +
                  " != documented " + std::to_string(d->param_count) + " (" +
                  d->signature + ")";
        return r;
    }
    // Convention must be established (Unknown refuses dispatch).
    if (d->convention == Convention::Unknown) {
        ApiCallResult r;
        r.error = "calling convention not established for " + export_name;
        return r;
    }
    // Time-sensitive-thread gate (documented per-API note parsed by the
    // descriptor's notes field at authoring time — captured in the impl).
    std::shared_ptr<IApiImplementation> impl;
    {
        std::lock_guard lock(lock_);
        const auto it = impls_.find(desc_key(library, export_name));
        if (it == impls_.end()) {
            ApiCallResult r;
            r.error = "no implementation registered for " + library + "!" +
                      export_name;
            r.note = std::string("compatibility status: ") +
                     api_status_to_name(d->compat);
            return r;
        }
        impl = it->second.fn;   // shared_ptr copy under the lock: lifetime safe
    }
    // Invoke OUTSIDE the registry lock (implementations may call back).
    ApiCallResult out;
    out.ok = impl->invoke(ctx, out);
    if (!out.ok && out.error.empty()) out.error = "implementation rejected";
    return out;
}

ApiCallResult ApiRegistry::dispatch_ordinal(const std::string& library,
                                           std::uint32_t ordinal,
                                           const ApiContext& ctx) {
    const ApiDescriptor* d = find_ordinal(library, ordinal);
    if (d == nullptr) {
        ApiCallResult r;
        r.error = "no VERIFIED ordinal " + std::to_string(ordinal) + " for " +
                  library + " (ordinals are never invented)";
        return r;
    }
    return dispatch(library, d->export_name, ctx);
}

std::vector<ApiRegistry::RegistrationInfo> ApiRegistry::registrations() const {
    std::lock_guard lock(lock_);
    std::vector<RegistrationInfo> out;
    for (const auto& kv : impls_) {
        RegistrationInfo info;
        const std::size_t sep = kv.first.find('\x1F');
        info.library = kv.first.substr(0, sep);
        info.export_name = kv.first.substr(sep + 1);
        info.owner = kv.second.owner;
        info.test_only = kv.second.owner == 0;
        info.describe = kv.second.fn ? kv.second.fn->describe() : "";
        out.push_back(std::move(info));
    }
    return out;
}

bool ApiRegistry::has_implementation(const std::string& library,
                                    const std::string& export_name) const {
    std::lock_guard lock(lock_);
    return impls_.find(desc_key(library, export_name)) != impls_.end();
}

ApiRegistry& default_registry() {
    static ApiRegistry reg;
    return reg;
}

// ── 4. ApiResolver ────────────────────────────────────────────────────────

bool ApiResolver::resolve_module(const std::string& dll) {
    // Module-level gate: a module is "supported" when at least one
    // descriptor exists for it (partial support is honest support).
    std::lock_guard lock(reg_.lock_);
    const std::string norm = registry::normalize_module_name(dll);
    for (const auto& kv : reg_.descriptors_) {
        if (kv.first.rfind(norm + '\x1F', 0) == 0) return true;
    }
    return false;
}

loader::ImportBinding ApiResolver::resolve(const loader::ImportLookup& lookup) {
    loader::ImportBinding b;
    b.lookup = lookup;
    const ApiDescriptor* d =
        lookup.by_ordinal
            ? reg_.find_ordinal(lookup.dll, lookup.ordinal)
            : reg_.find(lookup.dll, lookup.symbol);
    if (d == nullptr) {
        // No verified descriptor: distinguish "known module, unknown API"
        // from "unknown module".
        const bool known_module = resolve_module(lookup.dll);
        b.status = known_module ? loader::ImportStatus::Unresolved
                                 : loader::ImportStatus::Unsupported;
        b.note = known_module
                     ? std::string("module known (partial support) but this "
                       "export has no verified descriptor")
                     : std::string("no verified descriptors for this module "
                       "(missing library from the compatibility runtime's "
                       "evidence base)");
        return b;
    }
    // Implementation present?
    {
        std::lock_guard lock(reg_.lock_);
        const auto it = reg_.impls_.find(desc_key(d->library, d->export_name));
        if (it == reg_.impls_.end()) {
            b.status = loader::ImportStatus::Unresolved;
            b.note = std::string("verified descriptor exists (") +
                     api_status_to_name(d->compat) +
                     ") but no implementation is registered: " + d->evidence;
            return b;
        }
    }
    // Bind: synthetic dispatch address = implementation ticket.
    b.status = loader::ImportStatus::Resolved;
    b.value = (d->category == registry::ApiCategory::XboxGdk ? 0x51000000ull : 0x51010000ull) +
              (next_id_++);
    b.note = "dispatch-table binding (id " + std::to_string(next_id_ - 1) +
             "); evidence " + d->evidence + " " + d->evidence_url;
    return b;
}

// ── 5. delay-load imports ─────────────────────────────────────────────────

namespace {

// RVA → file offset (loader discipline; duplicated locally because the
// loader's helper is file-internal).
std::uint64_t rva_to_off(const pe::PeImage& img, std::uint32_t rva, bool& ok) {
    ok = false;
    if (rva < img.opt.size_of_headers) {
        ok = true;
        return rva;
    }
    for (const auto& s : img.sections) {
        if (s.contains_rva(rva) && s.has_raw_data) {
            const std::uint64_t in = rva - s.virtual_address;
            if (in >= s.size_of_raw_data) return 0;
            ok = true;
            return s.raw_data_offset + in;
        }
    }
    return 0;
}

bool rd_u32(const std::uint8_t* f, std::size_t n, std::uint64_t off,
            std::uint32_t& out) {
    if (off + 4 > n) return false;
    out = static_cast<std::uint32_t>(f[off]) |
          (static_cast<std::uint32_t>(f[off + 1]) << 8) |
          (static_cast<std::uint32_t>(f[off + 2]) << 16) |
          (static_cast<std::uint32_t>(f[off + 3]) << 24);
    return true;
}
bool rd_u64(const std::uint8_t* f, std::size_t n, std::uint64_t off,
            std::uint64_t& out) {
    if (off + 8 > n) return false;
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i)
        v = (v << 8) | f[off + static_cast<unsigned>(i)];
    out = v;
    return true;
}
bool rd_cstr(const std::uint8_t* f, std::size_t n, std::uint64_t off,
             std::size_t max_len, std::string& out) {
    out.clear();
    if (off >= n) return false;
    for (std::uint64_t p = off; p < n; ++p) {
        const char c = static_cast<char>(f[p]);
        if (c == '\0') return !out.empty() && out.size() <= max_len;
        if (out.size() == max_len) return false;
        out.push_back(c);
    }
    return false;
}

}  // namespace

Result<DelayLoadReport> resolve_delay_imports(
    AddressSpace& space, const loader::ImageLayoutInfo& layout,
    const pe::PeImage& img, const std::uint8_t* file, std::size_t file_size,
    ApiRegistry& reg, bool fail_on_unresolved) {
    using Ret = Result<DelayLoadReport>;
    DelayLoadReport rep;
    if (img.directories.size() <= pe::kDirDelayImport) return Ret(rep);
    const auto& dir = img.directories[pe::kDirDelayImport];
    if (dir.size == 0) return Ret(rep);

    // The delay directory is an array of 32-byte ImgDelayDescr records.
    bool ok = false;
    std::uint64_t off = rva_to_off(img, dir.rva, ok);
    if (!ok) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "delay-import directory RVA not file-backed");
    }
    if ((dir.size % 32) != 0) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "delay-import directory size not a multiple of 32");
    }
    const std::size_t count = dir.size / 32;
    if (count > 64) {
        return Ret(RuntimeErrc::OutOfResources, "too many delay descriptors");
    }

    std::vector<std::pair<std::uint64_t, MemProtect>> flipped;
    auto restore = [&]() {
        for (auto it = flipped.rbegin(); it != flipped.rend(); ++it)
            (void)space.protect_region(it->first, it->second);
    };

    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t d = off + i * 32;
        if (d + 32 > file_size) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "delay descriptor truncated");
        }
        std::uint32_t attrs = 0, name_rva = 0, iat_rva = 0, int_rva = 0;
        if (!rd_u32(file, file_size, d + 0, attrs) ||
            !rd_u32(file, file_size, d + 4, name_rva) ||
            !rd_u32(file, file_size, d + 12, iat_rva) ||
            !rd_u32(file, file_size, d + 16, int_rva)) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "delay descriptor read failure");
        }
        if (attrs == 0 && name_rva == 0 && iat_rva == 0 && int_rva == 0) {
            continue;  // terminator (all-zero record)
        }
        ++rep.descriptors;
        // RVA vs VA addressing (attr bit 0 = VA; documented in delayimp):
        const std::uint64_t base = img.opt.image_base;
        auto to_rva = [&](std::uint32_t v) -> std::uint32_t {
            return (attrs & 0x1) ? static_cast<std::uint32_t>(v - base) : v;
        };
        const std::uint32_t name_r = to_rva(name_rva);
        const std::uint32_t iat_r = to_rva(iat_rva);
        const std::uint32_t int_r = to_rva(int_rva);
        if (name_r == 0 || iat_r == 0) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "delay descriptor missing name or IAT");
        }
        std::string dll;
        bool nok = false;
        const std::uint64_t noff = rva_to_off(img, name_r, nok);
        if (!nok || !rd_cstr(file, file_size, noff, 512, dll)) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "delay-import DLL name unreadable");
        }
        // Walk the INT (or the IAT itself when INT is 0 — bound form).
        const std::uint32_t thunk_rva = int_r != 0 ? int_r : iat_r;
        bool tok = false;
        std::uint64_t t = rva_to_off(img, thunk_rva, tok);
        if (!tok) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "delay thunk table not file-backed");
        }
        // IAT slot k's VA in the mapped image.
        std::uint64_t k = 0;
        for (; t + 8 <= file_size; t += 8) {
            std::uint64_t tv = 0;
            if (!rd_u64(file, file_size, t, tv) || tv == 0) break;
            ++rep.entries;
            loader::ImportLookup look;
            look.dll = dll;
            if ((tv & 0x8000000000000000ull) != 0) {
                look.by_ordinal = true;
                look.ordinal = static_cast<std::uint32_t>(tv & 0xFFFF);
            } else {
                bool xok = false;
                const std::uint64_t hn = rva_to_off(
                    img, static_cast<std::uint32_t>(tv), xok);
                if (!xok || !rd_cstr(file, file_size, hn + 2, 512, look.symbol)) {
                    return Ret(RuntimeErrc::InvalidArgument,
                               "delay-import name unreadable");
                }
            }
            // Resolve through the same registry.
            ApiResolver resolver(reg);
            const auto binding = resolver.resolve(look);
            // Write the resolved value into the mapped IAT slot
            // (bounds-checked; RW flip + restore).
            const std::uint64_t slot_va = layout.actual_base + iat_r + k * 8;
            const loader::SectionLayout* host = nullptr;
            for (const auto& sl : layout.sections) {
                if (slot_va >= sl.mapped_base &&
                    slot_va + 8 <= sl.mapped_base + sl.mapped_size) {
                    host = &sl;
                    break;
                }
            }
            if (host == nullptr) {
                restore();
                return Ret(RuntimeErrc::InvalidArgument,
                           "delay IAT slot outside the mapped image");
            }
            const bool writable = host->protection == MemProtect::ReadWrite ||
                                 host->protection == MemProtect::Full;
            if (!writable) {
                auto pr = space.protect_region(host->mapped_base,
                                                MemProtect::ReadWrite);
                if (!pr.ok()) {
                    restore();
                    return Ret(pr.errc(), pr.context());
                }
                flipped.emplace_back(host->mapped_base, host->protection);
            }
            if (binding.status == loader::ImportStatus::Resolved) {
                auto dst = space.translate(slot_va);
                if (!dst.ok()) {
                    restore();
                    return Ret(dst.errc(), dst.context());
                }
                std::memcpy(dst.value(), &binding.value, 8);
                ++rep.resolved;
            } else {
                ++rep.unresolved;
                DelayLoadReport::UnresolvedEntry u;
                u.dll = dll;
                u.name = look.by_ordinal
                             ? "#" + std::to_string(look.ordinal)
                             : look.symbol;
                u.note = binding.note;
                rep.failures.push_back(std::move(u));
            }
            ++k;
        }
    }
    restore();
    if (fail_on_unresolved && rep.unresolved != 0) {
        return Ret(RuntimeErrc::MissingDependency,
                   std::to_string(rep.unresolved) +
                       " delay-load imports unresolved (policy: fail)");
    }
    return Ret(rep);
}

// ── 6. per-thread TLS initialization ──────────────────────────────────────

// (Exposed through api_compat.hpp's consumer — declared in gdk_services.hpp)

}  // namespace xbox2pc::rt::api
