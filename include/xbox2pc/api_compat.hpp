#pragma once
// xbox2pc/api_compat.hpp — M7 Xbox GDK & Game OS API compatibility
// foundation.
//
// Design (docs/api-compat.md):
//   1. ApiDescriptor: the VERIFIED identity of one Xbox-facing API —
//      library, export name, documented signature text, calling
//      convention, parameter count, return type class, category,
//      compatibility status, implementation status, and the EVIDENCE
//      citation. Descriptors are authored only from opened reference
//      pages (URLs recorded); nothing is inferred from name similarity.
//   2. ApiImplementation: one registered runtime function for a
//      descriptor. The dispatch ABI is an explicit C++ interface
//      (ApiContext + typed argument views) — NOT raw host function
//      pointers. Implementations are owned by services (M3 RtService
//      subclasses); the registry pins them through the object manager so
//      a destroyed service's registrations are revoked, never dangled.
//   3. ApiRegistry (rt namespace): thread-safe registration + lookup by
//      (library, name) and by verified ordinal. Conflicting registrations
//      are rejected (typed error), duplicates by a DIFFERENT owner are
//      rejected, re-registration by the same owner is idempotent-ish
//      (rejected with detail). Lookup is deterministic (std::map).
//   4. ApiDispatcher: validates arguments against the descriptor's
//      calling-convention metadata, then invokes the implementation
//      through the pinned reference. Structured errors: missing
//      implementation, unsupported API, argument validation, service
//      unavailable, signature mismatch.
//   5. ApiResolver: an IImportResolver (M6) that binds imported
//      (DLL, name/ordinal) pairs to REGISTERED implementations. The
//      binding VALUE is a runtime-assigned synthetic address encoding
//      the implementation id (dispatch table entry) — never a host
//      function pointer. Unregistered APIs resolve Unresolved with a
//      structured note; unsupported ones stay Unsupported.
//   6. Delay-load support: resolve_delay_imports walks directory 13's
//      descriptors, resolves through the same ApiRegistry, and writes
//      the bound entries into the mapped image's IAT slots (RW flip +
//      restore, bounds-checked inside the mapped image).
//   7. Calling conventions: metadata-only layer (Convention enum with
//      documented facts). Guest-code execution does not exist (M7
//      exclusion): a convention match authorizes METADATA agreement, never
//      host-ABI forwarding. The x64 Windows/Microsoft convention facts
//      are cited (Win32 ABI docs).
//
// Evidence tags used by the built-in descriptor table (all opened):
//   [GDK-INIT]    XGameRuntimeInitialize / Uninitialize / WithOptions
//   [GDK-SYS]     XSystem* (device type, console id, sandbox id,
//                 app-specific device id, runtime info)
//   [GDK-THREAD]  XThread* (time-sensitive set/query)
//   [GDK-TQ]      XTaskQueue* (create/dispatch/close/terminate)
//   [MS-QPC]      QueryPerformanceCounter / Frequency (Win32, kernel32)
//   [GDK-ERR]     GDK error codes doc (E_GAMERUNTIME_* semantics)

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/api_registry.hpp"
#include "xbox2pc/compat_db.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/runtime_error.hpp"
#include "xbox2pc/service_registry.hpp"

namespace xbox2pc::rt::exec { class GuestThreadEnvironment; }

namespace xbox2pc::rt::api {

// ── calling conventions (metadata layer) ──────────────────────────────────

enum class Convention : std::uint8_t {
    None,          // void()/pure query — no arguments
    X64Microsoft,  // x64 Windows/Microsoft calling convention (documented
                   // for x64: RCX/RDX/R8/R9 + stack, caller-cleanup)
    Unknown,       // not established for this API — dispatch refuses
};
const char* convention_to_name(Convention c);

// Return-type classes (dispatch validates the invocation kind).
enum class ReturnKind : std::uint8_t {
    Void,
    HResult,     // HRESULT: 0x00000000 S_OK / 0x8007.... errors
    Bool,        // Win32 BOOL (0 = failure)
    Uint32,      // DWORD / uint32_t scalar
    Uint64,      // SIZE_T / uint64_t scalar on x64
    Uint32Enum,  // enum class ... : uint32_t (e.g. XSystemDeviceType)
    Pointer,     // _Out_ pointer params; return is an out-param status
    Unknown,
};
const char* return_kind_to_name(ReturnKind r);

// ── statuses (spec vocabulary) ─────────────────────────────────────────────

enum class ApiStatus : std::uint8_t {
    NativeEquivalent,     // a host-native equivalent exists and is used
    FullyImplemented,    // runtime implementation covers documented behavior
    PartiallyImplemented,// subset of documented behavior (cited limits)
    Stubbed,              // deterministic stub returning documented defaults
    Unsupported,          // documented as impossible here (cited)
    Unknown,              // no evidence either way
};
const char* api_status_to_name(ApiStatus s);
std::optional<ApiStatus> api_status_from_name(const std::string& name);

// ── descriptor ─────────────────────────────────────────────────────────────

struct ApiDescriptor {
    std::string library;          // DLL as imported (case-insensitive match)
    std::string export_name;     // documented export name
    std::uint32_t ordinal = 0;    // 0 = name-only (NEVER invented)
    Convention convention = Convention::Unknown;
    std::uint16_t param_count = 0;   // documented parameter count
    ReturnKind ret = ReturnKind::Unknown;
    std::string signature;        // documented signature text (verbatim)
    registry::ApiCategory category = registry::ApiCategory::Unknown;
    ApiStatus compat = ApiStatus::Unknown;
    ApiStatus impl = ApiStatus::Unknown;   // implementation status
    std::string evidence;          // source tag
    std::string evidence_url;     // verified URL
    std::string notes;            // limitations, version notes

    // Validation used by register_descriptor + tests.
    std::vector<std::string> validate() const;
};

// ── dispatch types ─────────────────────────────────────────────────────────
//
// The invocation interface: arguments are passed as typed slots. Guest
// execution does not exist, so no host pointers are ever read from
// argument values — implementations interpret them as the documented
// parameter semantics (sizes, flags, buffer ids) through THIS layer only.

using GuestCallbackInvoker = std::function<Result<void>(std::uint64_t callback_va,
    std::uint64_t callback_context, bool canceled)>;

struct ApiContext {
    std::function<Result<void>(std::uint32_t)> set_last_error;
    std::function<Result<std::uint32_t>()> get_last_error;
    // The calling process (0 = runtime-global / no process).
    std::uint64_t process_id = 0;
    // Calling guest thread (0 = unavailable/runtime-global). Distinct from
    // process_id: thread-scoped APIs must never overload process identity.
    std::uint64_t thread_id = 0;
    // Argument slots (up to 8; documented x64 register parameters).
    static constexpr std::size_t kMaxArgs = 8;
    std::uint64_t args[kMaxArgs] = {0};
    std::size_t arg_count = 0;
    // Guest arrays decoded by the execution bridge; indexed by pointer argument slot.
    std::array<std::vector<std::uint64_t>, kMaxArgs> pointer_arrays;
    // Time-sensitive-thread check (XThreadIsTimeSensitive semantics):
    // APIs documented as unsafe on time-sensitive threads refuse when
    // the context thread is marked time-sensitive.
    bool thread_time_sensitive = false;
    // Present only while a guest execution backend is dispatching an API.
    // Lets manual task-queue dispatch re-enter the same bounded guest backend
    // without exposing a host function pointer to guest memory.
    GuestCallbackInvoker invoke_guest_callback;
    // True when the managed guest thread's cooperative execution has been canceled.
    std::function<bool()> cancellation_requested;
};

struct ApiCallResult {
    bool ok = false;               // the DISPATCH itself succeeded
    std::uint64_t return_value = 0;  // the documented return value
    std::string error;              // dispatch/implementation error text
    // The implementation's structured note (echoed in reports).
    std::string note;
    // Out-parameter slots (documented _Out_ parameters; M7's model):
    // one value + its byte size, echoed in dispatch-test output.
    std::uint64_t out_value = 0;
    std::uint64_t out_size = 0;
    bool has_out = false;
    // M9: the out payload BYTES (bounded; string outs carry
    // out_bytes_size bytes). The bridge writes out_bytes_size bytes to the
    // FIRST out pointer when present; the u64 out_value stays for
    // back-compat with M7/M8 reports.
    static constexpr std::size_t kMaxOutBytes = 256;
    std::array<std::uint8_t, kMaxOutBytes> out_bytes = {};
    std::size_t out_bytes_size = 0;
};

// One implementation: a controlled runtime function.
class IApiImplementation {
public:
    virtual ~IApiImplementation() = default;
    // Invoke under the descriptor's contract. Returning false = the
    // implementation rejected the call (its error goes to ApiCallResult).
    virtual bool invoke(const ApiContext& ctx, ApiCallResult& out) = 0;
    // Human-readable implementation description (reports).
    virtual std::string describe() const = 0;
};

// ── the runtime API registry ──────────────────────────────────────────────

class ApiRegistry {
public:
    ApiRegistry();   // loads the built-in evidence-based descriptor table
    ~ApiRegistry();

    // ── descriptors ──
    // Register/replace a descriptor (descriptor validation runs first;
    // a descriptor that fails validation is rejected). Returns false with
    // reasons on conflict with an EXISTING different descriptor.
    Result<void> add_descriptor(ApiDescriptor desc);

    // Lookups (case-insensitive library, exact export name).
    const ApiDescriptor* find(const std::string& library,
                              const std::string& export_name) const;
    const ApiDescriptor* find_ordinal(const std::string& library,
                                      std::uint32_t ordinal) const;
    // All descriptors sorted by (library, name) — deterministic.
    std::vector<const ApiDescriptor*> all() const;

    // ── implementations ──
    // Register an implementation owned by `owner` (an RtService-derived
    // object id; 0 = test-only registration — flagged in reports).
    // The implementation must match the descriptor's identity; a second
    // DIFFERENT implementation for the same API is a conflict.
    Result<void> register_implementation(const std::string& library,
                                         const std::string& export_name,
                                         std::shared_ptr<IApiImplementation> impl,
                                         std::uint64_t owner);

    // Revoke every registration an owner made (service shutdown path).
    Result<std::size_t> revoke_owner(std::uint64_t owner);

    // ── dispatch ──
    // Validate + invoke. The context's arg_count is checked against the
    // descriptor's param_count (mismatch = typed error); the convention
    // must be established; a missing implementation is a typed error.
    ApiCallResult dispatch(const std::string& library,
                           const std::string& export_name,
                           const ApiContext& ctx);

    // Dispatch by verified ordinal.
    ApiCallResult dispatch_ordinal(const std::string& library,
                                   std::uint32_t ordinal,
                                   const ApiContext& ctx);

    // ── introspection ──
    struct RegistrationInfo {
        std::string library;
        std::string export_name;
        std::uint64_t owner;
        bool test_only;         // owner == 0
        std::string describe;   // implementation's description
    };
    std::vector<RegistrationInfo> registrations() const;

    // True when an implementation is registered for (library, export).
    bool has_implementation(const std::string& library,
                            const std::string& export_name) const;
    std::size_t descriptor_count() const { return descriptors_.size(); }
    std::size_t implementation_count() const { return impls_.size(); }

private:
    friend class ApiResolver;   // module gate scans descriptors directly
    struct Impl {
        std::shared_ptr<IApiImplementation> fn;
        std::uint64_t owner = 0;
    };
    mutable std::mutex lock_;
    // key: normalized library '\x1F' export name
    std::map<std::string, ApiDescriptor> descriptors_;
    std::map<std::string, Impl> impls_;
    // ordinal key: normalized library '\x1F' #ordinal (only verified ones)
    std::map<std::string, const ApiDescriptor*> ordinal_index_;
    // Registry-wide monotonic ID prevents binding collisions across resolver instances.
    std::uint32_t next_binding_id_ = 1;
};

// Convenience: the process-wide default registry (tests/CLI construct
// their own; services use the one passed at initialization).
ApiRegistry& default_registry();

// ── the import resolver (M6 integration) ──────────────────────────────────

// Binds imports to REGISTERED implementations. The binding value is a
// synthetic guest dispatch address in the reserved GDK/Win32 ranges; it is
// never a host pointer. The loader preserves the exact ImportLookup and
// value in LoadDiagnostics, and ExecutionContext copies that identity into
// ExecutionRequest so the engine can resolve the descriptor safely.
class ApiResolver : public loader::IImportResolver {
public:
    explicit ApiResolver(ApiRegistry& reg) : reg_(reg) {}

    loader::ImportBinding resolve(const loader::ImportLookup& lookup) override;
    bool resolve_module(const std::string& dll) override;

    // Number of bindings issued (deterministic counter).
    std::uint64_t bindings_issued() const { return bindings_issued_.load(std::memory_order_relaxed); }

private:
    ApiRegistry& reg_;
    std::atomic<std::uint64_t> bindings_issued_{0};
};

// ── delay-load imports ────────────────────────────────────────────────────

// Resolve directory-13 delay-load imports of a MAPPED image through the
// registry and write the resolved entries into the mapped IAT slots.
// Failed entries are reported (never silently ignored); writes are
// bounds-checked inside the mapped image and the section is RW-flipped
// then restored (M6 discipline).
struct DelayLoadReport {
    std::size_t descriptors = 0;      // delay descriptors walked
    std::size_t entries = 0;          // thunks walked
    std::size_t resolved = 0;         // bound through the registry
    std::size_t unresolved = 0;       // no implementation (reported)
    struct UnresolvedEntry {
        std::string dll;
        std::string name;    // or ordinal text
        std::string note;
    };
    std::vector<UnresolvedEntry> failures;
};
Result<DelayLoadReport> resolve_delay_imports(
    AddressSpace& space, const loader::ImageLayoutInfo& layout,
    const pe::PeImage& img, const std::uint8_t* file, std::size_t file_size,
    ApiRegistry& reg, bool fail_on_unresolved);

}  // namespace xbox2pc::rt::api
