#pragma once
// xbox2pc/graphics_provider.hpp — M11 Phase 8 graphics provider seam.
//
// Design (docs/graphics-roadmap.md):
//   1. Graphics imports resolve through ApiRegistry to an
//      IGraphicsProvider owned by the runtime. The provider is selected
//      explicitly; the initial (and currently only) implementation is the
//      deterministic NullGraphicsProvider.
//   2. The interface models only operations whose public ABI and
//      semantics are supported by evidence (documented on MS Learn).
//      Every provider call produces a trace record with API identity,
//      guest process identity, input summary, result, and
//      implemented/stubbed status.
//   3. Opaque device/queue/fence/command-list objects are runtime-owned
//      RuntimeObjects with process-scoped handles from the M4 table.
//      Host pointers are never exposed to guest code; wrong-type, stale,
//      and cross-process handles fail with typed errors.
//   4. The null provider RECORDS command-list calls without executing
//      them, records submission ordering, and fails closed on any
//      semantics it cannot model exactly. Compatibility reporting must
//      label null-provider behavior as Stubbed, never Supported.
//
// This is a provider seam for import dispatch and object-lifetime
// testing, not a renderer, and not a claim of graphics compatibility.

#include <cstdint>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/runtime_error.hpp"
#include "xbox2pc/runtime_object.hpp"

namespace xbox2pc::rt::gfx {

// One provider-call trace record. The trace is the test boundary: it
// proves dispatch reached the provider with the right identity and that
// nothing was silently swallowed.
struct GraphicsTraceRecord {
    std::string api;               // e.g. "D3D12CreateDevice"
    std::uint64_t process_id = 0;
    std::string input_summary;     // short, bounded guest-argument summary
    std::uint64_t result_value = 0;
    bool implemented = false;      // false = stubbed/recorded-only
    bool ok = false;               // dispatch-level success
};

// Status of one provider operation.
enum class GraphicsProviderStatus {
    Ok,               // documented semantics were modeled
    Stubbed,          // recorded only; no execution
    Unsupported,      // semantics not established -> explicit failure
    InvalidHandle,    // wrong type / stale / cross-process handle
    Error,            // provider-side failure
};

const char* provider_status_name(GraphicsProviderStatus s);

// The provider seam. Every method is synchronous and must not call back
// into guest code. Implementations must be safe for concurrent calls
// from multiple guest threads (internal locking is per-provider).
class IGraphicsProvider {
public:
    virtual ~IGraphicsProvider() = default;

    virtual const char* name() const = 0;

    // D3D12CreateDevice(IUnknown* adapter, D3D_FEATURE_LEVEL minFeature,
    //                    REFIID riid, void** ppDevice) -> HRESULT.
    // The null provider creates a runtime-owned device object, issues a
    // process-table handle, and writes the handle VALUE to the guest
    // output slot. Returns S_OK-shaped 0 on success.
    virtual Result<std::uint64_t> create_device(
        std::uint64_t process_id, std::uint64_t adapter,
        std::uint32_t feature_level, std::uint64_t riid,
        std::uint64_t out_device_slot) = 0;

    // Validate a guest-visible device handle: right type, right process,
    // current generation. Returns the pinned object id on success.
    virtual Result<void> validate_device(std::uint64_t process_id,
                                         std::uint64_t handle) = 0;

    // Command-list recording (null provider): records the call against
    // the device, executes nothing. Unknown commands are Unsupported.
    virtual Result<void> record_command(std::uint64_t process_id,
                                        std::uint64_t device_handle,
                                        const std::string& command) = 0;

    // Queue submission: records the ordering (device, sequence) without
    // executing. Fence semantics beyond ordering are not modeled.
    virtual Result<std::uint64_t> submit(std::uint64_t process_id,
                                         std::uint64_t device_handle) = 0;

    // Read-only trace access for tests and compatibility reporting.
    virtual std::vector<GraphicsTraceRecord> trace_snapshot() const = 0;
    virtual void clear_trace() = 0;

    // Test seam: drop every provider-owned object (process teardown path
    // normally retires them via the service's exit observer).
    virtual Result<void> release_process_objects(std::uint64_t process_id) = 0;
};

}  // namespace xbox2pc::rt::gfx
