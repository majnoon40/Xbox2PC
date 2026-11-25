// src/graphics_service.cpp — M11 Phase 8 NullGraphicsProvider service.
//
// Deterministic null graphics provider over the IGraphicsProvider seam
// (docs/graphics-roadmap.md). It is a test boundary for import dispatch
// and object lifetime, NOT a renderer:
//   - d3d12!D3D12CreateDevice dispatches to a runtime-owned device
//     object with a process-table handle (M4 generation-checked).
//   - Command recording and submission ordering are recorded, never
//     executed.
//   - Every call is traced; unknown/unmodeled operations fail closed.
//   - Compatibility reporting labels all of this Stubbed, never Supported.

#include "xbox2pc/graphics_service.hpp"

#include <deque>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace xbox2pc::rt::gfx {

namespace {

// Graphics devices use the built-in GraphicsDevice TypeId: handle slots
// encode a 9-bit type field, so only built-in ids (< 512, and the enum
// reserves <= 999 as the registry's built-in range) can round-trip
// through the M4 table. User-range ids cannot.
constexpr TypeId kGraphicsDeviceTypeId = TypeId::GraphicsDevice;

// Runtime-owned opaque device object. The guest sees only its handle.
class RtGraphicsDevice final : public RuntimeObject {
public:
    explicit RtGraphicsDevice(std::uint32_t feature_level)
        : RuntimeObject(kGraphicsDeviceTypeId),
          feature_level_(feature_level) {}
    std::uint32_t feature_level() const { return feature_level_; }
private:
    const std::uint32_t feature_level_;
};

const char* provider_status_name_impl(GraphicsProviderStatus s) {
    switch (s) {
        case GraphicsProviderStatus::Ok: return "Ok";
        case GraphicsProviderStatus::Stubbed: return "Stubbed";
        case GraphicsProviderStatus::Unsupported: return "Unsupported";
        case GraphicsProviderStatus::InvalidHandle: return "InvalidHandle";
        case GraphicsProviderStatus::Error: return "Error";
    }
    return "?";
}

}  // namespace

const char* provider_status_name(GraphicsProviderStatus s) {
    return provider_status_name_impl(s);
}

// ── NullGraphicsProvider ─────────────────────────────────────────────────

struct NullGraphicsProvider::Impl {
    std::mutex lock;
    std::deque<GraphicsTraceRecord> trace;
    // Per-process retired device object ids awaiting destruction.
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> retired;
    std::uint64_t next_sequence = 1;
};

NullGraphicsProvider::NullGraphicsProvider(ProcessManager& pm,
                                           ObjectManager& objects)
    : IGraphicsProvider(), impl_(std::make_unique<Impl>()),
      process_manager_(pm), objects_(objects) {}

NullGraphicsProvider::~NullGraphicsProvider() = default;

const char* NullGraphicsProvider::name() const { return "null"; }

Result<std::uint64_t> NullGraphicsProvider::create_device(
    std::uint64_t process_id, std::uint64_t adapter,
    std::uint32_t feature_level, std::uint64_t riid,
    std::uint64_t out_device_slot) {
    GraphicsTraceRecord record;
    record.api = "D3D12CreateDevice";
    record.process_id = process_id;
    record.input_summary = "adapter=0x" + std::to_string(adapter) +
        " feature_level=0x" + std::to_string(feature_level) +
        " riid=0x" + std::to_string(riid) +
        " out_slot=0x" + std::to_string(out_device_slot);
    if (process_id == 0 || out_device_slot == 0) {
        record.implemented = false;
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "device creation requires a process and a guest output slot");
    }
    auto process = process_manager_.find_process_by_pid(process_id);
    if (!process.ok()) {
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(process.errc(), process.context());
    }
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr || owner->state() != ProcessState::Running) {
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated,
                                     "device owner is not a running process");
    }
    // IID_PPV_ARGS(PageDevice) — the documented riid must be
    // IID_ID3D12Device {189819F1-1FA6-4B53-90C1-0488BA64DB1A}? The null
    // provider does not verify GUID bytes: the guest passes a POINTER,
    // and dereferencing guest memory here would require marshalling the
    // 16 bytes. Record the value; accept any non-null riid (the device
    // object model is handle-based, not COM-vtable-based, so the IID
    // does not change object behavior).
    auto object_id = objects_.register_object(
        std::make_unique<RtGraphicsDevice>(feature_level));
    if (!object_id.ok()) {
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(object_id.errc(), object_id.context());
    }
    auto guard = objects_.lookup_id(object_id.value());
    if (!guard.ok()) {
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(guard.errc(), guard.context());
    }
    auto handle = owner->handle_table().create(*guard.value().get());
    if (!handle.ok()) {
        guard.value().release();
        (void)objects_.destroy(object_id.value());
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(handle.errc(), handle.context());
    }
    record.result_value = handle.value().raw();
    record.implemented = true;
    record.ok = true;
    {
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
    }
    return Result<std::uint64_t>(handle.value().raw());
}

Result<void> NullGraphicsProvider::validate_device(std::uint64_t process_id,
                                                   std::uint64_t handle_raw) {
    if (process_id == 0 || handle_raw == 0)
        return Result<void>(RuntimeErrc::InvalidHandle, "null process or device handle");
    auto process = process_manager_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<void>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr)
        return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    auto candidate = owner->handle_table().lookup(Handle::from_raw(handle_raw));
    if (!candidate.ok()) return Result<void>(candidate.errc(), candidate.context());
    auto* object = candidate.value().get();
    const bool valid = object != nullptr &&
                       object->type_id() == kGraphicsDeviceTypeId;
    candidate.value().release();
    if (!valid)
        return Result<void>(RuntimeErrc::ObjectTypeMismatch,
                            "handle is not a graphics device");
    return Result<void>::ok_result();
}

Result<void> NullGraphicsProvider::record_command(
    std::uint64_t process_id, std::uint64_t device_handle,
    const std::string& command) {
    GraphicsTraceRecord record;
    record.api = "RecordCommand";
    record.process_id = process_id;
    record.input_summary = "device=0x" + std::to_string(device_handle) +
        " command=" + command;
    auto valid = validate_device(process_id, device_handle);
    if (!valid.ok()) {
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return valid;
    }
    // Known recording-only commands. Anything else is Unsupported —
    // the null provider must not pretend to understand semantics it
    // cannot model exactly.
    static const char* kKnown[] = {"ResourceBarrier", "ClearRenderTargetView",
                                   "DrawInstanced", "DrawIndexedInstanced",
                                   "SetPipelineState", "SetGraphicsRootSignature"};
    bool known = false;
    for (const char* k : kKnown) {
        if (command == k) { known = true; break; }
    }
    record.implemented = known;
    record.ok = known;
    {
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
    }
    if (!known)
        return Result<void>(RuntimeErrc::PlatformUnsupported,
                            "null provider does not model command: " + command);
    return Result<void>::ok_result();
}

Result<std::uint64_t> NullGraphicsProvider::submit(
    std::uint64_t process_id, std::uint64_t device_handle) {
    GraphicsTraceRecord record;
    record.api = "Submit";
    record.process_id = process_id;
    record.input_summary = "device=0x" + std::to_string(device_handle);
    auto valid = validate_device(process_id, device_handle);
    if (!valid.ok()) {
        record.ok = false;
        std::lock_guard lock(impl_->lock);
        impl_->trace.push_back(record);
        return Result<std::uint64_t>(valid.errc(), valid.context());
    }
    std::uint64_t sequence = 0;
    {
        std::lock_guard lock(impl_->lock);
        sequence = impl_->next_sequence++;
        record.result_value = sequence;
        record.implemented = true;  // ordering IS the documented contract modeled
        record.ok = true;
        impl_->trace.push_back(record);
    }
    return Result<std::uint64_t>(sequence);
}

std::vector<GraphicsTraceRecord> NullGraphicsProvider::trace_snapshot() const {
    std::lock_guard lock(impl_->lock);
    return std::vector<GraphicsTraceRecord>(impl_->trace.begin(),
                                            impl_->trace.end());
}

void NullGraphicsProvider::clear_trace() {
    std::lock_guard lock(impl_->lock);
    impl_->trace.clear();
}

Result<void> NullGraphicsProvider::release_process_objects(
    std::uint64_t process_id) {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->retired.find(process_id);
    if (it == impl_->retired.end()) return Result<void>::ok_result();
    auto ids = std::move(it->second);
    impl_->retired.erase(it);
    for (const auto id : ids) (void)objects_.destroy(id);
    return Result<void>::ok_result();
}

}  // namespace xbox2pc::rt::gfx

// ── GraphicsService ──────────────────────────────────────────────────────

namespace xbox2pc::rt::gfx {

struct GraphicsService::Impl {
    std::unique_ptr<NullGraphicsProvider> provider;
};

GraphicsService::GraphicsService(api::ApiRegistry& api_reg,
                                 ProcessManager& pm)
    : RtService("gfx_null_provider"),
      impl_(std::make_unique<Impl>()) {
    impl_->provider = std::make_unique<NullGraphicsProvider>(pm, pm.objects());

    // Register the one evidence-backed graphics import dispatch.
    class CreateDeviceImpl : public api::IApiImplementation {
    public:
        explicit CreateDeviceImpl(IGraphicsProvider& provider)
            : provider_(provider) {}
        bool invoke(const api::ApiContext& ctx,
                    api::ApiCallResult& out) override {
            if (ctx.arg_count != 4) return false;
            // D3D12CreateDevice(adapter, minFeatureLevel, riid, ppDevice).
            // The output slot receives the device HANDLE value (the null
            // provider's opaque object model is handle-based).
            auto r = provider_.create_device(
                ctx.process_id, ctx.args[0],
                static_cast<std::uint32_t>(ctx.args[1]), ctx.args[2],
                ctx.args[3]);
            out.return_value = r.ok() ? 0u : 0x80004005u;  // S_OK / E_FAIL
            if (r.ok()) {
                out.out_bytes_size = 8;
                out.has_out = true;
                for (unsigned i = 0; i < 8; ++i)
                    out.out_bytes[i] = static_cast<std::uint8_t>(
                        r.value() >> (8 * i));
            } else {
                out.note = r.error_string();
            }
            return r.ok();
        }
        std::string describe() const override {
            return "D3D12: D3D12CreateDevice (null provider; traced, stubbed)";
        }
    private:
        IGraphicsProvider& provider_;
    };

    const auto owner = id();
    (void)api_reg.register_implementation(
        "d3d12", "D3D12CreateDevice",
        std::make_shared<CreateDeviceImpl>(*impl_->provider), owner);
}

GraphicsService::~GraphicsService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

IGraphicsProvider& GraphicsService::provider() { return *impl_->provider; }
const IGraphicsProvider& GraphicsService::provider() const {
    return *impl_->provider;
}

std::vector<GraphicsTraceRecord> GraphicsService::trace_snapshot() const {
    return impl_->provider->trace_snapshot();
}

void GraphicsService::clear_trace() { impl_->provider->clear_trace(); }

}  // namespace xbox2pc::rt::gfx
