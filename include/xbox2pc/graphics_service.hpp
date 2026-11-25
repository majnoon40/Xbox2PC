#pragma once
// xbox2pc/graphics_service.hpp — M11 Phase 8 graphics service.
//
// Owns the selected IGraphicsProvider and registers the evidence-backed
// graphics imports (d3d12!D3D12CreateDevice) with the ApiRegistry.
// Object lifetime: devices are runtime-owned RuntimeObjects with
// process-scoped M4 handles; a process-exit observer retires them.

#include <memory>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/graphics_provider.hpp"
#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/service_registry.hpp"

namespace xbox2pc::rt::gfx {

// The deterministic null provider (docs/graphics-roadmap.md): devices are
// runtime-owned objects with process-scoped M4 handles; command records
// and submission ordering are traced but never executed; every call is
// traced; unmodeled semantics fail closed. Concurrency-safe.
class NullGraphicsProvider : public IGraphicsProvider {
public:
    NullGraphicsProvider(ProcessManager& pm, ObjectManager& objects);
    ~NullGraphicsProvider() override;

    const char* name() const override;

    Result<std::uint64_t> create_device(
        std::uint64_t process_id, std::uint64_t adapter,
        std::uint32_t feature_level, std::uint64_t riid,
        std::uint64_t out_device_slot) override;
    Result<void> validate_device(std::uint64_t process_id,
                                 std::uint64_t handle) override;
    Result<void> record_command(std::uint64_t process_id,
                                std::uint64_t device_handle,
                                const std::string& command) override;
    Result<std::uint64_t> submit(std::uint64_t process_id,
                                 std::uint64_t device_handle) override;
    std::vector<GraphicsTraceRecord> trace_snapshot() const override;
    void clear_trace() override;
    Result<void> release_process_objects(std::uint64_t process_id) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ProcessManager& process_manager_;
    ObjectManager& objects_;
};

// The graphics service. Registers one import implementation
// (d3d12!D3D12CreateDevice) that dispatches to the provider. Trace
// records are exposed for tests and compatibility reporting.
class GraphicsService : public RtService {
public:
    GraphicsService(api::ApiRegistry& api_reg, ProcessManager& pm);
    ~GraphicsService() override;

    // The active provider (the null provider is the only one today).
    IGraphicsProvider& provider();
    const IGraphicsProvider& provider() const;

    // Test/admin surface over the provider.
    std::vector<GraphicsTraceRecord> trace_snapshot() const;
    void clear_trace();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace xbox2pc::rt::gfx
