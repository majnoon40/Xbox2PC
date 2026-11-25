// tests/m11_graphics_test.cpp — M11 Phase 8 graphics provider suite.
//
// Builds a project-authored test PE that imports d3d12!D3D12CreateDevice,
// dispatches it through the ApiRegistry into the null graphics provider,
// and verifies the roadmap contract: opaque process-scoped device handles,
// wrong-type/stale/cross-process rejection, command recording and
// submission ordering, per-call tracing, and fail-closed unknown commands.
// The test DLL is authored by this project (pe_builder); no Microsoft GDK
// binaries, headers, or redistributables are involved.

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/graphics_provider.hpp"
#include "xbox2pc/graphics_service.hpp"
#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/sync_objects.hpp"

namespace {

using namespace xbox2pc;
using rt::ModuleDescriptor;
using rt::ProcessManager;
using rt::RuntimeConfig;
using rt::RuntimeCore;
using rt::gfx::GraphicsService;
using rt::gfx::GraphicsTraceRecord;
using rt::api::ApiContext;
using rt::api::ApiRegistry;

struct GraphicsWorld {
    // reg FIRST => destroyed LAST (services hold references).
    ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    GraphicsService* gfx = nullptr;

    GraphicsWorld() : pm(core.objects()) {
        auto gfx_s = std::make_unique<GraphicsService>(reg, pm);
        gfx = gfx_s.get();
        EXPECT_TRUE(core.services().register_service(std::move(gfx_s)).ok());
        EXPECT_TRUE(core.initialize().ok());
    }
    ~GraphicsWorld() { (void)core.shutdown(); }

    rt::Handle last_handle;

    std::uint64_t new_process(const char* name) {
        auto p = pm.create_process(name, 32ull << 20);
        EXPECT_TRUE(p.ok());
        last_handle = p.value();
        ModuleDescriptor module;
        module.module_name = name;
        module.is_valid_pe = true;
        EXPECT_TRUE(pm.initialize_process(p.value(), module,
                                          RuntimeConfig{}).ok());
        EXPECT_TRUE(pm.start_process(p.value()).ok());
        const auto pid = pm.resolve_pid(p.value());
        EXPECT_TRUE(pid.ok());
        return pid.value();
    }
};

// Project-authored test DLL: one import (d3d12!D3D12CreateDevice) so the
// loader/dependency layer sees the graphics dependency, plus a marker
// export. No Microsoft artifacts are embedded.
test::PeBuildSpec MakeTestDllSpec() {
    test::PeBuildSpec spec;
    spec.section_names = {".text", ".rdata", ".data"};
    test::ImportDll dll;
    dll.name = "d3d12.dll";
    test::ImportFunc func;
    func.name = "D3D12CreateDevice";
    dll.funcs.push_back(func);
    spec.imports.push_back(dll);
    test::ExportFunc marker;
    marker.name = "Xbox2PCTestDllMarker";
    marker.rva = spec.entry_point_rva;
    spec.exports.push_back(marker);
    return spec;
}

TEST(M11Graphics, TestDllImportsD3D12CreateDevice) {
    const auto spec = MakeTestDllSpec();
    const test::PeBuilder builder(spec);
    const auto image = builder.build();
    ASSERT_FALSE(image.empty());

    diag::Diagnostics diags;
    const auto img = pe::parse(image.data(), image.size(), "graphics-test-dll", diags);
    ASSERT_TRUE(diags.count(diag::Severity::Error) == 0);
    ASSERT_TRUE(img.imports.present);
    ASSERT_EQ(img.imports.entries.size(), 1u);
    EXPECT_EQ(img.imports.entries[0].dll_name, "d3d12.dll");
    ASSERT_EQ(img.imports.entries[0].functions.size(), 1u);
    EXPECT_EQ(img.imports.entries[0].functions[0], "D3D12CreateDevice");
}

TEST(M11Graphics, CreateDeviceDispatchHandleAndTrace) {
    GraphicsWorld w;
    const auto pid = w.new_process("graphics-guest.exe");

    ApiContext ctx;
    ctx.process_id = pid;
    ctx.arg_count = 4;
    ctx.args[0] = 0;                    // adapter: nullptr (default)
    ctx.args[1] = 0xB000;               // D3D_FEATURE_LEVEL_11_0
    ctx.args[2] = 0x7fff0000;           // riid pointer (non-null; not dereferenced)
    ctx.args[3] = 0x50001000;           // ppDevice guest output slot

    const auto result = w.reg.dispatch("d3d12", "D3D12CreateDevice", ctx);
    EXPECT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.return_value, 0u);  // S_OK

    // The output bytes carry the 8-byte device handle value.
    ASSERT_TRUE(result.has_out);
    ASSERT_GE(result.out_bytes_size, 8u);
    std::uint64_t device = 0;
    for (unsigned i = 0; i < 8; ++i)
        device |= static_cast<std::uint64_t>(result.out_bytes[i]) << (8 * i);
    ASSERT_NE(device, 0ull);
    // M11 Phase 3 invariant: issued handles are four-aligned.
    EXPECT_EQ(device % 4, 0ull);

    // Trace: exactly one record with the right identity.
    const auto trace = w.gfx->trace_snapshot();
    ASSERT_EQ(trace.size(), 1u);
    EXPECT_EQ(trace[0].api, "D3D12CreateDevice");
    EXPECT_EQ(trace[0].process_id, pid);
    EXPECT_TRUE(trace[0].ok);
    EXPECT_TRUE(trace[0].implemented);

    // The handle validates from its own process...
    auto valid = w.gfx->provider().validate_device(pid, device);
    EXPECT_TRUE(valid.ok()) << valid.error_string();
}

TEST(M11Graphics, HandleTypeProcessAndStaleChecks) {
    GraphicsWorld w;
    const auto pid_a = w.new_process("graphics-owner.exe");
    const rt::Handle process_a = w.last_handle;
    const auto pid_b = w.new_process("graphics-other.exe");

    ApiContext ctx;
    ctx.process_id = pid_a;
    ctx.arg_count = 4;
    ctx.args[0] = 0;
    ctx.args[1] = 0xB000;
    ctx.args[2] = 0x7fff0000;
    ctx.args[3] = 0x50001000;
    const auto created = w.reg.dispatch("d3d12", "D3D12CreateDevice", ctx);
    ASSERT_TRUE(created.ok);
    std::uint64_t device = 0;
    for (unsigned i = 0; i < 8; ++i)
        device |= static_cast<std::uint64_t>(created.out_bytes[i]) << (8 * i);
    ASSERT_NE(device, 0ull);

    // Cross-process: B cannot use A's device handle.
    auto cross = w.gfx->provider().validate_device(pid_b, device);
    EXPECT_FALSE(cross.ok());

    // Wrong-type: an event handle is not a device handle.
    // (Create an event in the same process through the runtime table.)
    auto event_obj = std::make_unique<rt::RtEvent>(false, false);
    auto reg = w.pm.objects().register_object(std::move(event_obj));
    ASSERT_TRUE(reg.ok());
    auto guard = w.pm.objects().lookup_id(reg.value());
    ASSERT_TRUE(guard.ok());
    auto proc = w.pm.find_process(process_a);
    ASSERT_TRUE(proc.ok());
    auto* owner = proc.value().get()->as<rt::ManagedProcess>();
    ASSERT_NE(owner, nullptr);
    auto event_handle = owner->handle_table().create(*guard.value().get());
    ASSERT_TRUE(event_handle.ok());
    auto wrong = w.gfx->provider().validate_device(
        pid_a, event_handle.value().raw());
    EXPECT_FALSE(wrong.ok());

    // Stale: close the device's handle, then validation must fail.
    auto closed = owner->handle_table().close(rt::Handle::from_raw(device));
    ASSERT_TRUE(closed.ok());
    auto stale = w.gfx->provider().validate_device(pid_a, device);
    EXPECT_FALSE(stale.ok());

    // Null and misaligned (M11 tag bits) handles reject.
    EXPECT_FALSE(w.gfx->provider().validate_device(pid_a, 0).ok());
    EXPECT_FALSE(w.gfx->provider().validate_device(pid_a, device | 1ull).ok());
}

TEST(M11Graphics, CommandRecordingSubmissionAndUnknownFailClosed) {
    GraphicsWorld w;
    const auto pid = w.new_process("graphics-recorder.exe");

    ApiContext ctx;
    ctx.process_id = pid;
    ctx.arg_count = 4;
    ctx.args[0] = 0;
    ctx.args[1] = 0xB000;
    ctx.args[2] = 0x7fff0000;
    ctx.args[3] = 0x50001000;
    const auto created = w.reg.dispatch("d3d12", "D3D12CreateDevice", ctx);
    ASSERT_TRUE(created.ok);
    std::uint64_t device = 0;
    for (unsigned i = 0; i < 8; ++i)
        device |= static_cast<std::uint64_t>(created.out_bytes[i]) << (8 * i);
    ASSERT_NE(device, 0ull);

    // Known commands record (recorded, not executed).
    EXPECT_TRUE(w.gfx->provider().record_command(pid, device, "ResourceBarrier").ok());
    EXPECT_TRUE(w.gfx->provider().record_command(pid, device, "DrawInstanced").ok());

    // Unknown command semantics fail closed — never fake success.
    auto unknown = w.gfx->provider().record_command(pid, device, "ExecuteIndirectMeta");
    EXPECT_FALSE(unknown.ok());

    // Submission ordering is monotone per provider instance.
    auto s1 = w.gfx->provider().submit(pid, device);
    auto s2 = w.gfx->provider().submit(pid, device);
    ASSERT_TRUE(s1.ok());
    ASSERT_TRUE(s2.ok());
    EXPECT_LT(s1.value(), s2.value());

    // Trace captures every call in order, with implemented/stubbed status.
    const auto trace = w.gfx->trace_snapshot();
    ASSERT_GE(trace.size(), 6u);  // create + 2 records + 1 unknown + 2 submits
    int unknown_records = 0;
    for (const auto& rec : trace) {
        if (rec.api == "RecordCommand" &&
            rec.input_summary.find("ExecuteIndirectMeta") != std::string::npos) {
            ++unknown_records;
            EXPECT_FALSE(rec.implemented);
        }
    }
    EXPECT_EQ(unknown_records, 1);

    // The trace records on an invalid device too (fail-visible discipline).
    EXPECT_FALSE(w.gfx->provider().submit(pid, 0xdead00ull).ok());
    const auto after = w.gfx->trace_snapshot();
    EXPECT_EQ(after.size(), trace.size() + 1u);
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
