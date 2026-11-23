// xbox2pc/tests/api_compat_test.cpp — M7 test suite.
//
// Coverage map (spec §12):
//   12.1 registry     — ApiRegistryTest (add/lookup/ordinal/conflict/
//                        validation/concurrent/thread-safety)
//   12.2 dispatcher   — ApiDispatcherTest (valid/missing/unsupported/
//                        argcount/convention/concurrent/service-shutdown)
//   12.3 resolver     — ApiResolverTest (name/ordinal/missing/unknown/
//                        delay/rollback/repeat)
//   12.4 Game OS      — GdkServiceTest (lifecycle ref-count, ids, queues,
//                        timing, shutdown revocation)
//   12.5 GDK services — service init ordering + failure rollback
//   12.6 TLS          — TlsTest (indices, template, zero-fill, multi-module,
//                        thread-after-load, release)
//   12.7 e2e          — ApiE2eTest (15-step path with delay-load + TLS +
//                        compat report + protections + cleanup)

#include <atomic>
#include <cstring>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <chrono>
#include <gtest/gtest.h>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/compat_report.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/package_vfs.hpp"
#include "xbox2pc/packages.hpp"
#include "xbox2pc/vfs_process.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/sync_objects.hpp"

using namespace xbox2pc::rt::api;
using namespace xbox2pc::rt::loader;
using xbox2pc::diag::Diagnostics;
using xbox2pc::pe::PeImage;
using xbox2pc::rt::ManagedProcess;
using xbox2pc::rt::ProcessManager;
using xbox2pc::rt::RuntimeCore;
using xbox2pc::rt::loader::ImportStatus;
using xbox2pc::rt::loader::ImageLoader;
using xbox2pc::rt::loader::LoadDiagnostics;
using xbox2pc::rt::loader::LoadResult;
using xbox2pc::rt::loader::TlsInfo;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

namespace {

// A live world with all three services initialized (registered BEFORE
// core.initialize() so initialize_all covers them).
struct ApiWorld {
    // Declaration order = destruction order is REVERSE. The registry must
    // OUTLIVE core (services hold ApiRegistry& reg_) and pm (TaskQueueService
    // holds ProcessManager& pm_): declare reg FIRST so it is destroyed LAST.
    ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    GameRuntimeService* grt = nullptr;
    TaskQueueService* tq = nullptr;
    TimingService* tim = nullptr;

    ApiWorld() : pm(core.objects()) {
        {
            auto grt_s = std::make_unique<GameRuntimeService>(reg, pm);
            auto tq_s = std::make_unique<TaskQueueService>(reg, pm);
            auto tim_s = std::make_unique<TimingService>(reg);
            grt = grt_s.get();
            tq = tq_s.get();
            tim = tim_s.get();
            EXPECT_TRUE(core.services().register_service(std::move(grt_s)).ok());
            EXPECT_TRUE(core.services().register_service(std::move(tq_s)).ok());
            EXPECT_TRUE(core.services().register_service(std::move(tim_s)).ok());
        }
        EXPECT_TRUE(core.initialize().ok());
    }
    ~ApiWorld() { (void)core.shutdown(); }

    xbox2pc::rt::Handle last_handle;

    ManagedProcess* new_process(const char* name) {
        auto p = pm.create_process(name, 32ull << 20);
        EXPECT_TRUE(p.ok());
        last_handle = p.value();
        auto found = core.objects().lookup_handle(p.value());
        return found.ok() ? found.value().get()->as<ManagedProcess>() : nullptr;
    }
};

// A minimal custom implementation for registration tests.
struct EchoImpl : public IApiImplementation {
    explicit EchoImpl(std::uint64_t value) : v_(value) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        out.return_value = v_;
        out.note = "echo";
        return true;
    }
    std::string describe() const override { return "echo test impl"; }

private:
    std::uint64_t v_;
};


struct GuestWaitThreadArgs {
    ApiRegistry* registry = nullptr;
    std::uint64_t process_id = 0;
    std::uint64_t handle = 0;
    std::atomic<bool> entered{false};
    std::atomic<bool> completed{false};
    std::atomic<std::uint64_t> wait_result{0};
};
void* guest_wait_thread_main(xbox2pc::rt::RtThread& self, void* raw) {
    auto* args = static_cast<GuestWaitThreadArgs*>(raw);
    ApiContext ctx;
    ctx.process_id = args->process_id;
    ctx.thread_id = self.thread_id();
    ctx.arg_count = 2;
    ctx.args[0] = args->handle;
    ctx.args[1] = 0xFFFFFFFFu;
    args->entered.store(true, std::memory_order_release);
    const auto result = args->registry->dispatch("kernel32", "WaitForSingleObject", ctx);
    args->wait_result.store(result.ok ? result.return_value : 0xDEADu,
                            std::memory_order_release);
    args->completed.store(true, std::memory_order_release);
    return nullptr;
}

}  // namespace

// ── 12.1 registry ─────────────────────────────────────────────────────────

TEST(ApiRegistryTest, BuiltInDescriptorsLoadAndValidate) {
    ApiRegistry reg;
    EXPECT_GE(reg.descriptor_count(), 18u);
    for (const auto* d : reg.all()) {
        EXPECT_TRUE(d->validate().empty())
            << d->library << "!" << d->export_name << ": "
            << (d->validate().empty() ? "" : d->validate().front());
        EXPECT_EQ(d->evidence_url.rfind("https://", 0), 0u);
    }
}

TEST(ApiRegistryTest, M10DescriptorsMatchImplementedPartialCoverage) {
    ApiRegistry reg;
    const auto* alloc = reg.find("kernel32", "VirtualAlloc");
    const auto* query = reg.find("kernel32", "VirtualQuery");
    const auto* free = reg.find("kernel32", "VirtualFree");
    const auto* protect = reg.find("kernel32", "VirtualProtect");
    const auto* wait = reg.find("kernel32", "WaitForSingleObject");
    const auto* wait_many = reg.find("kernel32", "WaitForMultipleObjects");
    ASSERT_NE(alloc, nullptr);
    ASSERT_NE(query, nullptr);
    ASSERT_NE(free, nullptr);
    ASSERT_NE(protect, nullptr);
    ASSERT_NE(wait, nullptr);
    ASSERT_NE(wait_many, nullptr);
    EXPECT_EQ(wait_many->impl, ApiStatus::PartiallyImplemented);
    EXPECT_NE(wait_many->notes.find("wait-any"), std::string::npos);
    EXPECT_NE(wait_many->notes.find("wait-all is unsupported"), std::string::npos);
    EXPECT_EQ(alloc->impl, ApiStatus::PartiallyImplemented);
    EXPECT_NE(alloc->notes.find("fixed-address"), std::string::npos);
    EXPECT_NE(query->notes.find("MEM_IMAGE"), std::string::npos);
    EXPECT_NE(query->notes.find("allocation protection"), std::string::npos);
    EXPECT_NE(free->notes.find("page-range MEM_DECOMMIT"), std::string::npos);
    EXPECT_NE(protect->notes.find("page-range protection"), std::string::npos);
    EXPECT_NE(wait->notes.find("guest mutex"), std::string::npos);
    EXPECT_NE(wait->notes.find("guest semaphore"), std::string::npos);
    const auto* semaphore = reg.find("kernel32", "ReleaseSemaphore");
    ASSERT_NE(semaphore, nullptr);
    EXPECT_NE(semaphore->notes.find("optional lpPreviousCount output"), std::string::npos);
    const auto* submit = reg.find("xgameruntime", "XTaskQueueSubmitCallback");
    const auto* delayed = reg.find("xgameruntime", "XTaskQueueSubmitDelayedCallback");
    const auto* duplicate_queue = reg.find("xgameruntime", "XTaskQueueDuplicateHandle");
    ASSERT_NE(submit, nullptr);
    ASSERT_NE(delayed, nullptr);
    ASSERT_NE(duplicate_queue, nullptr);
    EXPECT_EQ(submit->compat, ApiStatus::PartiallyImplemented);
    EXPECT_EQ(submit->impl, ApiStatus::Unsupported);
    EXPECT_NE(submit->notes.find("guest callback invocation"), std::string::npos);
    EXPECT_EQ(delayed->compat, ApiStatus::PartiallyImplemented);
    EXPECT_EQ(delayed->impl, ApiStatus::Unsupported);
    EXPECT_NE(delayed->notes.find("timer scheduling"), std::string::npos);
    EXPECT_EQ(duplicate_queue->impl, ApiStatus::PartiallyImplemented);
    EXPECT_NE(duplicate_queue->notes.find("same-process duplicate handles"), std::string::npos);
    const auto* close = reg.find("kernel32", "CloseHandle");
    ASSERT_NE(close, nullptr);
    EXPECT_NE(close->notes.find("guest mutex"), std::string::npos);
    EXPECT_NE(close->notes.find("guest semaphore"), std::string::npos);
}
 
TEST(ApiRegistryTest, LookupCaseFoldingMatchesTheOsLoader) {
    // Windows/GDK loader export resolution is case-insensitive for both
    // module and export names (documented loader behavior). The registry
    // mirrors it; a DIFFERENT name never matches regardless of case.
    ApiRegistry reg;
    EXPECT_NE(reg.find("xgameruntime", "XGameRuntimeInitialize"), nullptr);
    EXPECT_NE(reg.find("XGAMERUNTIME.DLL", "XGameRuntimeInitialize"), nullptr);
    EXPECT_NE(reg.find("xgameruntime", "xgameruntimeinitialize"), nullptr);
    EXPECT_EQ(reg.find("xgameruntime", "completelydifferentname"), nullptr);
}

TEST(ApiRegistryTest, ConflictingDescriptorRejected) {
    ApiRegistry reg;
    ApiDescriptor d = *reg.find("xgameruntime", "XGameRuntimeInitialize");
    d.signature = "HRESULT FAKE(int)";   // different content
    auto r = reg.add_descriptor(d);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), xbox2pc::rt::RuntimeErrc::AlreadyExists);
    // Idempotent re-add of the SAME descriptor is fine.
    ApiDescriptor same = *reg.find("xgameruntime", "XGameRuntimeInitialize");
    EXPECT_TRUE(reg.add_descriptor(same).ok());
}

TEST(ApiRegistryTest, InvalidDescriptorsRejected) {
    ApiRegistry reg;
    ApiDescriptor d;
    d.library = "fakelib";
    d.export_name = "FakeApi";
    // Missing evidence URL etc.
    auto r = reg.add_descriptor(d);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), xbox2pc::rt::RuntimeErrc::InvalidArgument);
}

TEST(ApiRegistryTest, ImplementationRegistrationAndOwnership) {
    ApiRegistry reg;
    // Registering for a NON-descriptor API is refused (verified identity).
    auto r0 = reg.register_implementation("fakelib", "Nope",
                                          std::make_shared<EchoImpl>(1), 0);
    EXPECT_FALSE(r0.ok());
    EXPECT_EQ(r0.errc(), xbox2pc::rt::RuntimeErrc::NotFound);

    auto r1 = reg.register_implementation(
        "xgameruntime", "XGameRuntimeInitialize",
        std::make_shared<EchoImpl>(7), /*owner=*/100);
    EXPECT_TRUE(r1.ok());
    EXPECT_TRUE(reg.has_implementation("xgameruntime", "XGameRuntimeInitialize"));
    // A DIFFERENT owner cannot replace it.
    auto r2 = reg.register_implementation(
        "xgameruntime", "XGameRuntimeInitialize",
        std::make_shared<EchoImpl>(8), /*owner=*/200);
    EXPECT_FALSE(r2.ok());
    EXPECT_EQ(r2.errc(), xbox2pc::rt::RuntimeErrc::AlreadyExists);
    // The same owner CAN re-register (service re-init).
    auto r3 = reg.register_implementation(
        "xgameruntime", "XGameRuntimeInitialize",
        std::make_shared<EchoImpl>(9), /*owner=*/100);
    EXPECT_TRUE(r3.ok());
    // Revoke by owner removes exactly theirs.
    auto revoked = reg.revoke_owner(100);
    ASSERT_TRUE(revoked.ok());
    EXPECT_GE(revoked.value(), 1u);
    EXPECT_FALSE(reg.has_implementation("xgameruntime", "XGameRuntimeInitialize"));
}

TEST(ApiRegistryTest, ConcurrentLookupAndDispatch) {
    ApiWorld w;
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    std::atomic<int> ok_count{0};
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            while (!stop.load()) {
                ApiContext ctx;
                auto r = w.reg.dispatch("xgameruntime", "XGameRuntimeInitialize", ctx);
                if (r.ok) ++ok_count;
                (void)w.reg.find("xgameruntime", "XSystemGetDeviceType");
            }
        });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    stop.store(true);
    for (auto& t : threads) t.join();
    EXPECT_GT(ok_count.load(), 0);
}

// ── 12.2 dispatcher ──────────────────────────────────────────────────────

TEST(ApiDispatcherTest, DocumentedSemanticsPerApi) {
    ApiWorld w;
    // GRT init: S_OK + per-process count.
    ApiContext ctx;
    auto r = w.reg.dispatch("xgameruntime", "XGameRuntimeInitialize", ctx);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.return_value, kSOk);
    // DeviceType: documented Unknown fallback (0x00).
    r = w.reg.dispatch("xgameruntime", "XSystemGetDeviceType", ctx);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.return_value, 0u);
    // SandboxId: documented RETAIL fallback + size validation.
    ApiContext ctx3;
    ctx3.arg_count = 3;
    ctx3.args[0] = 64;
    r = w.reg.dispatch("xgameruntime", "XSystemGetXboxLiveSandboxId", ctx3);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.return_value, kSOk);
    EXPECT_TRUE(r.has_out);
    EXPECT_EQ(r.out_value, 6u);   // "RETAIL" length
    ctx3.args[0] = 2;   // too small (documented ERROR_INSUFFICIENT_BUFFER)
    r = w.reg.dispatch("xgameruntime", "XSystemGetXboxLiveSandboxId", ctx3);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.return_value, kEInsufficientBuffer);
    // ConsoleId: 30-char documented all-zero fallback.
    ctx3.args[0] = 64;
    r = w.reg.dispatch("xgameruntime", "XSystemGetConsoleId", ctx3);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.out_value, 38u);
    // QPC: nonzero return (documented BOOL) + monotonic out value.
    ApiContext q;
    q.arg_count = 1;
    q.args[0] = 0x7000;
    r = w.reg.dispatch("kernel32", "QueryPerformanceCounter", q);
    EXPECT_TRUE(r.ok);
    EXPECT_NE(r.return_value, 0u);
    EXPECT_GT(r.out_value, 0u);
    ApiContext qf;
    qf.arg_count = 1;
    r = w.reg.dispatch("kernel32", "QueryPerformanceFrequency", qf);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.out_value, 1'000'000'000u);   // PAL ns clock
}

TEST(ApiDispatcherTest, ValidationRejections) {
    ApiWorld w;
    ApiContext ctx;
    // Missing descriptor.
    auto r = w.reg.dispatch("xgameruntime", "TotallyMadeUp", ctx);
    EXPECT_FALSE(r.ok);
    // Argument-count mismatch (documented 3 params).
    ApiContext ctx3;
    ctx3.arg_count = 3;
    r = w.reg.dispatch("xgameruntime", "XSystemGetConsoleId", ctx);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("argument count"), std::string::npos);
    // No implementation (revoked service path): use a fresh registry
    // WITHOUT services.
    ApiRegistry bare;
    r = bare.dispatch("xgameruntime", "XGameRuntimeInitialize", ctx);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("no implementation"), std::string::npos);
    // Convention Unknown refuses dispatch (descriptor-level): author one.
    ApiDescriptor u;
    u.library = "testlib";
    u.export_name = "UnknownConv";
    u.convention = Convention::Unknown;
    u.param_count = 0;
    u.ret = ReturnKind::Void;
    u.signature = "void UnknownConv()";
    u.category = xbox2pc::registry::ApiCategory::XboxGdk;
    u.compat = ApiStatus::Unknown;
    u.impl = ApiStatus::Unknown;
    u.evidence = "[TEST]";
    u.evidence_url = "https://example.com/test";
    // Convention Unknown fails validation -> cannot even register.
    EXPECT_FALSE(bare.add_descriptor(u).ok());
}

TEST(ApiDispatcherTest, ServiceShutdownRevokesImplementations) {
    ApiWorld w;
    EXPECT_TRUE(w.reg.has_implementation("xgameruntime", "XSystemGetDeviceType"));
    // Shutdown all services: implementations revoked.
    EXPECT_TRUE(w.core.services().shutdown_all().ok());
    EXPECT_FALSE(w.reg.has_implementation("xgameruntime", "XSystemGetDeviceType"));
    EXPECT_FALSE(w.reg.has_implementation("kernel32", "QueryPerformanceCounter"));
    ApiContext ctx;
    auto r = w.reg.dispatch("xgameruntime", "XSystemGetDeviceType", ctx);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("no implementation"), std::string::npos);
}

// ── 12.3 resolver + delay-load ─────────────────────────────────────────────

TEST(ApiResolverTest, ResolverStates) {
    ApiWorld w;
    ApiResolver resolver(w.reg);
    // Known module + implemented API -> Resolved with a synthetic value.
    ImportLookup look;
    look.dll = "xgameruntime";
    look.symbol = "XGameRuntimeInitialize";
    auto b = resolver.resolve(look);
    EXPECT_EQ(b.status, ImportStatus::Resolved);
    EXPECT_EQ(b.value, 0x51000001ull);
    EXPECT_TRUE(xbox2pc::rt::exec::is_api_binding(b.value));

    // Win32 imports use the second reserved binding subrange.
    look.dll = "kernel32";
    look.symbol = "CreateEventW";
    auto win32 = resolver.resolve(look);
    EXPECT_EQ(win32.status, ImportStatus::Resolved);
    EXPECT_EQ(win32.value, 0x51010002ull);
    EXPECT_TRUE(xbox2pc::rt::exec::is_api_binding(win32.value));

    // A second resolver sharing the same registry receives a distinct ID.
    ApiResolver second_resolver(w.reg);
    ImportLookup second_lookup;
    second_lookup.dll = "xgameruntime";
    second_lookup.symbol = "XGameRuntimeInitialize";
    const auto second_binding = second_resolver.resolve(second_lookup);
    EXPECT_EQ(second_binding.status, ImportStatus::Resolved);
    EXPECT_EQ(second_binding.value, 0x51000003ull);
    EXPECT_NE(second_binding.value, b.value);
    EXPECT_EQ(resolver.bindings_issued(), 2u);
    EXPECT_EQ(second_resolver.bindings_issued(), 1u);

    // Known module + unimplemented export -> Unresolved (descriptor, no impl
    // cannot happen here: all 16 are implemented; use an unlisted export).
    look.symbol = "XSystemAllowFullDownloadBandwidth";   // documented but NOT in our table
    b = resolver.resolve(look);
    EXPECT_EQ(b.status, ImportStatus::Unresolved);   // module known, export unknown
    // Unknown module -> module gate false -> Unsupported.
    look.dll = "nonexistent.dll";
    look.symbol = "Whatever";
    EXPECT_FALSE(resolver.resolve_module("nonexistent.dll"));
    b = resolver.resolve(look);
    EXPECT_EQ(b.status, ImportStatus::Unsupported);
    // Ordinal resolution never invented: no verified ordinals exist.
    look.by_ordinal = true;
    look.ordinal = 5;
    look.dll = "xgameruntime";
    b = resolver.resolve(look);
    EXPECT_NE(b.status, ImportStatus::Resolved);   // never a fake ordinal binding
}

TEST(ApiResolverTest, FullLoadThroughApiResolver) {
    ApiWorld w;
    PeBuildSpec spec;
    spec.imports = {
        {"xgameruntime", {{"XGameRuntimeInitialize", 1}}},
        {"kernel32", {{"QueryPerformanceCounter", 1}}},
    };
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = PeBuilder(spec).build();
    Diagnostics pd;
    auto img = xbox2pc::pe::parse(image.data(), image.size(), "api.exe", pd);
    (void)w.new_process("api-host.exe");   // handle captured in w.last_handle
    ImageLoader loader;
    ApiResolver resolver(w.reg);
    LoadDiagnostics ld;
    LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), w.last_handle,
                               img, image.data(), image.size(),
                               &resolver, ld, out);
    ASSERT_TRUE(h.ok()) << out.error;
    EXPECT_EQ(out.exec.imports_resolved, 2u);
    // The IAT slots hold synthetic registry bindings (nonzero).
    for (const auto& b : ld.imports) {
        EXPECT_EQ(b.status, ImportStatus::Resolved);
        EXPECT_NE(b.value, 0u);
    }
    ASSERT_TRUE(loader.unload_image(w.pm, w.core.objects(), w.last_handle,
                                    h.value())
                    .ok());
}

TEST(ApiResolverTest, UnknownImportFailsLoadWithRollback) {
    ApiWorld w;
    PeBuildSpec spec;
    spec.imports = {{"mystery.dll", {{"Secret", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = PeBuilder(spec).build();
    Diagnostics pd;
    auto img = xbox2pc::pe::parse(image.data(), image.size(), "mystery.exe", pd);
    auto* proc = w.new_process("mystery-host.exe");
    ASSERT_NE(proc, nullptr);
    auto& space = proc->address_space();
    const auto before = space.stats().region_count;
    ImageLoader loader;
    ApiResolver resolver(w.reg);
    LoadDiagnostics ld;
    LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), w.last_handle, img,
                               image.data(), image.size(), &resolver, ld, out);
    EXPECT_FALSE(h.ok());
    EXPECT_EQ(out.final_state, xbox2pc::rt::loader::LoadState::Failed);
    EXPECT_EQ(h.errc(), xbox2pc::rt::RuntimeErrc::MissingDependency);
    EXPECT_EQ(space.stats().region_count, before);   // full rollback
}

TEST(DelayImportTest, ResolveWritesMappedIatAndReports) {
    ApiWorld w;
    PeBuildSpec spec;
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    spec.delay_imports = {{"xgameruntime", {{"XSystemGetDeviceType", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto image = PeBuilder(spec).build();
    Diagnostics pd;
    auto img = xbox2pc::pe::parse(image.data(), image.size(), "delay.exe", pd);
    auto* proc = w.new_process("delay-host.exe");
    ImageLoader loader;
    ApiResolver resolver(w.reg);
    LoadDiagnostics ld;
    LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), w.last_handle, img,
                               image.data(), image.size(), &resolver, ld, out);
    ASSERT_TRUE(h.ok()) << out.error;

    auto drep = resolve_delay_imports(proc->address_space(), out.layout, img,
                                     image.data(), image.size(), w.reg, false);
    ASSERT_TRUE(drep.ok()) << drep.error_string();
    EXPECT_EQ(drep.value().descriptors, 1u);
    EXPECT_EQ(drep.value().entries, 1u);
    EXPECT_EQ(drep.value().resolved, 1u);
    EXPECT_EQ(drep.value().unresolved, 0u);

    // The delay IAT slot now holds the synthetic binding value (nonzero,
    // inside the mapped image): find the slot from the parsed image's
    // delay-import IAT rva.
    const auto& di = img.delay_imports.entries.front();
    const std::uint64_t slot_va = out.layout.actual_base + di.iat_rva;
    auto dst = proc->address_space().translate(slot_va);
    ASSERT_TRUE(dst.ok());
    std::uint64_t v = 0;
    std::memcpy(&v, dst.value(), 8);
    EXPECT_NE(v, 0u);   // bound through the registry

    // Unresolved policy: fail_on_unresolved with an unknown delay import.
    PeBuildSpec bad_spec;
    bad_spec.delay_imports = {{"ghost.dll", {{"Boo", 1}}}};
    bad_spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    auto bad_image = PeBuilder(bad_spec).build();
    Diagnostics bd;
    auto bad_img = xbox2pc::pe::parse(bad_image.data(), bad_image.size(), "bad.exe", bd);
    auto* bad_proc = w.new_process("bad-host.exe");
    LoadDiagnostics bld;
    LoadResult bout;
    auto bh = loader.load_image(w.pm, w.core.objects(), w.last_handle,
                                bad_img, bad_image.data(), bad_image.size(),
                                nullptr, bld, bout);
    if (bh.ok()) {
        auto bres = resolve_delay_imports(bad_proc->address_space(),
                                          bout.layout,
                                          bad_img, bad_image.data(),
                                          bad_image.size(), w.reg, true);
        ASSERT_FALSE(bres.ok());
        EXPECT_EQ(bres.errc(), xbox2pc::rt::RuntimeErrc::MissingDependency);
        (void)loader.unload_image(w.pm, w.core.objects(), w.last_handle, bh.value());
    } else {
        // Image with ONLY delay imports and no resolver: load failed at
        // the regular-import gate (no regular imports, resolver null OK).
        ADD_FAILURE() << "unexpected load failure: " << bout.error;
    }
}

// ── 12.4/12.5 GDK + Game OS services ──────────────────────────────────────

TEST(GdkServiceTest, LifecycleRefCountPerProcess) {
    ApiWorld w;
    auto r1 = w.grt->grt_initialize(1001);
    ASSERT_TRUE(r1.ok());
    EXPECT_EQ(r1.value(), 1u);
    auto r2 = w.grt->grt_initialize(1001);   // documented: each component calls
    ASSERT_TRUE(r2.ok());
    EXPECT_EQ(r2.value(), 2u);
    EXPECT_TRUE(w.grt->grt_uninitialize(1001).ok());   // -> 1
    EXPECT_TRUE(w.grt->grt_uninitialize(1001).ok());   // -> 0 (state gone)
    // Uninit below zero is ignored (documented).
    EXPECT_TRUE(w.grt->grt_uninitialize(1001).ok());
    // Processes are isolated.
    w.grt->grt_initialize(1002);
    auto r3 = w.grt->grt_initialize(1001);
    ASSERT_TRUE(r3.ok());
    EXPECT_EQ(r3.value(), 1u);   // restarted at 1, not 2
}

TEST(GdkServiceTest, Win32EventApiLifecycleAndProcessIsolation) {
    ApiWorld w; auto* p=w.new_process("event-api.exe"); ASSERT_NE(p,nullptr);
    auto pid=w.pm.resolve_pid(w.last_handle); ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor event_module;
    event_module.module_name = "event-test.exe";
    event_module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, event_module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());
    ApiContext c; c.process_id=pid.value(); c.arg_count=4;
    c.args[0]=0; c.args[1]=1; c.args[2]=0; c.args[3]=0;
    const auto handles_before=p->handle_table().live_count();
    auto created=w.reg.dispatch("kernel32","CreateEventW",c);
    ASSERT_TRUE(created.ok); ASSERT_NE(created.return_value,0u);
    const auto h=created.return_value;
    EXPECT_EQ(p->handle_table().live_count(),handles_before+1);
    c.arg_count=2; c.args[0]=h; c.args[1]=0;
    auto timeout=w.reg.dispatch("kernel32","WaitForSingleObject",c);
    ASSERT_TRUE(timeout.ok); EXPECT_EQ(timeout.return_value,0x102u);
    c.arg_count=1; c.args[0]=h;
    auto set=w.reg.dispatch("kernel32","SetEvent",c);
    ASSERT_TRUE(set.ok); EXPECT_EQ(set.return_value,1u);
    c.arg_count=2; c.args[0]=h; c.args[1]=0;
    auto signaled=w.reg.dispatch("kernel32","WaitForSingleObject",c);
    ASSERT_TRUE(signaled.ok); EXPECT_EQ(signaled.return_value,0u);
    auto still_signaled=w.reg.dispatch("kernel32","WaitForSingleObject",c);
    ASSERT_TRUE(still_signaled.ok); EXPECT_EQ(still_signaled.return_value,0u);
    c.arg_count=1; c.args[0]=h;
    auto reset=w.reg.dispatch("kernel32","ResetEvent",c);
    ASSERT_TRUE(reset.ok); EXPECT_EQ(reset.return_value,1u);
    c.arg_count=2; c.args[0]=h; c.args[1]=0;
    auto timeout2=w.reg.dispatch("kernel32","WaitForSingleObject",c);
    ASSERT_TRUE(timeout2.ok); EXPECT_EQ(timeout2.return_value,0x102u);
    c.process_id=pid.value()+1; c.arg_count=1; c.args[0]=h;
    auto foreign=w.reg.dispatch("kernel32","SetEvent",c);
    ASSERT_TRUE(foreign.ok); EXPECT_EQ(foreign.return_value,0u);
    // Restore the owning process before creating another process-owned handle.
    c.process_id=pid.value();
    // Auto-reset consumes the initial signal after exactly one successful wait.
    c.arg_count=4; c.args[0]=0; c.args[1]=0; c.args[2]=1; c.args[3]=0;
    auto auto_event=w.reg.dispatch("kernel32","CreateEventW",c);
    ASSERT_TRUE(auto_event.ok); ASSERT_NE(auto_event.return_value,0u);
    c.arg_count=2; c.args[0]=auto_event.return_value; c.args[1]=0;
    auto first_auto=w.reg.dispatch("kernel32","WaitForSingleObject",c);
    ASSERT_TRUE(first_auto.ok); EXPECT_EQ(first_auto.return_value,0u);
    auto second_auto=w.reg.dispatch("kernel32","WaitForSingleObject",c);
    ASSERT_TRUE(second_auto.ok); EXPECT_EQ(second_auto.return_value,0x102u);
    c.arg_count=1; c.args[0]=auto_event.return_value;
    auto close_auto=w.reg.dispatch("kernel32","CloseHandle",c);
    ASSERT_TRUE(close_auto.ok); EXPECT_EQ(close_auto.return_value,1u);

    c.process_id=pid.value();
    c.arg_count=1; c.args[0]=h;  // Close the original manual-reset event, not the auto-reset event already closed above.
    auto closed=w.reg.dispatch("kernel32","CloseHandle",c);
    ASSERT_TRUE(closed.ok); EXPECT_EQ(closed.return_value,1u);
    EXPECT_EQ(p->handle_table().live_count(),handles_before);
    auto stale=w.reg.dispatch("kernel32","SetEvent",c);
    ASSERT_TRUE(stale.ok); EXPECT_EQ(stale.return_value,0u);
}



TEST(GdkServiceTest, ProcessSuspendResumesBlockedWin32EventWait) {
    ApiWorld w;
    (void)w.new_process("suspend-blocked-wait.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "suspend-blocked-wait.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    ApiContext create;
    create.process_id = pid.value();
    create.arg_count = 4;
    create.args[0] = 0; create.args[1] = 1;
    create.args[2] = 0; create.args[3] = 0;
    const auto event = w.reg.dispatch("kernel32", "CreateEventW", create);
    ASSERT_TRUE(event.ok); ASSERT_NE(event.return_value, 0u);

    GuestWaitThreadArgs args;
    args.registry = &w.reg;
    args.process_id = pid.value();
    args.handle = event.return_value;
    auto thread_handle = w.pm.spawn_thread(w.last_handle, guest_wait_thread_main,
                                           &args, "suspend-blocked-event-wait");
    ASSERT_TRUE(thread_handle.ok());
    auto process_ref = w.pm.find_process(w.last_handle);
    ASSERT_TRUE(process_ref.ok());
    auto* managed = process_ref.value().get()->as<ManagedProcess>();
    ASSERT_NE(managed, nullptr);
    const auto ids = managed->thread_ids();
    ASSERT_EQ(ids.size(), 1u);
    auto thread_ref = w.core.objects().lookup_id(ids.front());
    ASSERT_TRUE(thread_ref.ok());
    auto* thread = thread_ref.value().get()->as<xbox2pc::rt::RtThread>();
    ASSERT_NE(thread, nullptr);

    const auto blocked_deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(2);
    while (thread->state() != xbox2pc::rt::ThreadState::Blocked &&
           std::chrono::steady_clock::now() < blocked_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(args.entered.load(std::memory_order_acquire));
    ASSERT_EQ(thread->state(), xbox2pc::rt::ThreadState::Blocked);

    ASSERT_TRUE(w.pm.suspend_process(w.last_handle).ok());
    const auto parked_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (!thread->execution_control()->is_parked() &&
           std::chrono::steady_clock::now() < parked_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(thread->execution_control()->is_parked());
    EXPECT_FALSE(args.completed.load(std::memory_order_acquire));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(args.completed.load(std::memory_order_acquire));

    ASSERT_TRUE(w.pm.resume_process(w.last_handle).ok());
    const auto resumed_deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(2);
    while (thread->execution_control()->is_parked() &&
           std::chrono::steady_clock::now() < resumed_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(thread->execution_control()->is_parked());
    ASSERT_TRUE(w.grt->set_event(pid.value(), event.return_value).ok());

    const auto completed_deadline = std::chrono::steady_clock::now() +
                                    std::chrono::seconds(2);
    while (!args.completed.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < completed_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_TRUE(args.completed.load(std::memory_order_acquire));
    EXPECT_EQ(args.wait_result.load(std::memory_order_acquire), 0u);
    ASSERT_TRUE(thread->join_ns(xbox2pc::pal::kInfiniteTimeout).ok());
    ASSERT_TRUE(w.pm.terminate_process(w.last_handle, 0).ok());
}

TEST(GdkServiceTest, ProcessTerminationCancelsBlockedGuestSyncWait) {
    ApiWorld w;
    (void)w.new_process("cancel-wait.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "cancel-wait.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    ApiContext create;
    create.process_id = pid.value();
    create.arg_count = 4;
    create.args[0] = 0; create.args[1] = 1;
    create.args[2] = 0; create.args[3] = 0;
    const auto event = w.reg.dispatch("kernel32", "CreateEventW", create);
    ASSERT_TRUE(event.ok); ASSERT_NE(event.return_value, 0u);

    GuestWaitThreadArgs args;
    args.registry = &w.reg;
    args.process_id = pid.value();
    args.handle = event.return_value;
    auto thread = w.pm.spawn_thread(w.last_handle, guest_wait_thread_main,
                                    &args, "blocked-sync-wait");
    ASSERT_TRUE(thread.ok());
    while (!args.entered.load(std::memory_order_acquire))
        std::this_thread::yield();

    auto process_ref = w.pm.find_process(w.last_handle);
    ASSERT_TRUE(process_ref.ok());
    auto* managed = process_ref.value().get()->as<ManagedProcess>();
    ASSERT_NE(managed, nullptr);
    const auto thread_ids = managed->thread_ids();
    ASSERT_EQ(thread_ids.size(), 1u);
    auto thread_ref = w.core.objects().lookup_id(thread_ids.front());
    ASSERT_TRUE(thread_ref.ok());
    auto* runtime_thread = thread_ref.value().get()->as<xbox2pc::rt::RtThread>();
    ASSERT_NE(runtime_thread, nullptr);
    bool observed_blocked = false;
    for (int i = 0; i < 1000; ++i) {
        if (runtime_thread->state() == xbox2pc::rt::ThreadState::Blocked) {
            observed_blocked = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Process teardown requests cooperative stop; the wait must observe it,
    // restore the guest thread's lifecycle state, and return from the wait.
    const auto terminated = w.pm.terminate_process(w.last_handle, 0);
    EXPECT_TRUE(terminated.ok());
    EXPECT_TRUE(observed_blocked);
    EXPECT_EQ(args.wait_result.load(std::memory_order_acquire), 0xFFFFFFFFu);
}

TEST(GdkServiceTest, Win32GuestMutexAndSemaphoreLifecycle) {
    ApiWorld w;
    auto* process = w.new_process("sync-objects.exe");
    ASSERT_NE(process, nullptr);
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "sync-objects.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    ApiContext ctx;
    ctx.process_id = pid.value();
    ctx.thread_id = 101;
    ctx.arg_count = 3;
    ctx.args[0] = 0; ctx.args[1] = 1; ctx.args[2] = 0;
    auto created_mutex = w.reg.dispatch("kernel32", "CreateMutexW", ctx);
    ASSERT_TRUE(created_mutex.ok); ASSERT_NE(created_mutex.return_value, 0u);
    const auto mutex_handle = created_mutex.return_value;

    ctx.arg_count = 2; ctx.args[0] = mutex_handle; ctx.args[1] = 0;
    auto recursive = w.reg.dispatch("kernel32", "WaitForSingleObject", ctx);
    ASSERT_TRUE(recursive.ok); EXPECT_EQ(recursive.return_value, 0u);
    ctx.arg_count = 1; ctx.args[0] = mutex_handle;
    auto release_once = w.reg.dispatch("kernel32", "ReleaseMutex", ctx);
    ASSERT_TRUE(release_once.ok); EXPECT_EQ(release_once.return_value, 1u);
    auto release_twice = w.reg.dispatch("kernel32", "ReleaseMutex", ctx);
    ASSERT_TRUE(release_twice.ok); EXPECT_EQ(release_twice.return_value, 1u);
    ctx.thread_id = 202; ctx.arg_count = 2; ctx.args[0] = mutex_handle; ctx.args[1] = 0;
    auto acquired_other = w.reg.dispatch("kernel32", "WaitForSingleObject", ctx);
    ASSERT_TRUE(acquired_other.ok); EXPECT_EQ(acquired_other.return_value, 0u);
    ctx.arg_count = 1; ctx.args[0] = mutex_handle;
    auto released_other = w.reg.dispatch("kernel32", "ReleaseMutex", ctx);
    ASSERT_TRUE(released_other.ok); EXPECT_EQ(released_other.return_value, 1u);

    ctx.arg_count = 4; ctx.args[0] = 0; ctx.args[1] = 1; ctx.args[2] = 2; ctx.args[3] = 0;
    auto created_semaphore = w.reg.dispatch("kernel32", "CreateSemaphoreW", ctx);
    ASSERT_TRUE(created_semaphore.ok); ASSERT_NE(created_semaphore.return_value, 0u);
    const auto semaphore_handle = created_semaphore.return_value;
    ctx.arg_count = 2; ctx.args[0] = semaphore_handle; ctx.args[1] = 0;
    auto consumed = w.reg.dispatch("kernel32", "WaitForSingleObject", ctx);
    ASSERT_TRUE(consumed.ok); EXPECT_EQ(consumed.return_value, 0u);
    auto timed_out = w.reg.dispatch("kernel32", "WaitForSingleObject", ctx);
    ASSERT_TRUE(timed_out.ok); EXPECT_EQ(timed_out.return_value, 0x102u);
    ctx.arg_count = 3; ctx.args[0] = semaphore_handle; ctx.args[1] = 1; ctx.args[2] = 0;
    auto released = w.reg.dispatch("kernel32", "ReleaseSemaphore", ctx);
    ASSERT_TRUE(released.ok); EXPECT_EQ(released.return_value, 1u);
    // A non-null PreviousCount receives the count before the release.
    ctx.args[2] = 0x12345000;
    auto released_with_previous = w.reg.dispatch("kernel32", "ReleaseSemaphore", ctx);
    ASSERT_TRUE(released_with_previous.ok);
    EXPECT_EQ(released_with_previous.return_value, 1u);
    ASSERT_TRUE(released_with_previous.has_out);
    ASSERT_EQ(released_with_previous.out_bytes_size, sizeof(std::int32_t));
    std::int32_t previous_count = -1;
    std::memcpy(&previous_count, released_with_previous.out_bytes.data(),
                sizeof(previous_count));
    EXPECT_EQ(previous_count, 1);
    ctx.arg_count = 2; ctx.args[0] = semaphore_handle; ctx.args[1] = 0;
    auto consumed_again = w.reg.dispatch("kernel32", "WaitForSingleObject", ctx);
    ASSERT_TRUE(consumed_again.ok); EXPECT_EQ(consumed_again.return_value, 0u);

    ctx.arg_count = 1; ctx.args[0] = mutex_handle;
    EXPECT_EQ(w.reg.dispatch("kernel32", "CloseHandle", ctx).return_value, 1u);
    ctx.args[0] = semaphore_handle;
    EXPECT_EQ(w.reg.dispatch("kernel32", "CloseHandle", ctx).return_value, 1u);
}

TEST(GdkServiceTest, GuestWaitAnySelectsSignaledObjectAndHonorsTimeout) {
    ApiWorld w;
    (void)w.new_process("wait-any.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "wait-any.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    auto first = w.grt->create_event(pid.value(), true, false);
    auto second = w.grt->create_event(pid.value(), true, true);
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    const std::vector<std::uint64_t> handles{first.value(), second.value()};
    auto selected = w.grt->wait_objects_any(pid.value(), 0, handles, 0);
    ASSERT_TRUE(selected.ok());
    EXPECT_EQ(selected.value(), 1u); // WAIT_OBJECT_0 + second index

    ApiContext multi_ctx;
    multi_ctx.process_id = pid.value();
    multi_ctx.arg_count = 4;
    multi_ctx.args[0] = 2;
    multi_ctx.args[1] = 0x1000; // pointer is represented by the marshalling plan
    multi_ctx.args[2] = 0;      // wait-any
    multi_ctx.args[3] = 0;      // poll
    multi_ctx.pointer_arrays[1] = handles;
    auto win32_multi = w.reg.dispatch("kernel32", "WaitForMultipleObjects", multi_ctx);
    ASSERT_TRUE(win32_multi.ok);
    EXPECT_EQ(win32_multi.return_value, 1u);
    multi_ctx.args[2] = 1; // wait-all requires every handle to be signaled
    auto wait_all = w.reg.dispatch("kernel32", "WaitForMultipleObjects", multi_ctx);
    ASSERT_TRUE(wait_all.ok);
    EXPECT_EQ(wait_all.return_value, 0x102u); // WAIT_TIMEOUT, not WAIT_FAILED

    const std::vector<std::uint64_t> only_unsignaled{first.value()};
    auto timed_out = w.grt->wait_objects_any(pid.value(), 0, only_unsignaled, 0);
    ASSERT_TRUE(timed_out.ok());
    EXPECT_EQ(timed_out.value(), 0x102u); // WAIT_TIMEOUT

    auto auto_reset = w.grt->create_event(pid.value(), false, true);
    ASSERT_TRUE(auto_reset.ok());
    const std::vector<std::uint64_t> auto_reset_only{auto_reset.value()};
    auto consumed = w.grt->wait_objects_any(pid.value(), 0, auto_reset_only, 0);
    ASSERT_TRUE(consumed.ok());
    EXPECT_EQ(consumed.value(), 0u);
    auto no_longer_signaled = w.grt->wait_object(pid.value(), 0, auto_reset.value(), 0);
    ASSERT_TRUE(no_longer_signaled.ok());
    EXPECT_EQ(no_longer_signaled.value(), 0x102u); // auto-reset signal consumed exactly once

    auto semaphore = w.grt->create_semaphore(pid.value(), 1, 2);
    ASSERT_TRUE(semaphore.ok());
    const std::vector<std::uint64_t> mixed_waitables{first.value(), semaphore.value()};
    auto semaphore_selected = w.grt->wait_objects_any(pid.value(), 0, mixed_waitables, 0);
    ASSERT_TRUE(semaphore_selected.ok());
    EXPECT_EQ(semaphore_selected.value(), 1u); // semaphore is the second ready object
    auto semaphore_consumed = w.grt->wait_object(pid.value(), 0, semaphore.value(), 0);
    ASSERT_TRUE(semaphore_consumed.ok());
    EXPECT_EQ(semaphore_consumed.value(), 0x102u); // wait-any consumes semaphore count

    auto mutex = w.grt->create_mutex(pid.value(), 501, false);
    ASSERT_TRUE(mutex.ok());
    auto acquired_mutex = w.grt->wait_object(pid.value(), 501, mutex.value(), 0);
    ASSERT_TRUE(acquired_mutex.ok());
    EXPECT_EQ(acquired_mutex.value(), 0u);
    xbox2pc::rt::abandon_guest_mutexes_for_thread(501);
    const std::vector<std::uint64_t> abandoned_only{mutex.value()};
    auto abandoned = w.grt->wait_objects_any(pid.value(), 502, abandoned_only, 0);
    ASSERT_TRUE(abandoned.ok());
    EXPECT_EQ(abandoned.value(), 0x80u); // WAIT_ABANDONED_0 for selected mutex

    const std::vector<std::uint64_t> duplicate{first.value(), first.value()};
    EXPECT_FALSE(w.grt->wait_objects_any(pid.value(), 0, duplicate, 0).ok());
    const std::vector<std::uint64_t> too_many(65, first.value());
    EXPECT_FALSE(w.grt->wait_objects_any(pid.value(), 0, too_many, 0).ok());
}
 
TEST(GdkServiceTest, GuestWaitAllAcquiresAtomicallyAndRollsBackOnTimeout) {
    ApiWorld w;
    (void)w.new_process("wait-all.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "wait-all.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    auto auto_event = w.grt->create_event(pid.value(), false, true);
    auto semaphore = w.grt->create_semaphore(pid.value(), 0, 1);
    ASSERT_TRUE(auto_event.ok());
    ASSERT_TRUE(semaphore.ok());
    const std::vector<std::uint64_t> mixed{auto_event.value(), semaphore.value()};

    auto timed_out = w.grt->wait_objects_all(pid.value(), 0, mixed, 0);
    ASSERT_TRUE(timed_out.ok());
    EXPECT_EQ(timed_out.value(), 0x102u);

    // The auto-reset event was consumed during the failed probe, then restored.
    const std::vector<std::uint64_t> event_only{auto_event.value()};
    auto restored = w.grt->wait_objects_any(pid.value(), 0, event_only, 0);
    ASSERT_TRUE(restored.ok());
    EXPECT_EQ(restored.value(), 0u);

    ASSERT_TRUE(w.grt->set_event(pid.value(), auto_event.value()).ok());
    ASSERT_TRUE(w.grt->release_semaphore(pid.value(), semaphore.value(), 1).ok());
    auto acquired = w.grt->wait_objects_all(pid.value(), 0, mixed, 0);
    ASSERT_TRUE(acquired.ok());
    EXPECT_EQ(acquired.value(), 0u); // WAIT_OBJECT_0
    EXPECT_EQ(w.grt->wait_object(pid.value(), 0, auto_event.value(), 0).value(),
              0x102u);
    EXPECT_EQ(w.grt->wait_object(pid.value(), 0, semaphore.value(), 0).value(),
              0x102u);

    // A successful wait-all owns every acquired mutex until the guest releases it.
    auto manual_event = w.grt->create_event(pid.value(), true, true);
    auto mutex = w.grt->create_mutex(pid.value(), 0, false);
    ASSERT_TRUE(manual_event.ok());
    ASSERT_TRUE(mutex.ok());
    const std::vector<std::uint64_t> event_and_mutex{
        manual_event.value(), mutex.value()};
    auto mutex_all = w.grt->wait_objects_all(pid.value(), 700, event_and_mutex, 0);
    ASSERT_TRUE(mutex_all.ok());
    EXPECT_EQ(mutex_all.value(), 0u);
    ASSERT_TRUE(w.grt->release_mutex(pid.value(), mutex.value(), 700).ok());

    // Failed wait-all must not consume an abandoned-mutex notification.
    auto abandoned_mutex = w.grt->create_mutex(pid.value(), 701, false);
    auto unavailable = w.grt->create_semaphore(pid.value(), 0, 1);
    ASSERT_TRUE(abandoned_mutex.ok());
    ASSERT_TRUE(unavailable.ok());
    ASSERT_TRUE(w.grt->wait_object(pid.value(), 701, abandoned_mutex.value(), 0).ok());
    xbox2pc::rt::abandon_guest_mutexes_for_thread(701);
    const std::vector<std::uint64_t> abandoned_and_unavailable{
        abandoned_mutex.value(), unavailable.value()};
    auto abandoned_timeout = w.grt->wait_objects_all(
        pid.value(), 702, abandoned_and_unavailable, 0);
    ASSERT_TRUE(abandoned_timeout.ok());
    EXPECT_EQ(abandoned_timeout.value(), 0x102u);
    auto still_abandoned = w.grt->wait_object(pid.value(), 702,
                                               abandoned_mutex.value(), 0);
    ASSERT_TRUE(still_abandoned.ok());
    EXPECT_EQ(still_abandoned.value(), 0x80u);
    ASSERT_TRUE(w.grt->release_mutex(pid.value(), abandoned_mutex.value(), 702).ok());

    // Guest ABI dispatch reaches the wait-all path as well.
    ApiContext ctx;
    ctx.process_id = pid.value();
    ctx.thread_id = 703;
    ctx.arg_count = 4;
    ctx.args[0] = 2;
    ctx.args[1] = 0x1000;
    ctx.args[2] = 1;
    ctx.args[3] = 0;
    ctx.pointer_arrays[1] = event_and_mutex;
    auto api_wait_all = w.reg.dispatch("kernel32", "WaitForMultipleObjects", ctx);
    ASSERT_TRUE(api_wait_all.ok);
    EXPECT_EQ(api_wait_all.return_value, 0u);
    ASSERT_TRUE(w.grt->release_mutex(pid.value(), mutex.value(), 703).ok());

    for (const auto handle : {auto_event.value(), semaphore.value(),
                              manual_event.value(), mutex.value(),
                              abandoned_mutex.value(), unavailable.value()})
        EXPECT_TRUE(w.grt->close_sync_handle(pid.value(), handle).ok());
}

TEST(GdkServiceTest, Win32EventHandlesAreReleasedOnProcessExit) {
    ApiWorld w; auto* p=w.new_process("event-exit.exe"); ASSERT_NE(p,nullptr);
    auto pid=w.pm.resolve_pid(w.last_handle); ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor event_module;
    event_module.module_name = "event-exit-test.exe";
    event_module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, event_module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());
    const auto objects_before=w.core.objects().object_count();
    auto h=w.grt->create_event(pid.value(),false,true); ASSERT_TRUE(h.ok());
    EXPECT_EQ(w.core.objects().object_count(),objects_before+1);
    ASSERT_TRUE(w.pm.terminate_process(w.last_handle,0).ok());
    EXPECT_FALSE(w.grt->set_event(pid.value(),h.value()).ok());
    EXPECT_EQ(w.core.objects().object_count(),objects_before);
}

TEST(GdkServiceTest, DocumentedIdFallbacks) {
    ApiWorld w;
    std::uint64_t used = 0;
    auto cid = w.grt->console_id(64, &used);
    ASSERT_TRUE(cid.ok());
    EXPECT_EQ(cid.value(), "00000000.00000000.00000000.00000000.00");
    EXPECT_EQ(used, 38u);
    EXPECT_FALSE(w.grt->console_id(8, nullptr).ok());   // documented bound
    auto sid = w.grt->sandbox_id(64, &used);
    ASSERT_TRUE(sid.ok());
    EXPECT_EQ(sid.value(), "RETAIL");
    auto aid = w.grt->app_device_id(64, &used);
    ASSERT_TRUE(aid.ok());
    EXPECT_EQ(aid.value(), std::string(40, '0'));
}

TEST(GdkServiceTest, TaskQueueLifecycle) {
    ApiWorld w;
    constexpr std::uint64_t owner_pid = 77;
    auto q = w.tq->create_queue(
        owner_pid,
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(q.ok());
    const std::uint64_t id = q.value();
    // Dispatch on an empty manual queue: documented false.
    auto d = w.tq->dispatch(owner_pid, id, XTaskQueuePort::Work, 0);
    ASSERT_TRUE(d.ok());
    EXPECT_FALSE(d.value());

    const auto dispatch_start = std::chrono::steady_clock::now();
    auto timed_dispatch = w.tq->dispatch(owner_pid, id, XTaskQueuePort::Work, 15);
    const auto dispatch_elapsed = std::chrono::steady_clock::now() - dispatch_start;
    ASSERT_TRUE(timed_dispatch.ok());
    EXPECT_FALSE(timed_dispatch.value());
    EXPECT_GE(dispatch_elapsed, std::chrono::milliseconds(10));
    // An infinite manual dispatch must wake when the queue is terminated.
    std::atomic<bool> dispatch_done{false};
    std::atomic<bool> dispatch_ok{false};
    std::atomic<bool> dispatch_value{true};
    std::thread blocked_dispatch([&] {
        const auto result = w.tq->dispatch(
            owner_pid, id, XTaskQueuePort::Completion, 0xFFFFFFFFu);
        dispatch_ok.store(result.ok(), std::memory_order_release);
        dispatch_value.store(result.ok() && result.value(), std::memory_order_release);
        dispatch_done.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_FALSE(dispatch_done.load(std::memory_order_acquire));
    // Terminate: pending dispatch wakes, returns false; no callbacks exist.
    EXPECT_TRUE(w.tq->terminate_queue(owner_pid, id, true).ok());
    blocked_dispatch.join();
    EXPECT_TRUE(dispatch_done.load(std::memory_order_acquire));
    EXPECT_TRUE(dispatch_ok.load(std::memory_order_acquire));
    EXPECT_FALSE(dispatch_value.load(std::memory_order_acquire));
    d = w.tq->dispatch(owner_pid, id, XTaskQueuePort::Work, 0);
    EXPECT_FALSE(d.value());
    // Close drops the queue.
    EXPECT_TRUE(w.tq->close_queue(owner_pid, id).ok());
    auto gone = w.tq->dispatch(owner_pid, id, XTaskQueuePort::Work, 0);
    EXPECT_FALSE(gone.ok());   // unknown handle now
    // Unknown mode values rejected.
    EXPECT_FALSE(w.tq->create_queue(owner_pid, 99, 2).ok());
}

TEST(GdkServiceTest, TaskQueueDuplicateHandlesShareLifetime) {
    ApiWorld w;
    constexpr std::uint64_t owner_pid = 303;
    auto created = w.tq->create_queue(
        owner_pid,
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(created.ok());
    const auto original = created.value();

    auto duplicated = w.tq->duplicate_queue(owner_pid, original);
    ASSERT_TRUE(duplicated.ok());
    EXPECT_NE(duplicated.value(), original);
    EXPECT_EQ(w.tq->live_queues(), 1u); // one queue object, two handles

    std::atomic<bool> dispatch_done{false};
    std::atomic<bool> dispatch_ok{false};
    std::thread blocked_dispatch([&] {
        const auto result = w.tq->dispatch(
            owner_pid, original, XTaskQueuePort::Work, 0xFFFFFFFFu);
        dispatch_ok.store(result.ok(), std::memory_order_release);
        dispatch_done.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_FALSE(dispatch_done.load(std::memory_order_acquire));

    // Closing the original handle cannot cancel a wait whose duplicated
    // handle still retains the same queue object.
    EXPECT_TRUE(w.tq->close_queue(owner_pid, original).ok());
    EXPECT_EQ(w.tq->live_queues(), 1u);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_FALSE(dispatch_done.load(std::memory_order_acquire));

    EXPECT_TRUE(w.tq->terminate_queue(owner_pid, duplicated.value(), true).ok());
    blocked_dispatch.join();
    EXPECT_TRUE(dispatch_done.load(std::memory_order_acquire));
    EXPECT_TRUE(dispatch_ok.load(std::memory_order_acquire));
    EXPECT_TRUE(w.tq->dispatch(owner_pid, duplicated.value(),
                               XTaskQueuePort::Work, 0).ok());

    EXPECT_TRUE(w.tq->close_queue(owner_pid, duplicated.value()).ok());
    EXPECT_EQ(w.tq->live_queues(), 0u);
}

TEST(GdkServiceTest, TaskQueueDuplicateHandleApiWritesOutHandle) {
    ApiWorld w;
    (void)w.new_process("task-queue-duplicate-api.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());

    auto created = w.tq->create_queue(
        pid.value(),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(created.ok());

    ApiContext ctx;
    ctx.process_id = pid.value();
    ctx.arg_count = 2;
    ctx.args[0] = created.value();
    ctx.args[1] = 0x10000; // bridge validates/writes this guest output pointer
    const auto result = w.reg.dispatch("xgameruntime",
                                       "XTaskQueueDuplicateHandle", ctx);
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.return_value, 0u); // S_OK
    ASSERT_TRUE(result.has_out);
    EXPECT_EQ(result.out_size, 8u);
    EXPECT_NE(result.out_value, 0u);
    EXPECT_NE(result.out_value, created.value());

    EXPECT_TRUE(w.tq->close_queue(pid.value(), created.value()).ok());
    EXPECT_TRUE(w.tq->dispatch(pid.value(), result.out_value,
                               XTaskQueuePort::Work, 0).ok());
    EXPECT_TRUE(w.tq->close_queue(pid.value(), result.out_value).ok());
    EXPECT_EQ(w.tq->live_queues(), 0u);
    ASSERT_TRUE(w.pm.terminate_process(w.last_handle, 0).ok());
}

TEST(GdkServiceTest, ProcessExitReleasesDuplicatedTaskQueueAndWakesDispatch) {
    ApiWorld w;
    (void)w.new_process("task-queue-process-exit.exe");
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "task-queue-process-exit.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module, xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());
    const auto pid_result = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid_result.ok());
    const auto pid = pid_result.value();

    auto created = w.tq->create_queue(
        pid,
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(created.ok());
    auto duplicate = w.tq->duplicate_queue(pid, created.value());
    ASSERT_TRUE(duplicate.ok());
    EXPECT_EQ(w.tq->live_queues(), 1u);

    std::atomic<bool> done{false};
    std::atomic<bool> succeeded{false};
    std::thread waiter([&] {
        const auto result = w.tq->dispatch(
            pid, duplicate.value(), XTaskQueuePort::Work, 0xFFFFFFFFu);
        succeeded.store(result.ok(), std::memory_order_release);
        done.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_FALSE(done.load(std::memory_order_acquire));

    const auto terminated = w.pm.terminate_process(w.last_handle, 0);
    waiter.join();
    ASSERT_TRUE(terminated.ok());
    EXPECT_TRUE(done.load(std::memory_order_acquire));
    EXPECT_TRUE(succeeded.load(std::memory_order_acquire));
    EXPECT_EQ(w.tq->live_queues(), 0u);
    EXPECT_FALSE(w.tq->dispatch(pid, created.value(),
                                XTaskQueuePort::Work, 0).ok());
    EXPECT_FALSE(w.tq->dispatch(pid, duplicate.value(),
                                XTaskQueuePort::Work, 0).ok());
}

TEST(GdkServiceTest, TaskQueueFinalCloseWakesDispatchAcrossAliases) {
    ApiWorld w;
    constexpr std::uint64_t owner_pid = 404;
    auto created = w.tq->create_queue(
        owner_pid,
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(created.ok());
    auto duplicate = w.tq->duplicate_queue(owner_pid, created.value());
    ASSERT_TRUE(duplicate.ok());

    std::atomic<bool> done{false};
    std::atomic<bool> ok{false};
    std::thread waiter([&] {
        const auto result = w.tq->dispatch(
            owner_pid, duplicate.value(), XTaskQueuePort::Completion, 0xFFFFFFFFu);
        ok.store(result.ok(), std::memory_order_release);
        done.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_FALSE(done.load(std::memory_order_acquire));

    const auto close_original = w.tq->close_queue(owner_pid, created.value());
    EXPECT_TRUE(close_original.ok());
    EXPECT_FALSE(done.load(std::memory_order_acquire));
    const auto close_duplicate = w.tq->close_queue(owner_pid, duplicate.value());
    EXPECT_TRUE(close_duplicate.ok());
    waiter.join();
    EXPECT_TRUE(done.load(std::memory_order_acquire));
    EXPECT_TRUE(ok.load(std::memory_order_acquire));
    EXPECT_EQ(w.tq->live_queues(), 0u);
}

TEST(GdkServiceTest, TaskQueueHandlesAreProcessScoped) {
    ApiWorld w;
    constexpr std::uint64_t owner_pid = 101;
    constexpr std::uint64_t foreign_pid = 202;
    auto q = w.tq->create_queue(
        owner_pid,
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(q.ok());
    EXPECT_FALSE(w.tq->dispatch(foreign_pid, q.value(),
                                XTaskQueuePort::Work, 0).ok());
    EXPECT_FALSE(w.tq->duplicate_queue(foreign_pid, q.value()).ok());
    EXPECT_FALSE(w.tq->terminate_queue(foreign_pid, q.value(), false).ok());
    EXPECT_FALSE(w.tq->close_queue(foreign_pid, q.value()).ok());
    EXPECT_EQ(w.tq->live_queues(), 1u);
    EXPECT_TRUE(w.tq->dispatch(owner_pid, q.value(),
                               XTaskQueuePort::Work, 0).ok());
    EXPECT_FALSE(w.tq->dispatch(owner_pid, q.value(),
                                static_cast<XTaskQueuePort>(99), 0).ok());
    EXPECT_TRUE(w.tq->close_queue(owner_pid, q.value()).ok());
    EXPECT_EQ(w.tq->live_queues(), 0u);
}

TEST(GdkServiceTest, ProcessExitReleasesOwnedTaskQueues) {
    ApiWorld w;
    (void)w.new_process("task-queue-exit.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    auto q = w.tq->create_queue(
        pid.value(),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual),
        static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual));
    ASSERT_TRUE(q.ok());
    EXPECT_EQ(w.tq->live_queues(), 1u);
    ASSERT_TRUE(w.pm.terminate_process(w.last_handle, 0).ok());
    EXPECT_EQ(w.tq->live_queues(), 0u);
    EXPECT_FALSE(w.tq->dispatch(pid.value(), q.value(),
                                XTaskQueuePort::Work, 0).ok());
}

TEST(GdkServiceTest, VirtualQueryReportsTrackedGuestRegions) {
    ApiWorld w; auto* proc = w.new_process("virtual-query.exe"); ASSERT_NE(proc,nullptr);
    const auto pid=w.pm.resolve_pid(w.last_handle); ASSERT_TRUE(pid.ok());
    auto base=w.pm.reserve_region(w.last_handle,0x2000,"query-region"); ASSERT_TRUE(base.ok());
    ASSERT_TRUE(w.pm.commit_region(w.last_handle,base.value()).ok());
    ASSERT_TRUE(w.pm.protect_region(w.last_handle,base.value(),xbox2pc::rt::MemProtect::ReadWrite,{}).ok());
    ApiContext ctx; ctx.process_id=pid.value(); ctx.arg_count=3; ctx.args[0]=base.value()+0x123; ctx.args[1]=0x100000; ctx.args[2]=48;
    const auto result=w.reg.dispatch("kernel32","VirtualQuery",ctx); ASSERT_TRUE(result.ok)<<result.error;
    EXPECT_EQ(result.return_value,48u); ASSERT_TRUE(result.has_out); EXPECT_EQ(result.out_bytes_size,48u);
    auto rd32=[&](const ApiCallResult& r,std::size_t o){std::uint32_t v=0;for(unsigned i=0;i<4;++i)v|=std::uint32_t(r.out_bytes[o+i])<<(8*i);return v;};
    auto rd64=[&](const ApiCallResult& r,std::size_t o){std::uint64_t v=0;for(unsigned i=0;i<8;++i)v|=std::uint64_t(r.out_bytes[o+i])<<(8*i);return v;};
    EXPECT_EQ(rd64(result,0),base.value()); EXPECT_EQ(rd64(result,8),base.value()); EXPECT_EQ(rd64(result,24),0x2000u);
    EXPECT_EQ(rd32(result,32),0x1000u); EXPECT_EQ(rd32(result,36),0x04u);
    EXPECT_EQ(rd32(result,16),0x04u); // original allocation protection
    EXPECT_EQ(rd32(result,40),0x20000u); // MEM_PRIVATE
    // Querying the second page still returns the full contiguous region,
    // rather than a page-relative suffix.
    ctx.args[0]=base.value()+0x1123;
    const auto second_page=w.reg.dispatch("kernel32","VirtualQuery",ctx);
    ASSERT_TRUE(second_page.ok); EXPECT_EQ(second_page.return_value,48u);
    EXPECT_EQ(rd64(second_page,0),base.value());
    EXPECT_EQ(rd64(second_page,24),0x2000u);
    // The gap immediately following the allocation is a MEM_FREE region.
    ctx.args[0]=base.value()+0x2123;
    const auto free_region=w.reg.dispatch("kernel32","VirtualQuery",ctx);
    ASSERT_TRUE(free_region.ok); EXPECT_EQ(free_region.return_value,48u);
    EXPECT_EQ(rd64(free_region,0),base.value()+0x2000);
    EXPECT_EQ(rd64(free_region,8),0u);
    EXPECT_EQ(rd64(free_region,24),proc->address_space().capacity()-0x2000);
    EXPECT_EQ(rd32(free_region,32),0x10000u); // MEM_FREE
    EXPECT_EQ(rd32(free_region,16),0u); // no AllocationProtect for MEM_FREE
    EXPECT_EQ(rd32(free_region,36),0x01u);    // PAGE_NOACCESS
    EXPECT_EQ(rd32(free_region,40),0u);       // no MEM_PRIVATE type for free memory
    ctx.args[0]=0x7FFFFFFFFFFFFFFFull; const auto bad=w.reg.dispatch("kernel32","VirtualQuery",ctx); ASSERT_TRUE(bad.ok); EXPECT_EQ(bad.return_value,0u);
    ctx.args[2]=47; const auto short_buf=w.reg.dispatch("kernel32","VirtualQuery",ctx); ASSERT_TRUE(short_buf.ok); EXPECT_EQ(short_buf.return_value,0u);
}

TEST(GdkServiceTest, Win32VirtualMemoryLifecycle) {
    ApiWorld w;
    (void)w.new_process("virtual-memory-api.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "virtual-memory-api.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module, xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());
    ApiContext ctx; ctx.process_id = pid.value(); ctx.arg_count = 4;
    ctx.args[0] = 0; ctx.args[1] = 0x3000; ctx.args[2] = 0x3000; ctx.args[3] = 0x04;
    const auto allocated = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(allocated.ok) << allocated.error;
    ASSERT_NE(allocated.return_value, 0u);
    const auto base = allocated.return_value;
    ctx.args[0] = base; ctx.args[1] = 0x3000; ctx.args[2] = 0x02; ctx.args[3] = 0x10000;
    const auto changed = w.reg.dispatch("kernel32", "VirtualProtect", ctx);
    ASSERT_TRUE(changed.ok); ASSERT_EQ(changed.return_value, 1u);
    ASSERT_TRUE(changed.has_out); ASSERT_EQ(changed.out_bytes_size, 4u);
    EXPECT_EQ(changed.out_bytes[0], 0x04u);
    ctx.args[0] = base; ctx.args[1] = 0x3000; ctx.args[2] = 0x01; ctx.args[3] = 0x10000;
    const auto no_access = w.reg.dispatch("kernel32", "VirtualProtect", ctx);
    ASSERT_TRUE(no_access.ok); ASSERT_EQ(no_access.return_value, 1u);
    EXPECT_EQ(no_access.out_bytes[0], 0x02u); // previous PAGE_READONLY
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0x100000; ctx.args[2] = 48;
    const auto query_after_protect = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(query_after_protect.ok);
    EXPECT_EQ(query_after_protect.return_value, 48u);
    EXPECT_EQ(query_after_protect.out_bytes[16], 0x04u);
    EXPECT_EQ(query_after_protect.out_bytes[36], 0x01u);
    ctx.args[0] = base; ctx.args[1] = 0; ctx.args[2] = 0x8000;
    const auto released = w.reg.dispatch("kernel32", "VirtualFree", ctx);
    ASSERT_TRUE(released.ok); EXPECT_EQ(released.return_value, 1u);
    const auto stats = w.pm.process_stats(w.last_handle);
    EXPECT_EQ(stats.reserved_bytes, 0u); EXPECT_EQ(stats.committed_bytes, 0u);
}

TEST(GdkServiceTest, VirtualAllocEnforcesWxPolicyForEveryAllocationForm) {
    ApiWorld w;
    (void)w.new_process("virtual-memory-wx.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "virtual-memory-wx.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    ApiContext ctx;
    ctx.process_id = pid.value();
    ctx.arg_count = 4;
    ctx.args[0] = 0;
    ctx.args[1] = 0x2000;
    ctx.args[2] = 0x3000;  // MEM_RESERVE | MEM_COMMIT
    ctx.args[3] = 0x40;    // PAGE_EXECUTE_READWRITE
    const auto combined = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(combined.ok);
    EXPECT_EQ(combined.return_value, 0u);

    ctx.args[2] = 0x2000;  // MEM_RESERVE only
    ctx.args[3] = 0x04;    // PAGE_READWRITE
    const auto reserved = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(reserved.ok);
    ASSERT_NE(reserved.return_value, 0u);
    const auto base = reserved.return_value;

    ctx.args[0] = base;
    ctx.args[2] = 0x1000;  // MEM_COMMIT into the existing reservation
    ctx.args[3] = 0x40;    // PAGE_EXECUTE_READWRITE
    const auto commit = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(commit.ok);
    EXPECT_EQ(commit.return_value, 0u);

    const auto stats = w.pm.process_stats(w.last_handle);
    EXPECT_EQ(stats.reserved_bytes, 0x2000u);
    EXPECT_EQ(stats.committed_bytes, 0u);

    ctx.arg_count = 3;
    ctx.args[0] = base;
    ctx.args[1] = 0;
    ctx.args[2] = 0x8000;  // MEM_RELEASE
    const auto released = w.reg.dispatch("kernel32", "VirtualFree", ctx);
    ASSERT_TRUE(released.ok);
    EXPECT_EQ(released.return_value, 1u);
}

TEST(GdkServiceTest, Win32VirtualMemoryReserveAndFlagValidation) {
    ApiWorld w;
    (void)w.new_process("virtual-memory-reserve.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle); ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "virtual-memory-reserve.exe"; module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module, xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());
    ApiContext ctx; ctx.process_id = pid.value(); ctx.arg_count = 4;
    ctx.args[0] = 0; ctx.args[1] = 0x2000; ctx.args[2] = 0x2000; ctx.args[3] = 0x04;
    const auto reserved = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(reserved.ok); ASSERT_NE(reserved.return_value, 0u);
    const auto base = reserved.return_value;
    ctx.args[0] = base; ctx.args[1] = 0x2000; ctx.args[2] = 0x1000; ctx.args[3] = 0x04;
    const auto committed = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(committed.ok); EXPECT_EQ(committed.return_value, base);
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0x1000; ctx.args[2] = 0x4000;
    const auto partial_decommit = w.reg.dispatch("kernel32", "VirtualFree", ctx);
    ASSERT_TRUE(partial_decommit.ok);
    EXPECT_EQ(partial_decommit.return_value, 1u);
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0x100000; ctx.args[2] = 48;
    const auto first_page_reserved = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(first_page_reserved.ok);
    ASSERT_EQ(first_page_reserved.return_value, 48u);
    EXPECT_EQ(first_page_reserved.out_bytes[32], 0x00u);
    EXPECT_EQ(first_page_reserved.out_bytes[33], 0x20u); // MEM_RESERVE
    ctx.args[0] = base + 0x1000;
    const auto second_page_committed = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(second_page_committed.ok);
    EXPECT_EQ(second_page_committed.out_bytes[32], 0x00u);
    EXPECT_EQ(second_page_committed.out_bytes[33], 0x10u); // MEM_COMMIT
    ctx.arg_count = 3; ctx.args[0] = base + 0x1000; ctx.args[1] = 0x1000; ctx.args[2] = 0x4000;
    const auto decommitted = w.reg.dispatch("kernel32", "VirtualFree", ctx);
    ASSERT_TRUE(decommitted.ok); EXPECT_EQ(decommitted.return_value, 1u);
    // MEM_DECOMMIT preserves the reservation while returning the region to MEM_RESERVE.
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0x100000; ctx.args[2] = 48;
    const auto after_decommit = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(after_decommit.ok);
    ASSERT_EQ(after_decommit.return_value, 48u);
    EXPECT_EQ(after_decommit.out_bytes[32], 0x00u);
    EXPECT_EQ(after_decommit.out_bytes[33], 0x20u); // MEM_RESERVE
    ctx.arg_count = 4; ctx.args[0] = base; ctx.args[1] = 0x2000; ctx.args[2] = 0x1000; ctx.args[3] = 0x04;
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualAlloc", ctx).return_value, base);
    ctx.args[2] = 0x800; // MEM_RESET is deliberately unsupported.
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualAlloc", ctx).return_value, 0u);
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0; ctx.args[2] = 0x8000;
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualFree", ctx).return_value, 1u);
}

TEST(GdkServiceTest, Win32VirtualMemorySupportsPartialPageRanges) {
    ApiWorld w;
    (void)w.new_process("virtual-memory-partial.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "virtual-memory-partial.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module, xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    ApiContext ctx;
    ctx.process_id = pid.value();
    ctx.arg_count = 4;
    ctx.args[0] = 0;
    ctx.args[1] = 4 * 4096;
    ctx.args[2] = 0x2000; // MEM_RESERVE
    ctx.args[3] = 0x04;   // PAGE_READWRITE
    const auto reserved = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(reserved.ok);
    ASSERT_NE(reserved.return_value, 0u);
    const auto base = reserved.return_value;

    // Commit a two-page subrange beginning one page into the reservation.
    ctx.args[0] = base + 4096;
    ctx.args[1] = 2 * 4096;
    ctx.args[2] = 0x1000; // MEM_COMMIT
    const auto committed = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(committed.ok);
    EXPECT_EQ(committed.return_value, base + 4096);

    // Change protection on just the first committed page.
    ctx.arg_count = 4;
    ctx.args[0] = base + 4096;
    ctx.args[1] = 4096;
    ctx.args[2] = 0x02; // PAGE_READONLY
    ctx.args[3] = 0x1000; // old protection output pointer
    const auto protected_range = w.reg.dispatch("kernel32", "VirtualProtect", ctx);
    ASSERT_TRUE(protected_range.ok);
    EXPECT_EQ(protected_range.return_value, 1u);
    ASSERT_EQ(protected_range.out_bytes_size, 4u);
    EXPECT_EQ(protected_range.out_bytes[0], 0x04u); // previous PAGE_READWRITE

    // A byte range crossing into the following reserved page must fail
    // without changing either page; a short range within the committed
    // page is rounded to that whole page.
    ctx.args[0] = base + 3 * 4096 - 64;
    ctx.args[1] = 128;
    ctx.args[2] = 0x02;
    ctx.args[3] = 0x1000;
    const auto crosses_reserved = w.reg.dispatch("kernel32", "VirtualProtect", ctx);
    ASSERT_TRUE(crosses_reserved.ok);
    EXPECT_EQ(crosses_reserved.return_value, 0u);
    ctx.args[1] = 64;
    const auto tail_page = w.reg.dispatch("kernel32", "VirtualProtect", ctx);
    ASSERT_TRUE(tail_page.ok);
    EXPECT_EQ(tail_page.return_value, 1u);
    EXPECT_EQ(tail_page.out_bytes[0], 0x04u); // second committed page was RW

    // A commit spanning an already-committed page and a reserved page is
    // idempotent for the former and applies the requested protection only
    // to the newly committed page.
    ctx.args[0] = base + 2 * 4096;
    ctx.args[1] = 2 * 4096;
    ctx.args[2] = 0x1000; // MEM_COMMIT
    ctx.args[3] = 0x04;   // PAGE_READWRITE
    const auto mixed_commit = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(mixed_commit.ok);
    EXPECT_EQ(mixed_commit.return_value, base + 2 * 4096);
    ctx.arg_count = 3;
    ctx.args[1] = 0x100000;
    ctx.args[2] = 48;
    auto existing_page = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(existing_page.ok);
    EXPECT_EQ(existing_page.out_bytes[36], 0x02u); // existing page stays READONLY
    ctx.args[0] = base + 3 * 4096;
    auto new_page = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(new_page.ok);
    EXPECT_EQ(new_page.out_bytes[33], 0x10u); // newly committed
    EXPECT_EQ(new_page.out_bytes[36], 0x04u); // requested READWRITE

    // Decommit the second page only, preserving the first page's protection.
    ctx.arg_count = 3;
    ctx.args[0] = base + 2 * 4096;
    ctx.args[1] = 4096;
    ctx.args[2] = 0x4000; // MEM_DECOMMIT
    const auto decommitted = w.reg.dispatch("kernel32", "VirtualFree", ctx);
    ASSERT_TRUE(decommitted.ok);
    EXPECT_EQ(decommitted.return_value, 1u);

    // Query all three segments independently.
    ctx.arg_count = 3;
    ctx.args[0] = base;
    ctx.args[1] = 0x100000;
    ctx.args[2] = 48;
    auto q = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(q.ok);
    EXPECT_EQ(q.out_bytes[32], 0x00u);
    EXPECT_EQ(q.out_bytes[33], 0x20u); // MEM_RESERVE
    ctx.args[0] = base + 4096;
    q = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(q.ok);
    EXPECT_EQ(q.out_bytes[32], 0x00u);
    EXPECT_EQ(q.out_bytes[33], 0x10u); // MEM_COMMIT
    EXPECT_EQ(q.out_bytes[36], 0x02u); // PAGE_READONLY
    ctx.args[0] = base + 2 * 4096;
    q = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(q.ok);
    EXPECT_EQ(q.out_bytes[32], 0x00u);
    EXPECT_EQ(q.out_bytes[33], 0x20u); // MEM_RESERVE

    // MEM_RELEASE still accepts only the original allocation base and frees
    // every metadata segment produced by partial operations.
    ctx.args[0] = base + 4096;
    ctx.args[1] = 0;
    ctx.args[2] = 0x8000;
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualFree", ctx).return_value, 0u);
    ctx.args[0] = base;
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualFree", ctx).return_value, 1u);
}

TEST(GdkServiceTest, VirtualQueryPreservesReservedAllocationProtection) {
    ApiWorld w;
    (void)w.new_process("virtual-query-allocation-protect.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "virtual-query-allocation-protect.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module, xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());
    ApiContext ctx; ctx.process_id = pid.value(); ctx.arg_count = 4;
    ctx.args[0] = 0; ctx.args[1] = 0x2000; ctx.args[2] = 0x2000; ctx.args[3] = 0x02;
    const auto reserved = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(reserved.ok); ASSERT_NE(reserved.return_value, 0u);
    const auto base = reserved.return_value;
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0x100000; ctx.args[2] = 48;
    const auto before_commit = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(before_commit.ok); ASSERT_EQ(before_commit.return_value, 48u);
    EXPECT_EQ(before_commit.out_bytes[16], 0x02u);
    EXPECT_EQ(static_cast<std::uint32_t>(before_commit.out_bytes[32]) |
                  (static_cast<std::uint32_t>(before_commit.out_bytes[33]) << 8),
              0x2000u); // little-endian MEMORY_BASIC_INFORMATION.State
    ctx.arg_count = 4; ctx.args[0] = base; ctx.args[1] = 0x2000; ctx.args[2] = 0x1000; ctx.args[3] = 0x04;
    const auto committed = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(committed.ok); EXPECT_EQ(committed.return_value, base);
    ctx.arg_count = 3; ctx.args[0] = base; ctx.args[1] = 0x100000; ctx.args[2] = 48;
    const auto after_commit = w.reg.dispatch("kernel32", "VirtualQuery", ctx);
    ASSERT_TRUE(after_commit.ok);
    EXPECT_EQ(after_commit.out_bytes[16], 0x02u);
    EXPECT_EQ(after_commit.out_bytes[36], 0x04u);
    ctx.args[0] = base; ctx.args[1] = 0; ctx.args[2] = 0x8000;
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualFree", ctx).return_value, 1u);
}

TEST(GdkServiceTest, Win32VirtualAllocSupportsFixedAllocationGranularity) {
    ApiWorld w;
    (void)w.new_process("virtual-memory-fixed.exe");
    const auto pid = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid.ok());
    xbox2pc::rt::ModuleDescriptor module;
    module.module_name = "virtual-memory-fixed.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(w.last_handle, module,
                                        xbox2pc::rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(w.last_handle).ok());

    auto process = w.pm.find_process_by_pid(pid.value());
    ASSERT_TRUE(process.ok());
    auto* managed = process.value().get()->as<xbox2pc::rt::ManagedProcess>();
    ASSERT_NE(managed, nullptr);
    const std::uint64_t space_base = managed->address_space().base();
    const std::uint64_t fixed_base =
        (space_base + 0x1FFFFull) & ~0xFFFFull;
    ASSERT_NE(fixed_base, 0u);

    ApiContext ctx;
    ctx.process_id = pid.value();
    ctx.arg_count = 4;
    ctx.args[0] = fixed_base + 0x2345;  // reserve rounds down to 64-KiB
    ctx.args[1] = 0x2000;
    ctx.args[2] = 0x2000;  // MEM_RESERVE
    ctx.args[3] = 0x04;    // PAGE_READWRITE
    const auto reserved = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(reserved.ok);
    EXPECT_EQ(reserved.return_value, fixed_base);

    const auto overlap = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(overlap.ok);
    EXPECT_EQ(overlap.return_value, 0u);

    ctx.args[0] = fixed_base;
    ctx.args[2] = 0x1000;  // MEM_COMMIT
    const auto committed = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(committed.ok);
    EXPECT_EQ(committed.return_value, fixed_base);

    ctx.arg_count = 3;
    ctx.args[0] = fixed_base;
    ctx.args[1] = 0;
    ctx.args[2] = 0x8000;  // MEM_RELEASE
    const auto released = w.reg.dispatch("kernel32", "VirtualFree", ctx);
    ASSERT_TRUE(released.ok);
    EXPECT_EQ(released.return_value, 1u);

    ctx.arg_count = 4;
    ctx.args[0] = fixed_base + 0x1000;
    ctx.args[1] = 0x2000;
    ctx.args[2] = 0x3000;  // fixed MEM_RESERVE | MEM_COMMIT
    ctx.args[3] = 0x04;
    const auto combined = w.reg.dispatch("kernel32", "VirtualAlloc", ctx);
    ASSERT_TRUE(combined.ok);
    EXPECT_EQ(combined.return_value, fixed_base);
    ctx.arg_count = 3;
    ctx.args[0] = fixed_base;
    ctx.args[1] = 0;
    ctx.args[2] = 0x8000;
    EXPECT_EQ(w.reg.dispatch("kernel32", "VirtualFree", ctx).return_value, 1u);
}

TEST(GdkServiceTest, TimingNativeEquivalents) {
    ApiWorld w;
    auto v1 = w.tim->qpc_value();
    ASSERT_TRUE(v1.ok());
    auto v2 = w.tim->qpc_value();
    ASSERT_TRUE(v2.ok());
    EXPECT_GE(v2.value(), v1.value());   // monotonic
    EXPECT_EQ(w.tim->qpc_frequency().value(), 1'000'000'000ull);
}

TEST(GdkServiceTest, ThreadTimeSensitiveBitsAreProcessScoped) {
    ApiWorld w;
    EXPECT_TRUE(w.grt->set_time_sensitive(10, 7, true).ok());
    EXPECT_TRUE(w.grt->is_time_sensitive(10, 7).value());
    EXPECT_FALSE(w.grt->is_time_sensitive(20, 7).value());
    EXPECT_TRUE(w.grt->set_time_sensitive(20, 7, true).ok());
    EXPECT_TRUE(w.grt->is_time_sensitive(20, 7).value());
    EXPECT_TRUE(w.grt->is_time_sensitive(10, 7).value());
    EXPECT_TRUE(w.grt->set_time_sensitive(10, 7, false).ok());
    EXPECT_FALSE(w.grt->is_time_sensitive(10, 7).value());
    EXPECT_TRUE(w.grt->is_time_sensitive(20, 7).value());
    EXPECT_FALSE(w.grt->set_time_sensitive(0, 7, true).ok());
    EXPECT_FALSE(w.grt->is_time_sensitive(10, 0).ok());
    w.grt->release_process(20);
    EXPECT_FALSE(w.grt->is_time_sensitive(20, 7).value());
    EXPECT_FALSE(w.grt->is_time_sensitive(10, 7).value());
}

TEST(GdkServiceTest, ProcessTerminationReleasesGameRuntimeState) {
    ApiWorld w;
    (void)w.new_process("gdk-exit.exe");
    const auto pid_result = w.pm.resolve_pid(w.last_handle);
    ASSERT_TRUE(pid_result.ok());
    const std::uint64_t pid = pid_result.value();

    const auto first_init = w.grt->grt_initialize(pid);
    ASSERT_TRUE(first_init.ok());
    EXPECT_EQ(first_init.value(), 1u);
    const auto second_init = w.grt->grt_initialize(pid);
    ASSERT_TRUE(second_init.ok());
    EXPECT_EQ(second_init.value(), 2u);
    ASSERT_TRUE(w.grt->set_time_sensitive(pid, 17, true).ok());
    ASSERT_TRUE(w.grt->is_time_sensitive(pid, 17).value());

    ASSERT_TRUE(w.pm.terminate_process(w.last_handle, 0).ok());
    EXPECT_FALSE(w.grt->is_time_sensitive(pid, 17).value());
    const auto after_exit = w.grt->grt_initialize(pid);
    ASSERT_TRUE(after_exit.ok());
    EXPECT_EQ(after_exit.value(), 1u);
}

TEST(GdkServiceTest, ThreadTimeSensitiveDispatchUsesCallingThreadIdentity) {
    ApiWorld w;
    ApiContext ctx;
    ctx.process_id = 100;
    ctx.thread_id = 7;
    ctx.arg_count = 1;
    ctx.args[0] = 1;
    auto set = w.reg.dispatch("xgameruntime", "XThreadSetTimeSensitive", ctx);
    ASSERT_TRUE(set.ok);
    EXPECT_EQ(set.return_value, kSOk);
    // XThreadIsTimeSensitive has no arguments; the set call above takes one.
    ctx.arg_count = 0;
    ctx.process_id = 200;
    auto other_process = w.reg.dispatch("xgameruntime", "XThreadIsTimeSensitive", ctx);
    ASSERT_TRUE(other_process.ok);
    EXPECT_EQ(other_process.return_value, 0u);
    ctx.process_id = 100;
    auto same_thread = w.reg.dispatch("xgameruntime", "XThreadIsTimeSensitive", ctx);
    ASSERT_TRUE(same_thread.ok);
    EXPECT_EQ(same_thread.return_value, 1u);
    ctx.thread_id = 0;
    auto missing_identity = w.reg.dispatch("xgameruntime", "XThreadSetTimeSensitive", ctx);
    EXPECT_FALSE(missing_identity.ok);
}

TEST(GdkServiceTest, ServiceInitializationOrderingAndRollback) {
    // A service whose on_initialize FAILS: initialize_all must roll back
    // the earlier-initialized services.
    class FailingService : public xbox2pc::rt::RtService {
    public:
        FailingService() : RtService("failing") {}
        static const char* service_type_name() { return "failing"; }
        xbox2pc::rt::Result<void> on_initialize() override {
            return xbox2pc::rt::Result<void>(xbox2pc::rt::RuntimeErrc::ServiceFailed,
                                             "deliberate failure");
        }
    };
    ApiRegistry reg;
    RuntimeCore core;
    xbox2pc::rt::ProcessManager pm(core.objects());
    {
        auto grt = std::make_unique<GameRuntimeService>(reg, pm);
        EXPECT_TRUE(core.services().register_service(std::move(grt)).ok());
        EXPECT_TRUE(core.services()
                        .register_service(std::make_unique<FailingService>())
                        .ok());
    }
    auto init = core.initialize();
    EXPECT_FALSE(init.ok());
    // M3 semantics: a failed initialize_all reports the failure; services
    // initialized BEFORE the failing one remain Ready until an explicit
    // shutdown_all. After core.shutdown() (or shutdown_all), the API
    // implementations are revoked.
    ApiContext ctx;
    auto r = reg.dispatch("xgameruntime", "XSystemGetDeviceType", ctx);
    EXPECT_TRUE(r.ok);   // GameRuntimeService initialized first and stays Ready
    // core.shutdown() refuses from the Failed state (M3 rule); the explicit
    // registry shutdown is the sanctioned path here.
    EXPECT_TRUE(core.services().shutdown_all().ok());
    r = reg.dispatch("xgameruntime", "XSystemGetDeviceType", ctx);
    EXPECT_FALSE(r.ok);   // revoked at shutdown
}

TEST(GdkServiceTest, CurrentProcessAndThreadIdentityQueries) {
    ApiWorld w;
    ApiContext ctx;
    ctx.process_id = 0x1234;
    ctx.thread_id = 0x5678;

    const auto pid = w.reg.dispatch("kernel32", "GetCurrentProcessId", ctx);
    ASSERT_TRUE(pid.ok) << pid.error;
    EXPECT_EQ(pid.return_value, 0x1234u);

    const auto tid = w.reg.dispatch("kernel32", "GetCurrentThreadId", ctx);
    ASSERT_TRUE(tid.ok) << tid.error;
    EXPECT_EQ(tid.return_value, 0x5678u);

    ctx.process_id = 0;
    const auto no_process = w.reg.dispatch("kernel32", "GetCurrentProcessId", ctx);
    EXPECT_FALSE(no_process.ok);

    ctx.process_id = 0x1234;
    ctx.thread_id = 0;
    const auto no_thread = w.reg.dispatch("kernel32", "GetCurrentThreadId", ctx);
    EXPECT_FALSE(no_thread.ok);

    ctx.thread_id = static_cast<std::uint64_t>(
        std::numeric_limits<std::uint32_t>::max()) + 1;
    const auto overflow = w.reg.dispatch("kernel32", "GetCurrentThreadId", ctx);
    EXPECT_FALSE(overflow.ok);
}

// ── 12.6 TLS ──────────────────────────────────────────────────────────────

TEST(TlsTest, MultipleModulesDistinctIndicesAndInit) {
    ApiWorld w;
    PeBuildSpec specA;
    specA.tls.template_data = {1, 2, 3, 4};
    specA.tls.zero_fill = 8;
    auto imageA = PeBuilder(specA).build();
    Diagnostics dA;
    auto imgA = xbox2pc::pe::parse(imageA.data(), imageA.size(), "a.exe", dA);
    LoadDiagnostics ld;
    auto tlsA = decode_tls(imgA, imageA.data(), imageA.size(), ld);
    ASSERT_TRUE(tlsA.ok() && tlsA.value().has_value());

    PeBuildSpec specB;
    specB.tls.template_data = {9, 9};
    specB.tls.zero_fill = 2;
    auto imageB = PeBuilder(specB).build();
    Diagnostics dB;
    auto imgB = xbox2pc::pe::parse(imageB.data(), imageB.size(), "b.exe", dB);
    auto tlsB = decode_tls(imgB, imageB.data(), imageB.size(), ld);
    ASSERT_TRUE(tlsB.ok() && tlsB.value().has_value());

    auto ia = tls_assign_index(5001, "a.exe", *tlsA.value());
    auto ib = tls_assign_index(5001, "b.exe", *tlsB.value());
    ASSERT_TRUE(ia.ok() && ib.ok());
    EXPECT_NE(ia.value(), ib.value());
    // Same module re-request: stable index.
    auto ia2 = tls_assign_index(5001, "a.exe", *tlsA.value());
    EXPECT_EQ(ia2.value(), ia.value());
    // Different process: separate namespace.
    auto ic = tls_assign_index(5002, "a.exe", *tlsA.value());
    EXPECT_NE(ic.value(), ia.value());

    // Thread init: template copied + zero fill.
    auto t = std::make_unique<xbox2pc::rt::RtThread>(
        [](xbox2pc::rt::RtThread&, void*) -> void* { return nullptr; },
        nullptr, "tls-thread");
    auto& mgr = w.core.objects();
    auto regt = mgr.register_object(std::move(t));
    auto f = mgr.lookup_id(regt.value());
    auto* th = f.value().get()->as<xbox2pc::rt::RtThread>();
    ASSERT_NE(th, nullptr);
    ASSERT_TRUE(tls_init_thread(*th, ia.value(), imgA, imageA.data(),
                               imageA.size(), *tlsA.value())
                    .ok());
    auto got = th->tls_get(ia.value());
    ASSERT_TRUE(got.ok());
    EXPECT_EQ(got.value().size(), 4u + 8u);   // template + zero fill
    EXPECT_EQ(got.value()[0], 1);
    EXPECT_EQ(got.value()[4], 0);   // zero-filled tail

    // Release: index count returned; a new assign after release gets a NEW
    // index (no reuse of the freed slot id).
    auto released = tls_release_indices(5001);
    ASSERT_TRUE(released.ok());
    EXPECT_EQ(released.value(), 2u);
    auto ia3 = tls_assign_index(5001, "a.exe", *tlsA.value());
    EXPECT_NE(ia3.value(), ia.value());   // fresh id (documented-safe)
}

// Regression (found by the M7 TLS fuzz harness): a mutated/huge
// SizeOfZeroFill must be rejected with a typed OutOfResources, never
// trigger a multi-GB allocation.
TEST(TlsTest, HugeZeroFillRejectedNotAllocated) {
    ApiWorld w;
    PeBuildSpec spec;
    spec.tls.template_data = {1, 2};
    spec.tls.zero_fill = 0xFFFFFF00u;   // ~4 GiB
    auto image = PeBuilder(spec).build();
    Diagnostics pd;
    auto img = xbox2pc::pe::parse(image.data(), image.size(), "huge.exe", pd);
    LoadDiagnostics ld;
    auto tls = decode_tls(img, image.data(), image.size(), ld);
    ASSERT_TRUE(tls.ok() && tls.value().has_value());
    auto idx = tls_assign_index(7001, "huge.exe", *tls.value());
    ASSERT_TRUE(idx.ok());
    auto t = std::make_unique<xbox2pc::rt::RtThread>(
        [](xbox2pc::rt::RtThread&, void*) -> void* { return nullptr; },
        nullptr, "huge-tls");
    auto r = tls_init_thread(*t, idx.value(), img, image.data(),
                             image.size(), *tls.value());
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), xbox2pc::rt::RuntimeErrc::OutOfResources);
}

// ── compat report ────────────────────────────────────────────────────────

TEST(CompatReportTest, CodesAndHonestVerdict) {
    ApiWorld w;
    PeBuildSpec spec;
    spec.imports = {
        {"xgameruntime", {{"XGameRuntimeInitialize", 1}}},
        {"kernel32", {{"QueryPerformanceCounter", 1}}},
        {"mystery.dll", {{"UnknownThing", 1}}},
    };
    auto image = PeBuilder(spec).build();
    Diagnostics pd;
    auto img = xbox2pc::pe::parse(image.data(), image.size(), "rep.exe", pd);
    Diagnostics dd;
    auto dep = xbox2pc::deps::analyze(img, dd);
    auto rep = build_compat_report(img, dep, w.reg, nullptr);
    ASSERT_EQ(rep.rows.size(), 3u);
    EXPECT_EQ(rep.rows[0].code, CompatCode::OkImplemented);
    EXPECT_EQ(rep.rows[1].code, CompatCode::OkNative);
    EXPECT_EQ(rep.rows[2].code, CompatCode::UnknownImport);
    EXPECT_EQ(rep.counts[static_cast<std::size_t>(CompatCode::OkImplemented)], 1u);
    EXPECT_EQ(rep.counts[static_cast<std::size_t>(CompatCode::OkNative)], 1u);
    EXPECT_EQ(rep.counts[static_cast<std::size_t>(CompatCode::UnknownImport)], 1u);
    EXPECT_EQ(rep.verdict, "imports partially covered (see codes)");
    // Evidence citations ride along on verified rows.
    EXPECT_EQ(rep.rows[0].evidence.rfind("[GDK-INIT] https://", 0), 0u);
}

// ── 12.7 end-to-end: the 15-step path ────────────────────────────────────

TEST(ApiE2eTest, FullFifteenStepPathWithDelayLoadTlsReport) {
    // Fixture: normal + delay-load imports + TLS + relocations.
    PeBuildSpec spec;
    spec.imports = {
        {"xgameruntime", {{"XGameRuntimeInitialize", 1}}},
        {"kernel32", {{"QueryPerformanceCounter", 1}}},
    };
    spec.delay_imports = {{"xgameruntime", {{"XSystemGetDeviceType", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    spec.tls.template_data = {0xCA, 0xFE, 0xBA, 0xBE};
    spec.tls.zero_fill = 16;
    spec.tls.callback_vas = {0x140001100};
    auto image = PeBuilder(spec).build();

    // 1. Create an M4 process (with an M5 VFS namespace).
    ApiWorld w;
    auto p = xbox2pc::rt::create_process_with_vfs(w.pm, w.core.objects(),
                                                  "e2e.exe");
    ASSERT_TRUE(p.ok());
    auto found = w.core.objects().lookup_handle(p.value());
    auto* proc = found.value().get()->as<ManagedProcess>();

    // 2-3. Mount a synthetic XPK package containing the image.
    std::vector<xbox2pc::rt::XpkBuildEntry> entries = {
        {"content", true, {}},
        {"content/e2e.exe", false, std::string(image.begin(), image.end())},
    };
    auto bytes = xbox2pc::rt::xpk_build(entries);
    auto pkg = xbox2pc::rt::parse_package(bytes.data(), bytes.size(), "e2e.xpk", {});
    ASSERT_TRUE(pkg.ok());
    auto s = w.core.objects().lookup_id(std::strtoull(
        proc->meta("vfs_session").c_str(), nullptr, 10));
    auto* session = s.value().get()->as<xbox2pc::rt::VfsSession>();
    ASSERT_NE(session, nullptr);
    ASSERT_TRUE(session
                    ->mount_backend(std::make_unique<xbox2pc::rt::PackageVfsBackend>(
                                        std::move(pkg.value())),
                                    "/Pkg", true, 0)
                    .ok());

    // 4. Discover the executable (M5).
    auto dres = xbox2pc::rt::discover_in_namespace(
        session->namespace_(), xbox2pc::rt::VfsPath::parse("/Pkg").value(), 64);
    ASSERT_TRUE(dres.ok());
    EXPECT_EQ(dres.value().pe_modules, 1u);

    // 5. Read it through VFS handles.
    auto fh = xbox2pc::rt::proc_open_file(p.value(), "/Pkg/content/e2e.exe", false);
    ASSERT_TRUE(fh.ok());
    std::vector<std::uint8_t> buf(image.size());
    std::uint64_t total = 0;
    while (total < image.size()) {
        auto n = xbox2pc::rt::vfs_read(w.core.objects(), fh.value(),
                                       buf.data() + total,
                                       image.size() - total);
        ASSERT_TRUE(n.ok());
        if (n.value() == 0) break;
        total += n.value();
    }
    ASSERT_EQ(total, image.size());

    // 6. Load through M6 with the M7 resolver (validates, maps, relocates).
    Diagnostics pd;
    auto img = xbox2pc::pe::parse(buf.data(), buf.size(), "e2e.exe", pd);
    ImageLoader loader;
    ApiResolver resolver(w.reg);
    LoadDiagnostics ld;
    LoadResult out;
    auto h = loader.load_image(w.pm, w.core.objects(), p.value(), img,
                               buf.data(), buf.size(), &resolver, ld, out);
    ASSERT_TRUE(h.ok()) << out.error;
    EXPECT_EQ(out.final_state, xbox2pc::rt::loader::LoadState::Prepared);
    // Both normal imports resolved through the registry.
    EXPECT_EQ(out.exec.imports_resolved, 2u);

    // 9. Delay-load imports resolved.
    auto drep = resolve_delay_imports(proc->address_space(), out.layout, img,
                                     buf.data(), buf.size(), w.reg, false);
    ASSERT_TRUE(drep.ok()) << drep.error_string();
    EXPECT_EQ(drep.value().resolved, 1u);

    // 10. TLS state initialized for a thread.
    auto tls = decode_tls(img, buf.data(), buf.size(), ld);
    ASSERT_TRUE(tls.ok() && tls.value().has_value());
    const std::uint64_t pid = proc->pid();
    auto idx = tls_assign_index(pid, "e2e.exe", *tls.value());
    ASSERT_TRUE(idx.ok());
    auto t = std::make_unique<xbox2pc::rt::RtThread>(
        [](xbox2pc::rt::RtThread&, void*) -> void* { return nullptr; },
        nullptr, "e2e-thread");
    auto regt = w.core.objects().register_object(std::move(t));
    auto tf = w.core.objects().lookup_id(regt.value());
    auto* th = tf.value().get()->as<xbox2pc::rt::RtThread>();
    ASSERT_TRUE(tls_init_thread(*th, idx.value(), img, buf.data(),
                               buf.size(), *tls.value())
                    .ok());
    auto slot = th->tls_get(idx.value());
    ASSERT_TRUE(slot.ok());
    EXPECT_EQ(slot.value().size(), 4u + 16u);   // template + zero fill

    // 11. Compatibility report.
    Diagnostics dd;
    auto dep = xbox2pc::deps::analyze(img, dd);
    auto rep = build_compat_report(img, dep, w.reg, &drep.value());
    EXPECT_EQ(rep.rows.size(), 3u);   // 2 normal + 1 delay
    // 12. Memory protections intact (entry point executable).
    EXPECT_TRUE(proc->address_space()
                    .validate_access(out.exec.entry_va, false, true)
                    .ok());

    // 13. Unload the image.
    ASSERT_TRUE(loader.unload_image(w.pm, w.core.objects(), p.value(), h.value()).ok());
    // 14. Terminate the process.
    ASSERT_TRUE(w.pm.terminate_process(p.value(), 0).ok());
    // 15. All resources released.
    EXPECT_EQ(proc->address_space().stats().region_count, 0u);
    EXPECT_EQ(proc->address_space().stats().committed_bytes, 0u);
    EXPECT_EQ(tls_release_indices(pid).value(), 1u);
    ASSERT_TRUE(w.core.shutdown().ok());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
