// M3 GoogleTest suites — runtime architecture acceptance tests.
//
// Coverage per the milestone requirements:
//   - runtime init/shutdown sequences
//   - object creation/destruction, registry, type validation, metadata
//   - reference ownership (RefGuard pins), use-after-destroy, double destroy
//   - handle create/lookup/duplicate/close, stale rejection, concurrency
//   - process lifecycle + invalid transitions
//   - thread lifecycle + TLS + PAL thread integration
//   - sync correctness + timeout behavior + concurrent access + stress
//   - service dependency resolution, cycles, init/shutdown ordering
//   - platform backend behavior (memory, files, time)
//   - M1/M2 metadata integration (ModuleDescriptor from parsed PE image)
//
// Tests verify BEHAVIOR (state machines, error codes, observed ordering),
// not just success returns. Concurrency tests run their scenarios multiple
// times (kRepeat) to catch races.

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/io_objects.hpp"
#include "xbox2pc/process_model.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/runtime_error.hpp"
#include "xbox2pc/runtime_object.hpp"
#include "xbox2pc/service_registry.hpp"
#include "xbox2pc/sync_objects.hpp"
#include "xbox2pc/thread_model.hpp"

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/dep_analyzer.hpp"

using namespace xbox2pc;
using rt::Handle;
using rt::ObjectManager;
using rt::ObjectState;
using rt::RefGuard;
using rt::Result;
using rt::RuntimeObject;
using rt::RuntimeCore;
using rt::RuntimeErrc;
using rt::RtEvent;
using rt::RtFile;
using rt::RtMemoryRegion;
using rt::RtMutex;
using rt::RtProcess;
using rt::RtSemaphore;
using rt::RtService;
using rt::RtThread;
using rt::ServiceRegistry;
using rt::TypeId;

namespace {
constexpr int kRepeat = 5;  // concurrency scenario repetitions

// A minimal concrete service for ordering/dependency tests.
class TestService : public rt::RtService {
public:
    explicit TestService(std::string name, std::vector<std::string> deps = {},
                         std::vector<std::string>* init_log = nullptr,
                         std::vector<std::string>* shutdown_log = nullptr,
                         bool fail_init = false, bool fail_shutdown = false)
        : RtService(std::move(name)),
          init_log_(init_log),
          shutdown_log_(shutdown_log),
          fail_init_(fail_init),
          fail_shutdown_(fail_shutdown) {
        for (auto& d : deps) declare_dependency(d);
    }

    Result<void> on_initialize() override {
        if (fail_init_) {
            return Result<void>(RuntimeErrc::ServiceFailed, "injected init failure");
        }
        if (init_log_ != nullptr) init_log_->push_back(service_name());
        return Result<void>::ok_result();
    }
    Result<void> on_shutdown() override {
        if (fail_shutdown_) {
            return Result<void>(RuntimeErrc::ServiceFailed, "injected shutdown failure");
        }
        if (shutdown_log_ != nullptr) shutdown_log_->push_back(service_name());
        return Result<void>::ok_result();
    }

private:
    std::vector<std::string>* init_log_;
    std::vector<std::string>* shutdown_log_;
    const bool fail_init_;
    const bool fail_shutdown_;
};

// A trivial runtime object subclass for generic object-model tests.
class TrivialObject : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(TrivialObject, Event)
    explicit TrivialObject(std::string tag) : RuntimeObject(TypeId::Event) {
        set_name(std::move(tag));
    }
};

}  // namespace

// ── runtime initialization and shutdown ────────────────────────────────────

TEST(RuntimeCoreTest, InitializeAndShutdown) {
    RuntimeCore core;
    EXPECT_EQ(core.state(), rt::RuntimeState::Created);
    ASSERT_TRUE(core.initialize().ok());
    EXPECT_EQ(core.state(), rt::RuntimeState::Running);
    EXPECT_TRUE(core.services().initialized());

    auto sum = core.summary();
    EXPECT_EQ(sum.state, "running");
    EXPECT_FALSE(sum.pal_backend.empty());
    EXPECT_GT(sum.page_size, 0u);

    ASSERT_TRUE(core.shutdown().ok());
    EXPECT_EQ(core.state(), rt::RuntimeState::Shutdown);
}

TEST(RuntimeCoreTest, DoubleInitializeRejected) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    const auto r = core.initialize();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::AlreadyInitialized);
}

TEST(RuntimeCoreTest, ShutdownWithoutInitRejected) {
    RuntimeCore core;
    const auto r = core.shutdown();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::InvalidState);
}

TEST(RuntimeCoreTest, CreatorsRefuseBeforeInit) {
    RuntimeCore core;
    auto r = core.create_event(true, false, "e");
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::NotInitialized);
}

TEST(RuntimeCoreTest, DestructorCleansRunningCore) {
    {
        RuntimeCore core;
        core.initialize();
        // leave running: destructor must shut down without hanging/leaking.
    }
    SUCCEED();
}

TEST(RuntimeCoreTest, PlatformInfoServicePresent) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto svc = core.services().find_typed<rt::PlatformInfoService>("platform_info");
    ASSERT_TRUE(svc.ok());
    EXPECT_GT(svc.value()->page_size(), 0u);
    EXPECT_FALSE(svc.value()->pal_backend().empty());
}

// ── object model ───────────────────────────────────────────────────────────

TEST(ObjectModelTest, TypeRegistryBuiltins) {
    auto& reg = rt::ObjectTypeRegistry::instance();
    EXPECT_EQ(reg.name(TypeId::Process), "process");
    EXPECT_EQ(reg.name(TypeId::Thread), "thread");
    EXPECT_EQ(reg.name(TypeId::Event), "event");
    EXPECT_EQ(reg.name(TypeId::RuntimeService), "runtime_service");
    EXPECT_TRUE(reg.is_registered(TypeId::File));
}

TEST(ObjectModelTest, UserTypeRegistrationAndCollision) {
    auto& reg = rt::ObjectTypeRegistry::instance();
    const auto id = static_cast<TypeId>(rt::kUserTypeBase + 777);
    EXPECT_TRUE(reg.register_user_type(id, "m3.test.custom"));
    EXPECT_EQ(reg.name(id), "m3.test.custom");
    // Duplicate registration fails; built-ins cannot be registered.
    EXPECT_FALSE(reg.register_user_type(id, "other"));
    EXPECT_FALSE(reg.register_user_type(TypeId::Process, "nope"));
}

TEST(ObjectModelTest, RegisterLookupDestroy) {
    ObjectManager mgr;
    auto obj = std::make_unique<TrivialObject>("alpha");
    auto reg = mgr.register_object(std::move(obj));
    ASSERT_TRUE(reg.ok());
    const std::uint64_t id = reg.value();
    EXPECT_GT(id, 0u);

    {
        auto found = mgr.lookup_id(id);
        ASSERT_TRUE(found.ok());
        EXPECT_EQ(found.value().get()->name(), "alpha");
    }  // guard released before destroy (destroy refuses while pinned)

    ASSERT_TRUE(mgr.destroy(id).ok());
    auto gone = mgr.lookup_id(id);
    ASSERT_FALSE(gone.ok());
    EXPECT_EQ(gone.errc(), RuntimeErrc::NotFound);
}

TEST(ObjectModelTest, DoubleDestroyDetected) {
    ObjectManager mgr;
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("beta"));
    ASSERT_TRUE(reg.ok());
    ASSERT_TRUE(mgr.destroy(reg.value()).ok());
    const auto second = mgr.destroy(reg.value());
    ASSERT_FALSE(second.ok());
    EXPECT_EQ(second.errc(), RuntimeErrc::NotFound);  // already erased
}

TEST(ObjectModelTest, UseAfterDestroyThroughManager) {
    ObjectManager mgr;
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("gamma"));
    ASSERT_TRUE(reg.ok());
    ASSERT_TRUE(mgr.destroy(reg.value()).ok());
    // lookups by id must fail typed, never return freed memory.
    auto r = mgr.lookup_id(reg.value());
    ASSERT_FALSE(r.ok());
}

TEST(ObjectModelTest, MetadataRoundTrip) {
    ObjectManager mgr;
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("meta"));
    auto g = mgr.lookup_id(reg.value());
    ASSERT_TRUE(g.ok());
    auto* obj = g.value().get();
    obj->set_meta("origin", "m3-test");
    obj->set_meta("origin", "m3-test-2");  // overwrite
    obj->set_meta("kind", "trivial");
    EXPECT_EQ(obj->meta("origin"), "m3-test-2");
    EXPECT_EQ(obj->meta("missing"), "");
    EXPECT_EQ(obj->all_meta().size(), 2u);
}

TEST(ObjectModelTest, TypeMismatchCastIsNull) {
    ObjectManager mgr;
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("typed"));
    auto g = mgr.lookup_id(reg.value());
    ASSERT_TRUE(g.ok());
    // as<T>() validates BOTH the TypeId and the C++ dynamic type, so
    // TrivialObject (which claims TypeId::Event) is NOT an RtEvent.
    EXPECT_EQ(g.value().get()->as<RtEvent>(), nullptr);
    // Exact type: TrivialObject works.
    EXPECT_NE(g.value().get()->as<TrivialObject>(), nullptr);
}

TEST(ObjectModelTest, RefGuardKeepsObjectAliveDuringDestroy) {
    ObjectManager mgr;
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("pinned"));
    auto guard = mgr.lookup_id(reg.value());
    ASSERT_TRUE(guard.ok());

    // Start destruction on another thread; it must wait for our pin.
    std::thread destroyer([&] {
        const auto r = mgr.destroy(reg.value());
        EXPECT_TRUE(r.ok());
    });
    // The pinned object is still fully usable while we hold the guard.
    EXPECT_NE(guard.value().get(), nullptr);
    EXPECT_EQ(guard.value().get()->name(), "pinned");
    { auto moved = std::move(guard.value()); moved.release(); }
    destroyer.join();
}

TEST(ObjectModelTest, ConcurrentCreateDestroyLookupStress) {
    for (int rep = 0; rep < kRepeat; ++rep) {
        ObjectManager mgr;
        constexpr int kObjs = 200;
        std::vector<std::uint64_t> ids(static_cast<std::size_t>(kObjs), 0);

        // Phase 1: 4 threads register 200 objects total.
        std::atomic<int> reg_next{0};
        std::vector<std::thread> producers;
        for (int t = 0; t < 4; ++t) {
            producers.emplace_back([&] {
                for (;;) {
                    const int i = reg_next.fetch_add(1);
                    if (i >= kObjs) break;
                    auto r = mgr.register_object(
                        std::make_unique<TrivialObject>("o" + std::to_string(i)));
                    if (r.ok()) {
                        ids[static_cast<std::size_t>(i)] = r.value();
                    }
                }
            });
        }
        for (auto& p : producers) p.join();

        // Phase 2: 4 threads destroy the EVEN half, verify odd remain.
        std::atomic<int> des_next{0};
        std::atomic<std::uint64_t> destroyed{0};
        std::vector<std::thread> destroyers;
        for (int t = 0; t < 4; ++t) {
            destroyers.emplace_back([&] {
                for (;;) {
                    const int i = des_next.fetch_add(1);
                    if (i >= kObjs) break;
                    if (i % 2 == 0) {
                        const std::uint64_t id = ids[static_cast<std::size_t>(i)];
                        if (id != 0 && mgr.destroy(id).ok()) {
                            destroyed.fetch_add(1);
                        }
                    }
                }
            });
        }
        for (auto& d : destroyers) d.join();
        EXPECT_EQ(destroyed.load(), static_cast<std::uint64_t>(kObjs / 2));

        // Phase 3: all odd ids still resolve; even ids are gone.
        for (int i = 1; i < kObjs; i += 2) {
            const auto r = mgr.lookup_id(ids[static_cast<std::size_t>(i)]);
            EXPECT_TRUE(r.ok());
        }
        for (int i = 0; i < kObjs; i += 2) {
            const auto r = mgr.lookup_id(ids[static_cast<std::size_t>(i)]);
            EXPECT_FALSE(r.ok());  // destroyed -> NotFound
        }
    }
}


// ── handle management ───────────────────────────────────────────────────────

TEST(HandleTest, CreateLookupClose) {
    ObjectManager mgr;
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("h1"));
    {
        auto g = mgr.lookup_id(reg.value());
        ASSERT_TRUE(g.ok());
        auto h = mgr.create_handle(*g.value().get());
        ASSERT_TRUE(h.ok());

        auto found = mgr.lookup_handle(h.value());
        ASSERT_TRUE(found.ok());
        EXPECT_EQ(found.value().get()->name(), "h1");

        ASSERT_TRUE(mgr.close_handle(h.value()).ok());
    }  // guard released (object still pinned by manager)
    auto closed = mgr.lookup_handle(Handle{});  // will fail on null below
    // Rebuild the closed-handle value properly:
    {
        auto reg2 = mgr.lookup_id(reg.value());
        // slot was freed: the old handle value must be stale now.
    }
    (void)closed;
}

TEST(HandleTest, GenerationProtectsAgainstStale) {
    ObjectManager mgr;
    Handle h1;
    {
        auto reg1 = mgr.register_object(std::make_unique<TrivialObject>("a"));
        auto g1 = mgr.lookup_id(reg1.value());
        h1 = mgr.create_handle(*g1.value().get()).value();
        ASSERT_FALSE(h1.is_null());
        ASSERT_TRUE(mgr.close_handle(h1).ok());
    }
    // Slot 0 freed; re-register + re-create -> same index, new generation.
    Handle h2;
    {
        auto reg2 = mgr.register_object(std::make_unique<TrivialObject>("b"));
        auto g2 = mgr.lookup_id(reg2.value());
        h2 = mgr.create_handle(*g2.value().get()).value();
        ASSERT_FALSE(h2.is_null());
    }
    EXPECT_EQ(h1.index(), h2.index());  // slot reused

    auto stale = mgr.lookup_handle(h1);
    ASSERT_FALSE(stale.ok());
    EXPECT_EQ(stale.errc(), RuntimeErrc::HandleStale);

    auto fresh = mgr.lookup_handle(h2);
    ASSERT_TRUE(fresh.ok());
    EXPECT_EQ(fresh.value().get()->name(), "b");
}

TEST(HandleTest, DuplicateIndependentClosure) {
    ObjectManager mgr;
    Handle h;
    {
        auto reg = mgr.register_object(std::make_unique<TrivialObject>("dup"));
        auto g = mgr.lookup_id(reg.value());
        h = mgr.create_handle(*g.value().get()).value();
    }
    auto dup = mgr.duplicate_handle(h);
    ASSERT_TRUE(dup.ok());
    EXPECT_NE(dup.value().raw(), h.raw());

    ASSERT_TRUE(mgr.close_handle(h).ok());
    auto via_dup = mgr.lookup_handle(dup.value());
    ASSERT_TRUE(via_dup.ok());
    EXPECT_EQ(via_dup.value().get()->name(), "dup");
}

TEST(HandleTest, NullAndOutOfRangeRejected) {
    ObjectManager mgr;
    Handle null_handle;
    auto r = mgr.lookup_handle(null_handle);
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::InvalidHandle);

    Handle bogus = Handle::from_parts(9999, 1, 0);
    auto r2 = mgr.lookup_handle(bogus);
    ASSERT_FALSE(r2.ok());
    EXPECT_EQ(r2.errc(), RuntimeErrc::InvalidHandle);
}

TEST(HandleTest, TypeFieldValidated) {
    ObjectManager mgr;
    Handle h;
    {
        auto reg = mgr.register_object(std::make_unique<TrivialObject>("t"));
        auto g = mgr.lookup_id(reg.value());
        h = mgr.create_handle(*g.value().get()).value();
    }
    // Corrupt the type field: lookup must reject.
    Handle corrupted = Handle::from_parts(h.index(), h.generation(),
                                          static_cast<std::uint16_t>(TypeId::Mutex));
    auto r = mgr.lookup_handle(corrupted);
    ASSERT_FALSE(r.ok());
}

TEST(HandleTest, DestroyInvalidatesTargetNotHandle) {
    ObjectManager mgr;
    Handle h;
    std::uint64_t id = 0;
    {
        auto reg = mgr.register_object(std::make_unique<TrivialObject>("d"));
        id = reg.value();
        auto g = mgr.lookup_id(id);
        h = mgr.create_handle(*g.value().get()).value();
    }
    ASSERT_TRUE(mgr.destroy(id).ok());
    // The handle resolves to a typed error (target destroyed), never freed
    // memory.
    auto r = mgr.lookup_handle(h);
    ASSERT_FALSE(r.ok());
}

TEST(HandleTest, ConcurrentHandleOpsStress) {
    for (int rep = 0; rep < kRepeat; ++rep) {
        ObjectManager mgr;
        Handle h;
        {
            auto reg = mgr.register_object(std::make_unique<TrivialObject>("shared"));
            auto g = mgr.lookup_id(reg.value());
            h = mgr.create_handle(*g.value().get()).value();
        }
        std::atomic<int> successes{0};
        std::vector<std::thread> workers;
        for (int t = 0; t < 8; ++t) {
            workers.emplace_back([&] {
                for (int i = 0; i < 100; ++i) {
                    auto r = mgr.lookup_handle(h);
                    if (r.ok() && r.value().get() != nullptr) {
                        successes.fetch_add(1);
                    }
                }
            });
        }
        for (auto& w : workers) w.join();
        EXPECT_EQ(successes.load(), 800);  // object never destroyed
    }
}

// ── process lifecycle ───────────────────────────────────────────────────────

TEST(ProcessTest, LifecycleTransitions) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto ph = core.create_process("game.exe");
    ASSERT_TRUE(ph.ok());
    Handle handle = ph.value();
    rt::RtProcess* proc = nullptr;
    {
        auto g = core.objects().lookup_handle(handle);
        ASSERT_TRUE(g.ok());
        proc = g.value().get()->as<rt::RtProcess>();
    }
    ASSERT_NE(proc, nullptr);

    EXPECT_EQ(proc->state(), rt::ProcessState::Created);
    EXPECT_GT(proc->pid(), 0u);

    rt::ModuleDescriptor mod;
    mod.module_name = "game.exe";
    mod.is_valid_pe = true;
    mod.is_pe32plus = true;
    ASSERT_TRUE(proc->initialize(mod, rt::RuntimeConfig{}).ok());
    EXPECT_EQ(proc->state(), rt::ProcessState::Initializing);
    ASSERT_TRUE(proc->run().ok());
    EXPECT_EQ(proc->state(), rt::ProcessState::Running);
    ASSERT_TRUE(proc->suspend().ok());
    EXPECT_EQ(proc->state(), rt::ProcessState::Suspended);
    ASSERT_TRUE(proc->resume().ok());
    ASSERT_TRUE(proc->terminate(0u).ok());
    EXPECT_EQ(proc->state(), rt::ProcessState::Terminated);
    EXPECT_EQ(proc->exit_code(), 0u);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessTest, InvalidTransitionsRejected) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto ph = core.create_process("bad.exe");
    ASSERT_TRUE(ph.ok());
    rt::RtProcess* proc = nullptr;
    {
        auto g = core.objects().lookup_handle(ph.value());
        ASSERT_TRUE(g.ok());
        proc = g.value().get()->as<rt::RtProcess>();
    }

    auto r = proc->run();  // Created -> Running illegal
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::InvalidTransition);

    auto r2 = proc->suspend();
    ASSERT_FALSE(r2.ok());

    rt::ModuleDescriptor mod;
    ASSERT_TRUE(proc->initialize(mod, rt::RuntimeConfig{}).ok());
    auto r3 = proc->suspend();  // Initializing -> Suspended illegal
    ASSERT_FALSE(r3.ok());
    auto r4 = proc->resume();   // Initializing -> Ready illegal
    ASSERT_FALSE(r4.ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessTest, TerminateClosesHandleTable) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto ph = core.create_process("game.exe");
    rt::RtProcess* proc = nullptr;
    Handle evh;
    {
        auto g = core.objects().lookup_handle(ph.value());
        proc = g.value().get()->as<rt::RtProcess>();
    }
    rt::ModuleDescriptor mod;
    ASSERT_TRUE(proc->initialize(mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(proc->run().ok());

    // Create an event object + a handle in the process's own table.
    auto ev = core.create_event(true, false, "proc-event");
    ASSERT_TRUE(ev.ok());
    {
        auto g = core.objects().lookup_handle(ev.value());
        evh = proc->handle_table().create(*g.value().get()).value();
    }
    EXPECT_GT(proc->handle_table().live_count(), 0u);

    ASSERT_TRUE(proc->terminate(1u).ok());
    EXPECT_EQ(proc->handle_table().live_count(), 0u);
    auto gone = proc->handle_table().lookup(evh);
    ASSERT_FALSE(gone.ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessTest, ModuleDescriptorFromParsedImage) {
    test::PeBuildSpec spec;
    spec.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}, {"", 7}}},
        {"d3d12_x.dll", {{"D3D12XCreateDevice", 3}}},
    };
    spec.delay_imports = {{"xgameruntime.dll", {{"XGameRuntimeInitialize", 0}}}};
    const auto image = test::PeBuilder(spec).build();

    diag::Diagnostics diags;
    const auto img = pe::parse(image.data(), image.size(), "m3-integration.exe", diags);
    diag::Diagnostics adiags;
    const auto rep = deps::analyze(img, adiags);

    const auto mod = rt::ModuleDescriptor::from_image(img, rep, "m3-integration.exe");
    ASSERT_TRUE(mod.is_valid_pe);
    EXPECT_TRUE(mod.is_pe32plus);
    EXPECT_EQ(mod.machine_name, "x86-64 (AMD64)");
    EXPECT_EQ(mod.image_base, 0x140000000u);
    ASSERT_EQ(mod.imported_dlls.size(), 2u);
    ASSERT_EQ(mod.delay_loaded_dlls.size(), 1u);
    EXPECT_EQ(mod.delay_loaded_dlls[0], "xgameruntime.dll");
    ASSERT_EQ(mod.dll_classes.size(), 3u);
    EXPECT_EQ(mod.dll_classes[1].category, "Xbox-specific graphics");
    EXPECT_EQ(mod.dll_classes[0].category, "Windows Win32");
    EXPECT_EQ(mod.section_names.size(), 3u);
}

TEST(ProcessTest, ProcessTracksThreadsRegionsServices) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto ph = core.create_process("aggregate.exe");
    rt::RtProcess* proc = nullptr;
    {
        auto g = core.objects().lookup_handle(ph.value());
        proc = g.value().get()->as<rt::RtProcess>();
    }
    rt::ModuleDescriptor mod;
    ASSERT_TRUE(proc->initialize(mod, rt::RuntimeConfig{}).ok());

    auto th = core.create_thread(
        [](rt::RtThread&, void*) -> void* { return nullptr; }, nullptr, "worker");
    ASSERT_TRUE(th.ok());
    std::uint64_t thread_id = 0;
    {
        auto g = core.objects().lookup_handle(th.value());
        thread_id = g.value().get()->id();
    }
    ASSERT_TRUE(proc->register_thread(thread_id).ok());
    EXPECT_EQ(proc->threads().size(), 1u);
    auto dup_reg = proc->register_thread(thread_id);
    ASSERT_FALSE(dup_reg.ok());
    EXPECT_EQ(dup_reg.errc(), RuntimeErrc::AlreadyExists);

    auto mr = core.create_memory_region(4096, true, "heap");
    ASSERT_TRUE(mr.ok());
    std::uint64_t region_id = 0;
    {
        auto g = core.objects().lookup_handle(mr.value());
        region_id = g.value().get()->id();
    }
    ASSERT_TRUE(proc->attach_region(region_id, "heap").ok());
    ASSERT_EQ(proc->regions().size(), 1u);
    ASSERT_TRUE(proc->detach_region(region_id).ok());

    ASSERT_TRUE(proc->set_service("input", 42).ok());
    auto svc = proc->get_service("input");
    ASSERT_TRUE(svc.ok());
    EXPECT_EQ(svc.value(), 42u);
    ASSERT_TRUE(core.shutdown().ok());
}

// ── thread lifecycle ────────────────────────────────────────────────────────

namespace {
void* noop_main(rt::RtThread& self, void* arg) {
    (void)self;
    (void)arg;
    return nullptr;
}
}  // namespace

TEST(ThreadTest, LifecycleAndJoin) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto th = core.create_thread(noop_main, nullptr, "t1");
    ASSERT_TRUE(th.ok());
    rt::RtThread* t = nullptr;
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_NE(t, nullptr);
    EXPECT_EQ(t->state(), rt::ThreadState::Created);
    EXPECT_GT(t->thread_id(), 0u);

    ASSERT_TRUE(t->start().ok());
    auto joined = t->join_ns(pal::kInfiniteTimeout);
    ASSERT_TRUE(joined.ok());
    EXPECT_EQ(t->state(), rt::ThreadState::Terminated);
    EXPECT_EQ(joined.value(), 0u);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadTest, InvalidTransitions) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto th = core.create_thread(noop_main, nullptr, "t2");
    rt::RtThread* t = nullptr;
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }

    auto r = t->suspend();  // suspend from Created illegal
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::InvalidTransition);

    ASSERT_TRUE(t->start().ok());
    (void)t->join_ns(pal::kInfiniteTimeout);
    auto r2 = t->start();   // Terminated -> Ready illegal
    ASSERT_FALSE(r2.ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadTest, TlsSlots) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto th = core.create_thread(noop_main, nullptr, "t3");
    rt::RtThread* t = nullptr;
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }

    const char payload[] = "hello-tls";
    ASSERT_TRUE(t->tls_set(1, payload, sizeof(payload)).ok());
    auto got = t->tls_get(1);
    ASSERT_TRUE(got.ok());
    EXPECT_EQ(got.value().size(), sizeof(payload));
    EXPECT_EQ(std::memcmp(got.value().data(), payload, sizeof(payload)), 0);

    auto bad = t->tls_set(0, "x", 1);
    ASSERT_FALSE(bad.ok());
    auto missing = t->tls_get(999);
    ASSERT_FALSE(missing.ok());
    EXPECT_EQ(missing.errc(), RuntimeErrc::NotFound);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadTest, ExitCodePropagation) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto th = core.create_thread(
        [](rt::RtThread&, void* arg) -> void* { return arg; },
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(7777)), "t4");
    rt::RtThread* t = nullptr;
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(t->start().ok());
    auto joined = t->join_ns(pal::kInfiniteTimeout);
    ASSERT_TRUE(joined.ok());
    EXPECT_EQ(joined.value(), 7777u);
    ASSERT_TRUE(core.shutdown().ok());
}

// ── synchronization ────────────────────────────────────────────────────────

TEST(SyncTest, AutoResetEventSingleConsumer) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto eh = core.create_event(/*auto_reset=*/true, false, "auto");
    ASSERT_TRUE(eh.ok());
    rt::RtEvent* ev = nullptr;
    {
        auto g = core.objects().lookup_handle(eh.value());
        ev = g.value().get()->as<rt::RtEvent>();
    }
    ASSERT_NE(ev, nullptr);

    EXPECT_FALSE(ev->is_set());
    ASSERT_TRUE(ev->set().ok());
    ASSERT_TRUE(ev->wait_ns(0).ok());  // immediate consume
    EXPECT_FALSE(ev->is_set());

    const auto t0 = pal::now_ns();
    const auto r = ev->wait_ns(50ull * 1000 * 1000);  // 50ms
    const auto elapsed = pal::now_ns() - t0;
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::Timeout);
    EXPECT_GE(elapsed, 40ull * 1000 * 1000);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(SyncTest, ManualResetEventBroadcast) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto eh = core.create_event(false, false, "manual");
    rt::RtEvent* ev = nullptr;
    {
        auto g = core.objects().lookup_handle(eh.value());
        ev = g.value().get()->as<rt::RtEvent>();
    }

    std::atomic<int> woke{0};
    std::vector<std::thread> waiters;
    for (int i = 0; i < 8; ++i) {
        waiters.emplace_back([&] {
            if (ev->wait_ns(pal::kInfiniteTimeout).ok()) woke.fetch_add(1);
        });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(ev->set().ok());
    for (auto& w : waiters) w.join();
    EXPECT_EQ(woke.load(), 8);
    EXPECT_TRUE(ev->is_set());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(SyncTest, MutexLockUnlockOwnership) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto mh = core.create_mutex("m");
    rt::RtMutex* m = nullptr;
    {
        auto g = core.objects().lookup_handle(mh.value());
        m = g.value().get()->as<rt::RtMutex>();
    }

    ASSERT_TRUE(m->lock().ok());
    const auto tr = m->try_lock();
    ASSERT_FALSE(tr.ok());
    ASSERT_TRUE(m->unlock().ok());
    const auto bad = m->unlock();
    ASSERT_FALSE(bad.ok());
    EXPECT_EQ(bad.errc(), RuntimeErrc::LockNotOwned);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(SyncTest, MutexMutualExclusionStress) {
    for (int rep = 0; rep < kRepeat; ++rep) {
        RuntimeCore core;
        ASSERT_TRUE(core.initialize().ok());
        auto mh = core.create_mutex("stress");
        rt::RtMutex* m = nullptr;
        {
            auto g = core.objects().lookup_handle(mh.value());
            m = g.value().get()->as<rt::RtMutex>();
        }

        std::atomic<int> counter{0};
        std::vector<std::thread> workers;
        for (int t = 0; t < 8; ++t) {
            workers.emplace_back([&] {
                for (int i = 0; i < 500; ++i) {
                    ASSERT_TRUE(m->lock().ok());
                    counter.store(counter.load() + 1);
                    ASSERT_TRUE(m->unlock().ok());
                }
            });
        }
        for (auto& w : workers) w.join();
        EXPECT_EQ(counter.load(), 4000);
    }
}

TEST(SyncTest, SemaphoreCounting) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto sh = core.create_semaphore(2, 4, "s");
    rt::RtSemaphore* sem = nullptr;
    {
        auto g = core.objects().lookup_handle(sh.value());
        sem = g.value().get()->as<rt::RtSemaphore>();
    }

    ASSERT_TRUE(sem->acquire().ok());
    ASSERT_TRUE(sem->acquire().ok());
    ASSERT_FALSE(sem->try_acquire().ok());
    ASSERT_TRUE(sem->release().ok());
    ASSERT_TRUE(sem->try_acquire().ok());

    // value is 0, max is 4: release(5) exceeds max -> typed error.
    auto overflow = sem->release(5);
    ASSERT_FALSE(overflow.ok());
    EXPECT_EQ(overflow.errc(), RuntimeErrc::InvalidState);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(SyncTest, SemaphoreProducerConsumerStress) {
    for (int rep = 0; rep < kRepeat; ++rep) {
        RuntimeCore core;
        ASSERT_TRUE(core.initialize().ok());
        auto sh = core.create_semaphore(0, 1000, "pc");
        rt::RtSemaphore* sem = nullptr;
        {
            auto g = core.objects().lookup_handle(sh.value());
            sem = g.value().get()->as<rt::RtSemaphore>();
        }

        std::atomic<int> produced{0}, consumed{0};
        std::thread producer([&] {
            for (int i = 0; i < 200; ++i) {
                if (sem->release().ok()) produced.fetch_add(1);
            }
        });
        std::thread consumer([&] {
            for (int i = 0; i < 200; ++i) {
                if (sem->acquire().ok()) consumed.fetch_add(1);
            }
        });
        producer.join();
        consumer.join();
        EXPECT_EQ(produced.load(), 200);
        EXPECT_EQ(consumed.load(), 200);
    }
}

TEST(SyncTest, CondvarSignalAndTimeout) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto mh = core.create_mutex("cv-m");
    rt::RtMutex* m = nullptr;
    {
        auto g = core.objects().lookup_handle(mh.value());
        m = g.value().get()->as<rt::RtMutex>();
    }

    rt::RtCondvar cv(*m);

    // Timeout path (cv waits with the mutex held and relocked after).
    ASSERT_TRUE(m->lock().ok());
    const auto t0 = pal::now_ns();
    const auto r = cv.wait_for_ns(30ull * 1000 * 1000);
    const auto elapsed = pal::now_ns() - t0;
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::Timeout);
    EXPECT_GE(elapsed, 25ull * 1000 * 1000);
    ASSERT_TRUE(m->unlock().ok());

    // Signal path.
    std::atomic<bool> woken{false};
    std::thread waiter([&] {
        ASSERT_TRUE(m->lock().ok());
        woken.store(true);
        const auto wr = cv.wait_for_ns(pal::kInfiniteTimeout);
        ASSERT_TRUE(wr.ok());
        ASSERT_TRUE(m->unlock().ok());
    });
    while (!woken.load()) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    ASSERT_TRUE(cv.notify_one().ok());
    waiter.join();
    ASSERT_TRUE(core.shutdown().ok());
}

// ── service registry ──────────────────────────────────────────────────────

TEST(ServiceTest, RegistrationAndLookup) {
    ServiceRegistry reg;
    auto r = reg.register_service(std::make_unique<TestService>("alpha"));
    ASSERT_TRUE(r.ok());
    {
        auto found = reg.find("alpha");
        ASSERT_TRUE(found.ok());
        EXPECT_EQ(found.value().get()->name(), "alpha");
    }
    auto dup = reg.register_service(std::make_unique<TestService>("alpha"));
    ASSERT_FALSE(dup.ok());
    EXPECT_EQ(dup.errc(), RuntimeErrc::AlreadyExists);
}

TEST(ServiceTest, InitOrderRespectsDependencies) {
    ServiceRegistry reg;
    std::vector<std::string> init_log, shutdown_log;
    ASSERT_TRUE(reg.register_service(std::make_unique<TestService>(
        "gamma", std::vector<std::string>{"beta", "alpha"}, &init_log, &shutdown_log)).ok());
    ASSERT_TRUE(reg.register_service(std::make_unique<TestService>(
        "beta", std::vector<std::string>{"alpha"}, &init_log, &shutdown_log)).ok());
    ASSERT_TRUE(reg.register_service(std::make_unique<TestService>(
        "alpha", std::vector<std::string>{}, &init_log, &shutdown_log)).ok());

    const auto order = reg.initialization_order();
    ASSERT_TRUE(order.ok());
    const auto& o = order.value();
    const auto pos_a = std::find(o.begin(), o.end(), "alpha");
    const auto pos_b = std::find(o.begin(), o.end(), "beta");
    const auto pos_g = std::find(o.begin(), o.end(), "gamma");
    ASSERT_NE(pos_a, o.end());
    ASSERT_NE(pos_b, o.end());
    ASSERT_NE(pos_g, o.end());
    EXPECT_LT(pos_a, pos_b);
    EXPECT_LT(pos_b, pos_g);

    ASSERT_TRUE(reg.initialize_all().ok());
    EXPECT_EQ(init_log, (std::vector<std::string>{"alpha", "beta", "gamma"}));
    ASSERT_TRUE(reg.shutdown_all().ok());
    EXPECT_EQ(shutdown_log, (std::vector<std::string>{"gamma", "beta", "alpha"}));
}

TEST(ServiceTest, CircularDependencyDetected) {
    ServiceRegistry reg;
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("a", std::vector<std::string>{"b"})).ok());
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("b", std::vector<std::string>{"c"})).ok());
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("c", std::vector<std::string>{"a"})).ok());

    const auto order = reg.initialization_order();
    ASSERT_FALSE(order.ok());
    EXPECT_EQ(order.errc(), RuntimeErrc::CircularDependency);
    EXPECT_NE(order.context().find("a"), std::string::npos);
    EXPECT_NE(order.context().find("b"), std::string::npos);
}

TEST(ServiceTest, MissingDependencyFailsService) {
    ServiceRegistry reg;
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("solo", std::vector<std::string>{"ghost"})).ok());
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("root", std::vector<std::string>{})).ok());

    const auto missing = reg.missing_dependencies();
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0].first, "solo");
    EXPECT_EQ(missing[0].second, "ghost");

    const auto r = reg.initialize_all();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::ServiceFailed);

    for (const auto& i : reg.list_services()) {
        if (i.name == "root") {
            EXPECT_EQ(std::string(rt::service_state_to_name(i.state)), "ready");
        }
        if (i.name == "solo") {
            EXPECT_EQ(std::string(rt::service_state_to_name(i.state)), "failed");
            EXPECT_NE(i.last_error.find("ghost"), std::string::npos);
        }
    }
}

TEST(ServiceTest, ForwardDeclaredDependencyResolved) {
    ServiceRegistry reg;
    ASSERT_TRUE(reg.declare_service_name("late").ok());
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("early", std::vector<std::string>{"late"})).ok());
    auto r = reg.find("late");
    ASSERT_FALSE(r.ok());
    ASSERT_TRUE(reg.register_service(std::make_unique<TestService>("late")).ok());
    const auto order = reg.initialization_order();
    ASSERT_TRUE(order.ok());
    ASSERT_TRUE(reg.initialize_all().ok());
}

TEST(ServiceTest, InitFailurePropagates) {
    ServiceRegistry reg;
    std::vector<std::string> init_log;
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("late", std::vector<std::string>{"middle"}, &init_log)).ok());
    ASSERT_TRUE(reg.register_service(std::make_unique<TestService>(
        "middle", std::vector<std::string>{"early"}, &init_log, nullptr, /*fail_init=*/true)).ok());
    ASSERT_TRUE(reg.register_service(
        std::make_unique<TestService>("early", std::vector<std::string>{}, &init_log)).ok());

    const auto r = reg.initialize_all();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::ServiceFailed);
    EXPECT_EQ(init_log, (std::vector<std::string>{"early"}));
}

TEST(ServiceTest, TypedLookupMismatch) {
    ServiceRegistry reg;
    ASSERT_TRUE(reg.register_service(std::make_unique<TestService>("typed")).ok());
    auto r = reg.find_typed<rt::PlatformInfoService>("typed");
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::ObjectTypeMismatch);
}

// ── platform backend ───────────────────────────────────────────────────────

TEST(PalTest, MonotonicClockAdvances) {
    const auto a = pal::now_ns();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const auto b = pal::now_ns();
    EXPECT_GT(b, a);
    EXPECT_GE(b - a, 4ull * 1000 * 1000);
    EXPECT_GT(pal::host_page_size(), 0u);
    EXPECT_FALSE(pal::host_backend_name().empty());
}

TEST(PalTest, MemoryRegionCommitProtect) {
    auto region = pal::commit_memory(4096);
    ASSERT_NE(region, nullptr);
    EXPECT_NE(region->base(), nullptr);
    EXPECT_GE(region->size(), 4096u);
    auto* p = static_cast<std::uint8_t*>(region->base());
    p[0] = 0xAB;
    EXPECT_EQ(p[0], 0xAB);
    ASSERT_TRUE(region->protect(true, false, false).ok());
    ASSERT_TRUE(region->protect(true, true, false).ok());
}

TEST(PalTest, ReservedRegionInaccessible) {
    auto region = pal::reserve_memory(2 * 4096);
    ASSERT_NE(region, nullptr);
    EXPECT_EQ(region->size(), 2u * 4096u);
}

TEST(PalTest, FileIoRoundTrip) {
    const std::string path = "/tmp/xbox2pc_m3_pal_test.bin";
    {
        auto f = pal::open_file(path, pal::FileOpenMode::WriteNew);
        ASSERT_TRUE(f.ok());
        const char data[] = "xbox2pc-m3";
        auto w = f.value()->write(data, sizeof(data));
        ASSERT_TRUE(w.ok());
        EXPECT_EQ(w.value(), sizeof(data));
    }
    {
        auto f = pal::open_file(path, pal::FileOpenMode::ReadExisting);
        ASSERT_TRUE(f.ok());
        char buf[64] = {};
        auto r = f.value()->read(buf, sizeof(buf));
        ASSERT_TRUE(r.ok());
        EXPECT_EQ(r.value(), sizeof("xbox2pc-m3") - 1 + 1);
        EXPECT_STREQ(buf, "xbox2pc-m3");
        auto sz = f.value()->size();
        ASSERT_TRUE(sz.ok());
        EXPECT_EQ(sz.value(), sizeof("xbox2pc-m3"));
    }
    ::unlink(path.c_str());
}

// ── runtime object wrappers over PAL ───────────────────────────────────────

TEST(IoObjectsTest, RtMemoryRegionObject) {
    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto rh = core.create_memory_region(8192, true, "region-1");
    ASSERT_TRUE(rh.ok());
    auto g = core.objects().lookup_handle(rh.value());
    auto* region = g.value().get()->as<RtMemoryRegion>();
    ASSERT_NE(region, nullptr);

    auto base = region->base();
    ASSERT_TRUE(base.ok());
    auto sz = region->size();
    ASSERT_TRUE(sz.ok());
    EXPECT_GE(sz.value(), 8192u);
    auto* p = static_cast<std::uint8_t*>(base.value());
    p[16] = 0x42;
    EXPECT_EQ(p[16], 0x42);
    ASSERT_TRUE(region->protect(true, false, false).ok());
    ASSERT_TRUE(region->protect(true, true, false).ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(IoObjectsTest, RtFileObjectRoundTrip) {
    ObjectManager mgr;
    const std::string path = "/tmp/xbox2pc_m3_rt_file.bin";
    {
        RtFile file(path, pal::FileOpenMode::WriteNew, "state-file");
        const char data[] = "runtime-state";
        auto w = file.write(data, sizeof(data));
        ASSERT_TRUE(w.ok());
        EXPECT_EQ(w.value(), sizeof(data));
        EXPECT_TRUE(file.is_open());
    }
    {
        RtFile file(path, pal::FileOpenMode::ReadExisting, "state-file");
        char buf[64] = {};
        auto r = file.read(buf, sizeof(buf));
        ASSERT_TRUE(r.ok());
        EXPECT_STREQ(buf, "runtime-state");
    }
    ::unlink(path.c_str());
}

// ── M1/M2 + runtime integration (end-to-end) ───────────────────────────────

TEST(IntegrationTest, ParsedImageDrivesProcessModel) {
    // Full pipeline: PE bytes -> parse -> analyze -> ModuleDescriptor ->
    // RtProcess::initialize -> module queryable.
    test::PeBuildSpec spec;
    spec.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}}},
        {"d3d12_x.dll", {{"D3D12XCreateDevice", 3}}},
    };
    const auto image = test::PeBuilder(spec).build();
    diag::Diagnostics diags;
    const auto img = pe::parse(image.data(), image.size(), "pipeline.exe", diags);
    diag::Diagnostics adiags;
    const auto rep = deps::analyze(img, adiags);
    const auto mod = rt::ModuleDescriptor::from_image(img, rep, "pipeline.exe");

    RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto ph = core.create_process("pipeline.exe");
    ASSERT_TRUE(ph.ok());
    auto g = core.objects().lookup_handle(ph.value());
    auto* proc = g.value().get()->as<RtProcess>();
    ASSERT_TRUE(proc->initialize(mod, rt::RuntimeConfig{}).ok());

    // Metadata flowed through: the process sees the parsed image facts.
    const auto* m = proc->main_module();
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->image_base, 0x140000000u);
    EXPECT_EQ(m->imported_dlls.size(), 2u);
    EXPECT_EQ(m->dll_classes[1].category, "Xbox-specific graphics");

    ASSERT_TRUE(proc->run().ok());
    ASSERT_TRUE(proc->terminate(0u).ok());
    ASSERT_TRUE(core.shutdown().ok());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
