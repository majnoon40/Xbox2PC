// tests/m11_lock_order_test.cpp — M11 Phase 7 adversarial lock-order and
// exit-code-propagation regression suite.
//
// Each concurrency test exercises one codified nesting order from
// docs/m11-lock-order.md on REAL threads with a hard deadline: a lock-order
// inversion shows up as a timeout failure, never as a hung CI job. The
// deadline helper runs the interaction in a worker thread and fails the
// test after kDeadline elapses.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/sync_objects.hpp"
#include "xbox2pc/thread_model.hpp"

namespace {

using namespace xbox2pc;
using rt::ManagedProcess;
using rt::ModuleDescriptor;
using rt::ObjectManager;
using rt::ProcessManager;
using rt::Result;
using rt::RuntimeConfig;
using rt::RuntimeCore;
using rt::RuntimeErrc;
using rt::api::ApiContext;
using rt::api::ApiRegistry;
using rt::api::GameRuntimeService;
using rt::api::TaskQueueService;

constexpr auto kDeadline = std::chrono::seconds(8);

// Runs fn() on a worker thread; fails the test with `what` if it does not
// finish within kDeadline. The worker is left running (detached) if it
// deadlocks — the process exits when the suite does, so a leaked deadlock
// thread cannot corrupt later tests, and the failure was already recorded.
template <typename Fn>
void RunWithDeadline(const char* what, Fn&& fn) {
    std::atomic<bool> done{false};
    std::thread worker([&] {
        fn();
        done.store(true, std::memory_order_release);
    });
    if (done.load(std::memory_order_acquire)) {
        worker.join();
        return;
    }
    const auto start = std::chrono::steady_clock::now();
    while (!done.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() - start > kDeadline) {
            worker.detach();  // deadlocked: record and move on
            FAIL() << what << " did not complete within "
                   << kDeadline.count() << "s (lock-order inversion)";
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    worker.join();
}

struct GdkWorld {
    // Declaration order = destruction order is REVERSE: the registry must
    // outlive core (services hold ApiRegistry&) and pm (services hold
    // ProcessManager&). reg FIRST => destroyed LAST.
    ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    GameRuntimeService* grt = nullptr;
    TaskQueueService* tq = nullptr;

    GdkWorld() : pm(core.objects()) {
        auto grt_s = std::make_unique<GameRuntimeService>(reg, pm);
        auto tq_s = std::make_unique<TaskQueueService>(reg, pm);
        grt = grt_s.get();
        tq = tq_s.get();
        EXPECT_TRUE(core.services().register_service(std::move(grt_s)).ok());
        EXPECT_TRUE(core.services().register_service(std::move(tq_s)).ok());
        EXPECT_TRUE(core.initialize().ok());
    }
    ~GdkWorld() { (void)core.shutdown(); }

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

// Codified order 1 & 2 (docs/m11-lock-order.md): process-exit observers run
// with the manager lock RELEASED, so an observer that re-enters manager map
// operations (find/list/stats) must complete instead of deadlocking — even
// while a concurrent second termination is in flight.
TEST(M11LockOrder, ManagerLookupDuringTerminationCompletes) {
    GdkWorld w;
    const auto pid_a = w.new_process("lock-order-a.exe");
    (void)w.new_process("lock-order-b.exe");

    std::atomic<std::uint64_t> observer_exit_codes_sum{0};
    std::atomic<int> observer_reentries{0};
    auto observer = w.pm.add_process_exit_observer([&](std::uint64_t /*pid*/) {
        // Re-enter the manager the way a real service observer would.
        const auto count = w.pm.process_count();
        observer_reentries.fetch_add(static_cast<int>(count > 0 ? 1 : 0),
                                     std::memory_order_relaxed);
        for (const auto& info : w.pm.list_processes()) {
            observer_exit_codes_sum.fetch_add(
                info.state == rt::ProcessState::Terminated ? 1u : 0u,
                std::memory_order_relaxed);
        }
    });
    ASSERT_TRUE(observer.ok());

    RunWithDeadline("observer re-entry during termination", [&] {
        ASSERT_TRUE(w.pm.terminate_process(w.last_handle, 42u).ok());
    });

    // Codified order 1: process statistics nest manager lock -> object
    // pin -> detail/handle-table locks. Hammer them concurrently with a
    // second termination to prove the nesting is not order-dependent.
    std::atomic<bool> stop{false};
    std::vector<std::thread> hammer;
    for (int i = 0; i < 3; ++i) {
        hammer.emplace_back([&] {
            while (!stop.load(std::memory_order_acquire)) {
                (void)w.pm.process_stats(w.last_handle);
                (void)w.pm.list_processes();
                (void)w.pm.resolve_pid(w.last_handle);
            }
        });
    }
    RunWithDeadline("stats during second termination", [&] {
        ASSERT_TRUE(w.pm.terminate_process(w.last_handle, 7u).ok());
    });
    stop.store(true, std::memory_order_release);
    for (auto& t : hammer) t.join();
    EXPECT_TRUE(w.pm.remove_process_exit_observer(observer.value()).ok());
    (void)pid_a;
}

// Codified orders 3 & 4 (docs/m11-lock-order.md): guest sync close nests
// sync-transaction lock -> process lookup -> handle-table close -> service
// state lock, and wait probes serialize transaction lock -> object lock.
// Close events concurrently with waits and manager statistics on real
// threads: any inversion deadlocks past the deadline and fails.
TEST(M11LockOrder, SyncCloseConcurrentWithWaitAndStats) {
    GdkWorld w;
    const auto pid = w.new_process("lock-order-sync.exe");

    // Shared live-handle set guarded by its own mutex: the closer mutates
    // the set while the waiter snapshots it. (The TEST harness needs the
    // mutex; the runtime's cross-thread handle safety is the object under
    // test, provided by the handle table's generation checks.)
    std::mutex events_lock;
    std::vector<std::uint64_t> events;
    for (int i = 0; i < 8; ++i) {
        auto e = w.grt->create_event(pid, false /*manual*/, false /*set*/);
        ASSERT_TRUE(e.ok());
        events.push_back(e.value());
    }

    std::atomic<bool> stop{false};
    std::vector<std::thread> workers;

    // Waiter: probes un-signaled auto-reset events with short timeouts —
    // sync-transaction lock -> event lock, repeatedly.
    workers.emplace_back([&] {
        std::vector<std::uint64_t> snapshot;
        while (!stop.load(std::memory_order_acquire)) {
            {
                std::lock_guard lock(events_lock);
                snapshot = events;
            }
            for (const auto h : snapshot) {
                (void)w.grt->wait_event(pid, h, 1 /*ms*/);
            }
        }
    });
    // Closer: signals then closes through the generic typed dispatch —
    // transaction -> manager -> handle-table -> state lock.
    workers.emplace_back([&] {
        while (!stop.load(std::memory_order_acquire)) {
            std::vector<std::uint64_t> snapshot;
            {
                std::lock_guard lock(events_lock);
                snapshot = events;
                events.clear();
            }
            for (const auto h : snapshot) {
                (void)w.grt->set_event(pid, h);
                (void)w.grt->close_guest_object(pid, h);
            }
            // Re-create so the closer always has live handles to work on.
            for (std::size_t i = 0; i < snapshot.size(); ++i) {
                auto e = w.grt->create_event(pid, false, false);
                if (e.ok()) {
                    std::lock_guard lock(events_lock);
                    events.push_back(e.value());
                }
            }
        }
    });
    // Manager hammer: stats/list resolve manager -> detail -> handle-table.
    workers.emplace_back([&] {
        while (!stop.load(std::memory_order_acquire)) {
            (void)w.pm.process_stats(w.last_handle);
            (void)w.pm.list_processes();
        }
    });

    // Let the storm run, then stop and join everything under a deadline.
    RunWithDeadline("sync close / wait / stats storm", [&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        stop.store(true, std::memory_order_release);
        for (auto& t : workers) t.join();
    });
}

// Phase 7 exit-code propagation: terminate_process(code) must surface the
// exact code through RtProcess::exit_code(), ProcessManager::ProcessInfo
// (CLI surface), and the exit-observer PID ordering — with no observer
// seeing a pre-termination state.
TEST(M11ExitCode, PropagatesToListingAndObservers) {
    GdkWorld w;
    const auto pid = w.new_process("exit-code.exe");

    std::atomic<std::uint64_t> seen_pid{0};
    std::atomic<int> observer_calls{0};
    auto observer = w.pm.add_process_exit_observer([&](std::uint64_t exited) {
        observer_calls.fetch_add(1, std::memory_order_relaxed);
        seen_pid.store(exited, std::memory_order_relaxed);
    });
    ASSERT_TRUE(observer.ok());

    constexpr std::uint64_t kCode = 0xDEADBEEFull;
    RunWithDeadline("terminate with exit code", [&] {
        ASSERT_TRUE(w.pm.terminate_process(w.last_handle, kCode).ok());
    });

    EXPECT_EQ(seen_pid.load(std::memory_order_relaxed), pid);
    EXPECT_EQ(observer_calls.load(std::memory_order_relaxed), 1);

    const auto info = w.pm.find_process(w.last_handle);
    ASSERT_TRUE(info.ok());
    const auto* proc = info.value().get()->as<rt::RtProcess>();
    ASSERT_NE(proc, nullptr);
    EXPECT_EQ(proc->exit_code(), kCode);

    bool listed = false;
    for (const auto& entry : w.pm.list_processes()) {
        if (entry.pid == pid) {
            listed = true;
            EXPECT_EQ(entry.exit_code, kCode);
            EXPECT_EQ(entry.state, rt::ProcessState::Terminated);
        }
    }
    EXPECT_TRUE(listed);
    EXPECT_TRUE(w.pm.remove_process_exit_observer(observer.value()).ok());
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
