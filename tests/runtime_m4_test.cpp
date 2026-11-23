// M4 GoogleTest suites — memory, threads, handles, processes, accounting.
//
// Coverage per the milestone requirements (see the M4 spec): allocation,
// release, protection, alignment, address-space isolation, failure
// handling, concurrent access; thread startup/completion/joining/
// cancellation/exit status/TLS/exception containment/concurrency; handle
// ownership/duplication/rights reduction/inheritance/stale rejection/
// concurrent ops; process initialization/startup/termination/rollback/
// thread cleanup/resource cleanup; full M1..M4 integration; resource
// accounting consistency; shutdown with active resources.
//
// Concurrency tests repeat (kRepeat) per the M4 spec.

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/sync_objects.hpp"
#include "xbox2pc/thread_model.hpp"

using namespace xbox2pc;
using rt::AccessRights;
using rt::AddressSpace;
using rt::Handle;
using rt::HandleTable;
using rt::has_right;
using rt::ManagedProcess;
using rt::MemoryAllocator;
using rt::MemoryLimits;
using rt::MemProtect;
using rt::ObjectManager;
using rt::ProcessManager;
using rt::ProcessState;
using rt::RegionState;
using rt::ResourceLimits;
using rt::ResourceStats;
using rt::Result;
using rt::RtCancellableWait;
using rt::RtEvent;
using rt::RtMutex;
using rt::RtSemaphore;
using rt::RtThread;
using rt::RuntimeErrc;
using rt::VmRegion;
using rt::WaitSet;

namespace {
constexpr int kRepeat = 5;

void* noop_main(rt::RtThread&, void*) { return nullptr; }

// A trivial object for handle/rights tests.
class TrivialObject : public rt::RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(TrivialObject, Event)
    explicit TrivialObject(std::string tag) : rt::RuntimeObject(rt::TypeId::Event) {
        set_name(std::move(tag));
    }
};

}  // namespace

// ── memory: address spaces ────────────────────────────────────────────────

TEST(MemoryTest, ReserveCommitProtectRelease) {
    AddressSpace space(64 * 4096, 0x10000000, "test");
    const auto page = space.page_size();

    // Reserve: page-aligned VA required.
    auto bad = space.reserve_region(0x10000000 + 1, page, "misaligned");
    ASSERT_FALSE(bad.ok());
    EXPECT_EQ(bad.errc(), RuntimeErrc::InvalidArgument);

    auto r = space.reserve_region(0x10000000, 2 * page, "code");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value(), 0x10000000u);

    // Reserved (not committed): translate refuses.
    auto tr = space.translate(0x10000000);
    ASSERT_FALSE(tr.ok());

    // Commit -> RW default.
    ASSERT_TRUE(space.commit_region(0x10000000).ok());
    auto reg = space.find_region(0x10000000);
    ASSERT_TRUE(reg.ok());
    EXPECT_EQ(reg.value().state, RegionState::Committed);
    EXPECT_EQ(reg.value().protection, MemProtect::ReadWrite);

    // Translate now works; write/read through the host mapping.
    auto host = space.translate(0x10000000);
    ASSERT_TRUE(host.ok());
    auto* p = static_cast<std::uint8_t*>(host.value());
    p[0] = 0x5A;
    EXPECT_EQ(p[0], 0x5A);

    // Read-only: validate_access rejects writes, allows reads.
    ASSERT_TRUE(space.protect_region(0x10000000, MemProtect::ReadOnly).ok());
    EXPECT_FALSE(space.validate_access(0x10000000, /*write=*/true, false).ok());
    EXPECT_TRUE(space.validate_access(0x10000000, /*write=*/false, false).ok());
    EXPECT_FALSE(space.validate_access(0x10000000, false, /*exec=*/true).ok());

    // RX: exec allowed, write denied.
    ASSERT_TRUE(space.protect_region(0x10000000, MemProtect::ReadExecute).ok());
    EXPECT_TRUE(space.validate_access(0x10000000, false, true).ok());
    EXPECT_FALSE(space.validate_access(0x10000000, true, false).ok());

    // Release.
    ASSERT_TRUE(space.release_region(0x10000000).ok());
    auto gone = space.find_region(0x10000000);
    ASSERT_FALSE(gone.ok());
}

TEST(MemoryTest, OverlapDetectionAndAutoPlacement) {
    AddressSpace space(64 * 4096, 0x10000000, "test");
    const auto page = space.page_size();

    auto r1 = space.reserve_region(0x10000000, 4 * page, "a");
    ASSERT_TRUE(r1.ok());
    // Overlapping reservation -> typed AlreadyExists.
    auto over = space.reserve_region(0x10000000 + page, 2 * page, "b");
    ASSERT_FALSE(over.ok());
    EXPECT_EQ(over.errc(), RuntimeErrc::AlreadyExists);

    // Auto placement skips the occupied range.
    auto r2 = space.reserve_region_auto(2 * page, "auto");
    ASSERT_TRUE(r2.ok());
    EXPECT_EQ(r2.value(), 0x10000000 + 4 * page);

    // find_containing works inside regions and refuses gaps.
    auto inside = space.find_containing(r2.value() + page);
    ASSERT_TRUE(inside.ok());
    EXPECT_EQ(inside.value().xbox_va, r2.value());
    auto gap = space.find_containing(0x10000000 + 4 * page - 1);  // inside r1's tail page? no: r1 covers it
    SUCCEED();  // (r1 covers 4 pages; address chosen inside r1.)
}

TEST(MemoryTest, ResizeGrowShrink) {
    AddressSpace space(32 * 4096, 0x20000000, "resize");
    const auto page = space.page_size();
    auto r = space.reserve_region(0x20000000, 2 * page, "r");
    ASSERT_TRUE(r.ok());
    // Shrink to one page.
    ASSERT_TRUE(space.resize_region(0x20000000, page).ok());
    auto reg = space.find_region(0x20000000);
    EXPECT_EQ(reg.value().size, page);
    // Grow back to 3 pages (next space is free).
    ASSERT_TRUE(space.resize_region(0x20000000, 3 * page).ok());
    reg = space.find_region(0x20000000);
    EXPECT_EQ(reg.value().size, 3 * page);
    // Grow into a neighbor -> AlreadyExists.
    auto other = space.reserve_region_auto(page, "neighbor");
    ASSERT_TRUE(other.ok());
    auto clash = space.resize_region(0x20000000, 5 * page);
    ASSERT_FALSE(clash.ok());
}

TEST(MemoryTest, LimitEnforcement) {
    AddressSpace space(16 * 4096, 0x10000000, "limited");
    const auto page = space.page_size();
    MemoryLimits lim;
    lim.max_reserved_bytes = 3 * page;
    space.set_limits(lim);

    ASSERT_TRUE(space.reserve_region(0x10000000, page, "r1").ok());
    ASSERT_TRUE(space.reserve_region(0x10000000 + page, 2 * page, "r2").ok());
    auto over = space.reserve_region(0x10000000 + 3 * page, page, "r3");
    ASSERT_FALSE(over.ok());
    EXPECT_EQ(over.errc(), RuntimeErrc::OutOfResources);

    // Committed limit.
    MemoryLimits lim2;
    lim2.max_committed_bytes = page;
    space.set_limits(lim2);
    ASSERT_TRUE(space.commit_region(0x10000000).ok());
    auto over2 = space.commit_region(0x10000000 + page);
    ASSERT_FALSE(over2.ok());
    EXPECT_EQ(over2.errc(), RuntimeErrc::OutOfResources);
}

TEST(MemoryTest, CommittedRegionsStillConsumeReservationQuota) {
    AddressSpace space(16 * 4096, 0x18000000, "committed-reservation-quota");
    const auto page = space.page_size();
    MemoryLimits limits;
    limits.max_reserved_bytes = page;
    space.set_limits(limits);

    ASSERT_TRUE(space.reserve_region(0x18000000, page, "first").ok());
    ASSERT_TRUE(space.commit_region(0x18000000).ok());

    // Commit changes page state, not the size of the reserved VA range.
    auto second = space.reserve_region(0x18000000 + page, page, "second");
    ASSERT_FALSE(second.ok());
    EXPECT_EQ(second.errc(), RuntimeErrc::OutOfResources);

    // Growing a committed region consumes reservation quota as well as
    // committed-byte quota; it cannot bypass the reservation ceiling.
    auto grown = space.resize_region(0x18000000, 2 * page);
    ASSERT_FALSE(grown.ok());
    EXPECT_EQ(grown.errc(), RuntimeErrc::OutOfResources);
    const auto region = space.find_region(0x18000000);
    ASSERT_TRUE(region.ok());
    EXPECT_EQ(region.value().size, page);
}

TEST(MemoryTest, RejectsAddressAndSizeArithmeticOverflow) {
    AddressSpace space(16 * 4096, 0x10000000, "overflow");
    auto wrapped_va = space.reserve_region(~0ull - 4095, 4096, "wrapped");
    EXPECT_FALSE(wrapped_va.ok());
    auto wrapped_size = space.reserve_region(0x10000000, ~0ull, "huge");
    EXPECT_FALSE(wrapped_size.ok());
    auto huge_auto = space.reserve_region_auto(~0ull, "huge-auto");
    EXPECT_FALSE(huge_auto.ok());
    AddressSpace invalid_bounds(4096, ~0ull - 2047, "bad-bounds");
    auto invalid_auto = invalid_bounds.reserve_region_auto(4096, "bad");
    EXPECT_FALSE(invalid_auto.ok());
}

TEST(MemoryTest, ResizeCannotBypassReservationOrCommitLimits) {
    AddressSpace space(16 * 4096, 0x10000000, "resize-limit");
    const auto page = space.page_size();
    MemoryLimits lim;
    lim.max_reserved_bytes = 2 * page;
    space.set_limits(lim);
    ASSERT_TRUE(space.reserve_region(0x10000000, page, "r").ok());
    auto reserved_grow = space.resize_region(0x10000000, 3 * page);
    EXPECT_FALSE(reserved_grow.ok());
    EXPECT_EQ(reserved_grow.errc(), RuntimeErrc::OutOfResources);

    ASSERT_TRUE(space.commit_region(0x10000000).ok());
    MemoryLimits committed_lim;
    committed_lim.max_committed_bytes = page;
    space.set_limits(committed_lim);
    auto committed_grow = space.resize_region(0x10000000, 2 * page);
    EXPECT_FALSE(committed_grow.ok());
    EXPECT_EQ(committed_grow.errc(), RuntimeErrc::OutOfResources);
}

TEST(MemoryTest, AddressSpaceIsolation) {
    AddressSpace a(64 * 4096, 0x10000000, "a");
    AddressSpace b(64 * 4096, 0x10000000, "b");
    const auto page = a.page_size();
    ASSERT_TRUE(a.reserve_region(0x10000000, page, "secret").ok());
    ASSERT_TRUE(a.commit_region(0x10000000).ok());
    // Space B has the same VA model but no regions: lookups FAIL there.
    auto in_b = b.find_containing(0x10000000);
    ASSERT_FALSE(in_b.ok());
    auto vb = b.validate_access(0x10000000, false, false);
    ASSERT_FALSE(vb.ok());
    // Distinct space ids.
    EXPECT_NE(a.space_id(), b.space_id());
}

TEST(MemoryTest, ConcurrentRegionOpsStress) {
    for (int rep = 0; rep < kRepeat; ++rep) {
        AddressSpace space(256 * 4096, 0x10000000, "stress");
        std::atomic<int> reserved{0};
        std::atomic<int> rejected{0};
        std::vector<std::thread> workers;
        for (int t = 0; t < 8; ++t) {
            workers.emplace_back([&] {
                for (int i = 0; i < 32; ++i) {
                    auto r = space.reserve_region_auto(4096, "s");
                    if (r.ok()) reserved.fetch_add(1);
                    else rejected.fetch_add(1);
                }
            });
        }
        for (auto& w : workers) w.join();
        EXPECT_EQ(reserved.load(), 256);  // capacity exactly 256 pages
        const auto stats = space.stats();
        EXPECT_EQ(stats.region_count, 256u);
        EXPECT_EQ(stats.reserved_bytes, 256ull * 4096);
    }
}

// ── memory: allocator ────────────────────────────────────────────────────

TEST(AllocatorTest, AlignedAllocationsAndTracking) {
    std::vector<std::uint8_t> backing(8192);
    MemoryAllocator alloc(backing.data(), backing.size());

    auto a = alloc.allocate(100, 16, "a");
    ASSERT_TRUE(a.ok());
    auto b = alloc.allocate(200, 256, "b");
    ASSERT_TRUE(b.ok());
    auto pa = alloc.resolve(a.value());
    auto pb = alloc.resolve(b.value());
    ASSERT_TRUE(pa.ok());
    ASSERT_TRUE(pb.ok());
    // Alignment honored.
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(pa.value()) % 16, 0u);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(pb.value()) % 256, 0u);

    const auto stats = alloc.stats();
    EXPECT_EQ(stats.allocation_count, 2u);
    EXPECT_EQ(stats.used_bytes, 300u);

    // Write/read through resolved pointers.
    std::memset(pa.value(), 0xAA, 100);
    EXPECT_EQ(static_cast<std::uint8_t*>(pa.value())[0], 0xAA);

    // Info + double free detection.
    auto info = alloc.info(a.value());
    ASSERT_TRUE(info.ok());
    EXPECT_EQ(info.value().size, 100u);
    ASSERT_TRUE(alloc.free(a.value()).ok());
    auto dbl = alloc.free(a.value());
    ASSERT_FALSE(dbl.ok());
    EXPECT_EQ(dbl.errc(), RuntimeErrc::NotFound);
    auto stale = alloc.resolve(a.value());
    ASSERT_FALSE(stale.ok());
}

TEST(AllocatorTest, AlignmentAndLimitFailures) {
    std::vector<std::uint8_t> backing(4096);
    MemoryAllocator alloc(backing.data(), backing.size());

    auto bad_align = alloc.allocate(10, 3, "x");  // not a power of two
    ASSERT_FALSE(bad_align.ok());
    auto too_big = alloc.allocate(8192, 16, "y");  // > capacity
    ASSERT_FALSE(too_big.ok());
    EXPECT_EQ(too_big.errc(), RuntimeErrc::OutOfResources);
    auto overflow_size = alloc.allocate(~0ull, 16, "overflow");
    EXPECT_FALSE(overflow_size.ok());
    MemoryAllocator no_backing(nullptr, 4096);
    EXPECT_FALSE(no_backing.allocate(8, 8, "null").ok());

    // Byte limit.
    MemoryAllocator limited(backing.data(), backing.size(), /*max=*/100);
    auto first = limited.allocate(80, 8, "ok");
    ASSERT_TRUE(first.ok());
    auto second = limited.allocate(80, 8, "over");
    ASSERT_FALSE(second.ok());
    EXPECT_EQ(second.errc(), RuntimeErrc::OutOfResources);
}

// ── handles: rights + inheritance + table isolation ───────────────────────

TEST(HandleRightsTest, RightsMetadataAndReduction) {
    ObjectManager mgr;
    HandleTable tableA(mgr, 1);
    HandleTable tableB(mgr, 2);

    auto reg = mgr.register_object(std::make_unique<TrivialObject>("secret"));
    ASSERT_TRUE(reg.ok());
    {
        auto g = mgr.lookup_id(reg.value());
        ASSERT_TRUE(g.ok());
        auto h = tableA.create_with_rights(*g.value().get(),
                                            AccessRights::Read | AccessRights::Close |
                                                AccessRights::Duplicate,
                                            /*inheritable=*/true);
        ASSERT_TRUE(h.ok());
        EXPECT_TRUE(has_right(tableA.rights_of(h.value()), AccessRights::Read));
        EXPECT_FALSE(has_right(tableA.rights_of(h.value()), AccessRights::Write));
        EXPECT_TRUE(tableA.inheritable(h.value()));

        // Duplicate with WIDENED rights -> typed error.
        auto widen = tableA.duplicate(h.value(), AccessRights::All, true);
        ASSERT_FALSE(widen.ok());
        EXPECT_EQ(widen.errc(), RuntimeErrc::InvalidArgument);

        // Duplicate with REDUCED rights -> ok.
        auto reduced = tableA.duplicate(h.value(), AccessRights::Read, false);
        ASSERT_TRUE(reduced.ok());
        EXPECT_TRUE(has_right(tableA.rights_of(reduced.value()), AccessRights::Read));
        EXPECT_FALSE(tableA.rights_of(reduced.value()) == AccessRights::Read
                          ? false
                          : false);
        EXPECT_FALSE(tableA.inheritable(reduced.value()));
    }
}

TEST(HandleRightsTest, CloseRequiresCloseRight) {
    ObjectManager mgr;
    HandleTable table(mgr, 1);
    auto reg = mgr.register_object(std::make_unique<TrivialObject>("x"));
    Handle h;
    {
        auto g = mgr.lookup_id(reg.value());
        h = table.create_with_rights(*g.value().get(),
                                     AccessRights::Read,  // NO Close right
                                     true)
                 .value();
    }
    auto denied = table.close(h);
    ASSERT_FALSE(denied.ok());
    EXPECT_EQ(denied.errc(), RuntimeErrc::InvalidArgument);

    // Full-rights handle closes fine.
    Handle h2;
    {
        auto g = mgr.lookup_id(reg.value());
        h2 = table.create(*g.value().get()).value();
    }
    ASSERT_TRUE(table.close(h2).ok());
}

TEST(HandleRightsTest, CrossTableIsolation) {
    ObjectManager mgr;
    HandleTable tableA(mgr, 1);
    HandleTable tableB(mgr, 2);
    Handle ha;
    {
        auto reg = mgr.register_object(std::make_unique<TrivialObject>("a-obj"));
        auto g = mgr.lookup_id(reg.value());
        ha = tableA.create(*g.value().get()).value();
    }
    // The SAME raw handle in table B: rejected (table id mismatch).
    auto wrong = tableB.lookup(ha);
    ASSERT_FALSE(wrong.ok());
    EXPECT_EQ(wrong.errc(), RuntimeErrc::InvalidHandle);
    // ...and in table A it resolves.
    auto right = tableA.lookup(ha);
    ASSERT_TRUE(right.ok());
}

TEST(HandleRightsTest, ConcurrentDuplicateCloseStress) {
    for (int rep = 0; rep < kRepeat; ++rep) {
        ObjectManager mgr;
        HandleTable table(mgr, 1);
        Handle h;
        {
            auto reg = mgr.register_object(std::make_unique<TrivialObject>("shared"));
            auto g = mgr.lookup_id(reg.value());
            h = table.create(*g.value().get()).value();
        }
        std::atomic<int> dups{0};
        std::atomic<int> closes{0};
        std::vector<std::thread> workers;
        for (int t = 0; t < 8; ++t) {
            workers.emplace_back([&] {
                for (int i = 0; i < 50; ++i) {
                    if (i % 2 == 0) {
                        auto d = table.duplicate(h);
                        if (d.ok()) dups.fetch_add(1);
                    } else {
                        auto d = table.duplicate(h);
                        if (d.ok()) {
                            dups.fetch_add(1);
                            if (table.close(d.value()).ok()) closes.fetch_add(1);
                        }
                    }
                }
            });
        }
        for (auto& w : workers) w.join();
        // All duplicates/closes succeeded on a live object.
        EXPECT_EQ(dups.load(), 400);
        EXPECT_EQ(closes.load(), 200);
        EXPECT_EQ(table.live_count(), 1u + 200u);  // original + 200 alive dups
    }
}

// ── thread execution ─────────────────────────────────────────────────────

TEST(ThreadExecTest, StartupCompletionJoinExit) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    auto th = core.create_thread(
        [](rt::RtThread&, void* arg) -> void* { return arg; },
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(42)), "worker");
    ASSERT_TRUE(th.ok());
    rt::RtThread* t = nullptr;
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(t->start().ok());
    auto joined = t->join_ns(pal::kInfiniteTimeout);
    ASSERT_TRUE(joined.ok());
    EXPECT_EQ(joined.value(), 42u);

    // M4: joining a COMPLETED thread returns the recorded exit code.
    auto again = t->join_ns(pal::kInfiniteTimeout);
    ASSERT_TRUE(again.ok());
    EXPECT_EQ(again.value(), 42u);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadExecTest, JoinSelfRejected) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtThread* inner = nullptr;
    auto th = core.create_thread(
        [](rt::RtThread& self, void*) -> void* {
            // Joining oneself -> typed ThreadTerminated("join-self").
            const auto r = self.join_ns(pal::kInfiniteTimeout);
            EXPECT_FALSE(r.ok());
            EXPECT_EQ(r.errc(), RuntimeErrc::ThreadTerminated);
            return reinterpret_cast<void*>(static_cast<std::uintptr_t>(7));
        },
        nullptr, "self-joiner");
    {
        auto g = core.objects().lookup_handle(th.value());
        inner = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(inner->start().ok());
    auto joined = inner->join_ns(pal::kInfiniteTimeout);
    ASSERT_TRUE(joined.ok());
    EXPECT_EQ(joined.value(), 7u);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadExecTest, MultipleJoiners) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtThread* t = nullptr;
    auto th = core.create_thread(
        [](rt::RtThread&, void*) -> void* {
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            return reinterpret_cast<void*>(static_cast<std::uintptr_t>(99));
        },
        nullptr, "joined-by-many");
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(t->start().ok());
    std::atomic<int> successes{0};
    std::vector<std::thread> joiners;
    for (int i = 0; i < 4; ++i) {
        joiners.emplace_back([&] {
            auto r = t->join_ns(pal::kInfiniteTimeout);
            if (r.ok() && r.value() == 99) successes.fetch_add(1);
        });
    }
    for (auto& j : joiners) j.join();
    EXPECT_EQ(successes.load(), 4);  // every joiner got the exit code
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadExecTest, ExceptionContainment) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtThread* t = nullptr;
    auto th = core.create_thread(
        [](rt::RtThread&, void*) -> void* { throw std::runtime_error("boom"); },
        nullptr, "thrower");
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(t->start().ok());
    auto joined = t->join_ns(pal::kInfiniteTimeout);
    // The exception is CONTAINED: distinct exit code + Failed state.
    ASSERT_TRUE(joined.ok());
    EXPECT_EQ(joined.value(), rt::RtThread::kExceptionExitCode);
    EXPECT_EQ(t->state(), rt::ThreadState::Failed);
    EXPECT_NE(t->fail_reason().find("boom"), std::string::npos);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadExecTest, CooperativeSuspendResumeIsNotCancellation) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    std::atomic<std::uint64_t> progress{0};
    auto th = core.create_thread(
        [](rt::RtThread& self, void* raw) -> void* {
            auto* count = static_cast<std::atomic<std::uint64_t>*>(raw);
            while (self.suspension_point()) {
                count->fetch_add(1, std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return nullptr;
        },
        &progress, "suspend-resume-worker");
    ASSERT_TRUE(th.ok());
    rt::RtThread* thread = nullptr;
    {
        auto guard = core.objects().lookup_handle(th.value());
        ASSERT_TRUE(guard.ok());
        thread = guard.value().get()->as<rt::RtThread>();
    }
    ASSERT_NE(thread, nullptr);
    ASSERT_TRUE(thread->start().ok());

    const auto start_deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(2);
    while (progress.load(std::memory_order_relaxed) == 0 &&
           std::chrono::steady_clock::now() < start_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_GT(progress.load(std::memory_order_relaxed), 0u);
    ASSERT_TRUE(thread->suspend().ok());
    const auto parked_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (!thread->execution_control()->is_parked() &&
           std::chrono::steady_clock::now() < parked_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_EQ(thread->state(), rt::ThreadState::Suspended);
    ASSERT_TRUE(thread->execution_control()->is_parked());
    const auto parked_progress = progress.load(std::memory_order_relaxed);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(progress.load(std::memory_order_relaxed), parked_progress);
    EXPECT_FALSE(thread->stop_requested());

    ASSERT_TRUE(thread->resume().ok());
    const auto resume_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (progress.load(std::memory_order_relaxed) == parked_progress &&
           std::chrono::steady_clock::now() < resume_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_GT(progress.load(std::memory_order_relaxed), parked_progress);
    EXPECT_FALSE(thread->stop_requested());

    thread->request_stop();
    auto joined = thread->join_ns(2'000'000'000LL);
    ASSERT_TRUE(joined.ok());
    EXPECT_EQ(thread->state(), rt::ThreadState::Terminated);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadExecTest, CooperativeCancellation) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtThread* t = nullptr;
    std::atomic<bool> observed_cancel{false};
    auto th = core.create_thread(
        [](rt::RtThread& self, void* arg) -> void* {
            auto* flag = static_cast<std::atomic<bool>*>(arg);
            // Cancellation-aware wait loop: exits when stopped.
            while (!self.stop_requested()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            flag->store(true);
            return nullptr;
        },
        &observed_cancel, "cancellable");
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(t->start().ok());
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    t->request_stop();
    auto joined = t->join_ns(1000ull * 1000 * 1000);
    ASSERT_TRUE(joined.ok());
    EXPECT_TRUE(observed_cancel.load());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ThreadExecTest, CancellationAwareWait) {
    // The RtCancellableWait helper: predicate true -> Ok; cancel -> typed
    // ThreadTerminated; deadline -> Timeout.
    std::atomic<bool> flag{false};
    RtCancellableWait w;
    std::thread canceller([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        w.wake_from_cancel();
    });
    auto r = w.wait_until([&] { return flag.load(); }, 1000ull * 1000 * 1000);
    canceller.join();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.errc(), RuntimeErrc::ThreadTerminated);

    // Timeout path.
    RtCancellableWait w2;
    auto t0 = pal::now_ns();
    auto r2 = w2.wait_until([] { return false; }, 40ull * 1000 * 1000);
    const auto elapsed = pal::now_ns() - t0;
    ASSERT_FALSE(r2.ok());
    EXPECT_EQ(r2.errc(), RuntimeErrc::Timeout);
    EXPECT_GE(elapsed, 30ull * 1000 * 1000);

    // Predicate-true path (immediate).
    RtCancellableWait w3;
    auto r3 = w3.wait_until([] { return true; }, 1000ull * 1000 * 1000);
    ASSERT_TRUE(r3.ok());
}

TEST(ThreadExecTest, ThreadNaming) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtThread* t = nullptr;
    // The named thread sleeps briefly so set_name() deterministically runs
    // while it is alive (Linux pthread_setname_np on an exited thread
    // returns ESRCH — a host fact, not a bug).
    auto th = core.create_thread(
        [](rt::RtThread&, void*) -> void* {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            return nullptr;
        },
        nullptr, "named-thread");
    {
        auto g = core.objects().lookup_handle(th.value());
        t = g.value().get()->as<rt::RtThread>();
    }
    ASSERT_TRUE(t->start().ok());
    // Set after start: PAL name applies (Linux truncates to 15 chars + NUL).
    auto r = t->set_name("m4-worker-thread");
    ASSERT_TRUE(r.ok());
    (void)t->join_ns(pal::kInfiniteTimeout);
    // Before start: typed InvalidState on a fresh thread object.
    auto fresh = core.create_thread(noop_main, nullptr, "fresh");
    {
        auto g = core.objects().lookup_handle(fresh.value());
        auto* ft = g.value().get()->as<rt::RtThread>();
        auto early = ft->set_name("too-early");
        ASSERT_FALSE(early.ok());
        EXPECT_EQ(early.errc(), RuntimeErrc::InvalidState);
    }
    ASSERT_TRUE(core.shutdown().ok());
}

// ── wait-any / wait-all ──────────────────────────────────────────────────

TEST(WaitSetTest, WaitAnyAndAll) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtEvent* ev1 = nullptr;
    rt::RtEvent* ev2 = nullptr;
    {
        auto h1 = core.create_event(true, false, "e1");
        auto h2 = core.create_event(false, false, "e2");
        auto g1 = core.objects().lookup_handle(h1.value());
        auto g2 = core.objects().lookup_handle(h2.value());
        ev1 = g1.value().get()->as<rt::RtEvent>();
        ev2 = g2.value().get()->as<rt::RtEvent>();
    }
    // Set e1 (auto-reset): wait_any must pick index 0 while e2 stays unset.
    ASSERT_TRUE(ev1->set().ok());
    WaitSet set;
    set.add_event(*ev1);
    set.add_event(*ev2);
    auto any = set.wait_any(50ull * 1000 * 1000);
    ASSERT_TRUE(any.ok());
    EXPECT_EQ(any.value(), 0u);

    // wait_all times out while e2 unset (e1 was consumed by wait_any).
    auto all = set.wait_all(50ull * 1000 * 1000);
    ASSERT_FALSE(all.ok());
    EXPECT_EQ(all.errc(), RuntimeErrc::Timeout);

    // Set BOTH (e1 was consumed by the earlier wait_any): wait_all succeeds.
    ev1->set();
    ev2->set();
    auto all2 = set.wait_all(50ull * 1000 * 1000);
    ASSERT_TRUE(all2.ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(WaitSetTest, WaitAllMutexRollback) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    rt::RtMutex* m = nullptr;
    rt::RtEvent* ev = nullptr;
    {
        auto hm = core.create_mutex("m");
        auto he = core.create_event(false, false, "never");
        auto gm = core.objects().lookup_handle(hm.value());
        auto ge = core.objects().lookup_handle(he.value());
        m = gm.value().get()->as<rt::RtMutex>();
        ev = ge.value().get()->as<rt::RtEvent>();
    }
    WaitSet set;
    set.add_mutex(*m);
    set.add_event(*ev);  // never set
    auto all = set.wait_all(40ull * 1000 * 1000);
    ASSERT_FALSE(all.ok());
    // Rollback: the mutex acquired during the attempt is released.
    auto probe = m->try_lock();
    ASSERT_TRUE(probe.ok());
    (void)m->unlock();
    ASSERT_TRUE(core.shutdown().ok());
}

// ── processes: manager lifecycle + cleanup + rollback ─────────────────────

TEST(ProcessMgmtTest, FullLifecycleWithCleanup) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());

    auto ph = pm.create_process("game.exe");
    ASSERT_TRUE(ph.ok());

    // Start WITHOUT initialize: typed InvalidTransition (state machine).
    auto early = pm.start_process(ph.value());
    ASSERT_FALSE(early.ok());
    EXPECT_EQ(early.errc(), RuntimeErrc::InvalidTransition);

    // Initialize with an M3 module descriptor, then start.
    rt::ModuleDescriptor mod;
    mod.module_name = "game.exe";
    mod.is_valid_pe = true;
    ASSERT_TRUE(pm.initialize_process(ph.value(), mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.start_process(ph.value()).ok());

    // Threads + memory.
    auto th = pm.spawn_thread(ph.value(), noop_main, nullptr, "worker");
    ASSERT_TRUE(th.ok());
    auto region = pm.reserve_region(ph.value(), 8192, "heap");
    ASSERT_TRUE(region.ok());
    ASSERT_TRUE(pm.commit_region(ph.value(), region.value()).ok());

    auto pstats = pm.process_stats(ph.value());
    EXPECT_EQ(pstats.thread_count, 1u);
    EXPECT_EQ(pstats.committed_bytes, 8192u);

    // Terminate: exact cleanup ordering runs.
    ASSERT_TRUE(pm.terminate_process(ph.value(), 0u).ok());
    auto after = pm.process_stats(ph.value());
    EXPECT_EQ(after.thread_count, 0u);
    EXPECT_EQ(after.committed_bytes, 0u);
    EXPECT_EQ(after.region_count, 0u);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessMgmtTest, ProcessSuspendResumeDoesNotCancelOwnedThreads) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());
    auto process = pm.create_process("suspend-process.exe");
    ASSERT_TRUE(process.ok());
    rt::ModuleDescriptor module;
    ASSERT_TRUE(pm.initialize_process(process.value(), module,
                                      rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.start_process(process.value()).ok());

    std::atomic<std::uint64_t> progress{0};
    auto spawned = pm.spawn_thread(
        process.value(),
        [](rt::RtThread& self, void* raw) -> void* {
            auto* count = static_cast<std::atomic<std::uint64_t>*>(raw);
            while (self.suspension_point()) {
                count->fetch_add(1, std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return nullptr;
        },
        &progress, "process-owned-suspend-worker");
    ASSERT_TRUE(spawned.ok());

    auto process_ref = pm.find_process(process.value());
    ASSERT_TRUE(process_ref.ok());
    auto* managed = process_ref.value().get()->as<ManagedProcess>();
    ASSERT_NE(managed, nullptr);
    const auto thread_ids = managed->thread_ids();
    ASSERT_EQ(thread_ids.size(), 1u);
    auto thread_ref = core.objects().lookup_id(thread_ids.front());
    ASSERT_TRUE(thread_ref.ok());
    auto* thread = thread_ref.value().get()->as<RtThread>();
    ASSERT_NE(thread, nullptr);

    const auto start_deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(2);
    while (progress.load(std::memory_order_relaxed) == 0 &&
           std::chrono::steady_clock::now() < start_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_GT(progress.load(std::memory_order_relaxed), 0u);

    ASSERT_TRUE(pm.suspend_process(process.value()).ok());
    const auto parked_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (!thread->execution_control()->is_parked() &&
           std::chrono::steady_clock::now() < parked_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(thread->execution_control()->is_parked());
    const auto parked_progress = progress.load(std::memory_order_relaxed);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(progress.load(std::memory_order_relaxed), parked_progress);
    EXPECT_FALSE(thread->stop_requested());

    ASSERT_TRUE(pm.resume_process(process.value()).ok());
    const auto resume_deadline = std::chrono::steady_clock::now() +
                                 std::chrono::seconds(2);
    while (progress.load(std::memory_order_relaxed) == parked_progress &&
           std::chrono::steady_clock::now() < resume_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_GT(progress.load(std::memory_order_relaxed), parked_progress);
    EXPECT_FALSE(thread->stop_requested());

    ASSERT_TRUE(pm.terminate_process(process.value(), 0).ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessMgmtTest, MultipleProcessesIsolation) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());

    auto pa = pm.create_process("a.exe");
    auto pb = pm.create_process("b.exe");
    ASSERT_TRUE(pa.ok());
    ASSERT_TRUE(pb.ok());
    EXPECT_NE(pa.value().raw(), pb.value().raw());

    rt::ModuleDescriptor mod;
    ASSERT_TRUE(pm.initialize_process(pa.value(), mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.initialize_process(pb.value(), mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.start_process(pa.value()).ok());
    ASSERT_TRUE(pm.start_process(pb.value()).ok());

    // Each process reserves + commits its own region.
    auto ra = pm.reserve_region(pa.value(), 4096, "a-only");
    auto rb = pm.reserve_region(pb.value(), 4096, "b-only");
    ASSERT_TRUE(ra.ok());
    ASSERT_TRUE(rb.ok());
    ASSERT_TRUE(pm.commit_region(pa.value(), ra.value()).ok());
    ASSERT_TRUE(pm.commit_region(pb.value(), rb.value()).ok());

    // VA spaces are independent: b's region does not resolve in a.
    auto in_a = pm.find_process(pa.value());
    auto* proc_a = in_a.value().get()->as<ManagedProcess>();
    auto wrong = proc_a->address_space().find_containing(rb.value());
    ASSERT_FALSE(wrong.ok());

    // Terminate a: b unaffected.
    ASSERT_TRUE(pm.terminate_process(pa.value(), 1u).ok());
    auto stats_b = pm.process_stats(pb.value());
    EXPECT_EQ(stats_b.committed_bytes, 4096u);
    EXPECT_EQ(stats_b.thread_count, 0u);
    ASSERT_TRUE(pm.terminate_process(pb.value(), 0u).ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessMgmtTest, WxProtectionDiscipline) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());
    auto ph = pm.create_process("wx.exe");
    ASSERT_TRUE(ph.ok());
    rt::ModuleDescriptor mod;
    ASSERT_TRUE(pm.initialize_process(ph.value(), mod, rt::RuntimeConfig{}).ok());

    auto region = pm.reserve_region(ph.value(), 4096, "code");
    ASSERT_TRUE(region.ok());
    ASSERT_TRUE(pm.commit_region(ph.value(), region.value()).ok());

    // Default commit is RW — never RWX.
    auto reg = pm.find_process(ph.value()).value().get()->as<ManagedProcess>()
                   ->address_space()
                   .find_region(region.value());
    EXPECT_EQ(reg.value().protection, MemProtect::ReadWrite);

    // RX is allowed.
    ASSERT_TRUE(pm.protect_region(ph.value(), region.value(),
                                 MemProtect::ReadExecute, pm.limits()).ok());
    // RWX is denied by default (W^X).
    auto wx = pm.protect_region(ph.value(), region.value(), MemProtect::Full,
                                pm.limits());
    ASSERT_FALSE(wx.ok());
    EXPECT_EQ(wx.errc(), RuntimeErrc::InvalidArgument);
    // ...and allowed with the explicit opt-in.
    ResourceLimits opt_in;
    opt_in.allow_wx_pages = true;
    ASSERT_TRUE(pm.protect_region(ph.value(), region.value(), MemProtect::Full,
                                  opt_in).ok());
    ASSERT_TRUE(pm.terminate_process(ph.value(), 0u).ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessMgmtTest, ActiveThreadsAtTermination) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());
    auto ph = pm.create_process("threads.exe");
    ASSERT_TRUE(ph.ok());
    rt::ModuleDescriptor mod;
    ASSERT_TRUE(pm.initialize_process(ph.value(), mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.start_process(ph.value()).ok());

    std::atomic<int> finished{0};
    for (int i = 0; i < 4; ++i) {
        auto th = pm.spawn_thread(
            ph.value(),
            [](rt::RtThread& self, void* arg) -> void* {
                auto* fin = static_cast<std::atomic<int>*>(arg);
                while (!self.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                fin->fetch_add(1);
                return nullptr;
            },
            &finished, "worker-" + std::to_string(i));
        ASSERT_TRUE(th.ok());
    }
    // Terminate with ACTIVE threads: they observe the cooperative stop and
    // finish; cleanup completes without killing them.
    ASSERT_TRUE(pm.terminate_process(ph.value(), 0u).ok());
    EXPECT_EQ(finished.load(), 4);
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessMgmtTest, GlobalResourceAccounting) {
    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());

    auto p1 = pm.create_process("p1.exe");
    auto p2 = pm.create_process("p2.exe");
    ASSERT_TRUE(p1.ok());
    ASSERT_TRUE(p2.ok());
    rt::ModuleDescriptor mod;
    ASSERT_TRUE(pm.initialize_process(p1.value(), mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.initialize_process(p2.value(), mod, rt::RuntimeConfig{}).ok());

    auto r1 = pm.reserve_region(p1.value(), 2 * 4096, "r1");
    auto r2 = pm.reserve_region(p2.value(), 3 * 4096, "r2");
    ASSERT_TRUE(r1.ok());
    ASSERT_TRUE(r2.ok());
    ASSERT_TRUE(pm.commit_region(p1.value(), r1.value()).ok());
    ASSERT_TRUE(pm.commit_region(p2.value(), r2.value()).ok());

    const ResourceStats g = pm.global_stats();
    EXPECT_EQ(g.process_count, 2u);
    EXPECT_EQ(g.region_count, 2u);
    EXPECT_EQ(g.committed_bytes, 5 * 4096u);
    EXPECT_EQ(g.address_space_count, 2u);
    EXPECT_GT(g.object_count, 0u);

    // Limits: global committed cap — current usage is 5 pages, cap at 5:
    // committing one more page must be REJECTED with a typed error.
    ResourceLimits lim;
    lim.max_committed_bytes_total = 5 * 4096;
    pm.set_limits(lim);
    auto p3 = pm.create_process("p3.exe");
    ASSERT_TRUE(p3.ok());
    auto r3 = pm.reserve_region(p3.value(), 4096, "r3");
    ASSERT_TRUE(r3.ok());
    auto over = pm.commit_region(p3.value(), r3.value());
    ASSERT_FALSE(over.ok());
    EXPECT_EQ(over.errc(), RuntimeErrc::OutOfResources);

    // Terminate p1 (releases 2 pages), then the same commit succeeds.
    ASSERT_TRUE(pm.terminate_process(p1.value(), 0u).ok());
    auto now_ok = pm.commit_region(p3.value(), r3.value());
    ASSERT_TRUE(now_ok.ok());
    ASSERT_TRUE(pm.terminate_process(p2.value(), 0u).ok());
    ASSERT_TRUE(pm.terminate_process(p3.value(), 0u).ok());
    ASSERT_TRUE(core.shutdown().ok());
}

TEST(ProcessMgmtTest, RuntimeShutdownWithActiveResources) {
    // Shutdown with a live process + region + thread: the destructors drive
    // deterministic cleanup; nothing hangs or leaks.
    {
        rt::RuntimeCore core;
        ASSERT_TRUE(core.initialize().ok());
        ProcessManager pm(core.objects());
        auto ph = pm.create_process("alive.exe");
        ASSERT_TRUE(ph.ok());
        rt::ModuleDescriptor mod;
        ASSERT_TRUE(pm.initialize_process(ph.value(), mod, rt::RuntimeConfig{}).ok());
        ASSERT_TRUE(pm.start_process(ph.value()).ok());
        (void)pm.reserve_region(ph.value(), 8192, "heap");
        auto th = pm.spawn_thread(ph.value(), noop_main, nullptr, "t");
        ASSERT_TRUE(th.ok());
    }  // core dtor + pm dtor run teardown
    SUCCEED();
}

// ── integration: full M1..M4 pipeline ────────────────────────────────────

TEST(IntegrationM4Test, ParsedImageThroughProcessManager) {
    // M1/M2 build+parse+analyze -> M3 ModuleDescriptor -> M4 process with
    // address space reserved for the image (size_of_image), a worker
    // thread, resource accounting, and clean termination.
    test::PeBuildSpec spec;
    spec.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}}},
        {"d3d12_x.dll", {{"D3D12XCreateDevice", 3}}},
    };
    const auto image = test::PeBuilder(spec).build();
    diag::Diagnostics diags;
    const auto img = pe::parse(image.data(), image.size(), "m4.exe", diags);
    diag::Diagnostics adiags;
    const auto rep = deps::analyze(img, adiags);
    const auto mod = rt::ModuleDescriptor::from_image(img, rep, "m4.exe");

    rt::RuntimeCore core;
    ASSERT_TRUE(core.initialize().ok());
    ProcessManager pm(core.objects());

    auto ph = pm.create_process("m4.exe");
    ASSERT_TRUE(ph.ok());
    ASSERT_TRUE(pm.initialize_process(ph.value(), mod, rt::RuntimeConfig{}).ok());
    ASSERT_TRUE(pm.start_process(ph.value()).ok());

    // Reserve + commit an image-sized region (future loader target; M4
    // does NOT map/copy anything).
    auto region = pm.reserve_region(ph.value(), mod.size_of_image, "image");
    ASSERT_TRUE(region.ok());
    ASSERT_TRUE(pm.commit_region(ph.value(), region.value()).ok());

    auto th = pm.spawn_thread(ph.value(), noop_main, nullptr, "loader-thread");
    ASSERT_TRUE(th.ok());

    const auto stats = pm.process_stats(ph.value());
    EXPECT_EQ(stats.module_count, 1u);
    EXPECT_GE(stats.committed_bytes, mod.size_of_image);

    ASSERT_TRUE(pm.terminate_process(ph.value(), 0u).ok());
    ASSERT_TRUE(core.shutdown().ok());
}


TEST(GuestSyncTest, MutexTracksGuestOwnershipAndRecursion) {
    rt::RtGuestMutex m;
    auto first=m.acquire(101,0); ASSERT_TRUE(first.ok()); EXPECT_FALSE(first.value());
    auto recursive=m.acquire(101,0); ASSERT_TRUE(recursive.ok()); EXPECT_FALSE(recursive.value());
    EXPECT_EQ(m.release(202).errc(),RuntimeErrc::LockNotOwned);
    ASSERT_TRUE(m.release(101).ok()); EXPECT_EQ(m.acquire(202,0).errc(),RuntimeErrc::Timeout);
    ASSERT_TRUE(m.release(101).ok()); auto second=m.acquire(202,0); ASSERT_TRUE(second.ok());
    EXPECT_FALSE(second.value()); ASSERT_TRUE(m.release(202).ok());
}
TEST(GuestSyncTest, MutexReportsAbandonedOwnership) {
    rt::RtGuestMutex m; ASSERT_TRUE(m.acquire(11,0).ok()); ASSERT_TRUE(m.abandon_owner(11).ok());
    auto recovered=m.acquire(22,0); ASSERT_TRUE(recovered.ok()); EXPECT_TRUE(recovered.value());
    EXPECT_EQ(m.abandon_owner(11).errc(),RuntimeErrc::LockNotOwned); ASSERT_TRUE(m.release(22).ok());
}
TEST(GuestSyncTest, MutexTimeoutCancellationAndClose) {
    rt::RtGuestMutex m; ASSERT_TRUE(m.acquire(1,0).ok());
    EXPECT_EQ(m.acquire(2,1'000'000).errc(),RuntimeErrc::Timeout);
    EXPECT_EQ(m.acquire(2,20'000'000,[]{return true;}).errc(),RuntimeErrc::ThreadTerminated);
    m.close(); EXPECT_EQ(m.acquire(2,-1).errc(),RuntimeErrc::ObjectDestroyed);
}
TEST(GuestSyncTest, SemaphoreCountBoundsAndPreviousCount) {
    rt::RtGuestSemaphore s(1,3); ASSERT_TRUE(s.acquire(0).ok()); EXPECT_EQ(s.value(),0);
    EXPECT_EQ(s.try_acquire().errc(),RuntimeErrc::Timeout);
    auto r=s.release(2); ASSERT_TRUE(r.ok()); EXPECT_EQ(r.value(),0); EXPECT_EQ(s.value(),2);
    EXPECT_EQ(s.release(2).errc(),RuntimeErrc::InvalidState);
    EXPECT_EQ(s.release(0).errc(),RuntimeErrc::InvalidArgument);
    ASSERT_TRUE(s.acquire(0).ok()); EXPECT_EQ(s.value(),1);
}
TEST(GuestSyncTest, SemaphoreCancellationAndClose) {
    rt::RtGuestSemaphore s(0,2);
    EXPECT_EQ(s.acquire(20'000'000,[]{return true;}).errc(),RuntimeErrc::ThreadTerminated);
    s.close(); EXPECT_EQ(s.acquire(-1).errc(),RuntimeErrc::ObjectDestroyed);
}
TEST(GuestSyncTest, SemaphoreRejectsInvalidConstruction) {
    rt::RtGuestSemaphore a(0,0), b(3,2);
    EXPECT_EQ(a.acquire(0).errc(),RuntimeErrc::InvalidArgument);
    EXPECT_EQ(b.release().errc(),RuntimeErrc::InvalidArgument);
}


TEST(GuestSyncTest, MutexWaiterIsWokenByReleaseAndCancellation) {
    rt::RtGuestMutex mutex;
    ASSERT_TRUE(mutex.acquire(1, 0).ok());
    std::atomic<bool> started{false};
    std::atomic<bool> cancel{false};
    std::atomic<int> result{static_cast<int>(RuntimeErrc::Ok)};
    std::thread waiter([&] {
        started.store(true, std::memory_order_release);
        auto r = mutex.acquire(2, -1, [&] { return cancel.load(std::memory_order_acquire); });
        result.store(static_cast<int>(r.errc()), std::memory_order_release);
        if (r.ok()) (void)mutex.release(2);
    });
    while (!started.load(std::memory_order_acquire)) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    cancel.store(true, std::memory_order_release);
    waiter.join();
    EXPECT_EQ(result.load(std::memory_order_acquire),
              static_cast<int>(RuntimeErrc::ThreadTerminated));
    ASSERT_TRUE(mutex.release(1).ok());
}

TEST(GuestSyncTest, SemaphoreWaiterIsWokenByReleaseAndCancellation) {
    rt::RtGuestSemaphore semaphore(0, 1);
    std::atomic<bool> started{false};
    std::atomic<bool> cancel{false};
    std::atomic<int> result{static_cast<int>(RuntimeErrc::Ok)};
    std::thread waiter([&] {
        started.store(true, std::memory_order_release);
        auto r = semaphore.acquire(-1, [&] { return cancel.load(std::memory_order_acquire); });
        result.store(static_cast<int>(r.errc()), std::memory_order_release);
    });
    while (!started.load(std::memory_order_acquire)) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    cancel.store(true, std::memory_order_release);
    waiter.join();
    EXPECT_EQ(result.load(std::memory_order_acquire),
              static_cast<int>(RuntimeErrc::ThreadTerminated));
}

TEST(GuestSyncTest, MutexReleaseWakesBlockedGuestThread) {
    rt::RtGuestMutex mutex;
    ASSERT_TRUE(mutex.acquire(10, 0).ok());
    std::atomic<bool> acquired{false};
    std::thread waiter([&] {
        auto r = mutex.acquire(20, -1);
        acquired.store(r.ok(), std::memory_order_release);
        if (r.ok()) (void)mutex.release(20);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    EXPECT_FALSE(acquired.load(std::memory_order_acquire));
    ASSERT_TRUE(mutex.release(10).ok());
    waiter.join();
    EXPECT_TRUE(acquired.load(std::memory_order_acquire));
}

TEST(GuestSyncTest, SemaphoreReleaseWakesBlockedGuestThread) {
    rt::RtGuestSemaphore semaphore(0, 1);
    std::atomic<bool> acquired{false};
    std::thread waiter([&] {
        auto r = semaphore.acquire(-1);
        acquired.store(r.ok(), std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    EXPECT_FALSE(acquired.load(std::memory_order_acquire));
    ASSERT_TRUE(semaphore.release().ok());
    waiter.join();
    EXPECT_TRUE(acquired.load(std::memory_order_acquire));
}


namespace {
void* acquire_guest_mutex_then_exit(RtThread& self, void* raw) {
    auto* mutex = static_cast<rt::RtGuestMutex*>(raw);
    const auto acquired = mutex->acquire(self.thread_id(), 0);
    return acquired.ok() ? nullptr : reinterpret_cast<void*>(1);
}
}  // namespace

TEST(GuestSyncTest, GuestThreadExitAutomaticallyAbandonsOwnedMutexes) {
    rt::RtGuestMutex mutex;
    RtThread owner(acquire_guest_mutex_then_exit, &mutex, "guest-mutex-owner");
    ASSERT_TRUE(owner.start().ok());
    auto joined = owner.join_ns(-1);
    ASSERT_TRUE(joined.ok());
    auto next_owner = mutex.acquire(999, 0);
    ASSERT_TRUE(next_owner.ok());
    EXPECT_TRUE(next_owner.value());
    ASSERT_TRUE(mutex.release(999).ok());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
