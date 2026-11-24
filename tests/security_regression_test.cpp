// tests/security_regression_test.cpp — adversarial security & correctness
// regression tests covering memory protection boundaries, PAL integer/lifecycle
// hardening, NX enforcement, PE export parsing complexity, interpreter
// fault-atomicity, handle type-tag validation, and loader relocation rollback.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_exceptions.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/platform.hpp"
#include "xbox2pc/runtime_error.hpp"
#include "xbox2pc/runtime_object.hpp"
#include "xbox2pc/x86_interpreter.hpp"

namespace {

using xbox2pc::rt::AccessRights;
using xbox2pc::rt::AddressSpace;
using xbox2pc::rt::Handle;
using xbox2pc::rt::HandleTable;
using xbox2pc::rt::MemProtect;
using xbox2pc::rt::ObjectManager;
using xbox2pc::rt::RuntimeErrc;
using xbox2pc::rt::RuntimeObject;
using xbox2pc::rt::TypeId;
using xbox2pc::rt::api::ApiRegistry;
using xbox2pc::rt::cpu::CpuState;
using xbox2pc::rt::cpu::Gpr;
using xbox2pc::rt::exec::DeterministicBackend;
using xbox2pc::rt::exec::ExecutionConfig;
using xbox2pc::rt::exec::ExecutionRequest;
using xbox2pc::rt::exec::GuestFault;
using xbox2pc::rt::exec::Outcome;
using xbox2pc::rt::exec::kCompletionSentinel;
using xbox2pc::rt::guest::GuestMemErrc;
using xbox2pc::rt::guest::GuestMemory;
using xbox2pc::rt::loader::ImageLoader;
using xbox2pc::rt::loader::LoadDiagnostics;
using xbox2pc::rt::x86::Interpreter;

class TestSecurityObj final : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(TestSecurityObj, Event)
    TestSecurityObj() : RuntimeObject(TypeId::Event) {}
    ~TestSecurityObj() override = default;
};

// ── 1. Memory management: NoAccess reads must fail cleanly, never SIGSEGV ──

TEST(MemoryManagementSecurity, NoAccessReadRejectedWithoutHostCrash) {
    const std::uint64_t page = xbox2pc::pal::host_page_size();
    AddressSpace space(16 * page, 0x10000000ull, "noaccess-test");
    GuestMemory mem(space);

    auto rsv = space.reserve_region(0x10000000ull, 2 * page, "guarded");
    ASSERT_TRUE(rsv.ok());
    const std::uint64_t va = rsv.value();

    ASSERT_TRUE(space.commit_range(va, page, MemProtect::ReadWrite).ok());
    ASSERT_TRUE(mem.write_u32(va, 0xDEADBEEFu).ok());

    // Transition committed page to NoAccess (host PROT_NONE).
    ASSERT_TRUE(space.protect_region(va, MemProtect::NoAccess).ok());

    auto acc_r = space.validate_access(va, false, false);
    EXPECT_FALSE(acc_r.ok());
    EXPECT_EQ(acc_r.errc(), RuntimeErrc::InvalidArgument);

    const auto range = mem.validate(va, 4, false, false);
    EXPECT_FALSE(range.ok());
    EXPECT_EQ(range.err, GuestMemErrc::PermissionDenied);

    // Typed and raw reads must return errors instead of dereferencing PROT_NONE.
    EXPECT_FALSE(mem.read_u8(va).ok());
    EXPECT_FALSE(mem.read_u32(va).ok());
    std::uint8_t buf[4] = {};
    EXPECT_FALSE(mem.read(va, buf, sizeof(buf)).ok());

    // Also test direct commit_range with MemProtect::NoAccess.
    const std::uint64_t va2 = va + page;
    ASSERT_TRUE(space.commit_range(va2, page, MemProtect::NoAccess).ok());
    EXPECT_FALSE(space.validate_access(va2, false, false).ok());
    EXPECT_FALSE(mem.read_u8(va2).ok());

    // Restoring to ReadOnly permits reads while still blocking writes.
    ASSERT_TRUE(space.protect_region(va, MemProtect::ReadOnly).ok());
    auto val = mem.read_u32(va);
    ASSERT_TRUE(val.ok());
    EXPECT_EQ(val.value(), 0xDEADBEEFu);
    EXPECT_FALSE(mem.write_u32(va, 0x11223344u).ok());
}

// ── 2. PAL Linux memory region: integer overflow bounds-check bypass ───────

TEST(PalLinuxSecurity, MemoryRegionSubrangeOverflowRejected) {
    const std::uint64_t page = xbox2pc::pal::host_page_size();
    constexpr std::uint64_t kMaxU64 = std::numeric_limits<std::uint64_t>::max();

    // Zero and alignment-overflow sizes must be rejected at map() time.
    EXPECT_EQ(xbox2pc::pal::reserve_memory(0), nullptr);
    EXPECT_EQ(xbox2pc::pal::commit_memory(0), nullptr);
    EXPECT_EQ(xbox2pc::pal::reserve_memory(kMaxU64), nullptr);
    EXPECT_EQ(xbox2pc::pal::commit_memory(kMaxU64 - 1), nullptr);

    auto region = xbox2pc::pal::reserve_memory(2 * page);
    ASSERT_NE(region, nullptr);

    // offset + size wraps to 0 (<= size_) if checked naively.
    const std::uint64_t wrap_size = (kMaxU64 - page) + 1ull;
    EXPECT_FALSE(region->protect_subrange(page, wrap_size, true, true, false).ok());
    EXPECT_FALSE(region->commit_subrange(page, wrap_size).ok());
    EXPECT_FALSE(region->decommit_subrange(page, wrap_size).ok());

    // Partial wrap and zero-length subranges must also fail.
    EXPECT_FALSE(region->protect_subrange(page, kMaxU64, true, false, false).ok());
    EXPECT_FALSE(region->commit_subrange(page, kMaxU64).ok());
    EXPECT_FALSE(region->protect_subrange(0, 0, true, false, false).ok());
    EXPECT_FALSE(region->commit_subrange(0, 0).ok());

    // Valid subrange operations still work.
    EXPECT_TRUE(region->commit_subrange(0, page).ok());
    EXPECT_TRUE(region->protect_subrange(0, page, true, false, false).ok());
    EXPECT_TRUE(region->decommit_subrange(0, page).ok());
}

// ── 3. Execution engine: completion-sentinel RET must enforce NX ───────────

TEST(ExecutionEngineSecurity, CompletionSentinelEnforcesExecutePermission) {
    const std::uint64_t page = xbox2pc::pal::host_page_size();
    AddressSpace space(16 * page, 0x20000000ull, "nx-sentinel-test");
    GuestMemory mem(space);

    auto data_rsv = space.reserve_region(0x20000000ull, page, "rw-data");
    ASSERT_TRUE(data_rsv.ok());
    ASSERT_TRUE(space.commit_range(data_rsv.value(), page, MemProtect::ReadWrite).ok());

    auto ro_rsv = space.reserve_region(0x20000000ull + page, page, "ro-data");
    ASSERT_TRUE(ro_rsv.ok());
    ASSERT_TRUE(space.commit_range(ro_rsv.value(), page, MemProtect::ReadWrite).ok());

    auto rx_rsv = space.reserve_region(0x20000000ull + 2 * page, page, "rx-code");
    ASSERT_TRUE(rx_rsv.ok());
    ASSERT_TRUE(space.commit_range(rx_rsv.value(), page, MemProtect::ReadWrite).ok());

    auto adj_rw_rsv = space.reserve_region(0x20000000ull + 3 * page, page, "adj-rw");
    ASSERT_TRUE(adj_rw_rsv.ok());
    ASSERT_TRUE(space.commit_range(adj_rw_rsv.value(), page, MemProtect::ReadWrite).ok());

    auto stk_rsv = space.reserve_region(0x20000000ull + 4 * page, 2 * page, "stack");
    ASSERT_TRUE(stk_rsv.ok());
    ASSERT_TRUE(space.commit_range(stk_rsv.value(), 2 * page, MemProtect::ReadWrite).ok());

    // Plant RET (0xC3) in RW data page and RET imm16 (0xC2 0x08 0x00) in RO page.
    ASSERT_TRUE(mem.write_u8(data_rsv.value(), 0xC3u).ok());
    ASSERT_TRUE(mem.write_u8(ro_rsv.value(), 0xC2u).ok());
    ASSERT_TRUE(mem.write_u8(ro_rsv.value() + 1, 0x08u).ok());
    ASSERT_TRUE(mem.write_u8(ro_rsv.value() + 2, 0x00u).ok());
    ASSERT_TRUE(space.protect_region(ro_rsv.value(), MemProtect::ReadOnly).ok());

    // Plant valid RET in RX page, and a straddling RET imm16 across RX->RW boundary.
    ASSERT_TRUE(mem.write_u8(rx_rsv.value(), 0xC3u).ok());
    const std::uint64_t boundary_va = rx_rsv.value() + page - 1;
    ASSERT_TRUE(mem.write_u8(boundary_va, 0xC2u).ok());
    ASSERT_TRUE(mem.write_u8(adj_rw_rsv.value(), 0x08u).ok());
    ASSERT_TRUE(mem.write_u8(adj_rw_rsv.value() + 1, 0x00u).ok());
    ASSERT_TRUE(space.protect_region(rx_rsv.value(), MemProtect::ReadExecute).ok());

    ApiRegistry registry;
    auto cfg_r = ExecutionConfig::default_validated();
    ASSERT_TRUE(cfg_r.ok());
    DeterministicBackend backend(registry, cfg_r.value());
    ASSERT_TRUE(backend.bind_execution_context(1, 1, space).ok());

    const std::uint64_t stack_top = stk_rsv.value() + 2 * page;
    const std::uint64_t rsp_va = stack_top - 16;

    auto run_at = [&](std::uint64_t entry_va) {
        EXPECT_TRUE(mem.write_u64(rsp_va, kCompletionSentinel).ok());
        CpuState cpu;
        cpu.reset();
        cpu.rip = entry_va;
        cpu.set_reg(Gpr::Sp, rsp_va);

        ExecutionRequest req;
        req.entry_va = entry_va;
        req.stack_top_va = stack_top;
        req.stack_size = 2 * page;
        req.completion_va = kCompletionSentinel;

        std::atomic<bool> interrupted{false};
        return backend.run(req, cpu, interrupted);
    };

    // Case A: 0xC3 on RW page must fault with PermissionExec, not return.
    const auto res_rw = run_at(data_rsv.value());
    EXPECT_EQ(res_rw.outcome, Outcome::Faulted);
    ASSERT_TRUE(res_rw.exception.has_value());
    EXPECT_EQ(res_rw.exception->fault, GuestFault::PermissionExec);

    // Case B: 0xC2 imm16 on RO page must fault with PermissionExec.
    const auto res_ro = run_at(ro_rsv.value());
    EXPECT_EQ(res_ro.outcome, Outcome::Faulted);
    ASSERT_TRUE(res_ro.exception.has_value());
    EXPECT_EQ(res_ro.exception->fault, GuestFault::PermissionExec);

    // Case C: 0xC2 straddling RX -> RW page boundary must not complete.
    const auto res_straddle = run_at(boundary_va);
    EXPECT_EQ(res_straddle.outcome, Outcome::Faulted);

    // Case D: positive control — 0xC3 on RX page completes normally.
    const auto res_rx = run_at(rx_rsv.value());
    EXPECT_EQ(res_rx.outcome, Outcome::Returned);
}

// ── 4. PE export table: O(N + M) parsing avoids quadratic CPU DoS ──────────

TEST(PeParserSecurity, LargeExportTableParsesInLinearTime) {
    constexpr std::uint32_t kExportCount = 8000u;

    xbox2pc::test::PeBuildSpec spec;
    spec.exports.reserve(kExportCount);
    for (std::uint32_t i = 0; i < kExportCount; ++i) {
        xbox2pc::test::ExportFunc ef;
        ef.rva = 0x1000u + (i % 64u);
        if ((i % 2u) == 0u) {
            ef.name = "exp_" + std::to_string(i);
        }
        spec.exports.push_back(std::move(ef));
    }
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    xbox2pc::diag::Diagnostics diags;
    const auto t0 = std::chrono::steady_clock::now();
    const auto img = xbox2pc::pe::parse(bytes.data(), bytes.size(),
                                        "large-exports.dll", diags);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    EXPECT_TRUE(img.exports.present);
    ASSERT_EQ(img.exports.functions.size(), kExportCount);
    EXPECT_EQ(img.exports.functions[0].name, "exp_0");
    EXPECT_TRUE(img.exports.functions[1].name.empty());
    EXPECT_EQ(img.exports.functions[kExportCount - 2].name,
              "exp_" + std::to_string(kExportCount - 2));
    // Linear O(N + M) parsing completes in milliseconds even under ASan/TSan.
    EXPECT_LT(elapsed_ms, 5000);
}

// ── 5. PAL Linux sync: timed-wait overflow & semaphore overflow/broadcast ──

TEST(PalLinuxSecurity, TimedWaitsAndSemaphoreOverflowSafe) {
    // Semaphore signed-overflow check near INT64_MAX (must not trigger UBSan).
    constexpr std::int64_t kMaxI64 = std::numeric_limits<std::int64_t>::max();
    auto sem_max = xbox2pc::pal::make_semaphore(kMaxI64 - 1, kMaxI64);
    ASSERT_NE(sem_max, nullptr);
    auto ovf = sem_max->release(5u);
    EXPECT_FALSE(ovf.ok());
    EXPECT_EQ(ovf.errc(), RuntimeErrc::InvalidState);
    EXPECT_EQ(sem_max->value(), kMaxI64 - 1);

    // Large release count must use broadcast rather than an O(count) signal loop.
    auto sem_bulk = xbox2pc::pal::make_semaphore(0, 1'000'000);
    ASSERT_NE(sem_bulk, nullptr);
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(sem_bulk->release(1'000'000u).ok());
    const auto bulk_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    EXPECT_EQ(sem_bulk->value(), 1'000'000);
    EXPECT_LT(bulk_ms, 2000);

    // Event timed wait with huge timeout must saturate safely (no overflow/EINVAL).
    auto ev = xbox2pc::pal::make_event(false, false);
    ASSERT_NE(ev, nullptr);
    std::thread ev_setter([&ev]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        (void)ev->set();
    });
    const auto ev_r = ev->wait_ns(std::numeric_limits<xbox2pc::pal::MonotonicNs>::max());
    ev_setter.join();
    EXPECT_TRUE(ev_r.ok());

    // Condvar timed wait with huge timeout must saturate safely (no overflow/EINVAL).
    auto mtx = xbox2pc::pal::make_mutex();
    auto cv = xbox2pc::pal::make_condvar();
    ASSERT_NE(mtx, nullptr);
    ASSERT_NE(cv, nullptr);
    bool ready = false;
    std::thread cv_notifier([&mtx, &cv, &ready]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        (void)mtx->lock();
        ready = true;
        (void)cv->notify_one();
        (void)mtx->unlock();
    });
    ASSERT_TRUE(mtx->lock().ok());
    while (!ready) {
        const auto cv_r = cv->wait_for_ns(
            *mtx, std::numeric_limits<xbox2pc::pal::MonotonicNs>::max());
        EXPECT_TRUE(cv_r.ok());
        if (!cv_r.ok()) break;
    }
    ASSERT_TRUE(mtx->unlock().ok());
    cv_notifier.join();
    EXPECT_TRUE(ready);
}

// ── 6. PAL Linux thread: double-start and post-detach lifecycle guards ─────

TEST(PalLinuxSecurity, ThreadDoubleStartAndDetachGuards) {
    auto noop_entry = +[](void* arg) -> void* {
        (void)arg;
        return nullptr;
    };

    auto t1 = xbox2pc::pal::make_host_thread();
    ASSERT_NE(t1, nullptr);
    ASSERT_TRUE(t1->start(noop_entry, nullptr).ok());

    // Second start() on an already-started PalThread must fail cleanly.
    const auto second = t1->start(noop_entry, nullptr);
    EXPECT_FALSE(second.ok());
    EXPECT_EQ(second.errc(), RuntimeErrc::InvalidState);

    EXPECT_TRUE(t1->join().ok());

    // Detach state tracking: second detach() and subsequent join() must fail.
    struct DetachSignal {
        std::shared_ptr<xbox2pc::pal::PalEvent> done;
    };
    auto done_ev = std::shared_ptr<xbox2pc::pal::PalEvent>(
        xbox2pc::pal::make_event(false, false).release());
    ASSERT_NE(done_ev, nullptr);

    auto detach_entry = +[](void* arg) -> void* {
        std::unique_ptr<DetachSignal> sig(static_cast<DetachSignal*>(arg));
        (void)sig->done->set();
        return nullptr;
    };

    auto t2 = xbox2pc::pal::make_host_thread();
    ASSERT_NE(t2, nullptr);
    auto* sig = new DetachSignal{done_ev};
    auto started = t2->start(detach_entry, sig);
    if (!started.ok()) {
        delete sig;
        FAIL() << "Failed to start detachable thread";
    }
    ASSERT_TRUE(t2->detach().ok());

    const auto detach_again = t2->detach();
    EXPECT_FALSE(detach_again.ok());
    EXPECT_EQ(detach_again.errc(), RuntimeErrc::InvalidState);

    const auto join_detached = t2->join();
    EXPECT_FALSE(join_detached.ok());
    EXPECT_EQ(join_detached.errc(), RuntimeErrc::InvalidState);

    // Wait for detached thread completion for clean LSan/TSan teardown.
    EXPECT_TRUE(done_ev->wait_ns(5'000'000'000LL).ok());
}

// ── 7. x86 interpreter: shift/rotate fault-atomicity preserves RFLAGS ──────

TEST(X86InterpreterSecurity, ShiftRotateFaultAtomicityPreservesRflags) {
    const std::uint64_t page = xbox2pc::pal::host_page_size();
    AddressSpace space(8 * page, 0x30000000ull, "shift-atomicity-test");
    GuestMemory mem(space);

    auto code_rsv = space.reserve_region(0x30000000ull, page, "code");
    ASSERT_TRUE(code_rsv.ok());
    ASSERT_TRUE(space.commit_range(code_rsv.value(), page, MemProtect::ReadWrite).ok());

    auto ro_rsv = space.reserve_region(0x30000000ull + page, page, "ro-mem");
    ASSERT_TRUE(ro_rsv.ok());
    ASSERT_TRUE(space.commit_range(ro_rsv.value(), page, MemProtect::ReadWrite).ok());
    ASSERT_TRUE(mem.write_u64(ro_rsv.value(), 0x8000000000000001ull).ok());
    ASSERT_TRUE(space.protect_region(ro_rsv.value(), MemProtect::ReadOnly).ok());

    // 3-byte encodings operating on qword ptr [rdi], 1:
    // SHL (48 D1 27), SHR (48 D1 2F), SAR (48 D1 3F), ROL (48 D1 07), ROR (48 D1 0F).
    const std::vector<std::vector<std::uint8_t>> insns = {
        {0x48u, 0xD1u, 0x27u},
        {0x48u, 0xD1u, 0x2Fu},
        {0x48u, 0xD1u, 0x3Fu},
        {0x48u, 0xD1u, 0x07u},
        {0x48u, 0xD1u, 0x0Fu},
    };

    for (std::size_t idx = 0; idx < insns.size(); ++idx) {
        const std::uint64_t va = code_rsv.value() + idx * 16u;
        ASSERT_TRUE(mem.write(va, insns[idx].data(), insns[idx].size()).ok());
    }
    ASSERT_TRUE(space.protect_region(code_rsv.value(), MemProtect::ReadExecute).ok());

    constexpr std::uint64_t kSentinelFlags =
        xbox2pc::rt::cpu::kRflagsReset |
        xbox2pc::rt::cpu::kFlagCF |
        xbox2pc::rt::cpu::kFlagOF |
        xbox2pc::rt::cpu::kFlagZF |
        xbox2pc::rt::cpu::kFlagPF;

    for (std::size_t idx = 0; idx < insns.size(); ++idx) {
        const std::uint64_t va = code_rsv.value() + idx * 16u;
        CpuState cpu;
        cpu.reset();
        cpu.rip = va;
        cpu.rflags = kSentinelFlags;
        cpu.set_reg(Gpr::Di, ro_rsv.value());

        Interpreter interp(cpu, mem);
        const auto sr = interp.step_at_rip();
        EXPECT_FALSE(sr.ok()) << "instruction index " << idx;
        EXPECT_EQ(sr.fault().fault, GuestFault::PermissionWrite);
        EXPECT_EQ(cpu.rip, va);
        EXPECT_EQ(cpu.rflags, kSentinelFlags) << "RFLAGS mutated on failed shift/rotate " << idx;
    }
}

// ── 8. Handle manager: type-tag enforcement & atomic duplicate ─────────────

TEST(HandleManagerSecurity, TypeTagEnforcedOnCloseRightsAndInheritable) {
    ObjectManager mgr;
    auto obj = std::make_unique<TestSecurityObj>();
    auto* raw_obj = obj.get();
    auto reg = mgr.register_object(std::move(obj));
    ASSERT_TRUE(reg.ok());

    HandleTable& table = mgr.table();
    auto h_res = table.create_with_rights(*raw_obj, AccessRights::All, true);
    ASSERT_TRUE(h_res.ok());
    const Handle h = h_res.value();

    // Forge a handle with identical table_id/index/generation but wrong TypeId.
    const Handle forged = Handle::from_parts(
        h.index(), h.generation(),
        static_cast<std::uint16_t>(TypeId::File),
        h.table_id());
    ASSERT_NE(forged, h);

    EXPECT_EQ(table.rights_of(forged), AccessRights::None);
    EXPECT_FALSE(table.inheritable(forged));

    const auto close_forged = table.close(forged);
    EXPECT_FALSE(close_forged.ok());
    EXPECT_EQ(close_forged.errc(), RuntimeErrc::InvalidHandle);

    const auto dup_forged = table.duplicate(forged);
    EXPECT_FALSE(dup_forged.ok());
    EXPECT_EQ(dup_forged.errc(), RuntimeErrc::InvalidHandle);

    // Genuine handle must remain live and intact.
    EXPECT_TRUE(table.lookup(h).ok());
    EXPECT_EQ(table.rights_of(h), AccessRights::All);
    EXPECT_TRUE(table.inheritable(h));

    // Narrowing duplicate succeeds; widening from narrowed handle fails.
    auto narrow = table.duplicate(h, AccessRights::Read | AccessRights::Close, false);
    ASSERT_TRUE(narrow.ok());
    EXPECT_EQ(table.rights_of(narrow.value()), AccessRights::Read | AccessRights::Close);
    EXPECT_FALSE(table.inheritable(narrow.value()));
    EXPECT_FALSE(table.duplicate(narrow.value(), AccessRights::ReadWrite, false).ok());

    EXPECT_TRUE(table.close(narrow.value()).ok());
    EXPECT_TRUE(table.close(h).ok());
    EXPECT_TRUE(mgr.destroy(reg.value()).ok());
}

// ── 9. Image loader: relocation failure restores flipped section protections ─

TEST(ImageLoaderSecurity, RelocationFailureRestoresSectionProtections) {
    const std::uint64_t page = xbox2pc::pal::host_page_size();

    // Build a PE32+ image whose first relocation targets .text (RX -> RW flip)
    // and whose second relocation targets an out-of-image RVA (fails mid-loop).
    xbox2pc::test::PeBuildSpec spec;
    spec.image_base = 0x140000000ull;
    spec.text_payloads.push_back({0x1000u, {0x90u, 0x90u, 0x90u, 0x90u,
                                            0x90u, 0x90u, 0x90u, 0x90u,
                                            0x00u, 0x10u, 0x00u, 0x40u,
                                            0x01u, 0x00u, 0x00u, 0x00u}});
    spec.reloc_blocks = {
        {0x1000u, {{10u, 0x1008u, 0x140001000ull}}},
        {0x50000u, {{10u, 0x50008u, 0x140001000ull}}},
    };
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    xbox2pc::diag::Diagnostics parse_diags;
    const auto img = xbox2pc::pe::parse(bytes.data(), bytes.size(),
                                        "bad-reloc.exe", parse_diags);

    AddressSpace space(64 * page, 0x40000000ull, "reloc-rollback-test");
    ImageLoader loader;
    LoadDiagnostics diag;

    // Map at a different base so layout.relocated == true.
    auto mapped = loader.map_image(space, img, bytes.data(), bytes.size(),
                                   0x40000000ull, diag);
    ASSERT_TRUE(mapped.ok()) << mapped.context();
    ASSERT_TRUE(mapped.value().relocated);

    // Find .text section and verify it starts as ReadExecute.
    std::uint64_t text_va = 0;
    for (const auto& sl : mapped.value().sections) {
        if (sl.name == ".text") {
            text_va = sl.mapped_base;
            EXPECT_EQ(sl.protection, MemProtect::ReadExecute);
        }
    }
    ASSERT_NE(text_va, 0u);

    // apply_relocations must fail on the second block and restore .text to RX.
    auto rel = loader.apply_relocations(space, mapped.value(), img,
                                        bytes.data(), bytes.size(), diag);
    EXPECT_FALSE(rel.ok());

    auto reg = space.find_region(text_va);
    ASSERT_TRUE(reg.ok());
    EXPECT_EQ(reg.value().protection, MemProtect::ReadExecute);
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
