// xbox2pc/tests/m12_bridge_test.cpp — M12 P0.4 run-path marshalling tests.
//
// What-broke entry 12 pinned at the bridge level: the documented x64
// MEMORY_BASIC_INFORMATION is exactly 48 bytes with its padding;
// dwLength below 48 answers 0 and writes nothing; an out buffer that is
// not writable guest memory is rejected before dispatch. (The native
// run path answered 0 for every such call until the parent rebased
// host-form pointer arguments; that regression lives in
// m12_run_test.cpp.)
//
// The fixtures mirror execution_test.cpp's (a live registry-before-core
// world, a scratch region, a host stack writer); they are repeated here
// so this file stands alone against the M12 additions it covers.

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/gdk_services.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/runtime_core.hpp"
#include "xbox2pc/xbox_abi.hpp"

using namespace xbox2pc;
using namespace xbox2pc::rt;
using namespace xbox2pc::rt::exec;

namespace {

// A live world like M7's (registry before core; correct member order).
struct ExecWorld {
    api::ApiRegistry reg;
    RuntimeCore core;
    ProcessManager pm;
    api::GameRuntimeService* grt = nullptr;

    ExecWorld() : pm(core.objects()) {
        {
            auto grt_s = std::make_unique<api::GameRuntimeService>(reg, pm);
            grt = grt_s.get();
            EXPECT_TRUE(core.services().register_service(std::move(grt_s)).ok());
        }
        EXPECT_TRUE(core.initialize().ok());
    }
    ~ExecWorld() { (void)core.shutdown(); }

    std::pair<Handle, ManagedProcess*> new_process(const char* name,
                                                   std::uint64_t cap = 64ull << 20) {
        auto p = pm.create_process(name, cap);
        EXPECT_TRUE(p.ok());
        auto found = core.objects().lookup_handle(p.value());
        EXPECT_TRUE(found.ok());
        return {p.value(),
                found.value().get()->as<ManagedProcess>()};
    }
};

// A minimal in-space RW scratch region for guest-memory tests.
Handle scratch_region(ManagedProcess& proc, std::uint64_t size,
                      std::uint64_t* out_va) {
    auto r = proc.address_space().reserve_region_auto(size, "scratch");
    EXPECT_TRUE(r.ok());
    auto c = proc.address_space().commit_region(r.value());
    EXPECT_TRUE(c.ok());
    *out_va = r.value();
    return {};
}

// A tiny stack writer into a host buffer at a base VA (guest-mem-shaped).
struct HostStack {
    std::vector<std::uint8_t> mem;
    std::uint64_t base;
    explicit HostStack(std::uint64_t b, std::size_t n)
        : mem(n, 0), base(b) {}
    static rt::abi::StackWriter writer(HostStack* s) {
        rt::abi::StackWriter w;
        w.ctx = s;
        w.write = [](void* c, std::uint64_t va, const void* src,
                      std::size_t len) -> Result<void> {
            auto* self = static_cast<HostStack*>(c);
            if (va < self->base || va + len > self->base + self->mem.size()) {
                return Result<void>(RuntimeErrc::InvalidArgument, "out of stack");
            }
            std::memcpy(self->mem.data() + (va - self->base), src, len);
            return Result<void>::ok_result();
        };
        return w;
    }
};

// M12 P0 (what-broke entry 12): VirtualQuery through the marshalling
// plan. The documented x64 MEMORY_BASIC_INFORMATION is exactly 48 bytes
// with its padding; dwLength below 48 answers 0 and writes nothing; a
// non-writable out buffer is rejected by the bridge before dispatch
// (the run path answered 0 for every such call until the native parent
// rebased host-form pointer arguments).
TEST(BridgeTest, VirtualQueryMarshalsExactAndShortBuffers) {
    ExecWorld w;
    auto [ph, proc] = w.new_process("vq-bridge.exe");
    const auto pid_r = w.pm.resolve_pid(ph);
    ASSERT_TRUE(pid_r.ok());
    const auto pid = pid_r.value();
    ModuleDescriptor module;
    module.module_name = "vq-bridge.exe";
    module.is_valid_pe = true;
    ASSERT_TRUE(w.pm.initialize_process(ph, module, RuntimeConfig{}).ok());
    ASSERT_TRUE(w.pm.start_process(ph).ok());
    // The tracked committed region the run path's VirtualAlloc produces.
    auto base = w.pm.reserve_region(ph, 0x2000, "vq-bridge-region");
    ASSERT_TRUE(base.ok());
    ASSERT_TRUE(w.pm.commit_region(ph, base.value()).ok());
    ASSERT_TRUE(w.pm.protect_region(ph, base.value(), MemProtect::ReadWrite, {}).ok());
    guest::GuestMemory mem(proc->address_space());
    const auto* descriptor = w.reg.find("kernel32", "VirtualQuery");
    ASSERT_NE(descriptor, nullptr);
    auto plan = plan_for_descriptor(*descriptor);
    ASSERT_TRUE(plan.ok());

    std::uint64_t buffer_va = 0;
    scratch_region(*proc, 0x1000, &buffer_va);
    auto fill = [&](std::uint64_t pattern) {
        for (std::uint64_t i = 0; i < 48; i += 8)
            ASSERT_TRUE(mem.write_u64(buffer_va + i, pattern + i).ok());
    };
    auto dispatch_vq = [&](cpu::CpuState& c, std::uint64_t length,
                           std::uint64_t buffer) {
        std::vector<rt::abi::ArgValue> vals(3);
        vals[0].ptr_va = base.value() + 0x123;   // lpAddress (inside the region)
        vals[0].int_v = base.value() + 0x123;
        vals[0].kind = rt::abi::ArgKind::Ptr;
        vals[1].ptr_va = buffer;                 // lpBuffer
        vals[1].int_v = buffer;
        vals[1].kind = rt::abi::ArgKind::Ptr;
        vals[2].int_v = length;                  // dwLength
        HostStack st(0x2003F000ull, 0x1000);
        auto prep = rt::abi::prepare_call(
            c, 0x51000010, plan.value().call, vals, HostStack::writer(&st));
        EXPECT_TRUE(prep.ok()) << prep.error_string();
        return marshal_and_dispatch(c, mem, w.reg, plan.value(), pid, 0, 64, 91);
    };

    // Exact buffer: dwLength 48 == sizeof(x64 MEMORY_BASIC_INFORMATION).
    // The call dispatches, RAX carries the bytes written (48), and the
    // structure lands at its documented offsets.
    {
        fill(0xAAAAAAAAAAAAAAAAull);
        cpu::CpuState c;
        c.reset();
        c.set_reg(cpu::Gpr::Sp, 0x20040000);
        auto r = dispatch_vq(c, 48, buffer_va);
        ASSERT_TRUE(r.ok()) << r.error_string();
        ASSERT_TRUE(r.value().api_result.ok) << r.value().api_result.error;
        EXPECT_EQ(r.value().api_result.return_value, 48u);
        EXPECT_EQ(c.reg(cpu::Gpr::Rax), 48u);
        auto rd32 = [&](std::uint64_t o) {
            auto v = mem.read_u32(buffer_va + o);
            return v.ok() ? v.value() : 0xEEEEEEEEu;
        };
        auto rd64 = [&](std::uint64_t o) {
            auto v = mem.read_u64(buffer_va + o);
            return v.ok() ? v.value() : 0xEEEEEEEEEEEEEEEEull;
        };
        EXPECT_EQ(rd64(0), base.value());   // BaseAddress
        EXPECT_EQ(rd64(8), base.value());   // AllocationBase
        EXPECT_EQ(rd32(16), 0x04u);         // AllocationProtect (retained)
        EXPECT_EQ(rd32(20), 0u);            // PartitionId
        EXPECT_EQ(rd64(24), 0x2000u);       // RegionSize
        EXPECT_EQ(rd32(32), 0x1000u);       // State: MEM_COMMIT
        EXPECT_EQ(rd32(36), 0x04u);         // Protect: PAGE_READWRITE
        EXPECT_EQ(rd32(40), 0x20000u);      // Type: MEM_PRIVATE
        EXPECT_EQ(rd32(44), 0u);            // x64 structure padding
    }

    // Short buffer: dwLength 47 answers 0 (zero bytes written) and the
    // implementation leaves the caller's buffer untouched.
    {
        fill(0xBBBBBBBBBBBBBBBBull);
        cpu::CpuState c;
        c.reset();
        c.set_reg(cpu::Gpr::Sp, 0x20040000);
        auto r = dispatch_vq(c, 47, buffer_va);
        ASSERT_TRUE(r.ok()) << r.error_string();
        ASSERT_TRUE(r.value().api_result.ok) << r.value().api_result.error;
        EXPECT_EQ(r.value().api_result.return_value, 0u);
        EXPECT_EQ(c.reg(cpu::Gpr::Rax), 0u);
        for (std::uint64_t i = 0; i < 48; i += 8) {
            auto v = mem.read_u64(buffer_va + i);
            ASSERT_TRUE(v.ok());
            EXPECT_EQ(v.value(), 0xBBBBBBBBBBBBBBBBull + i) << "offset " << i;
        }
    }

    // An out buffer that is not writable guest memory is rejected by the
    // bridge's pointer validation before dispatch (the plan declares a
    // 48-byte out dereference).
    {
        cpu::CpuState c;
        c.reset();
        c.set_reg(cpu::Gpr::Sp, 0x20040000);
        auto r = dispatch_vq(c, 48, 0xDEAD0000);
        EXPECT_FALSE(r.ok());
    }
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
