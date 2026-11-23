// M9 §5: stack, flags and conversion semantics tests.
//
// Hand-derived expectations from the Intel SDM: PUSH/POP register and
// immediate forms with stack-pointer movement, PUSHFQ/POPFQ, CLC/STC/CMC/
// CLD/STD, CBW/CWDE/CQO/CDQ at all operand sizes, LEAVE frame teardown.
// The §5 extended-state matrix (XMM/MXCSR/x87/SSE/AVX/atomics) is
// deliberately NOT supported here — a separate test pins that every
// SIMD-class encoding is rejected typed (UnsupportedSimd), so extended
// state is never claimed.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/x64_decoder.hpp"
#include "xbox2pc/x86_interpreter.hpp"

namespace rt = xbox2pc::rt;
using rt::AddressSpace;
using rt::MemProtect;
using rt::cpu::CpuState;
using rt::cpu::Gpr;
using rt::guest::GuestMemory;
using rt::x86::Interpreter;

namespace {

constexpr std::uint64_t kCodeBase = 0x10000000;
constexpr std::uint64_t kDataBase = 0x10020000;
constexpr std::uint64_t kStackTop = 0x1002F000;

class X86StackFlagsTest : public ::testing::Test {
protected:
    void SetUp() override {
        space_ = std::make_unique<AddressSpace>(64 * 4096, 0x10000000, "sf");
        ASSERT_TRUE(space_->reserve_region(kCodeBase, 16 * 4096, "code").ok());
        ASSERT_TRUE(space_->reserve_region(kDataBase, 16 * 4096, "data").ok());
        ASSERT_TRUE(space_->commit_region(kCodeBase).ok());
        ASSERT_TRUE(space_->commit_region(kDataBase).ok());
        ASSERT_TRUE(space_->protect_region(kCodeBase, MemProtect::Full).ok());
        mem_ = std::make_unique<GuestMemory>(*space_);
        interp_ = std::make_unique<Interpreter>(cpu_, *mem_);
    }

    rt::x86::StepResult run(const std::vector<std::uint8_t>& code) {
        EXPECT_TRUE(mem_->write(kCodeBase, code.data(), code.size()).ok());
        cpu_.rip = kCodeBase;
        return interp_->step_at_rip();
    }

    std::unique_ptr<AddressSpace> space_;
    std::unique_ptr<GuestMemory> mem_;
    std::unique_ptr<Interpreter> interp_;
    CpuState cpu_;
};

}  // namespace

TEST_F(X86StackFlagsTest, PushPopRegister) {
    // PUSH rax then POP rcx round trip.
    cpu_.reset();
    cpu_.set_reg(Gpr::Rax, 0x123456789ABCDEF0ull);
    cpu_.set_reg(Gpr::Sp, kStackTop);
    ASSERT_TRUE(run({0x50}).ok());   // push rax
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], kStackTop - 8);
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(), 0x123456789ABCDEF0ull);
    cpu_.set_reg(Gpr::Rcx, 0);
    ASSERT_TRUE(run({0x59}).ok());   // pop rcx
    EXPECT_EQ(cpu_.gprs[1], 0x123456789ABCDEF0ull);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], kStackTop);
}

TEST_F(X86StackFlagsTest, PushImmediateSignExtends) {
    // PUSH imm8 sign-extends; PUSH imm32 sign-extends.
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop);
    ASSERT_TRUE(run({0x6A, 0x80}).ok());   // push -128
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(),
              static_cast<std::uint64_t>(-128));
    cpu_.set_reg(Gpr::Sp, kStackTop);
    ASSERT_TRUE(run({0x68, 0xFF, 0xFF, 0xFF, 0xFF}).ok());   // push -1
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(),
              static_cast<std::uint64_t>(-1));
}

TEST_F(X86StackFlagsTest, PushFromMemory) {
    // PUSH [rax] (FF /6 with a memory operand).
    const std::uint64_t slot = kDataBase + 0x10;
    ASSERT_TRUE(mem_->write_u64(slot, 0x5555).ok());
    cpu_.reset();
    cpu_.set_reg(Gpr::Rax, slot);
    cpu_.set_reg(Gpr::Sp, kStackTop);
    ASSERT_TRUE(run({0xFF, 0x30}).ok());   // push qword [rax]
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(), 0x5555ull);
}

TEST_F(X86StackFlagsTest, PushfPopfRoundTrip) {
    // PUSHFQ stores RFLAGS; POPFQ restores them (bit 1 forced to 1).
    cpu_.reset();
    cpu_.set_flag(rt::cpu::kFlagCF, true);
    cpu_.set_flag(rt::cpu::kFlagZF, true);
    cpu_.set_reg(Gpr::Sp, kStackTop);
    ASSERT_TRUE(run({0x9C}).ok());   // pushfq
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(), cpu_.rflags);
    // Flip flags, then POPFQ must restore the pushed value.
    cpu_.set_flag(rt::cpu::kFlagCF, false);
    cpu_.set_flag(rt::cpu::kFlagZF, false);
    ASSERT_TRUE(run({0x9D}).ok());   // popfq
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagZF));
    // The fixed bit stays 1 even if the pushed value had it cleared
    // (it cannot: PUSHFQ writes it as 1).
    EXPECT_EQ(cpu_.rflags & rt::cpu::kFlagFixed1, rt::cpu::kFlagFixed1);
}

TEST_F(X86StackFlagsTest, FlagInstructions) {
    // CLC / STC / CMC / CLD / STD.
    cpu_.reset();
    ASSERT_TRUE(run({0xF8}).ok());   // clc
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));
    ASSERT_TRUE(run({0xF9}).ok());   // stc
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    ASSERT_TRUE(run({0xF5}).ok());   // cmc
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));
    ASSERT_TRUE(run({0xFC}).ok());   // cld
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagDF));
    ASSERT_TRUE(run({0xFD}).ok());   // std
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagDF));
}

TEST_F(X86StackFlagsTest, CbwCwdeCqo) {
    // CBW (66 98): AL=0x80 -> AX=0xFF80.
    cpu_.reset();
    cpu_.gprs[0] = 0x80;
    ASSERT_TRUE(run({0x66, 0x98}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFFFF, 0xFF80u);
    // CWDE (98): AX=0xFF80 -> EAX=0xFFFFFF80.
    cpu_.gprs[0] = 0xFF80;
    ASSERT_TRUE(run({0x98}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFFFFFFFF, 0xFFFFFF80u);
    // CDQ (99): EAX=0xFFFFFF80 -> EDX=0xFFFFFFFF.
    cpu_.gprs[0] = 0xFFFFFF80;
    cpu_.gprs[2] = 0;
    ASSERT_TRUE(run({0x99}).ok());
    EXPECT_EQ(cpu_.gprs[2] & 0xFFFFFFFF, 0xFFFFFFFFu);
    // CQO (48 99): RAX=0x8000...0 -> RDX=0xFFFF...F.
    cpu_.gprs[0] = 0x8000000000000000ull;
    cpu_.gprs[2] = 0;
    ASSERT_TRUE(run({0x48, 0x99}).ok());
    EXPECT_EQ(cpu_.gprs[2], 0xFFFFFFFFFFFFFFFFull);
}

TEST_F(X86StackFlagsTest, LeaveTearsDownFrame) {
    // RBP = frame base with the saved RBP on the stack; LEAVE: RSP=RBPl;
    // RBP = [RSP]; RSP += 8.
    const std::uint64_t frame = kDataBase + 0x100;
    ASSERT_TRUE(mem_->write_u64(frame, 0x1111).ok());     // saved RBP
    cpu_.reset();
    cpu_.set_reg(Gpr::Bp, frame);
    cpu_.set_reg(Gpr::Sp, kStackTop);   // different from RBP
    ASSERT_TRUE(run({0xC9}).ok());      // leave
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Bp)], 0x1111ull);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], frame + 8);
}

// ── extended state: SIMD never silently passes ────────────────────────────

TEST_F(X86StackFlagsTest, SimdEncodingsAreTypedUnsupported) {
    // XMM/MXCSR/x87/SSE/AVX are outside the interpreter matrix; the decoder
    // already rejects them (UnsupportedSimd etc.). The interpreter must
    // surface the reject as a typed UnsupportedInstruction fault with no
    // state change — extended state is never claimed.
    const std::vector<std::vector<std::uint8_t>> simd = {
        {0x0F, 0x28, 0xC1},            // movaps xmm0, xmm1
        {0xF3, 0x0F, 0x10, 0xC1},      // movss xmm0, xmm1
        {0x66, 0x0F, 0xEF, 0xC1},     // pxor xmm0, xmm1
        {0xD8, 0xC1},                  // x87 fadd
        {0x0F, 0xC7, 0x08},            // cmpxchg8b [rax] (atomic class)
        {0xF0, 0x0F, 0xB0, 0x01},      // lock cmpxchg [rax], al
    };
    for (const auto& code : simd) {
        cpu_.reset();
        cpu_.set_reg(Gpr::Sp, kStackTop);
        cpu_.set_reg(Gpr::Rax, kDataBase);
        const CpuState before = cpu_;
        EXPECT_TRUE(mem_->write(kCodeBase, code.data(), code.size()).ok());
        cpu_.rip = kCodeBase;
        const auto res = interp_->step_at_rip();
        EXPECT_FALSE(res.ok()) << "SIMD encoding must not execute";
        EXPECT_EQ(res.fault().fault, rt::exec::GuestFault::UnsupportedInstruction);
        EXPECT_EQ(cpu_.rip, kCodeBase);
        EXPECT_TRUE(std::memcmp(cpu_.gprs, before.gprs, sizeof(cpu_.gprs)) == 0);
        // XMM/MXCSR untouched.
        EXPECT_TRUE(std::memcmp(cpu_.xmm.data(), before.xmm.data(),
                                sizeof(cpu_.xmm)) == 0);
        EXPECT_EQ(cpu_.mxcsr, before.mxcsr);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
