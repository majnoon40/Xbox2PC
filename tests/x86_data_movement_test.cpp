// M9 §3C/3E/3D: data movement, shifts/rotates and bit-operation tests.
//
// Hand-derived expectations from the Intel SDM:
//   - MOVZX/MOVSX/MOVSXD widening rules (LEA as address arithmetic),
//   - XCHG register/memory exchange (including the XCHG eAX, reg encoding),
//   - SHL/SHR/SAR for 8/16/32/64 widths with count 0 / count < width /
//     count >= width flag rules (CF = last bit out, OF only for count 1,
//     ZF/SF/PF from the result, count 0 touches nothing),
//   - ROL/ROR (CF from the rotated end), RCL/RCR (carry rotates through),
//   - BT/BTS/BTR/BTC with immediate and register bit positions (CF = the
//     old bit), bit index taken modulo the operand size.

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

class X86DataMovementTest : public ::testing::Test {
protected:
    void SetUp() override {
        space_ = std::make_unique<AddressSpace>(64 * 4096, 0x10000000, "dm");
        ASSERT_TRUE(space_->reserve_region(kCodeBase, 16 * 4096, "code").ok());
        ASSERT_TRUE(space_->reserve_region(kDataBase, 16 * 4096, "data").ok());
        ASSERT_TRUE(space_->commit_region(kCodeBase).ok());
        ASSERT_TRUE(space_->commit_region(kDataBase).ok());
        ASSERT_TRUE(space_->protect_region(kCodeBase, MemProtect::Full).ok());
        mem_ = std::make_unique<GuestMemory>(*space_);
        interp_ = std::make_unique<Interpreter>(cpu_, *mem_);
    }

    rt::x86::StepResult run(const std::vector<std::uint8_t>& code, std::uint64_t off = 0) {
        const std::uint64_t va = kCodeBase + off;
        EXPECT_TRUE(mem_->write(va, code.data(), code.size()).ok());
        cpu_.rip = va;
        return interp_->step_at_rip();
    }

    std::unique_ptr<AddressSpace> space_;
    std::unique_ptr<GuestMemory> mem_;
    std::unique_ptr<Interpreter> interp_;
    CpuState cpu_;
};

}  // namespace

// ── MOVZX / MOVSX / MOVSXD ─────────────────────────────────────────────────

TEST_F(X86DataMovementTest, MovzxMovsxWidths) {
    // MOVZX r64, r/m8: zero-extend.
    cpu_.gprs[0] = 0xFFFFFFFFFFFFFFFFull;
    cpu_.gprs[1] = 0xF0;                          // CL = 0xF0
    ASSERT_TRUE(run({0x48, 0x0F, 0xB6, 0xC1}).ok());   // movzx rax, cl
    EXPECT_EQ(cpu_.gprs[0], 0xF0ull);             // zero-extended
    // MOVZX r32, r/m8 zeroes the top 32.
    cpu_.gprs[0] = 0xFFFFFFFFFFFFFFFFull;
    ASSERT_TRUE(run({0x0F, 0xB6, 0xC1}).ok());        // movzx eax, cl
    EXPECT_EQ(cpu_.gprs[0], 0x00000000000000F0ull);
    // MOVSX r64, r/m8: sign-extend.
    cpu_.gprs[1] = 0x80;                          // CL = 0x80 (-128)
    ASSERT_TRUE(run({0x48, 0x0F, 0xBE, 0xC1}).ok());   // movsx rax, cl
    EXPECT_EQ(static_cast<std::int64_t>(cpu_.gprs[0]), -128);
    // MOVSX r32, r/m16 sign-extends into 32 bits, zero above.
    cpu_.gprs[1] = 0x8000;                        // CX = -32768
    ASSERT_TRUE(run({0x0F, 0xBF, 0xC1}).ok());        // movsx eax, cx
    EXPECT_EQ(cpu_.gprs[0], 0x00000000FFFF8000ull);
    // MOVSXD r64, r/m32.
    cpu_.gprs[1] = 0xFFFFFF80ull;                 // ECX = -128
    ASSERT_TRUE(run({0x48, 0x63, 0xC1}).ok());        // movsxd rax, ecx
    EXPECT_EQ(static_cast<std::int64_t>(cpu_.gprs[0]), -128);
}

TEST_F(X86DataMovementTest, MovzxFromMemory) {
    // MOVZX rax, byte [rax].
    const std::uint64_t slot = kDataBase + 0x10;
    ASSERT_TRUE(mem_->write_u8(slot, 0x80).ok());
    cpu_.gprs[0] = slot;
    ASSERT_TRUE(run({0x48, 0x0F, 0xB6, 0x00}).ok());   // movzx rax, byte [rax]
    EXPECT_EQ(cpu_.gprs[0], 0x80ull);
}

// ── LEA ───────────────────────────────────────────────────────────────────

TEST_F(X86DataMovementTest, LeaComputesEffectiveAddress) {
    // LEA rax, [rcx + rdx*4 + 0x10] with rcx=0x100, rdx=2.
    cpu_.gprs[1] = 0x100;    // rcx
    cpu_.gprs[2] = 2;        // rdx
    // ModRM 0x44: mod=01 (disp8), reg=000(rax), rm=100(SIB); SIB 0x91:
    // scale=4 (10b), index=rdx (010b), base=rcx (001b); disp8 0x10.
    ASSERT_TRUE(run({0x48, 0x8D, 0x44, 0x91, 0x10}).ok());   // lea rax,[rcx+rdx*4+0x10]
    EXPECT_EQ(cpu_.gprs[0], 0x100 + 2 * 4 + 0x10);
}

TEST_F(X86DataMovementTest, LeaRipRelative) {
    // LEA rax, [rip + 0] at code+0: value = next RIP = kCodeBase + 7.
    cpu_.gprs[0] = 0;
    ASSERT_TRUE(run({0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00}).ok());
    EXPECT_EQ(cpu_.gprs[0], kCodeBase + 7);
}

// ── XCHG ──────────────────────────────────────────────────────────────────

TEST_F(X86DataMovementTest, XchgRegisterAndMemory) {
    // XCHG rbx, rcx (REX.W 87 /r with mod 3, reg=rbx? Use 48 87 CB:
    // mod3 reg=001(rcx) rm=011(rbx) -> xchg rcx, rbx).
    cpu_.gprs[1] = 0x11;    // rcx
    cpu_.gprs[3] = 0x22;    // rbx
    ASSERT_TRUE(run({0x48, 0x87, 0xCB}).ok());   // xchg rcx, rbx
    EXPECT_EQ(cpu_.gprs[1], 0x22u);
    EXPECT_EQ(cpu_.gprs[3], 0x11u);
    // XCHG eAX, r8 (41 90): rax <-> r8.
    cpu_.gprs[0] = 0xAAAA;
    cpu_.gprs[8] = 0xBBBB;
    ASSERT_TRUE(run({0x41, 0x90}).ok());
    EXPECT_EQ(cpu_.gprs[0], 0xBBBBu);
    EXPECT_EQ(cpu_.gprs[8], 0xAAAAu);
    // XCHG memory: [rax] <-> rcx.
    const std::uint64_t slot = kDataBase + 0x20;
    ASSERT_TRUE(mem_->write_u64(slot, 0x7777).ok());
    cpu_.gprs[0] = slot;
    cpu_.gprs[1] = 0x8888;
    ASSERT_TRUE(run({0x48, 0x87, 0x08}).ok());   // xchg [rax], rcx
    EXPECT_EQ(mem_->read_u64(slot).value(), 0x8888u);
    EXPECT_EQ(cpu_.gprs[1], 0x7777u);
}

// ── shifts ────────────────────────────────────────────────────────────────

TEST_F(X86DataMovementTest, ShlShrSar64) {
    // SHL rax, 4: 0x12345 << 4.
    cpu_.gprs[0] = 0x12345;
    ASSERT_TRUE(run({0x48, 0xC1, 0xE0, 0x04}).ok());
    EXPECT_EQ(cpu_.gprs[0], 0x123450ull);
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));  // last bit out (bit 60) = 0
    // SHR rax, 8.
    cpu_.gprs[0] = 0x123456;
    ASSERT_TRUE(run({0x48, 0xC1, 0xE8, 0x08}).ok());
    EXPECT_EQ(cpu_.gprs[0], 0x1234ull);
    // SAR rax, 4 (negative value: sign fill).
    cpu_.gprs[0] = 0xFFFFFFFFFFFFFFF0ull;        // -16
    ASSERT_TRUE(run({0x48, 0xC1, 0xF8, 0x04}).ok());
    EXPECT_EQ(static_cast<std::int64_t>(cpu_.gprs[0]), -1);   // -16 >> 4 = -1
}

TEST_F(X86DataMovementTest, ShiftByClAndOne) {
    // SHL eax, CL with CL = 3.
    cpu_.gprs[0] = 1;
    cpu_.gprs[1] = 3;    // rcx low byte = 3
    ASSERT_TRUE(run({0xD3, 0xE0}).ok());   // shl eax, cl
    EXPECT_EQ(cpu_.gprs[0] & 0xFFFFFFFF, 8u);
    // SHL rax, 1 (D1 /4 with REX.W).
    cpu_.gprs[0] = 0x4000000000000000ull;
    ASSERT_TRUE(run({0x48, 0xD1, 0xE0}).ok());
    EXPECT_EQ(cpu_.gprs[0], 0x8000000000000000ull);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagOF));   // count 1: OF = sign flip
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));  // bit shifted out = 0
}

TEST_F(X86DataMovementTest, ShiftCountZeroTouchesNothing) {
    // SHL rax, 0: no flags change, no write.
    cpu_.gprs[0] = 5;
    cpu_.set_flag(rt::cpu::kFlagCF, true);
    cpu_.set_flag(rt::cpu::kFlagZF, true);
    ASSERT_TRUE(run({0x48, 0xC1, 0xE0, 0x00}).ok());
    EXPECT_EQ(cpu_.gprs[0], 5ull);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));   // unchanged
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagZF));    // unchanged
}

TEST_F(X86DataMovementTest, ShiftCountBeyondWidth) {
    // SHL al, 9: 8-bit operand: result 0, CF = 0 (the last bit shifted out
    // of an 8-bit value by 9 is beyond the width; SDM: CF undefined — the
    // engine clears it deterministically and documents that).
    cpu_.gprs[0] = 0x80;
    ASSERT_TRUE(run({0xC0, 0xE0, 0x09}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0u);
    // SHR rax, 64: masked to 0 (count & 0x3F): count 0 -> nothing.
    cpu_.gprs[0] = 7;
    ASSERT_TRUE(run({0x48, 0xC1, 0xE8, 0x40}).ok());
    EXPECT_EQ(cpu_.gprs[0], 7ull);   // count 0x40 & 0x3F = 0: untouched
}

TEST_F(X86DataMovementTest, ShiftFlagsFromResult) {
    // SHL al, 1: 0x40 -> 0x80: ZF=0, SF=1, PF of 0x80 (1 bit) = 0.
    cpu_.gprs[0] = 0x40;
    ASSERT_TRUE(run({0xD0, 0xE0}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0x80u);
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagZF));
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagSF));
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagPF));
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagOF));
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));   // 0x40's bit 7 was 0
}

// ── rotates ────────────────────────────────────────────────────────────────

TEST_F(X86DataMovementTest, RolRorFlagsAndValues) {
    // ROL al, 1: 0x80 -> 0x01, CF = 1 (bit rotated out), SF=0.
    cpu_.gprs[0] = 0x80;
    ASSERT_TRUE(run({0xD0, 0xC0}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0x01u);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    // ROR al, 1: 0x01 -> 0x80, CF = 1 (new LSB? no: bit out = old bit 0 = 1).
    cpu_.gprs[0] = 0x01;
    ASSERT_TRUE(run({0xD0, 0xC8}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0x80u);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    // ROL al, 8: full rotation -> same value, CF set (bit out = bit 0 of
    // the last intermediate? masked 8 % 8 = 0: no rotation, flags unchanged).
    cpu_.gprs[0] = 0x80;
    cpu_.set_flag(rt::cpu::kFlagCF, false);
    ASSERT_TRUE(run({0xC0, 0xC0, 0x08}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0x80u);
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));   // no rotation: unchanged
}

TEST_F(X86DataMovementTest, RclRcrRotateThroughCarry) {
    // RCL al, 1 with CF=1: 0x80 + carry-in -> 0x01 with CF=1.
    cpu_.gprs[0] = 0x80;
    cpu_.set_flag(rt::cpu::kFlagCF, true);
    ASSERT_TRUE(run({0xD0, 0xD0}).ok());   // rcl al, 1
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0x01u);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));   // old bit 7 rotated into CF
    // RCR al, 1 with CF=0: 0x01 -> 0x00, CF = old bit 0 = 1.
    cpu_.gprs[0] = 0x01;
    cpu_.set_flag(rt::cpu::kFlagCF, false);
    ASSERT_TRUE(run({0xD0, 0xD8}).ok());   // rcr al, 1
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0x00u);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
}

// ── bit ops ────────────────────────────────────────────────────────────────

TEST_F(X86DataMovementTest, BtFamily) {
    // BT eax, 3 with eax = 0x8: CF = 1, no write.
    cpu_.gprs[0] = 0x8;
    cpu_.set_flag(rt::cpu::kFlagCF, false);
    ASSERT_TRUE(run({0x0F, 0xBA, 0xE0, 0x03}).ok());
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    EXPECT_EQ(cpu_.gprs[0], 0x8ull);   // BT does not write
    // BTS eax, 0: sets bit 0, CF = old bit (0).
    cpu_.gprs[0] = 0x8;
    cpu_.set_flag(rt::cpu::kFlagCF, true);
    ASSERT_TRUE(run({0x0F, 0xBA, 0xE8, 0x00}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFFFFFFFF, 0x9u);
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));   // old bit 0 was 0
    // BTR eax, 3: clears bit 3, CF = 1 (old).
    cpu_.gprs[0] = 0x8;
    ASSERT_TRUE(run({0x0F, 0xBA, 0xF0, 0x03}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFFFFFFFF, 0x0u);
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    // BTC eax, 0: toggles bit 0.
    cpu_.gprs[0] = 0x8;
    ASSERT_TRUE(run({0x0F, 0xBA, 0xF8, 0x00}).ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFFFFFFFF, 0x9u);
    EXPECT_FALSE(cpu_.flag(rt::cpu::kFlagCF));
}

TEST_F(X86DataMovementTest, BtRegisterBitPosition) {
    // BT rax, rcx: bit position modulo 64. rcx = 65 -> bit 1.
    cpu_.gprs[0] = 0x2;    // bit 1 set
    cpu_.gprs[1] = 65;     // 65 % 64 = 1
    cpu_.set_flag(rt::cpu::kFlagCF, false);
    ASSERT_TRUE(run({0x48, 0x0F, 0xA3, 0xC8}).ok());   // bt rax, rcx
    EXPECT_TRUE(cpu_.flag(rt::cpu::kFlagCF));
    // BTS qword [rax], cl: sets bit (cl % 8) in memory.
    const std::uint64_t slot = kDataBase + 0x30;
    ASSERT_TRUE(mem_->write_u64(slot, 0).ok());
    cpu_.gprs[0] = slot;
    cpu_.gprs[1] = 9;    // 9 % 64 = 9 for a 64-bit operand
    ASSERT_TRUE(run({0x48, 0x0F, 0xAB, 0x08}).ok());   // bts [rax], cl
    EXPECT_EQ(mem_->read_u64(slot).value(), 1ull << 9);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
