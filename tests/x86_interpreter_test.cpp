// M9 §3B: interpreter arithmetic/logic semantics tests.
//
// Every expectation is hand-derived from the Intel SDM semantics tables.
// The fixture builds a real M4 AddressSpace (code RX, data RW) and runs
// instructions through Interpreter::step_at_rip(), checking:
//   - results at 8/16/32/64-bit widths (including sub-register merge
//     rules: 32-bit writes zero-extend, 8/16-bit writes merge),
//   - all six architectural flags (CF/PF/AF/ZF/SF/OF) on carry/borrow/
//     overflow/zero/sign cases, undefined flags left unchanged,
//   - typed faults (unmapped/permission) with all-or-nothing state,
//   - MUL/IMUL/DIV/IDIV register pairs and divide errors.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
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
using rt::x64::Decoded;
using rt::x86::Interpreter;

namespace {

constexpr std::uint64_t kCodeBase = 0x10000000;   // RX region
constexpr std::uint64_t kDataBase = 0x10020000;   // RW region
constexpr std::uint64_t kRegionPages = 16;

// Test fixture: one address space, an RX code region, an RW data region.
class X86SemanticsTest : public ::testing::Test {
protected:
    void SetUp() override {
        space_ = std::make_unique<AddressSpace>(64 * 4096, 0x10000000, "x86test");
        ASSERT_TRUE(space_->reserve_region(kCodeBase, kRegionPages * 4096, "code").ok());
        ASSERT_TRUE(space_->reserve_region(kDataBase, kRegionPages * 4096, "data").ok());
        ASSERT_TRUE(space_->commit_region(kCodeBase).ok());
        ASSERT_TRUE(space_->commit_region(kDataBase).ok());
        // Code region: writable staging (fixtures place bytes here through
        // GuestMemory, which requires RW); execution permission is granted
        // RX afterwards so instruction fetch passes validate_exec.
        ASSERT_TRUE(space_->protect_region(kCodeBase, MemProtect::Full).ok());
        mem_ = std::make_unique<GuestMemory>(*space_);
        interp_ = std::make_unique<Interpreter>(cpu_, *mem_);
    }

    // Writes code at kCodeBase + off and returns its VA.
    std::uint64_t code_at(std::uint64_t off, const std::vector<std::uint8_t>& bytes) {
        const std::uint64_t va = kCodeBase + off;
        EXPECT_TRUE(mem_->write(va, bytes.data(), bytes.size()).ok());
        return va;
    }

    // Places code at offset 0 and runs one step.
    Interpreter& load(const std::vector<std::uint8_t>& bytes) {
        cpu_.reset();
        cpu_.rip = code_at(0, bytes);
        return interp();
    }
    Interpreter& interp() { return *interp_; }
    CpuState& cpu() { return cpu_; }
    GuestMemory& mem() { return *mem_; }

    // Runs exactly one step and asserts success.
    void run_ok(const std::vector<std::uint8_t>& bytes) {
        cpu_.reset();
        cpu_.rip = code_at(0, bytes);
        ASSERT_TRUE(interp().step_at_rip().ok());
    }

    bool cf() const { return cpu_.flag(rt::cpu::kFlagCF); }
    bool pf() const { return cpu_.flag(rt::cpu::kFlagPF); }
    bool af() const { return cpu_.flag(rt::cpu::kFlagAF); }
    bool zf() const { return cpu_.flag(rt::cpu::kFlagZF); }
    bool sf() const { return cpu_.flag(rt::cpu::kFlagSF); }
    bool of() const { return cpu_.flag(rt::cpu::kFlagOF); }

    std::unique_ptr<AddressSpace> space_;
    std::unique_ptr<GuestMemory> mem_;
    std::unique_ptr<Interpreter> interp_;
    CpuState cpu_;
};

}  // namespace

// ── sub-register rules ─────────────────────────────────────────────────────

TEST_F(X86SemanticsTest, SubRegisterMergeRules) {
    // 32-bit write zero-extends; 8/16 merge; AH is the high byte of AX.
    run_ok({0xB8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77});   // mov eax, 0x77665544
    // 32-bit write to EAX must zero the top 32 bits — verify via a second
    // write after a 64-bit write.
    run_ok({0x48, 0xC7, 0xC0, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(cpu().gprs[0], 0x0000000004030201ull);
    run_ok({0xC7, 0xC0, 0x11, 0x22, 0x33, 0x44});               // mov eax, imm32
    EXPECT_EQ(cpu().gprs[0], 0x0000000044332211ull);
    // 8-bit merge into a slot whose top bytes are set.
    cpu().gprs[0] = 0xFFFFFFFFFFFFFFFFull;
    cpu().rip = code_at(0, {0xB0, 0x5A});                        // mov al, 0x5A
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0], 0xFFFFFFFFFFFFFF5Aull);
    // 16-bit merge.
    cpu().gprs[0] = 0xFFFFFFFFFFFFFFFFull;
    cpu().rip = code_at(0, {0x66, 0xB8, 0x34, 0x12});           // mov ax, 0x1234
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0], 0xFFFFFFFFFFFF1234ull);
    // AH write: high byte of slot 0.
    cpu().gprs[0] = 0xFFFFFFFFFFFF3412ull;
    cpu().rip = code_at(0, {0xB4, 0x77});                       // mov ah, 0x77
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0], 0xFFFFFFFFFFFF7712ull);
    // SPL (REX): low byte of RSP.
    cpu().gprs[4] = 0x1111111111111111ull;
    cpu().rip = code_at(0, {0x40, 0xB4, 0x99});                 // mov spl, 0x99
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[4], 0x1111111111111199ull);
}

// ── ADD / ADC / SUB / SBB / CMP flags ───────────────────────────────────────

TEST_F(X86SemanticsTest, ShlOverflowIncludesCarryOut) {
    cpu().set_reg(Gpr::Rax, 0x80);
    cpu().rip = code_at(0, {0xD0, 0xE0}); // shl al, 1
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax) & 0xFFu, 0u);
    EXPECT_TRUE(cf());
    EXPECT_TRUE(of());
}

TEST_F(X86SemanticsTest, RclOverflowUsesCarryFlag) {
    cpu().set_reg(Gpr::Rax, 0x80);
    cpu().set_flag(rt::cpu::kFlagCF, false);
    cpu().rip = code_at(0, {0xD0, 0xD0}); // rcl al, 1
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax) & 0xFFu, 0u);
    EXPECT_TRUE(cf());
    EXPECT_TRUE(of());
}

TEST_F(X86SemanticsTest, MemoryXchgIsRejectedAsImplicitlyAtomic) {
    const std::uint64_t slot = kDataBase + 0x40;
    ASSERT_TRUE(mem().write_u64(slot, 0x1122334455667788ull).ok());
    cpu().set_reg(Gpr::Rax, 0xAABBCCDD);
    cpu().set_reg(Gpr::Rbx, slot);
    cpu().rip = code_at(0, {0x48, 0x87, 0x03}); // xchg [rbx], rax
    auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::UnsupportedInstruction);
    EXPECT_EQ(mem().read_u64(slot).value(), 0x1122334455667788ull);
    EXPECT_EQ(cpu().reg(Gpr::Rax), 0xAABBCCDDu);
}

TEST_F(X86SemanticsTest, MemoryBitStringRegisterOffsetIsRejected) {
    const std::uint64_t slot = kDataBase + 0x40;
    ASSERT_TRUE(mem().write_u64(slot, 0).ok());
    cpu().set_reg(Gpr::Rax, 64);
    cpu().set_reg(Gpr::Rbx, slot);
    cpu().rip = code_at(0, {0x48, 0x0F, 0xAB, 0x03}); // bts [rbx], rax
    auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::UnsupportedInstruction);
    EXPECT_EQ(mem().read_u64(slot).value(), 0u);
}

TEST_F(X86SemanticsTest, PopMemoryFaultRestoresRsp) {
    const std::uint64_t stack = kDataBase + 0x100;
    ASSERT_TRUE(mem().write_u64(stack, 0x12345678).ok());
    cpu().set_reg(Gpr::Sp, stack);
    cpu().set_reg(Gpr::Rax, 0x99990000);
    cpu().rip = code_at(0, {0x8F, 0x00}); // pop qword ptr [rax]
    const auto before = cpu();
    auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(cpu().reg(Gpr::Sp), before.reg(Gpr::Sp));
    EXPECT_EQ(cpu().rip, before.rip);
}

TEST_F(X86SemanticsTest, Add64CarryAndAdcCarryIn) {
    cpu().set_reg(Gpr::Rax, ~0ull);
    cpu().rip = code_at(0, {0x48, 0x05, 0x01, 0x00, 0x00, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax), 0u);
    EXPECT_TRUE(cf());
    cpu().set_reg(Gpr::Rax, ~0ull);
    cpu().set_flag(rt::cpu::kFlagCF, true);
    cpu().rip = code_at(16, {0x48, 0x15, 0x00, 0x00, 0x00, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax), 0u);
    EXPECT_TRUE(cf());
}

TEST_F(X86SemanticsTest, ByteMulWithRexDoesNotClobberRsp) {
    cpu().set_reg(Gpr::Rax, 0x12);
    cpu().set_reg(Gpr::Rcx, 0x34);
    cpu().set_reg(Gpr::Sp, 0x1122334455667788ull);
    const auto rsp = cpu().reg(Gpr::Sp);
    cpu().rip = code_at(0, {0x40, 0xF6, 0xE1});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax) & 0xFFFFu, 0x03A8u);
    EXPECT_EQ(cpu().reg(Gpr::Sp), rsp);
}

TEST_F(X86SemanticsTest, AddAndCarryFlags) {
    // 8-bit ADD 0xF0 + 0x20: carry, AF, not zero, SF set, OF clear.
    cpu().reset();
    cpu().rip = code_at(0, {0xB0, 0xF0});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0x04, 0x20});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x10u);
    EXPECT_TRUE(cf());
    EXPECT_FALSE(af());   // 0x0 + 0x2: no carry out of bit 3
    EXPECT_FALSE(zf());
    EXPECT_FALSE(sf());   // 0x10: bit 7 clear
    EXPECT_FALSE(of());
}

TEST_F(X86SemanticsTest, AddSignedOverflow) {
    // 8-bit ADD 0x7F + 0x01 = 0x80: OF set, SF set.
    cpu().rip = code_at(0, {0xB0, 0x7F});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0x04, 0x01});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x80u);
    EXPECT_TRUE(of());
    EXPECT_TRUE(sf());
    EXPECT_FALSE(cf());
}

TEST_F(X86SemanticsTest, AddZeroSetsZfAndPf) {
    // 32-bit ADD 0xFFFFFFFF + 1 = 0: ZF, CF, PF (parity of 0 = even), AF.
    cpu().rip = code_at(0, {0xB8, 0xFF, 0xFF, 0xFF, 0xFF});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0x05, 0x01, 0x00, 0x00, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFFFFFFFF, 0u);
    EXPECT_TRUE(zf());
    EXPECT_TRUE(cf());
    EXPECT_TRUE(pf());   // 0x00 has even parity
    EXPECT_FALSE(sf());
}

TEST_F(X86SemanticsTest, AdcUsesAndSetsCarry) {
    // ADC with CF=0: plain add; with CF=1: +1 more.
    cpu().rip = code_at(0, {0xB0, 0x10});
    ASSERT_TRUE(interp().step_at_rip().ok());
    // ADC al, 0x20 with CF=0.
    cpu().rip = code_at(16, {0x14, 0x20});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x30u);
    // Set CF manually, ADC again.
    cpu().set_flag(rt::cpu::kFlagCF, true);
    cpu().rip = code_at(32, {0x14, 0x20});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x51u);   // 0x30 + 0x20 + 1
}

TEST_F(X86SemanticsTest, SubBorrowAndZero) {
    // 8-bit SUB 0x10 - 0x20: borrow (CF), SF, no OF (both positive).
    cpu().rip = code_at(0, {0xB0, 0x10});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0x2C, 0x20});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0xF0u);
    EXPECT_TRUE(cf());
    EXPECT_TRUE(sf());
    EXPECT_FALSE(of());
    EXPECT_FALSE(zf());
    // SUB equal operands: ZF, CF clear, PF set (0 = even parity).
    cpu().rip = code_at(32, {0x2C, 0xF0});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0u);
    EXPECT_TRUE(zf());
    EXPECT_FALSE(cf());
    EXPECT_TRUE(pf());
}

TEST_F(X86SemanticsTest, SubSignedOverflow) {
    // 8-bit SUB 0x80 - 0x01 = 0x7F: OF set (neg - pos -> pos).
    cpu().rip = code_at(0, {0xB0, 0x80});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0x2C, 0x01});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x7Fu);
    EXPECT_TRUE(of());
    EXPECT_FALSE(sf());
    EXPECT_FALSE(cf());
}

TEST_F(X86SemanticsTest, CmpDoesNotWriteBack) {
    // CMP r/m, reg: flags like SUB, destination untouched.
    cpu().rip = code_at(0, {0xB8, 0x37, 0x13, 0x00, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0xB9, 0x37, 0x13, 0x00, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(32, {0x39, 0xC8});   // cmp eax, ecx
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_TRUE(zf());
    EXPECT_EQ(cpu().gprs[0] & 0xFFFFFFFF, 0x1337u);
    EXPECT_EQ(cpu().gprs[1] & 0xFFFFFFFF, 0x1337u);
}

TEST_F(X86SemanticsTest, SbbBorrowChain) {
    // SBB al, 0 with CF=1: al - 0 - 1.
    cpu().rip = code_at(0, {0xB0, 0x05});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().set_flag(rt::cpu::kFlagCF, true);
    cpu().rip = code_at(16, {0x1C, 0x00});   // sbb al, 0
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x04u);
    EXPECT_FALSE(cf());   // 5 >= 0+1, no borrow out
}

// ── logic ops ───────────────────────────────────────────────────────────────

TEST_F(X86SemanticsTest, LogicFlagsClearCfOf) {
    // OR/AND/XOR/TEST clear CF and OF; AF undefined (must not change here).
    cpu().rip = code_at(0, {0xB0, 0x0F});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().set_flag(rt::cpu::kFlagCF, true);
    cpu().set_flag(rt::cpu::kFlagOF, true);
    cpu().set_flag(rt::cpu::kFlagAF, true);
    cpu().rip = code_at(16, {0x0C, 0xF0});   // or al, 0xF0
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0xFFu);
    EXPECT_FALSE(cf());
    EXPECT_FALSE(of());
    EXPECT_TRUE(af());   // undefined -> unchanged
    EXPECT_TRUE(sf());
    EXPECT_FALSE(zf());
    // TEST leaves the destination untouched.
    cpu().rip = code_at(32, {0xA8, 0x0F});   // test al, 0x0F
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0xFFu);   // unchanged
    EXPECT_FALSE(zf());
    EXPECT_FALSE(cf());
    // TEST to zero.
    cpu().rip = code_at(48, {0xA8, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_TRUE(zf());
}

TEST_F(X86SemanticsTest, XorAndParity) {
    // XOR al, al: ZF set, PF set (parity of 0x00 is even).
    cpu().rip = code_at(0, {0xB0, 0x55});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0x30, 0xC0});   // xor al, al
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0u);
    EXPECT_TRUE(zf());
    EXPECT_TRUE(pf());
    EXPECT_FALSE(sf());
}

// ── INC/DEC: no CF, but OF at the boundary ─────────────────────────────────

TEST_F(X86SemanticsTest, IncDecDoNotTouchCf) {
    cpu().rip = code_at(0, {0xB0, 0xFF});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().set_flag(rt::cpu::kFlagCF, true);
    cpu().rip = code_at(16, {0xFE, 0xC0});   // inc al
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x00u);
    EXPECT_TRUE(zf());
    EXPECT_TRUE(cf());   // untouched
    // INC at 0x7F -> 0x80: OF set, SF set.
    cpu().rip = code_at(32, {0xB0, 0x7F});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(48, {0xFE, 0xC0});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x80u);
    EXPECT_TRUE(of());
    EXPECT_TRUE(sf());   // 0x80
    // DEC at 0x80 (INT8_MIN) -> 0x7F: OF set (underflow), CF untouched.
    cpu().set_flag(rt::cpu::kFlagCF, false);
    cpu().rip = code_at(64, {0xFE, 0xC8});   // dec al (al = 0x80 here)
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x7Fu);
    EXPECT_TRUE(of());   // -128 - 1 underflows int8
    EXPECT_FALSE(cf());
}

// ── NEG/NOT ─────────────────────────────────────────────────────────────────

TEST_F(X86SemanticsTest, NegNot) {
    // NEG al of 0x05 -> 0xFB: CF (non-zero), SF, OF clear.
    cpu().rip = code_at(0, {0xB0, 0x05});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(16, {0xF6, 0xD8});   // neg al
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0xFBu);
    EXPECT_TRUE(cf());
    EXPECT_TRUE(sf());
    EXPECT_FALSE(of());
    // NEG of 0x80 (8-bit): OF set (INT8_MIN negated).
    cpu().rip = code_at(32, {0xB0, 0x80});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(48, {0xF6, 0xD8});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0x80u);
    EXPECT_TRUE(of());
    EXPECT_TRUE(cf());
    // NEG of 0: CF clear, ZF set.
    cpu().rip = code_at(64, {0xB0, 0x00});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().rip = code_at(80, {0xF6, 0xD8});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_TRUE(zf());
    EXPECT_FALSE(cf());
    // NOT: no flags at all — verify none changed.
    cpu().rip = code_at(96, {0xB0, 0x0F});
    ASSERT_TRUE(interp().step_at_rip().ok());
    cpu().set_flag(rt::cpu::kFlagCF, true);
    cpu().set_flag(rt::cpu::kFlagZF, false);
    cpu().rip = code_at(112, {0xF6, 0xD0});   // not al
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFF, 0xF0u);
    EXPECT_TRUE(cf());   // NOT touches nothing
}

// ── memory operands: base+index*scale+disp, RIP-relative, addr32 ────────────

TEST_F(X86SemanticsTest, MemoryOperands) {
    // ADD dword ptr [rax + rcx*4 + 8], eax: the EA hits the data slot.
    const std::uint64_t slot = kDataBase + 0x40;
    ASSERT_TRUE(mem().write_u32(slot, 1000).ok());
    cpu().gprs[0] = 7;                       // eax = 7 (added into memory)
    cpu().gprs[1] = 3;                       // rcx = 3 (index)
    // base = slot - 8 - 3*4; the test writes rax directly.
    cpu().gprs[0] = slot - 8 - 4 * 3;        // rax = base (overwrites eax)
    // Use RDX as base instead so EAX keeps its addend value.
    cpu().gprs[0] = 7;                       // eax = 7
    cpu().gprs[2] = slot - 8 - 4 * 3;        // rdx = base
    // Encoding: add eax, [rdx + rcx*4 + 8] -> REX 0, 03 /r mod=01 rm=100
    // SIB: scale=4(idx=rcx=001) base=rdx=010 => 0x4C? scale(2b)=10 -> 0b10'001'010
    cpu().rip = code_at(0, {0x03, 0x44, 0x8A, 0x08});   // add eax, [rdx+rcx*4+8]
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFFFFFFFF, 1007u);      // 7 + 1000
    EXPECT_EQ(mem().read_u32(slot).value(), 1000u);   // memory is the source
}

TEST_F(X86SemanticsTest, RipRelativeMemory) {
    // ADD eax, [rip + disp32]: target in the DATA region (needs a big disp).
    // Simpler: place the value right after the instruction inside the code
    // region is not writable — use a load into the data region instead.
    const std::uint64_t target = kDataBase + 0x10;
    ASSERT_TRUE(mem().write_u64(target, 0x1122334455667788ull).ok());
    // MOV rax, [rip + disp]: instruction at code+0..6, next rip = code+7.
    const std::uint64_t va = kCodeBase;
    const std::int64_t disp = static_cast<std::int64_t>(target) -
                              static_cast<std::int64_t>(va + 7);
    std::vector<std::uint8_t> code = {0x48, 0x8B, 0x05};
    for (int i = 0; i < 4; ++i) {
        code.push_back(static_cast<std::uint8_t>((disp >> (8 * i)) & 0xFF));
    }
    cpu().rip = code_at(0, code);
    // MOV is data movement — §3C. Use ADD rax, [rip+disp] instead (48 03 05).
    code[0] = 0x48; code[1] = 0x03;   // REX.W ADD r64, r/m64 (rm=101 mod=00)
    cpu().rip = code_at(0, code);
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0], 0x1122334455667788ull);
}

TEST_F(X86SemanticsTest, MemoryFaultIsAllOrNothing) {
    // ADD eax, [rax] with RAX pointing into the RX code region: read is
    // allowed (R), so this is fine; point at an unmapped VA instead.
    cpu().set_reg(Gpr::Rax, 0x99990000);   // unmapped
    cpu().rip = code_at(0, {0x03, 0x00});  // add eax, [rax]
    const CpuState before = cpu();
    const auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::InvalidAccess);
    EXPECT_EQ(r.fault().fault_rip, kCodeBase);
    EXPECT_EQ(cpu().rip, kCodeBase);   // no RIP advance
    EXPECT_TRUE(std::memcmp(cpu().gprs, before.gprs, sizeof(cpu().gprs)) == 0);
    EXPECT_EQ(cpu().rflags, before.rflags);
}

TEST_F(X86SemanticsTest, WriteToReadOnlyFaults) {
    // ADD dword ptr [rax], eax with RAX in a read-only region: denied.
    // The data region is protected ReadOnly for this test via a third region.
    const std::uint64_t ro_base = 0x10038000;   // inside the 64-page space
    ASSERT_TRUE(space_->reserve_region(ro_base, 4096, "ro").ok());
    ASSERT_TRUE(space_->commit_region(ro_base).ok());
    ASSERT_TRUE(space_->protect_region(ro_base, MemProtect::ReadOnly).ok());
    cpu().set_reg(Gpr::Rax, ro_base);
    cpu().rip = code_at(0, {0x01, 0x00});   // add [rax], eax
    const CpuState before = cpu();
    const auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::PermissionWrite);
    EXPECT_TRUE(std::memcmp(cpu().gprs, before.gprs, sizeof(cpu().gprs)) == 0);
}

// ── MUL/DIV families ────────────────────────────────────────────────────────

TEST_F(X86SemanticsTest, ByteDivWithRexWritesAxNotRsp) {
    cpu().set_reg(Gpr::Rax, 0x0100); // AX = 256
    cpu().set_reg(Gpr::Rcx, 2);      // divisor CL = 2
    cpu().set_reg(Gpr::Sp, 0x1122334455667788ull);
    const auto rsp = cpu().reg(Gpr::Sp);
    cpu().rip = code_at(0, {0x40, 0xF6, 0xF1}); // rex; div cl
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax) & 0xFFFFu, 0x0080u);
    EXPECT_EQ(cpu().reg(Gpr::Sp), rsp);
}

TEST_F(X86SemanticsTest, IdivByteAcceptsNegativeMinimumQuotient) {
    cpu().set_reg(Gpr::Rax, 0xFF80); // signed AX = -128
    cpu().set_reg(Gpr::Rcx, 1);     // divisor CL = 1
    cpu().set_reg(Gpr::Sp, 0x1122334455667788ull);
    const auto rsp = cpu().reg(Gpr::Sp);
    cpu().rip = code_at(0, {0x40, 0xF6, 0xF9}); // rex; idiv cl
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax) & 0xFFFFu, 0x0080u);
    EXPECT_EQ(cpu().reg(Gpr::Sp), rsp);
}

TEST_F(X86SemanticsTest, Div64HandlesRemainderHighBit) {
    // (2^127) / (2^63 + 1) = 2^64 - 2, remainder 2.
    cpu().set_reg(Gpr::Rdx, 0x8000000000000000ull);
    cpu().set_reg(Gpr::Rax, 0);
    cpu().set_reg(Gpr::Rbx, 0x8000000000000001ull);
    cpu().rip = code_at(0, {0x48, 0xF7, 0xF3});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().reg(Gpr::Rax), 0xFFFFFFFFFFFFFFFEull);
    EXPECT_EQ(cpu().reg(Gpr::Rdx), 2u);
}

TEST_F(X86SemanticsTest, MulUnsigned) {
    // 8-bit MUL: AX = AL * r/m8.
    cpu().rip = code_at(0, {0xB0, 0x12});   // mov al, 0x12
    ASSERT_TRUE(interp().step_at_rip().ok());
    // put 0x34 in CL; mul cl
    cpu().set_reg(Gpr::Rcx, 0x34);
    cpu().rip = code_at(16, {0xF6, 0xE1});   // mul cl
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFFFF, 0x12u * 0x34u);
    EXPECT_TRUE(cf());    // 0x12*0x34 = 0xA08 > 0xFF: upper half non-zero
}

TEST_F(X86SemanticsTest, Mul64UnsignedHiLo) {
    // 64-bit MUL: RDX:RAX = RAX * r/m64.
    const std::uint64_t a = 0x1234567812345678ull;
    const std::uint64_t b = 0x100000001ull;
    cpu().set_reg(Gpr::Rax, a);
    cpu().set_reg(Gpr::Rbx, b);
    cpu().rip = code_at(0, {0x48, 0xF7, 0xE3});   // mul rbx
    ASSERT_TRUE(interp().step_at_rip().ok());
    // expected product via the same half-pair math in the test:
    const std::uint64_t al = a & 0xFFFFFFFFull, ah = a >> 32;
    const std::uint64_t bl = b & 0xFFFFFFFFull, bh = b >> 32;
    const std::uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    const std::uint64_t mid = lh + hl;
    const std::uint64_t lo = ll + (mid << 32);
    const std::uint64_t hi = hh + (mid >> 32) + ((mid < lh) ? (1ull << 32) : 0) +
                             ((lo < ll) ? 1ull : 0);
    EXPECT_EQ(cpu().gprs[0], lo);
    EXPECT_EQ(cpu().gprs[2], hi);
    EXPECT_TRUE(cf());   // hi != 0
}

TEST_F(X86SemanticsTest, ImulThreeOperandSigned) {
    // IMUL r, r/m, imm: dst = r/m * imm (rcx = rax * 16).
    cpu().set_reg(Gpr::Rax, 0xFFFFFFFFFFFFFF80ull);   // rax = -128 as 64-bit
    cpu().rip = code_at(0, {0x48, 0x6B, 0xC8, 0x10});   // imul rcx, rax, 16
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(static_cast<std::int64_t>(cpu().gprs[1]), -2048);
    EXPECT_FALSE(of());
    // Overflow: 2^62 * 2^62 does not fit the signed 64-bit range.
    cpu().set_reg(Gpr::Rax, 0x4000000000000000ull);   // 2^62
    // imm32 0x40000000 = 2^30 (little endian bytes 00 00 00 40).
    cpu().rip = code_at(16, {0x48, 0x69, 0xC8, 0x00, 0x00, 0x00, 0x40});
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[1], 0u);                      // truncated product
    EXPECT_TRUE(of());   // 2^62 * 2^30 overflows int64
}

TEST_F(X86SemanticsTest, DivUnsigned) {
    // 32-bit DIV: EAX = EDX:EAX / r/m32.
    cpu().set_reg(Gpr::Rax, 1000);
    cpu().set_reg(Gpr::Rdx, 0);
    cpu().set_reg(Gpr::Rbx, 7);
    cpu().rip = code_at(0, {0xF7, 0xF3});   // div ebx
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(cpu().gprs[0] & 0xFFFFFFFF, 142u);   // 1000 / 7
    EXPECT_EQ(cpu().gprs[2] & 0xFFFFFFFF, 6u);    // remainder
}

TEST_F(X86SemanticsTest, DivByZeroIsTyped) {
    cpu().set_reg(Gpr::Rax, 100);
    cpu().set_reg(Gpr::Rdx, 0);
    cpu().set_reg(Gpr::Rbx, 0);
    cpu().rip = code_at(0, {0xF7, 0xF3});   // div ebx (ebx = 0)
    const CpuState before = cpu();
    const auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::DivideError);
    EXPECT_TRUE(std::memcmp(cpu().gprs, before.gprs, sizeof(cpu().gprs)) == 0);
}

TEST_F(X86SemanticsTest, DivQuotientOverflowIsTyped) {
    // EDX:EAX = 0x1_00000000 / 1: quotient 0x100000000 > 32 bits.
    cpu().set_reg(Gpr::Rax, 0);
    cpu().set_reg(Gpr::Rdx, 1);
    cpu().set_reg(Gpr::Rbx, 1);
    cpu().rip = code_at(0, {0xF7, 0xF3});
    const auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::DivideError);
}

TEST_F(X86SemanticsTest, IdivSigned) {
    // IDIV: -7 / 2 = -3 rem -1 (C++ semantics match x86 truncation).
    cpu().set_reg(Gpr::Rax, static_cast<std::uint64_t>(-7));
    cpu().set_reg(Gpr::Rdx, static_cast<std::uint64_t>(-1));   // sign-extend
    cpu().set_reg(Gpr::Rbx, 2);
    cpu().rip = code_at(0, {0x48, 0xF7, 0xFB});   // idiv rbx
    ASSERT_TRUE(interp().step_at_rip().ok());
    EXPECT_EQ(static_cast<std::int64_t>(cpu().gprs[0]), -3);
    EXPECT_EQ(static_cast<std::int64_t>(cpu().gprs[2]), -1);
}

TEST_F(X86SemanticsTest, IdivMinDivMinusOneIsTyped) {
    // INT64_MIN / -1 overflows.
    cpu().set_reg(Gpr::Rax, 0x8000000000000000ull);
    cpu().set_reg(Gpr::Rdx, 0x8000000000000000ull);   // (value irrelevant)
    cpu().set_reg(Gpr::Rbx, static_cast<std::uint64_t>(-1));
    // For 64-bit idiv the dividend is RDX:RAX = -1:0x8000... -> INT64_MIN
    // with RDX = -1 sign extension... set RDX = 0xFFFFFFFFFFFFFFFF:
    cpu().set_reg(Gpr::Rdx, 0xFFFFFFFFFFFFFFFFull);
    cpu().rip = code_at(0, {0x48, 0xF7, 0xFB});
    const auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::DivideError);
}

// ── unsupported mnemonics are typed, RIP stays put ──────────────────────────

TEST_F(X86SemanticsTest, UnsupportedIsTypedNoRipAdvance) {
    // A mnemonic still outside the matrix: LAHF is decoded but not
    // implemented -> typed unsupported (stack/flags/convert group is in).
    cpu().rip = code_at(0, {0x9F});   // lahf
    const CpuState before = cpu();
    const auto r = interp().step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::UnsupportedInstruction);
    EXPECT_EQ(cpu().rip, kCodeBase);
    EXPECT_TRUE(std::memcmp(cpu().gprs, before.gprs, sizeof(cpu().gprs)) == 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
