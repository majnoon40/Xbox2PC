// M9 §3A: interpreter control-flow semantics tests.
//
// Hand-derived expectations from the Intel SDM: Jcc truth table over all
// 16 condition codes, JMP/CALL/RET (direct and indirect through registers
// and memory), LOOP/LOOPE/LOOPNE/JRCXZ decrement rules, CMOVcc/SETcc.
// Every branch target is validated for exec permission; fault cases keep
// the CPU state all-or-nothing.

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
using rt::x86::Interpreter;

namespace {

constexpr std::uint64_t kCodeBase = 0x10000000;
constexpr std::uint64_t kDataBase = 0x10020000;
constexpr std::uint64_t kStackTop = 0x1002F000;   // inside the data region

class X86ControlFlowTest : public ::testing::Test {
protected:
    void SetUp() override {
        space_ = std::make_unique<AddressSpace>(64 * 4096, 0x10000000, "cf");
        ASSERT_TRUE(space_->reserve_region(kCodeBase, 16 * 4096, "code").ok());
        ASSERT_TRUE(space_->reserve_region(kDataBase, 16 * 4096, "data").ok());
        ASSERT_TRUE(space_->commit_region(kCodeBase).ok());
        ASSERT_TRUE(space_->commit_region(kDataBase).ok());
        ASSERT_TRUE(space_->protect_region(kCodeBase, MemProtect::Full).ok());
        mem_ = std::make_unique<GuestMemory>(*space_);
        interp_ = std::make_unique<Interpreter>(cpu_, *mem_);
    }

    std::uint64_t code_at(std::uint64_t off, const std::vector<std::uint8_t>& bytes) {
        const std::uint64_t va = kCodeBase + off;
        EXPECT_TRUE(mem_->write(va, bytes.data(), bytes.size()).ok());
        return va;
    }

    // One step with an initial CPU (RSP initialized to the stack top).
    rt::x86::StepResult step_at(std::uint64_t off,
                                const std::vector<std::uint8_t>& bytes) {
        cpu_.rip = code_at(off, bytes);
        return interp_->step_at_rip();
    }

    void set_flags(std::uint32_t mask, bool value) {
        cpu_.set_flag(mask, value);
    }

    std::unique_ptr<AddressSpace> space_;
    std::unique_ptr<GuestMemory> mem_;
    std::unique_ptr<Interpreter> interp_;
    CpuState cpu_;
};

}  // namespace

// ── Jcc truth table ────────────────────────────────────────────────────────

TEST_F(X86ControlFlowTest, JccTruthTable) {
    // flags: OF CF ZF SF PF. cc semantics (SDM):
    // 0 O  1 NO 2 B  3 AE 4 E  5 NE 6 BE 7 A
    // 8 S  9 NS A P  B NP C L  D GE E LE F G
    // Base flag state: OF=1, CF=0, ZF=0, SF=1, PF=1. Expected decisions
    // derived per condition definition (verified by hand):
    //   O=1 NO=0 B=0(CF) AE=1 E=0 NE=1 BE=0(A? no: CF=0,ZF=0 -> BE=0) A=1
    //   S=1 NS=0 P=1 NP=0 L=(SF!=OF)=0 GE=1 LE=0 G=1
    struct Row {
        std::uint32_t mask;
        bool value;
        bool expect[16];
    };
    // Expected decisions for each flipped state (SDM definitions):
    //   O=OF, NO=!OF, B=CF, AE=!CF, E=ZF, NE=!ZF, BE=CF|ZF, A=!(CF|ZF),
    //   S=SF, NS=!SF, P=PF, NP=!PF, L=SF!=OF, GE=SF==OF, LE=ZF|(SF!=OF),
    //   G=!ZF&(SF==OF). Base: OF=1 CF=0 ZF=0 SF=1 PF=1.
    const Row rows[] = {
        {rt::cpu::kFlagOF, false, {false, true,  false, true,  false, true,  false, true,  true,  false, true,  false, true,  false, true,  false}},
        {rt::cpu::kFlagCF, true,  {true,  false, true,  false, false, true,  true,  false, true,  false, true,  false, false, true,  false, true}},
        {rt::cpu::kFlagZF, true,  {true,  false, false, true,  true,  false, true,  false, true,  false, true,  false, false, true,  true,  false}},
        {rt::cpu::kFlagSF, false, {true,  false, false, true,  false, true,  false, true,  false, true,  true,  false, true,  false, true,  false}},
    };
    for (const Row& row : rows) {
        // Base flags: OF=1, CF=0, ZF=0, SF=1, PF=1; each row flips one.
        cpu_.reset();
        cpu_.set_reg(Gpr::Sp, kStackTop);
        set_flags(rt::cpu::kFlagOF, true);
        set_flags(rt::cpu::kFlagCF, false);
        set_flags(rt::cpu::kFlagZF, false);
        set_flags(rt::cpu::kFlagSF, true);
        set_flags(rt::cpu::kFlagPF, true);
        set_flags(row.mask, row.value);
        for (int cc = 0; cc < 16; ++cc) {
            // 70+cc rel8 with disp 0x10: taken -> rip = start + 2 + 0x10.
            cpu_.rip = code_at(0, {static_cast<std::uint8_t>(0x70 + cc), 0x10});
            const auto r = interp_->step_at_rip();
            ASSERT_TRUE(r.ok()) << "cc " << cc;
            const std::uint64_t taken_rip = kCodeBase + 2 + 0x10;
            EXPECT_EQ(cpu_.rip, row.expect[cc] ? taken_rip : kCodeBase + 2)
                << "cc " << cc;
        }
    }
}

TEST_F(X86ControlFlowTest, JccNotTakenStaysSequential) {
    // JE with ZF=0: rip advances past the 6-byte rel32 form.
    cpu_.reset();
    set_flags(rt::cpu::kFlagZF, false);
    cpu_.rip = code_at(0, {0x0F, 0x84, 0x40, 0x00, 0x00, 0x00});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 6);
}

// ── JMP ────────────────────────────────────────────────────────────────────

TEST_F(X86ControlFlowTest, JmpDirectRel8Rel32) {
    cpu_.rip = code_at(0, {0xEB, 0x10});   // jmp rel8
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 2 + 0x10);
    cpu_.rip = code_at(16, {0xE9, 0x00, 0x01, 0x00, 0x00});   // jmp rel32
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 16 + 5 + 0x100);
    // Backward jump: rel8 0xF0 = -16.
    cpu_.rip = code_at(32, {0xEB, 0xF0});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 32 + 2 - 16);
}

TEST_F(X86ControlFlowTest, JmpIndirectRegisterAndMemory) {
    // JMP rax.
    cpu_.set_reg(Gpr::Rax, kCodeBase + 0x80);
    cpu_.rip = code_at(0, {0xFF, 0xE0});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 0x80);
    // JMP [rax] (memory holds the target).
    const std::uint64_t slot = kDataBase + 0x20;
    ASSERT_TRUE(mem_->write_u64(slot, kCodeBase + 0x90).ok());
    cpu_.set_reg(Gpr::Rax, slot);
    cpu_.rip = code_at(16, {0xFF, 0x20});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 0x90);
}

TEST_F(X86ControlFlowTest, JmpToUnmappedFaults) {
    cpu_.rip = code_at(0, {0xFF, 0xE0});   // jmp rax
    cpu_.set_reg(Gpr::Rax, 0x99990000);
    const CpuState before = cpu_;
    const auto r = interp_->step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::InvalidAccess);
    EXPECT_EQ(r.fault().fault_address, 0x99990000u);
    EXPECT_EQ(cpu_.rip, kCodeBase);   // no advance
    EXPECT_TRUE(std::memcmp(cpu_.gprs, before.gprs, sizeof(cpu_.gprs)) == 0);
}

// ── CALL / RET ─────────────────────────────────────────────────────────────

TEST_F(X86ControlFlowTest, CallRel32PushesReturnAndJumps) {
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop);
    cpu_.rip = code_at(0, {0xE8, 0x40, 0x00, 0x00, 0x00});   // call rel32
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 5 + 0x40);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], kStackTop - 8);
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(), kCodeBase + 5);
}

TEST_F(X86ControlFlowTest, CallIndirectRegister) {
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop);
    cpu_.set_reg(Gpr::Rax, kCodeBase + 0x70);
    cpu_.rip = code_at(0, {0xFF, 0xD0});   // call rax
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 0x70);
    EXPECT_EQ(mem_->read_u64(kStackTop - 8).value(), kCodeBase + 2);
}

TEST_F(X86ControlFlowTest, RetPopsReturnAddress) {
    // Place a return address on the stack; RET pops it and adds imm16.
    const std::uint64_t target = kCodeBase + 0x50;
    ASSERT_TRUE(mem_->write_u64(kStackTop - 8, target).ok());
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop - 8);
    cpu_.rip = code_at(0, {0xC3});   // ret
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, target);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], kStackTop);
    // RET imm16: RSP += 16 extra after the pop.
    ASSERT_TRUE(mem_->write_u64(kStackTop - 8, target).ok());
    cpu_.set_reg(Gpr::Sp, kStackTop - 8);
    cpu_.rip = code_at(16, {0xC2, 0x10, 0x00});   // ret 0x10
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, target);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], kStackTop + 0x10);
}

TEST_F(X86ControlFlowTest, LoopTargetFaultDoesNotDecrementCounter) {
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop);
    cpu_.set_reg(Gpr::Rcx, 2);
    cpu_.rip = code_at(0xFFF0, {0xE2, 0x7F});
    const auto before = cpu_;
    const auto r = interp_->step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(cpu_.reg(Gpr::Rcx), before.reg(Gpr::Rcx));
    EXPECT_EQ(cpu_.rip, before.rip);
}

TEST_F(X86ControlFlowTest, LeaveReadFaultDoesNotReplaceRspOrRbp) {
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop);
    cpu_.set_reg(Gpr::Bp, 0x99990000);
    cpu_.rip = code_at(0, {0xC9});
    const auto before = cpu_;
    const auto r = interp_->step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(cpu_.reg(Gpr::Sp), before.reg(Gpr::Sp));
    EXPECT_EQ(cpu_.reg(Gpr::Bp), before.reg(Gpr::Bp));
    EXPECT_EQ(cpu_.rip, before.rip);
}

TEST_F(X86ControlFlowTest, CallRetRoundTrip) {
    // CALL + RET: the stack pointer returns to its start.
    // Layout: call at 0 pushes ret; the callee is a single RET at 0x40.
    code_at(0x40, {0xC3});
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop);
    cpu_.rip = code_at(0, {0xE8, 0x40 - 5, 0x00, 0x00, 0x00});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 0x40);
    const std::uint64_t sp_after_call = cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)];
    ASSERT_TRUE(interp_->step_at_rip().ok());   // executes the RET
    EXPECT_EQ(cpu_.rip, kCodeBase + 5);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], sp_after_call + 8);
    EXPECT_EQ(cpu_.gprs[static_cast<std::size_t>(Gpr::Sp)], kStackTop);
}

TEST_F(X86ControlFlowTest, RetToUnmappedFaults) {
    // Return address on the stack points at unmapped memory: typed fault,
    // with no partially committed stack adjustment.
    ASSERT_TRUE(mem_->write_u64(kStackTop - 8, 0x99990000).ok());
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, kStackTop - 8);
    cpu_.rip = code_at(0, {0xC3});
    const auto r = interp_->step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::InvalidAccess);
    EXPECT_EQ(r.fault().fault_address, 0x99990000u);
    EXPECT_EQ(cpu_.reg(Gpr::Sp), kStackTop - 8);
}

TEST_F(X86ControlFlowTest, PushBelowStackFaults) {
    // CALL with RSP = 4: the push would go below zero -> typed StackOverflow.
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, 4);
    cpu_.rip = code_at(0, {0xE8, 0x00, 0x00, 0x00, 0x00});
    const auto r = interp_->step_at_rip();
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.fault().fault, rt::exec::GuestFault::StackOverflow);
    EXPECT_EQ(cpu_.rip, kCodeBase);
}

// ── LOOP family ────────────────────────────────────────────────────────────

TEST_F(X86ControlFlowTest, LoopFamily) {
    // LOOP: decrements RCX; taken while RCX != 0 after decrement.
    cpu_.reset();
    cpu_.set_reg(Gpr::Rcx, 2);
    cpu_.rip = code_at(0, {0xE2, 0x08});   // loop rel8
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[1] & 0xFFFF'FFFF'FFFF'FFFF, 1u);
    EXPECT_EQ(cpu_.rip, kCodeBase + 2 + 0x08);   // taken (rcx 2->1)
    // rcx 1 -> 0: not taken.
    cpu_.rip = code_at(16, {0xE2, 0x08});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[1], 0u);
    EXPECT_EQ(cpu_.rip, kCodeBase + 16 + 2);
    // LOOPE: taken only when ZF=1 AND rcx-1 != 0.
    cpu_.set_reg(Gpr::Rcx, 3);
    set_flags(rt::cpu::kFlagZF, true);
    cpu_.rip = code_at(32, {0xE1, 0x08});   // loope rel8
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 32 + 2 + 0x08);
    // LOOPNE: taken when ZF=0 and rcx-1 != 0.
    cpu_.set_reg(Gpr::Rcx, 3);
    set_flags(rt::cpu::kFlagZF, false);
    cpu_.rip = code_at(48, {0xE0, 0x08});   // loopne rel8
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 48 + 2 + 0x08);
    // JRCXZ: taken when RCX == 0.
    cpu_.set_reg(Gpr::Rcx, 0);
    cpu_.rip = code_at(64, {0xE3, 0x08});   // jrcxz rel8
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 64 + 2 + 0x08);
}

TEST_F(X86ControlFlowTest, JecxzUses32BitCounter) {
    // 67h + E3 = JECXZ: uses the low 32 bits of RCX.
    cpu_.reset();
    cpu_.set_reg(Gpr::Rcx, 0x100000000ull);   // RCX != 0, ECX == 0
    cpu_.rip = code_at(0, {0x67, 0xE3, 0x08});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.rip, kCodeBase + 3 + 0x08);   // taken via ECX
}

// ── CMOVcc / SETcc ───────────────────────────────────────────────────────

TEST_F(X86ControlFlowTest, CmovccConditionalMove) {
    // CMOVE r64, r/m64: with ZF=1 RAX <- RCX; with ZF=0 untouched.
    // ModRM C8 = mod3 reg(rcx) rm(rax): cmove rcx, rax — rcx <- rax when
    // ZF=1. Swap the registers in the fixture so RAX holds the source.
    cpu_.reset();
    cpu_.set_reg(Gpr::Rax, 0x2222);    // source
    cpu_.set_reg(Gpr::Rcx, 0x1111);    // destination
    set_flags(rt::cpu::kFlagZF, true);
    cpu_.rip = code_at(0, {0x48, 0x0F, 0x44, 0xC8});   // cmove rcx, rax
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[1], 0x2222u);
    cpu_.set_reg(Gpr::Rcx, 0x1111);
    set_flags(rt::cpu::kFlagZF, false);
    cpu_.rip = code_at(16, {0x48, 0x0F, 0x44, 0xC8});
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[1], 0x1111u);   // unchanged
    EXPECT_EQ(cpu_.rip, kCodeBase + 16 + 4);
}

TEST_F(X86ControlFlowTest, CmovccFromMemory) {
    // CMOVNE rax, [rax]: reads memory only when taken? The engine reads the
    // source unconditionally (no side effects on reads).
    const std::uint64_t slot = kDataBase + 0x30;
    ASSERT_TRUE(mem_->write_u64(slot, 0x7777).ok());
    cpu_.reset();
    cpu_.set_reg(Gpr::Rax, slot);
    set_flags(rt::cpu::kFlagZF, false);   // NE true -> move happens
    cpu_.rip = code_at(0, {0x48, 0x0F, 0x45, 0x00});   // cmovne rax, [rax]
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[0], 0x7777u);
}

TEST_F(X86ControlFlowTest, SetccRegisterAndMemory) {
    // SETE al with ZF=1; SETNE al with ZF=1 (writes 0).
    cpu_.reset();
    set_flags(rt::cpu::kFlagZF, true);
    cpu_.rip = code_at(0, {0x0F, 0x94, 0xC0});   // sete al
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 1u);
    cpu_.rip = code_at(16, {0x0F, 0x95, 0xC0});   // setne al
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(cpu_.gprs[0] & 0xFF, 0u);
    // SETO byte ptr [rax] with OF=1.
    const std::uint64_t slot = kDataBase + 0x40;
    ASSERT_TRUE(mem_->write_u8(slot, 0).ok());
    cpu_.set_reg(Gpr::Rax, slot);
    set_flags(rt::cpu::kFlagOF, true);
    cpu_.rip = code_at(32, {0x0F, 0x90, 0x00});   // seto byte ptr [rax]
    ASSERT_TRUE(interp_->step_at_rip().ok());
    EXPECT_EQ(mem_->read_u8(slot).value(), 1u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
