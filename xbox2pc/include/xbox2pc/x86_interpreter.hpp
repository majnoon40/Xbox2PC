#pragma once
// xbox2pc/x86_interpreter.hpp — M9 instruction-semantics layer.
//
// Design (M9 §3): a semantics engine over the structured decoder
// (xbox2pc::rt::x64) that executes one decoded instruction against
// CpuState + GuestMemory with architectural effects:
//   - operand resolution (registers, immediates, every addressing mode,
//     sub-register reads/writes that merge into the full 64-bit slot),
//   - 8/16/32/64-bit widths, canonical flag updates including undefined
//     flags (left unchanged) per the SDM,
//   - typed faults, never silent fallbacks.
//
// This is a test/execution backend for the documented subset — not a
// complete x86-64 emulator (see docs/x86-64-instruction-support.md).
// Everything the decoder rejects is reported to the caller as a typed
// StepFault; RIP is never advanced after a failure.
//
// Excluded on purpose (decoder already rejects them): SIMD/AVX, x87,
// string ops, privileged/system ops, LOCK, VEX/EVEX, 3-byte maps.

#include <cstdint>
#include <string>

#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_exceptions.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/x64_decoder.hpp"

namespace xbox2pc::rt::x86 {

// ── step result ───────────────────────────────────────────────────────────
//
// ok(): the instruction executed; effects are applied to cpu and
// rip points at the next instruction (callers that need the faulting
// RIP can snapshot it before the call — step() itself never moves RIP
// on failure).
//
// fault(): typed GuestFault (InvalidAccess / PermissionRead /
// PermissionWrite / PermissionExec / InvalidInstruction /
// UnsupportedInstruction / StackOverflow / DivideError / Internal)
// with `fault_rip` = RIP of the failed instruction and
// `fault_address` set for memory faults. The CPU state is unchanged
// (all-or-nothing step) and RIP never advances on failure.
struct StepFault {
    exec::GuestFault fault = exec::GuestFault::Internal;
    std::uint64_t fault_rip = 0;      // RIP of the failed instruction
    std::uint64_t fault_address = 0;   // memory faults only (else 0)
    std::string detail;               // bounded human-readable cause
};

class StepResult {
public:
    static StepResult success() { return StepResult(true); }
    static StepResult failed(StepFault f) {
        StepResult r(false);
        r.fault_ = std::move(f);
        return r;
    }
    bool ok() const { return ok_; }
    const StepFault& fault() const { return fault_; }

private:
    explicit StepResult(bool ok) : ok_(ok) {}
    bool ok_ = false;
    StepFault fault_;
};

// ── value/operand plumbing ─────────────────────────────────────────────────

// A computed operand value: already masked to the operand's width.
struct Value {
    std::uint64_t raw = 0;    // zero-extended masked value
    std::uint8_t bits = 64;
    std::uint64_t sign_extended() const;   // only defined for bits < 64
};

// Reads one GPR at a sub-width (merges into the 64-bit slot): 32-bit
// reads zero-extend the low half; 8/16-bit reads take the low bytes,
// with the legacy rule that ids 4..7 without REX are the HIGH bytes
// (AH/CH/DH/BH). reg ids follow the decoder (0..15); a REX-present
// encoding is marked by reg >= 8 OR the explicit `rex_encoded` flag
// carried in the operand (the caller passes the Decoded's rex != 0).
std::uint64_t read_gpr(const cpu::CpuState& c, std::uint8_t reg,
                        std::uint8_t bits, bool rex_encoded = false);
// Writes one GPR at a sub-width: bits outside the operand width keep
// their old value (8/16) or are zeroed (32).
void write_gpr(cpu::CpuState& c, std::uint8_t reg, std::uint8_t bits,
               std::uint64_t value, bool rex_encoded = false);

// ── the engine ─────────────────────────────────────────────────────────────
//
// Interpreter state: the guest CPU + guest memory. All operand reads and
// writes go through GuestMemory (permission-checked, cross-region-safe).
// The engine holds no internal mutable state across steps (stateless
// beyond the references) — a failed step leaves the CPU as it was.
class Interpreter {
public:
    Interpreter(cpu::CpuState& cpu, guest::GuestMemory& mem)
        : cpu_(cpu), mem_(mem) {}

    // Executes one decoded instruction at cpu.rip. Requires the bytes at
    // [rip, rip+ins.length) to match `ins` — use decode_at_rip() to fetch
    // them (it validates exec permission like the engine loop).
    StepResult step(const x64::Decoded& ins);

    // Decodes the instruction at cpu.rip through guest memory (exec-
    // permission-checked). `fetched` receives the bytes (max 15).
    // Returns the decode result; the Decoded carries .length bytes.
    // Memory faults are reported through fault_out as typed StepFault.
    x64::DecodeResult decode_at_rip(StepFault* fault_out) const;

    // Convenience: decode_at_rip + step. This is what the execution
    // engine loop calls once per instruction.
    StepResult step_at_rip();

    // The interpreter's supported-instruction matrix (runtime mirror of
    // docs/x86-64-instruction-support.md; used by interpreter-info).
    static bool supports(x64::Mnemonic m);

private:
    cpu::CpuState& cpu_;
    guest::GuestMemory& mem_;
};

}  // namespace xbox2pc::rt::x86
