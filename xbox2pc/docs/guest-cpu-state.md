# Guest CPU State (M8)

**Status: implemented.** `xbox2pc_rt_cpu` (`guest_cpu_state.hpp/.cpp`)
models platform-independent x86-64 guest CPU state for the execution
subsystem. Storage is state only — **instruction-set support is a
property of the execution backend, not of this model** (see
[execution-engine.md](execution-engine.md) for what the deterministic
backend actually decodes).

## Registers

`CpuState` (POD-backed, deterministic, no uninitialized fields):

- GPRs: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8–R15 (16 × 64-bit).
- RIP (64-bit).
- RFLAGS (see below).
- XMM0–XMM15 (16 × 128-bit) — storage only. **YMM/ZMM are NOT
  modeled**: no backend in M8 uses them, and storage alone must not
  imply AVX/AVX2/AVX-512 support (spec rule). The representation is
  extensible (fixed-size arrays with versioned serialization) so a
  future backend can widen it deliberately.
- MXCSR (32-bit, documented standard init `0x1F80` — masks set,
  round-to-nearest, no FTZ [MS-X64CC]).
- x87 control word FCW (16-bit, documented init from the FPCSR table:
  exception masks all 1s, precision control = double (`10B`), round to
  nearest → `0x027F` [MS-X64CC]). x87 state is modeled for context
  completeness only; no FP instructions are executed by any M8 backend.

Deterministic initialization (documented): all GPRs/RSI/RIP = 0;
RFLAGS = `0x202` (bit 1 is the documented always-1 reserved bit;
IF=1 — implementation convention, marked unverified beyond those bits);
MXCSR = `0x1F80`, FCW = `0x027F` (documented standard values).
`reset()` returns to exactly this state; `validate()` rejects
non-canonical states (see below).

## RFLAGS representation

Documented bit positions (cited from the x64 architecture manuals as
used by [MS-X64CC]): CF=0, bit1=1 fixed, PF=2, AF=4, ZF=6, SF=7,
TF=8, IF=9, DF=10, OF=11; bits 3/5/12–31 reserved (stored as
whatever is set, but `canonical()` requires reserved bits zero except
bit 1); upper 32 bits zero. Helpers expose CF/PF/AF/ZF/SF/TF/IF/DF/OF.

## Access, snapshot, restore, validation

- `reg(Gpr)` / `set_reg(Gpr, u64)` — explicit, bounds-checked by enum.
- `snapshot()` → `CpuSnapshot` (independent copy: all GPRs, RIP,
  RFLAGS, XMM, MXCSR, FCW). `restore(snapshot)` is exact and refuses
  a snapshot that fails `validate()` on the CPU invariants (see
  below). Snapshots are value types — safe to copy, compare
  (`operator==`), and serialize.
- `serialize()` / `CpuSnapshot::deserialize` — stable diagnostics
  format: magic `X2PCSNAP`, version 1, fixed little-endian field order
  (RAX..R15, RIP, RFLAGS, MXCSR, FCW, XMM0..15). Round-trip is tested.
- `validate()` invariants: RSP 8-byte aligned and non-overflowing
  (> 4096, below `2^63`); RIP not zero; RFLAGS reserved bits clean;
  XMM/MXCSR/FCW untouched (any bit pattern allowed by the formats).
  Context validation composes this with process/thread checks.

## What is NOT claimed

- No AVX/AVX-512 state or support (storage doesn't exist and isn't
  claimed).
- No x87/MMX execution (FCW is stored only).
- No lazy/deferred state saves, no XSAVE area modeling — a real
  backend needing XSAVE layouts extends this model deliberately.
