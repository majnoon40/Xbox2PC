# M11.5 — Native-host execution slice

The first native-host backend executes a narrow class of synthetic x86-64
entrypoints directly on an x86-64 Linux host using the Microsoft x64 ABI.

## Supported boundary

- The entry VA must translate to committed guest memory with execute permission.
- Entry accepts up to four integer or small-aggregate arguments in the
  Microsoft x64 RCX/RDX/R8/R9 register positions, with integer or void returns.
  Pointer, floating-point/XMM, and stack arguments are rejected. Imports/API
  bindings and cooperative execution control are also rejected. Code must be
  position-independent with respect to the host mapping.
- The entry executes in a child process with a bounded lifetime. A host signal
  terminates that child and is reported as a guest fault; a timeout is reported
  as a budget fault.
- The returned RAX value is copied back to the parent runtime.
- Regression tests cover a normal return, an invalid-instruction host signal,
  and forced termination when the child exceeds its deadline.

## Explicit limitations

This is fault containment, not a security sandbox: the child inherits the
parent's user privileges and operating-system access. Use only trusted,
unencumbered synthetic fixtures.

## M11 Phase 5 (this branch): imports, TEB/GS, SEH, ExitProcess

- **Import ring** (ADR-0001): a shared-memory request/reply ring with
  eventfd doorbells carries every guest import call to the parent, which
  dispatches through the M7 `ApiRegistry` — the same bridge as the
  deterministic backend. No host function pointer ever enters guest
  memory. Measured ~143K calls/sec (spin-then-park host loop).
- **Thunk page**: imports land on a fixed page at the synthetic binding
  base (`mov r10, index; int3; ret`); the child's SIGTRAP handler reads
  the Microsoft x64 argument registers, performs the ring round trip,
  and fixes up RAX. IAT slots are patched parent-side (the child never
  needs write access; .text keeps its loader protection).
- **Guest stack + TEB**: the entry runs on the (rebased) guest stack
  with the completion sentinel planted as its return address; the mapped
  guest TEB is installed as the child's GS base via `arch_prctl`.
- **SEH (phase-1 dispatch)**: `RaiseException` through the ring runs
  `find_exception_handler` over the image's `.pdata`/`.xdata`; a found
  handler receives child control at the establisher frame
  (`GotoHandler` reply), and its return value becomes the run result.
- **ExitProcess**: terminate-after-reply contract; the child exits with
  the guest code, which the parent reports as the run result.
- **Structured faults**: fatal child signals classify into typed guest
  faults (SEGV/BUS -> InvalidAccess, ILL -> InvalidInstruction, FPE ->
  DivideError).
- **Flag**: everything above compiles only with
  `-DXBOX2PC_NATIVE_EXECUTION=ON` (default OFF); `xbox2pc run <file>
  --backend native` selects it. The deterministic backend is unchanged.
- **Samples**: `samples/` builds the two acceptance fixtures —
  exit-code-42 (ExitProcess ring round trip) and C++-style throw/catch
  (RaiseException + .pdata/.xdata handler). Both run through
  `xbox2pc run --backend=native`, are 100-run deterministic, and the
  suite is clean under ASan+UBSan and TSan with the flag both OFF and ON.

### Remaining limitations

The first slice does not provide compiler-generated TLS materialization
in the child, persistent guest-memory writeback accounting, instruction
tracing, or executing retail Xbox programs. Guest C++ exceptions model
as SEH `RaiseException` + unwind-handler transfer (Itanium-EH `throw`
in guest code is not interpreted). Those capabilities require later,
separately tested slices.
