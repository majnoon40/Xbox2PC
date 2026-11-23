# Execution Architecture (M8)

**Status: M8 complete.** The execution foundation connects M1–M7 into a
path from *prepared executable* to *executing guest instructions*: a
guest CPU state model, the Xbox x64 ABI, safe guest memory access, the
M7→M8 API marshalling bridge, an execution-engine interface with a
working deterministic backend, per-thread execution contexts with full
lifecycle, M6 loader integration, TLS callback scheduling, structured
guest exceptions, and enforced resource limits.

**It does NOT claim general x86-64 emulation or Xbox-title
compatibility** — the backend executes a documented instruction subset
and everything else is reported honestly.

## Libraries and dependency direction

```
rt_cpu (guest state)        -> rt_error
rt_abi (x64 ABI)            -> rt_cpu
rt_guestmem (guest memory)  -> rt_memory (M4)
rt_exceptions               -> rt_error
rt_execution (engine+bridge+context+TLS)
    -> rt_cpu, rt_abi, rt_guestmem, rt_exceptions, rt_api (M7),
       rt_loader (M6)
CLI -> all of the above
```

No library links upward into M6/M7 from below them; no global mutable
guest state (the engine binds per-run; contexts own their CPU state;
the only global is an atomic context counter).

## The execution contract

- **Entry point**: M6 `ExecDescription.entry_va`, validated inside the
  mapped image extent AND executable (RX/Full) via
  `validate_entry_point`.
- **Initial CPU state**: deterministic `CpuState::reset()` + ABI frame
  prepared on the context's in-space stack (RW, config-capped,
  16-aligned top [MS-X64STACK]).
- **Return address**: the *completion sentinel* (`0x5100FFFF`) — the
  engine's `RET` on the sentinel yields `Outcome::Returned` with RAX
  as the result. (Fixed during bring-up: capturing pre-call RIP made
  the first RET fault at 0.)
- **Imported APIs**: a guest `CALL` landing on an M7 binding value
  (`0x5100xxxx`) enters `marshal_and_dispatch` — arguments extracted
  per the ABI, pointers validated through guest memory, M7 registry
  dispatch, documented return state written back (RAX/XMM0, RSP pop),
  control returns to the engine at the guest return address. No host
  function pointers are ever exposed to guest code.
- **Termination**: context destroy (releases the stack region),
  image unload, process terminate — the e2e test verifies zero leaked
  regions and handles.

## Components (per-component docs)

- [guest-cpu-state.md](guest-cpu-state.md) — registers, RFLAGS,
  snapshot/serialization, validation.
- [xbox-x64-abi.md](xbox-x64-abi.md) — documented ABI + evidence.
- [guest-memory.md](guest-memory.md) — safe access over M4.
- [api-marshalling.md](api-marshalling.md) — the bridge.
- [execution-engine.md](execution-engine.md) — interface + backend.
- [guest-exceptions.md](guest-exceptions.md) — fault model.
- [tls-execution.md](tls-execution.md) — callback scheduling.

## Test/quality posture

24 execution tests + 7 fuzz harnesses (170,400 mutations) + 9
benchmarks; full suite (12 targets) green under ASan+UBSan, TSan, and a
fresh Release build; M1–M7 regressions green. Three real bugs were
found by the tests and fixed (RFLAGS mask bit 1; ABI callee-relative
frame writes; write_return Void strictness) — details in the component
docs.
