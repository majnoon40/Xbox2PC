# M9 — Repository Audit and Architecture Assessment

**Status: assessment only. Written before any M9 source change (M9 §2).**
Branch `feature/m9-execution-validation`, created from `feature/m8-execution-context` @ `12b144e` (verified with `git rev-parse`).

## 1. Repository state (verified, not assumed)

| Item | Observed |
| --- | --- |
| Starting branch / tip | `feature/m8-execution-context` @ `12b144e` ("M8: documentation") |
| `main` | not checked out, not modified |
| Remote | **none configured** (`git remote -v` prints nothing; `gh` is not installed) |
| Milestone commits present | M2 ×1, M3 ×10, M4 ×8, M5 ×9, M6 ×3, M7 ×4, M8 ×8 (M1 predates the tagged history) |
| gtest cases on the tree | 258 `TEST*` macros in 8 files (M8 `architecture.md` says 277 — wrong, corrected in M9) |
| ctest targets | 12 (8 unit suites + 3 fuzz suites + 1 bench) |

Because no remote exists, M9 cannot be pushed. The branch is left push-ready (fast-forwardable onto `12b144e`, no history rewrite, no merge), and the delivery report says so instead of claiming a push or a PR.

## 2. What M1–M8 already provide (inventory before adding anything)

| Milestone | Libraries | Public surface reused by M9 |
| --- | --- | --- |
| M1 PE32+ parser | `xbox2pc_pe_parser`, `xbox2pc_diagnostics`, `xbox2pc_json` | `pe::PeImage` (headers, sections, imports, delay imports, exports, relocs, TLS dir, exceptions), typed `ParseError` |
| M2 dependency analysis | `xbox2pc_dep_analyzer`, `xbox2pc_dep_graph` | `DependencyReport`, `FunctionImport`, edges, classification |
| M3 API registry + compat DB | `xbox2pc_api_registry`, `xbox2pc_compat_db`, `xbox2pc_rt_compat_report` | `ApiRegistry` (descriptors, evidence, dispatch), `CompatibilityDb`, `CompatReport` |
| M4 runtime core | `rt_error`, `rt_pal`, `rt_object`, `rt_handles`, `rt_sync`, `rt_thread`, `rt_io`, `rt_process`, `rt_services`, `rt_memory`, `rt_procman` | `Result<T>`, `AddressSpace` (reserve/commit/protect/translate/validate_access), `ManagedProcess`, handle tables, service registry |
| M5 VFS + packages | `rt_vfs`, `rt_vfs_backends`, `rt_package`, `rt_package_vfs`, `rt_vfs_process` | mounts, package (XVC/XPK) reading, asset discovery, per-process VFS |
| M6 loader | `rt_loader` | `ImageLoader::load_image`, `LoadResult`/`ExecDescription`, `LoadDiagnostics.imports` (`ImportBinding`), `decode_tls`, relocations, IAT writes |
| M7 runtime services | `rt_api`, `rt_gdk` | 16 documented API descriptors, `ApiContext`/`ApiCallResult`, `ApiResolver` (binding values `0x51000000+id`), `GameRuntimeService`, `TaskQueueService`, `TimingService` |
| M8 execution foundation | `rt_cpu`, `rt_abi`, `rt_guestmem`, `rt_exceptions`, `rt_execution` | `CpuState`, `CallSpec`/`prepare_call`/`extract_args`/`write_return`/`check_preserved`, `GuestMemory`, `GuestException`, `IExecutionEngine`, `DeterministicBackend`, `ExecutionContext`, TLS callback planning |

CLI already exposes `inspect`, `validate-pe`, `graph`, `dependencies`, `classify`, `map-image`, `load-image`, `imports`, `relocations`, `image-info`, `unload-image`, `mount`/`unmount`, `packages`, `discover`, `stat`, `read`, `list`, `api-list`, `api-info`, `api-status`, `dispatch-test`, `compat-report`, `gdk-services`, `gameos-services`, `runtime-*`, `memory-*`, `process-info`, `thread-info`, `handle-info`, `resource-info`, `cpu-state`, `abi-info`, `execution-info`, `tls-info`, `execute-test`. M9 preserves every one of them.

The M8 interpreter is an inline `switch` over raw bytes (`src/execution_engine.cpp`, `run()`): it recognises 15 instruction forms, reads operands one byte at a time through `GuestMemory`, and has no decoder data structure that anything else can reuse.

## 3. Audit findings (honest gaps in shipped M1–M8 behaviour)

These are real defects or overstatements found by reading the M8 code. M9 fixes them in new commits (M1–M8 history is untouched) and reports them in the delivery report.

| # | Finding | Evidence | M9 action |
| --- | --- | --- | --- |
| A1 | Landing on an API binding value always faults: the engine never calls `marshal_and_dispatch`; `ExecutionResult::api_calls` is never incremented. The header and `docs/execution-engine.md` describe the bridge as wired into execution. | `src/execution_engine.cpp` `run()`: `is_api_binding(rip)` branch → `InvalidState "API binding hit with no marshal plan bound"`; no assignment to `api_calls` anywhere in `src/` | Binding-value → plan table carried by the request; engine dispatches through the bridge and resumes at the guest return address (commit 4/8) |
| A2 | Bridge writes `out_value` (a byte count) as a `u64` into the first out pointer. For the device-id/sandbox-id APIs that pointer is the string buffer, so the guest never receives the string. | `src/execution_engine.cpp` `marshal_and_dispatch`: `mem.write_u64(args[idx].ptr_va, api_res.out_value)`; `src/gdk_services.cpp` sets `out_value = size` | Additive `out_bytes` payload on `ApiCallResult`; bridge copies bytes to the buffer and the length to the `used` pointer (commit 8) |
| A3 | `ContextLimiter::acquire()` is never called; the destructor calls `release()`, so the live-context counter underflows on the first destroyed context. | `src/execution_context.cpp:43` (release), `:65` (destructor), no call site for `acquire()` | Acquire in the constructor, cap enforced (commit 8) |
| A4 | `0x90` is treated as NOP even when a REX prefix is present; `41 90` is `XCHG r8, rax`. | `run()` `case 0x90` | Structured decoder encodes `90+r` as `XCHG` (commit 2/5) |
| A5 | TLS callback VAs in the M8 tests were preferred-base addresses that are not valid after mapping, so `plan_tls_callbacks` rejected them and no callback ever executed, while the doc reports the scheduling path as exercised. | `plan_tls_callbacks` validates `cb.va` with `validate_exec`; M8 test images carry no relocation for the callback array | Verified by a new test that actually executes a relocated callback; docs corrected (commit 8/14) |
| A6 | `execute-test` prints "teardown: regions after terminate" using statistics captured **before** terminate. | `tools/xbox2pc_cli.cpp:2759` | Captured after terminate; label corrected (commit 12) |
| A7 | `docs/architecture.md` claims 277 passing tests and "ASan+UBSan"; the tree has 258 gtest cases and the M8 ASan build used `-fsanitize=address` only. | `docs/architecture.md:3` | Numbers recomputed; M9 quality gate runs address **and** undefined-behavior sanitizers (commit 14/15) |
| A8 | No structured decoder, no instruction matrix, no binary-validation, static-analysis, compatibility-report, corpus, or differential-testing component exists. Everything in M9 §3–§16 is new. | tree | This assessment defines their boundaries below |

## 4. M9 architecture (what will be added and how it layers)

```
                    tools/xbox2pc_cli.cpp  (+ tools/m9_cli.cpp)
      ┌───────────────┬───────────────┬──────────────┬──────────────┐
      │               │               │              │              │
 rt_binary_validation  rt_static_analysis   rt_compat_readiness   rt_execution (M8)
      │               │               │              │              │
      │               └──────┬────────┘              │              │
      │                      │                       │              │
 xbox2pc_pe_parser (M1)   rt_x64_decoder  ───────────┴──────────────┘
                          (pure, no runtime deps)
```

**New components**

1. `xbox2pc_rt_x64_decoder` — `include/xbox2pc/x64_decoder.hpp`, `src/x64_decoder.cpp`. A pure function `x64::decode(bytes, len, rip) -> DecodeResult` with no dependency on the runtime or on guest memory. It parses legacy prefixes, REX (last-prefix-32 rule), one-byte and `0F` maps, ModRM/SIB, displacements and immediates at 8/16/32/64-bit widths, enforces the 15-byte instruction limit and the 32-bit address-size rule, and returns a typed reject for every encoding it does not accept: `Truncated`, `InvalidEncoding` (never a valid x86-64 instruction), `UnsupportedEncoding` (valid, deliberately not interpreted). Unknown bytes are never decoded as NOP.
2. Interpreter semantics — `src/x86_interpreter.cpp` inside `rt_execution`. Consumes `Decoded`, computes effective addresses, performs all memory access through `GuestMemory`, updates flags only where the architecture defines them, and raises `GuestException` with RIP left at the faulting instruction. `IExecutionEngine` is unchanged; `DeterministicBackend` keeps its `engine_kind() == "deterministic-test"` label and remains described as an interpreter for a documented subset.
3. `xbox2pc_rt_static_analysis` — conservative recursive-descent disassembly from declared entry points; every byte is classified `Confirmed`, `Candidate`, `Data`, `Unknown` or `Invalid`.
4. `xbox2pc_rt_binary_validation` — staged validation of a user-supplied file (identification → PE structure → imports → relocations → TLS → memory layout → execution compatibility), each stage returning a structured result.
5. `xbox2pc_rt_compat_readiness` — builds `binary-compatibility.json` with distinct readiness states; no single score.
6. Differential testing — a test-only harness that runs decoder-accepted instructions on the host CPU in a sealed arena and compares GPRs, RFLAGS, RIP, memory and stack with the interpreter. The reference shares no decoder or arithmetic helper with the interpreter.
7. Synthetic corpus + generator tool, end-to-end campaign, 11 CLI commands, 13 fuzz harnesses, benchmarks, 8 documents.

**Changed M8 code (additive or corrective only):** `CpuState` gains sub-register read/write helpers; `GuestMemory` gains a page-wise instruction fetch; `GuestFault` gains append-only codes (`DivideError`, `AlignmentFault`); `ApiCallResult` gains `out_bytes`; `ExecutionRequest` gains the binding→plan table; `ExecutionContext` acquires its limiter slot; `execution_engine.cpp` `run()`/`single_step()` are re-based on the decoder.

**Not added:** YMM/ZMM storage, VEX/EVEX decoding, x87 execution, LOCK'd atomics, string instructions, any Xbox API beyond the 16 documented M7 descriptors, and anything that touches DRM, encryption or signatures.

## 5. Constraints carried through M9

- No game executable is available or assumed. Every fixture is synthetic (built by `PeBuilder`) or public; results are never described as real-game validation. The real GTA VI gate stays **NOT YET VERIFIED**.
- Recognition of an API never implies implementation; unknown imports stay unresolved.
- No history rewrite, no force-push, no merge; `main` untouched.
