# M9 adversarial audit checklist

The M9 review checklist covers:

- Decoder: prefix/REX precedence, the 15-byte limit, truncation accounting,
  invalid versus unsupported classification, ModRM/SIB addressing, and
  operand-width metadata.
- Interpreter: partial-register writes, flag definedness, divide faults,
  memory permission faults, stack boundaries, and all-or-nothing failure.
- PE: parser exceptions, section raw/virtual bounds, overlap, entry-point
  containment, data-directory ranges, relocation block sizes/types/targets,
  import thunk bounds, TLS template and callback bounds.
- Static analysis: no CFG/reachability claims, bounded output, executable
  file-backed sections only, unsupported-byte evidence, invalid-encoding
  candidates, and truncated-tail uncertainty.
- Runtime: cleanup after failed map/load, W^X transitions, ABI stack/shadow
  space, guest pointer validation, and API marshalling failure paths.

This document is the audit checklist, not a claim that every item has been
reproduced or independently verified. Findings and fixes must cite a test or
a concrete source location in the final audit report.


## Source-audit findings (2026-11-23)

The following defects were reproduced by source-path analysis and corrected on
this branch. Their regression tests are committed; the tests still require a
green workflow on the resulting head commit before these fixes are considered
CI-verified.

1. **High — malformed executable sections could bypass the analysis work cap.**
   The original cap counted only successful decoder results. Unsupported and
   invalid encodings advanced the scan without incrementing that counter, so
   a hostile executable section could force work and report growth proportional
   to its full file-backed size. The cap now counts every decode attempt and
   marks the unscanned tail as uncertain. A regression test feeds more than
   one million unsupported EVEX-prefix bytes and checks that the cap is reached.

2. **Medium — metadata-only CLI commands performed unnecessary instruction
   analysis.** Commands such as `binary-info`, `binary-sections`, and
   `binary-imports` previously ran the full linear scan even though they did
   not emit its results. The CLI now runs static analysis only for
   `binary-analyze`, `binary-instructions`, `binary-compat`, and
   `binary-report`. Structural validation remains separate.

3. **High — decoder 15-byte boundary was off by one.** The prefix loop rejected
   an opcode at byte 15, despite the architectural maximum being 15 bytes.
   The byte-requirement helper also preferred “truncated” when an instruction
   could no longer fit within the 15-byte maximum. The decoder now permits a
   final-byte opcode, rejects a 16th byte, and prioritizes the architectural
   length violation over buffer truncation. Regression tests cover a 15-byte
   instruction, a 16-byte instruction, a 15-byte prefix-only stream, and an
   opcode at byte 15 that still requires a ModRM byte.

### Existing regression coverage reviewed

The repository already contains directed tests for PE section/header overlap,
out-of-image directories, malformed relocation blocks, TLS pointer/template
bounds, loader rollback and cleanup, W^X degradation, interpreter divide
faults and overflow, partial-register behavior, stack/branch faults, memory
bit-string indexing, ABI shadow space, register/stack argument allocation,
and nested guest calls. These existing tests are part of the project test
suite; this audit does not claim they were newly authored here.

### Verification status

The complete CI run for the pre-audit head
`5e685e1cd8bed5484c6a382746a43a47b13791da` completed successfully across
Debug GCC, Release GCC, Debug Clang, Release Clang, ASan+UBSan, and TSan.
The fixes above were committed afterward. Their workflow must complete on the
latest branch head before this audit can be marked fully verified.

`REAL_XBOX_EXECUTABLE_TESTED: NO`

`GTA_VI_COMPATIBILITY: NOT_VERIFIED`


4. **High — inconsistent PE data-directory RVA/size pairs could be treated as
   absent directories.** A nonzero RVA with zero size was silently skipped by
   the M6 pre-validation path; a zero RVA with nonzero size could be interpreted
   as a header-relative directory. The M9 validator now rejects mismatched
   pairs across the directory table, marks the corresponding import,
   relocation, or TLS stage invalid, and the compatibility report propagates an
   invalid import stage as `INVALID`. Directed tests cover regular imports,
   delay imports, relocations, and TLS, including both mismatch directions.



5. **Medium — ABI argument extraction did not bound the callee stack frame
   before adding the return-address, shadow-space, and stack-argument offsets
   to guest RSP.** A hostile near-maximum RSP could wrap a stack-argument
   address. Extraction now computes the complete frame size and rejects an
   overflowing range before invoking the stack reader. A regression test
   verifies that an overflowing frame is rejected without any stack read.



6. **Critical — API out-payload size was trusted when reading a fixed-capacity
   host array.** `ApiCallResult::out_bytes` is capped at 256 bytes, but an
   extensible API implementation could report a larger `out_bytes_size`.
   The bridge previously passed the larger size to the guest-memory writer,
   which could read beyond the host array. It now rejects oversized payloads
   before touching guest return state or reading the payload. A regression
   test registers a deliberately oversized implementation and verifies that
   dispatch fails without changing guest RSP/RAX.



7. **Medium — ABI call preparation changed GP/XMM registers before all stack
   writes had succeeded.** A stack-writer failure could therefore return an
   error with partially updated caller CPU state. Register updates are now
   staged in a CPU-state copy and committed only after stack arguments and the
   return-address write succeed. A regression test forces a stack-writer
   failure and checks that GP, XMM, RIP, and RFLAGS remain unchanged. Stack
   bytes already written by an arbitrary failing callback cannot be rolled
   back by the current `StackWriter` interface; they remain below the
   unmodified caller RSP and are not made the active call frame.

