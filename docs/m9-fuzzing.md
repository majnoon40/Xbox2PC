# M9 fuzzing plan and coverage

The branch adds a reproducible deterministic harness with fixed seeds:

- 200,000 arbitrary byte sequences through the x86-64 decoder, checking
  status/length/consumed-byte invariants.
- 10,000 mutated synthetic PE files through the PE parser, structural
  validator, and static analyzer, accepting typed parse rejections.

Existing repository harnesses additionally exercise loader PE headers,
relocation blocks, imports, TLS, mapping/unmapping, CPU state, ABI layouts,
guest memory ranges, execution requests, marshalling plans, API descriptors,
dispatch, delay-load metadata, and concurrent registry paths.

The M9 fuzz executable is part of CTest. Counts in source are configured
mutation counts, not proof of execution. Record actual run results from CI
before declaring a campaign complete. Sanitizer builds should run the same
CTest suite; longer campaigns can be repeated under ASan/UBSan and TSan.
