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
