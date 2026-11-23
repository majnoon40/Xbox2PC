# M9 binary compatibility report

The `binary-compat` command emits schema
`xbox2pc.binary-compatibility`, version 1. Each capability status is one of
`SUPPORTED`, `PARTIALLY_SUPPORTED`, `UNSUPPORTED`, `UNKNOWN`,
`NOT_TESTED`, or `INVALID`.

Status meanings:

- `SUPPORTED`: the named, narrow property was directly established.
- `PARTIALLY_SUPPORTED`: some observed cases are supported and at least one
  observed case is unsupported.
- `UNSUPPORTED`: the named property is contradicted by observed evidence.
- `UNKNOWN`: evidence is insufficient for a reliable classification.
- `NOT_TESTED`: the operation was not performed.
- `INVALID`: input failed validation for the named property.

Architecture is limited to PE32+/AMD64 identification. Xbox platform
provenance remains `UNKNOWN`; a Windows PE header is not proof of Xbox
targeting. Imports are parsed but runtime resolution remains `NOT_TESTED`.
Relocation blocks and TLS metadata are decoded by the existing M6 validators;
relocation application and callback execution are not performed. Instruction
status describes a linear decoder scan, not reachable code or a complete CFG.
Overall status deliberately remains `UNKNOWN` until Xbox-specific evidence
and runtime tests exist.

No percentages or guessed compatibility scores are emitted.
