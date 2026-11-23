# M9 validation results

This document is updated only from completed CI or locally captured runs.

## Current source state

The branch includes the structural validator, static instruction analyzer,
M9 binary CLI, versioned compatibility JSON, deterministic mutation harness,
and synthetic benchmark target.

## Results

No final M9 verification result is recorded yet. The newest commits must
complete the full CI matrix before the branch can be marked ready. Do not
infer success from a queued or in-progress run.

Pending gates:

- Fresh Release build and full CTest.
- Debug builds with GCC and Clang.
- ASan + UBSan.
- TSan.
- 210,000-iteration M9 decoder/PE fuzz harness.
- Existing M4–M8 fuzz and regression suites.
- Manual Release benchmark run and captured raw output.
- End-to-end synthetic M4–M9 lifecycle and cleanup checks.

`REAL_XBOX_EXECUTABLE_TESTED: NO`

`GTA_VI_COMPATIBILITY: NOT_VERIFIED`
