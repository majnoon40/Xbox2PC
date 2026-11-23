# M9 validation results

This document records evidence from completed CI runs only. It is not a claim that every M9 exit criterion is complete.

## Latest recorded CI run

Commit: `5e685e1cd8bed5484c6a382746a43a47b13791da`
Run: [GitHub Actions 45172979802](https://github.com/majnoon40/Xbox2PC/actions/runs/45172979802)

Completed successfully:

- Debug GCC build and all 25 CTest tests.
- Release GCC build and all 25 CTest tests.
- Debug Clang build and all 25 CTest tests.
- Release Clang build and all 25 CTest tests.
- Release GCC M9 synthetic benchmark step.
- CTest includes the M9 CLI integration test, M9 fuzz test, binary-validation test, and static-analysis test.
- The M9 fuzz test completed 200,000 decoder mutations and 10,000 synthetic-PE mutation iterations.

Captured Release GCC synthetic benchmark output on the GitHub-hosted `ubuntu-24.04` runner:

- Decoder: 44.191 ns/instruction (2,000,000 / 2,000,000 decoded).
- Structural PE validation: 1.293 us/file (10,000 / 10,000 structurally valid).
- Static analysis: 814.180 us/file (2,551 confirmed decodes/file).

ASan + UBSan and TSan jobs were still in progress when this document was updated. Their outcomes must be recorded only after completion.

## Remaining verification gates

- TSan result for the latest source commit.
- Adversarial source audit and regression tests for any reproducible defects.
- Confirm the existing M4-M8 benchmark outputs if they are to be included in the M9 performance report.
- Review the existing `ExecE2eTest.VfsPackageLoadResolveExecuteCleanup` integration test for missing failure/cleanup branches and add any justified cases.
- Final PR review and documentation consistency check.

`REAL_XBOX_EXECUTABLE_TESTED: NO`

`GTA_VI_COMPATIBILITY: NOT_VERIFIED`
