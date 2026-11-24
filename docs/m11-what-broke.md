# M11: What broke before the native-execution slice

This report records repository-verifiable compatibility gaps carried into M11. It is intentionally not a claim that every historical M1–M10 defect has been reconstructed: the M11 baseline audit is pinned to M10 merge commit 5dcda95b2620530c89ad0cb1ebb250cbae078cf4, and the findings below are limited to source behavior and tests inspected at that baseline or explicit follow-up changes on the M11 branch.

## Verified gaps and their consequences

| Area | Verified baseline behavior | Consequence for M11 | Status / evidence |
|---|---|---|---|
| PE execution | The available execution backend was interpreter-oriented; no in-process native x64 entry path was present. | Real compiler-generated PE code using normal x64 instructions and Windows ABI behavior could not be treated as runnable. | Open: M11 Phase 5. See docs/m11-baseline-audit.md §1 and the execution-engine source map. |
| Host ABI boundary | Guest API argument marshalling and guest-memory validation existed, but there was no native host-call thunk path. | Existing API metadata was not enough to safely transfer control from native guest code into host implementations. | Open: Phase 5. Preserve the M8 bridge and add tested Microsoft x64 ABI thunks. |
| Process/thread environment | The baseline did not provide a Windows TEB/PEB, guest GS base, or implicit TLS lifecycle. | Code relying on thread identity, last-error storage, TLS slots, or GS-relative access could not run correctly. | Partial: M11 added minimal TEB/PEB and per-thread TLS storage. Guest GS installation, full layout, TLS-directory integration and automatic callbacks remain open. |
| Handle ownership | M4 had generation-checked per-process handles, but task queues used a separate guest token namespace and generic CloseHandle coverage was incomplete. | Cross-service handle collisions, stale-token behavior and consistent close dispatch were not yet proven. | Partial/open: task queues have since moved into the process handle table, but complete object-type dispatch and required stale/cross-process tests remain open. |
| Process termination | Exit observers originally ran while holding the ProcessManager lock; blocked queue dispatch could prevent process termination from completing. | Observer re-entry could deadlock, and an idle infinite queue wait could keep a terminating process alive. | Improved on M11: observers now run unlocked and unregister drains active calls; queue dispatch observes cooperative cancellation in bounded 2 ms intervals. Current CI and TSAN stress evidence still required. |
| Global lock ordering | There was no repository-wide lock-order contract or complete adversarial lock-order test suite. | Fixing one observer deadlock does not prove manager/service interactions are deadlock-free. | Open: Phase 7 global lock-order audit and tests. |
| Large PE images | The baseline relocation path retained relocation entries and linearly searched sections while applying them. | Images with hundreds of thousands of relocations could have excessive memory use and poor scaling. | Open: benchmark and optimize only with measured evidence; do not infer scalability from small fixtures. |
| Platform providers | The baseline did not establish production graphics, audio, storage or networking providers. | API recognition or a synthetic import stub must not be reported as subsystem compatibility. | Explicit boundary: graphics roadmap only; graphics/audio/storage/networking remain stubbed or unsupported as listed in docs/api-compat.md. |

## M11 follow-up corrections

- Process-exit observers were moved out of the ProcessManager critical section. Observer removal prevents future snapshots and waits for active callbacks.
- Manual task-queue dispatch now checks the managed execution cancellation predicate during bounded wait slices. This is polling, not a registered cancellation waker.
- TLS callback planning now fails atomically if any non-null callback target is not executable mapped guest memory. This prevents silently running only a subset of a module's callback array.
- `kernel32!SetLastError` and `kernel32!GetLastError` now read/write the calling guest thread's TEB-backed last-error slot through `ApiContext`; calls without that thread environment are rejected.

These changes address specific failure modes; none proves the corresponding M11 phase complete by itself.

## Explicit non-claims

- No retail game compatibility is claimed.
- No undocumented Xbox syscall, structure layout, or retail binary behavior is inferred.
- No graphics/audio/storage/networking functionality is claimed from API names, registration, or placeholder objects.
- The 100-run deterministic requirement and full ASan/UBSan/TSan acceptance criteria remain required before M11 is complete.

## Source of truth

Use docs/m11-baseline-audit.md for the detailed source-level audit and pinned baseline source map. Use the M11 checklist in PR #15 for completion tracking. This report should be expanded only when a historical failure can be tied to a concrete commit, regression test, or source location.