# TLS Execution (M8)

Builds on M7's template initialization:
- `plan_tls_callbacks` reads the callback VA array from the MAPPED
  image through guest memory, bounds-checks the count against the
  config limit, validates every VA lands in an executable region,
  preserves order, and rejects the entire plan if any callback VA is
  unreadable or not executable. It never silently skips a malformed entry.
- `execute_tls_callbacks` invokes each through the ENGINE ONLY (the
  documented callback ABI: RCX=DllHandle, RDX=Reason
  DLL_PROCESS_ATTACH=1, R8=Reserved) — never host pointers. Failures
  are REPORTED per callback; callers must perform lifecycle cleanup after
  partial initialization. Recursion is impossible by construction
  (single pass, no re-entrancy).
- The builder's synthetic callback VAs are preferred-base values
  that relocation does not fix up — validation rejects them honestly
  (tested) rather than executing at stale addresses.
