# Guest Exceptions (M8)

`GuestException` records: fault code (`invalid-access`,
`permission-read/write/exec`, `invalid-instruction`,
`unsupported-instruction`, `stack-overflow`, `invalid-state`,
`marshal-failure`, `guest-terminated`, `budget-exceeded`, `internal`),
guest RIP, access type, faulting guest VA, process/thread identity,
recoverability (Recoverable = context reusable / Fatal = destroy),
and bounded diagnostics (`clamp_detail`). Guest exceptions NEVER
silently convert to successful returns — outcomes are Returned/
Completed/Interrupted/Terminated or Faulted-with-record. A failure in
one context cannot corrupt others (per-context state, no global mutable
guest state). Resource limits (stack, contexts, callbacks, dispatch
depth, guest-op size, instruction budget, diagnostic cap) are
`ExecutionConfig`-validated and enforced at each layer.
