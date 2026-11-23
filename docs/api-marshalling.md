# API Marshalling Bridge (M8)

`marshal_and_dispatch` connects guest execution to M7:
1. extract arguments per the ABI (registers + stack through guest
   memory),
2. validate pointer arguments (deref-size, in/out) — invalid guest
   pointers are typed rejects, never dereferences,
3. dispatch through the M7 `ApiRegistry` (per-process identity),
4. write the documented return state (RAX/XMM0, RSP pop) and out-buffer
   payloads through guest memory,
5. return control at the guest return address.

`plan_for_descriptor` builds marshalling plans only from an explicit
per-export signature whitelist. It covers the documented M7 signatures
plus M10 process/thread identity, partial `VirtualQuery`, and the
supported Win32 event/mutex/semaphore calls. Every entry defines its
register/stack and pointer/out-buffer layout; any API outside the
whitelist returns typed `NotFound` — layouts are never guessed.

M10 synchronization marshalling covers `CreateEventW`, `SetEvent`,
`ResetEvent`, `CreateMutexW`, `ReleaseMutex`, `CreateSemaphoreW`,
`ReleaseSemaphore` (including the optional previous-count output pointer),
`WaitForSingleObject`, and synchronization-handle `CloseHandle`.
No host function pointers are exposed to guest code; nested dispatch
depth is capped. Tests cover integer/pointer/out-buffer/error/
invalid-pointer/depth paths.

## Bounded guest handle-array marshalling

The M10 `WaitForMultipleObjects` subset uses an explicit pointer-array plan: the handle count is taken from the documented scalar parameter, capped at 64, and each 64-bit handle is read through `GuestMemory`. The bridge validates the complete guest array range before reading any element. The Win32 wrapper currently implements wait-any only; `bWaitAll=TRUE` fails closed. This does not provide scheduler-aware parking.

## Import-to-dispatch identity

The loader's `LoadDiagnostics::imports` records each resolved import's synthetic IAT value and original DLL/name-or-ordinal lookup. `ExecutionContext::prepare_entry` copies only resolved bindings into `ExecutionRequest::api_bindings`; the execution engine matches the exact landing value, looks up the verified descriptor, builds the whitelisted `MarshalPlan`, validates the guest return address, marshals through `GuestMemory`, and resumes at the saved guest return address. Binding-range values without a matching resolved import identity fail closed. GDK and Win32 bindings use separate bounded synthetic subranges; the completion sentinel is reserved and binding allocation stops before it can collide.

The engine integration is covered by a synthetic guest test that calls `XGameRuntimeInitialize` through a resolved binding and returns to guest code. This validates the API-call bridge path only; it does not imply broad Xbox API or retail-game compatibility.


## Delayed task-queue callback ABI boundary

`XTaskQueueSubmitDelayedCallback` has an explicit five-argument x64
marshalling plan (queue handle, port, delay in milliseconds, guest context,
guest callback address). This permits deterministic ABI decoding and import
inspection only. The API implementation remains unsupported: no timer,
queue-owned callback lifetime, cancellation delivery, or guest callback
invocation is provided. The descriptor must not be interpreted as evidence
that delayed callbacks execute.
