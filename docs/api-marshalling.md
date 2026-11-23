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
