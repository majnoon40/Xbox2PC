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

`plan_for_descriptor` builds marshalling plans only for explicitly listed,
evidence-backed signatures. The M10 list includes the M7 GDK calls plus
process/thread identity, VirtualQuery, and the currently supported Win32
event calls. Any other API is a typed `NotFound`; layouts are never guessed. No host function pointers are exposed to guest code; nested
dispatch depth is capped. Tests cover integer/pointer/out-buffer/
error/invalid-pointer/depth paths.
