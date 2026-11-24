# M11.5.1 — Native-host execution smoke slice

## Implemented

`NativeHostBackend` is an explicitly opted-in, Linux x86-64 in-process
backend for a very narrow trusted-code smoke test. Its SysV-to-Windows-x64
call thunk reserves the required 32-byte shadow area and enters the mapped
guest executable page with correct x64 call alignment. The regression test
runs a position-independent `mov eax, 42; ret` byte sequence from an
`AddressSpace` region protected RX and verifies RAX / return completion.

## Deliberate exclusions

This is not a sandbox and must only run trusted synthetic code. It has no
fault isolation: a bad native instruction can fault the host process. It
does not yet support imported APIs, guest pointer arguments, stack arguments,
XMM arguments, GS/TEB/PEB setup, implicit TLS, SEH/unwinding, or mid-call
cancellation. The backend rejects requests with resolved imports and does
not claim general PE compatibility. The interpreter remains the default and
the test oracle.

## Next native slices

1. Add guest fault capture with a narrowly scoped host signal/exception
   boundary and tests for illegal instruction / access faults.
2. Add Windows x64 argument and return marshalling, including shadow space,
   stack arguments, and XMM registers.
3. Provide a native guest-address mapping strategy or relocation-aware
   pointer translation so absolute guest VAs refer to the correct host
   mapping.
4. Install a host GS base pointing at a native TEB view whose PEB and TLS
   vector pointers are host-valid; preserve and restore host thread state.
5. Add native TLS callback and C++ unwind coverage only after those
   foundations are in place.
