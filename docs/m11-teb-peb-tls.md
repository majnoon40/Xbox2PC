# M11.3 — Guest TEB, PEB, and TLS storage

This slice adds a deliberately small x64 Windows user-mode environment in guest
memory. It is an ABI foundation, not a complete NT process environment.

## Ownership

- `GuestProcessEnvironment` owns one PEB allocation for a process.
- Every execution context for that process must receive the same
  `shared_ptr<GuestProcessEnvironment>`.
- Each `GuestThreadEnvironment` owns its own TEB and TLS vector and borrows
  the process PEB.
- Destroying an execution context releases its TEB/TLS allocations and drops
  its PEB reference. The PEB is released when the final shared context
  reference is dropped.

A supplied process environment is checked against both the process ID and
AddressSpace identity. A mismatched environment is rejected.

## Modeled x64 offsets

| Structure | Offset | Meaning |
|---|---:|---|
| TEB | 0x30 | Self pointer (NT_TIB.Self) |
| TEB | 0x40 | ClientId.UniqueProcess |
| TEB | 0x48 | ClientId.UniqueThread |
| TEB | 0x58 | ThreadLocalStoragePointer |
| TEB | 0x60 | ProcessEnvironmentBlock |
| TEB | 0x68 | LastErrorValue (DWORD) |
| PEB | 0x10 | ImageBaseAddress |

The TLS vector contains 64 pointer-sized entries. Installing a module TLS
block copies its initialized template bytes and leaves the requested
zero-fill tail cleared. The block pointer is written into the corresponding
vector slot. Index 0 is valid for this module-vector model.

## Explicit limitations

- This is not a full TEB or PEB; unmodeled fields remain zero.
- The runtime records the guest TEB VA as the guest GS base for later native
  entry thunks. It does not change the host thread's GS base.
- The deterministic interpreter does not yet implement GS-relative memory
  operands.
- The loader retains validated PE TLS template bytes, zero-fill size, and
  the AddressOfIndex RVA. prepare_entry copies the template into a per-thread
  TLS block and writes the process-assigned module index into the image slot.
  The process environment maintains a stable image-base-to-index mapping;
  collisions receive another free slot. The registry is bounded to 64 modules
  and assignments are not recycled during that environment's lifetime.
- LastErrorValue is stored per thread at TEB+0x68. The Win32
  SetLastError/GetLastError import adapters are connected through the
  execution-context marshalling bridge and use the same guest TEB storage.
- A bounded TLS callback planner validates the callback array and executable
  targets. The explicit callback runner accepts the four documented notification
  reasons (`DLL_PROCESS_ATTACH`, `DLL_PROCESS_DETACH`, `DLL_THREAD_ATTACH`,
  and `DLL_THREAD_DETACH`) and passes the selected reason in RDX. Automatic
  process/thread lifecycle wiring and compiler-generated TLS reads remain
  incomplete. Native GS
  setup remains a later phase.
- The 64-slot vector is a current runtime limit, not a claim about the full
  Windows TLS allocation model.


### LastError API bridge

`SetLastError` and `GetLastError` are registered kernel32 imports. `ExecutionContext` binds its non-owning `GuestThreadEnvironment` pointer to the engine; the marshalling bridge forwards that same pointer to API implementations. Both APIs read/write TEB `LastErrorValue` at offset `0x68`, with no separate host-side error map. Calls without an initialized guest thread environment are rejected. The pointer is valid only during synchronous execution-context dispatch.
