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
  TLS block and writes the caller-supplied module index into the image slot.
  A process-wide module-index allocator is not implemented yet.
- TLS callback execution and compiler-generated TLS reads are not claimed to
  work end to end; native GS setup remains a later phase.
- The 64-slot vector is a current runtime limit, not a claim about the full
  Windows TLS allocation model.
