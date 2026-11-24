# M11.4.3 — Guest virtual-address allocator seam

`GuestXMemAllocator` implements the internal `IXMemAllocator` contract over one committed `AddressSpace` arena. It delegates suballocation to the existing aligned first-fit `MemoryAllocator`, then converts host-buffer offsets into guest virtual addresses. Guest callers never receive host pointers.

## Contract

- The allocator reserves and commits its own arena; the `AddressSpace` must outlive the allocator.
- Returned addresses are guest VAs, aligned in guest-address coordinates.
- `query` and `free` accept exact allocation bases only; interior and stale addresses are rejected.
- Optional zero-initialization clears exactly the requested allocation size. `free(..., scrub=true)` clears the allocation before releasing it.
- Allocation metadata and byte limits are tracked; statistics expose used, capacity, allocation count, and peak usage.
- Destroying the allocator releases its entire arena reservation.

`ManagedProcess::ensure_xmem_allocator` lazily attaches one allocator to each process. The first successful call fixes its arena size and byte budget; later calls return that same allocator. After all guest threads have exited, process termination destroys the allocator before releasing the address space.

This is an allocator seam for later XMem adapters, not a claim about undocumented Xbox XMem flags, heap policies, quotas, or ABI behavior. It is not yet connected to `XMemAlloc`/`XMemFree` imports.
