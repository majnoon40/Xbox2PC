# M11.4.3 — Guest virtual-address allocator seam

`GuestXMemAllocator` implements the internal `IXMemAllocator` contract over one committed `AddressSpace` arena. It delegates suballocation to the existing aligned first-fit `MemoryAllocator`, then converts host-buffer offsets into guest virtual addresses. Guest callers never receive host pointers.

## Contract

- The allocator reserves and commits its own arena; the `AddressSpace` must outlive the allocator.
- Returned addresses are guest VAs, aligned in guest-address coordinates.
- `query` and `free` accept exact allocation bases only; interior and stale addresses are rejected.
- Optional zero-initialization clears exactly the requested allocation size. `free(..., scrub=true)` clears the allocation before releasing it.
- Allocation metadata and byte limits are tracked; statistics expose used, capacity, allocation count, and peak usage.
- Destroying the allocator releases its entire arena reservation.

`ManagedProcess::allocate_xmem` lazily creates one allocator per process; `free_xmem`, `query_xmem`, and `xmem_stats` operate through the same process lock. The first successful allocation fixes the arena size and byte budget; later allocation requests reuse that allocator. After all guest threads have exited, process termination destroys it before releasing the address space.

This is an allocator seam, not a claim about undocumented Xbox XMem flags, heap policies, quotas, or ABI behavior. The `XMemAlloc`/`XMemFree` adapters route through this seam: the low attribute byte maps to an 8..4096 alignment (default 8), `XMemFree` requires the exact allocation base, and remaining attribute bits are ignored.
