# Guest Memory Access (M8)

`GuestMemory` wraps an M4 `AddressSpace`:
- typed u8–u64 + range reads/writes; every access = region lookup +
  permission validation, page-wise `translate()` copies (no unchecked
  host pointer arithmetic; no arbitrary guest→host conversion).
- overflow-safe bounds (`va+len-1` checks), 1 MiB per-op cap.
- typed distinction: `InvalidAddress` (unmapped) vs
  `PermissionDenied` (mapped, wrong protection) vs `Overflow`/
  `TooLarge`/`CrossRegion`/`NullPointer`.
- single-region operations only; boundary walks at page granularity.
- bounded `read_cstr` (no unbounded allocation from guest sizes).
- W^X preserved: writes need RW/Full, execution needs RX/Full; the
  layer never flips protections. Tested adversarially (RX write and
  RW execute both refused).
