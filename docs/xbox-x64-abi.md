# Xbox x64 ABI (M8)

Models the Microsoft x64 calling convention from the opened reference
pages. Evidence tags (full URLs live in the header comments and the
descriptor table):

- **[MS-X64CC]** x64 calling convention:
  RCX/RDX/R8/R9 for integer/pointer args 1–4 (left-to-right); XMM0–3
  for FP args 1–4 *by position*; args 5+ on the stack, 8-byte slots;
  32-byte shadow space always reserved by the caller; aggregates of
  1/2/4/8 bytes pass like integers, larger ones by pointer; `__m128`
  always by pointer; varargs duplicate FP values into GP registers;
  returns: ≤64-bit scalars in RAX, FP/`__m128` in XMM0, larger
  aggregates via a hidden pointer in RCX returned in RAX; volatile
  RAX RCX RDX R8–R11 XMM0–5, nonvolatile RBX RBP RDI RSI R12–R15
  XMM6–15; MXCSR standard init 0x1F80, FPCSR 0x027F.
- **[MS-X64STACK]** stack usage: 16-byte alignment; return address at
  [RSP] on entry; the parameter home area sits above the return
  address; memory below RSP is volatile.

**Xbox-specific deviations: none are documented** for user-mode x64
code — therefore none are invented (every unverified case is a typed
reject). Implemented: `validate_call`, `compute_layout`,
`prepare_call` (callee-relative frame: return address at [callee RSP],
stack args at callee RSP+8+32 — fixed during bring-up when the tests
caught caller-relative writes), `extract_args`, `write_return`
(strict kind matching), `check_preserved` (nonvolatile set).
Unsupported → typed errors: `__m128` by value, varargs beyond 4
positions, aggregates not in {1,2,4,8} bytes.
