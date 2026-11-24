# M11.5 — Native-host execution slice

The first native-host backend executes a narrow class of synthetic x86-64
entrypoints directly on an x86-64 Linux host using the Microsoft x64 ABI.

## Supported boundary

- The entry VA must translate to committed guest memory with execute permission.
- Entry has no arguments, no import/API bindings, and no cooperative execution
  gate. The code must be position-independent with respect to the host mapping.
- The entry executes in a child process with a bounded lifetime. A host signal
  terminates that child and is reported as a guest fault; a timeout is reported
  as a budget fault.
- The returned RAX value is copied back to the parent runtime.

## Explicit limitations

This is fault containment, not a security sandbox: the child inherits the
parent's user privileges and operating-system access. Use only trusted,
unencumbered synthetic fixtures.

The first slice does not provide host GS/TEB setup, compiler-generated TLS,
guest import thunks, persistent guest-memory writeback, SEH, unwind support,
or instruction tracing. It does not execute retail Xbox programs. Those
capabilities require later, separately tested slices.
