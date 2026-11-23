# M9 execution and compatibility limitations

The M9 work does not implement a complete Xbox operating system or a complete
x86-64 emulator. The current execution backend remains a bounded deterministic
test interpreter with an explicitly documented instruction subset.

The static analyzer performs a linear decode of file-backed executable
sections. It cannot prove instruction reachability, function boundaries,
basic-block correctness, or the absence of embedded data. Decoder-confirmed
records are not proof that an instruction will execute.

The PE validator reuses the M1 parser and M6 pre-allocation validation,
relocation decoder, and TLS metadata decoder. It does not create a guest
address space, apply relocations, resolve imported APIs, initialize per-thread
TLS, or execute TLS callbacks.

A synthetic PE passing these checks is not an Xbox executable and is not
evidence of game compatibility. No real Xbox executable or GTA VI build has
been tested.
