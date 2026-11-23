# M9 benchmarks

`m9_bench` is a manual benchmark target over a deterministic synthetic PE
fixture. It measures:

1. Decoder throughput on a fixed four-byte instruction sequence.
2. Structural PE validation latency per file.
3. Static-analysis latency and average decoder-confirmed records per file.

The existing `execution_bench`, `loader_bench`, and
`api_compat_bench` cover execution, guest-memory operations, ABI/API
marshalling, loader phases, imports, and runtime lifecycle.

Build in Release mode and run each benchmark on an otherwise idle machine.
Record compiler/version, build type, CPU, OS, fixture size, iteration count,
and raw output. The benchmark source is infrastructure only; no performance
numbers are claimed until it is executed.
