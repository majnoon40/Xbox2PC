# M9 benchmarks

`m9_bench` is a deterministic synthetic-PE microbenchmark. The Release GCC GitHub Actions run on 2026-11-23 completed the benchmark step successfully.

## Captured CI result

Environment: GitHub-hosted `ubuntu-24.04` runner, GCC, CMake Release build. Fixture: 7,680-byte synthetic PE. These are one-run CI measurements, not portable performance guarantees.

| Measurement | Result | Work completed |
|---|---:|---:|
| Decoder | 44.191 ns/instruction | 2,000,000 / 2,000,000 decoded |
| Structural PE validation | 1.293 us/file | 10,000 / 10,000 structurally valid |
| Static analysis | 814.180 us/file | 2,551 confirmed decodes/file |

The benchmark output explicitly states that the fixture is synthetic and makes no Xbox-title compatibility claim.

## Scope and limitations

The benchmark measures decoder throughput on a fixed four-byte instruction sequence, structural PE validation latency per file, and static-analysis latency plus average decoder-confirmed records per file.

The existing `execution_bench`, `loader_bench`, and `api_compat_bench` cover other execution, guest-memory, loader, and marshalling paths. Their results have not been captured in this M9 report.

For reproducibility, record compiler/version, build type, CPU, OS, fixture size, iteration count, and raw output. CI values above are environment-specific observations, not target thresholds.
