# M9 CLI

All binary commands accept a PE file and optional `--json output.json`.
Without `--json`, the command prints JSON to stdout. Input files are capped
at 512 MiB by this command layer.

| Command | Purpose |
|---|---|
| `binary-analyze` | Combined PE, structural validation, instruction analysis, and compatibility report |
| `binary-info` | PE identity and image header summary |
| `binary-sections` | Section ranges and R/W/X flags |
| `binary-imports` | Parsed regular and delay-load import descriptors |
| `binary-relocations` | Decode relocation blocks and entries; does not apply them |
| `binary-tls` | Validate TLS metadata and report callback count; does not execute callbacks |
| `binary-instructions` | Conservative static decoder report |
| `binary-compat` | Emit the versioned compatibility JSON schema |
| `binary-report` | Combined report (same broad report payload as binary-analyze) |
| `interpreter-info` | Existing bounded interpreter capability summary |
| `interpreter-test` | Existing synthetic M4–M8 deterministic execution test |

Exit codes: 0 means the binary passed the validator's performed structural
checks; 1 means read, parse, or structural-validation failure; 2 means usage
error. A zero exit code is not an Xbox compatibility verdict.

The interpreter commands are delegated to the existing CLI execution
implementation. The backend is explicitly named `deterministic-test`, not a
general-purpose emulator.
