# Execution Engine (M8)

`IExecutionEngine` is the engine boundary — the runtime is never
coupled to one CPU implementation. `engine_kind()` labels backends
honestly: `deterministic-test` (what M8 ships), future `native-host` /
emulated backends. **The deterministic backend is a real interpreter
for a documented subset — not a mock, and explicitly NOT a general
x86-64 emulator.**

Subset (all fetches execute-checked, memory page-wise validated):
`MOV r64,imm64` · `MOV r64,r64` (89/8B) · `MOV r64,[r64+disp8]` and
store · `ADD/SUB/CMP r64,imm32` (CF/ZF/SF/OF) · `XOR r64,r64` (+
PF) · `PUSH/POP r64` · `CALL rel32` · `JMP rel32` · `RET` · `NOP`.
Anything else → `UnsupportedInstruction` (recoverable).

Contract: budgets (`max_instructions`), observable cancellation
(atomic flag polled per instruction), stack-floor overflow detection,
completion-sentinel returns, single-step (budget==1 is the step).
`ExecutionRequest` carries guest VAs only — never host pointers.
Imported-API entries (M7 binding values) route through the marshalling
bridge (see api-marshalling.md).
