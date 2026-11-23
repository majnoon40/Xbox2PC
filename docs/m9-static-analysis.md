# M9 static instruction analysis — conservative first pass

The analyzer scans only file-backed sections marked executable in the PE
section table. It reuses the M9 decoder and the interpreter's explicit
`Interpreter::supports` matrix and records:

- Decoder-recognized instructions as **confirmed decode records**. Each record
  separately states whether the current interpreter support matrix accepts
  its mnemonic. This does not prove reachability or execution.
- Valid but decoder-unsupported encodings with reject class, reason, byte
  evidence, RVA, and file offset.
- Decoder-recognized instructions outside the current interpreter subset as
  separate unsupported-execution regions.
- Invalid encodings as **candidate embedded-data regions**. This is a
  heuristic label, not a claim that the bytes are definitely data.
- Truncated tails and safety-cap stops as uncertain regions.
- FS/GS memory-segment use with instruction location and rendered mnemonic.

The scan is linear and intentionally does not claim complete control-flow
recovery, function boundaries, basic-block correctness, or a complete
disassembly. It does not execute instructions or map the image.
