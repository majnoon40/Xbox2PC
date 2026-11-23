# M9 static instruction analysis — conservative first pass

The analyzer scans only file-backed sections marked executable in the PE
section table. It reuses the M9 decoder and records:

- Decoder-recognized instructions as **confirmed decode records**. This does
  not prove reachability, execution, or semantic support by the interpreter.
- Valid but unsupported encodings with the decoder reject class, reason, byte
  evidence, RVA, and file offset.
- Invalid encodings as **candidate embedded-data regions**. This is a
  heuristic label, not a claim that the bytes are definitely data.
- Truncated tails and safety-cap stops as uncertain regions.
- FS/GS memory-segment use with instruction location and rendered mnemonic.

The scan is linear and intentionally does not claim complete control-flow
recovery, function boundaries, basic-block correctness, or a complete
disassembly. It does not execute instructions or map the image.
