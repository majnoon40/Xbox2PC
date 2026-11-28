#!/usr/bin/env bash
# Builds the M12 rung fixtures (B to G) from source with clang + lld-link.
#
# Usage: scripts/build-rung-fixtures.sh [out-dir]      (default build/rungs)
#
# Everything here is project-authored source under samples/rungs/.  The
# import libraries come from our own stub DLL sources (stub_*.c), linked as
# DLLs only so lld-link emits the .lib; no Microsoft file is involved
# (docs/input-policy.md).  PE timestamps are fixed so the images are
# reproducible for one toolchain; their hashes are recorded but not
# committed, since they change with the compiler version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/build/rungs}"
CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

mkdir -p "$OUT_DIR/assets"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
export SOURCE_DATE_EPOCH=0

for tool in "$CLANG" "$LLD_LINK" sha256sum python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: required tool not found: $tool" >&2
        exit 1
    }
done

R="$ROOT/samples/rungs"
CFLAGS=(--target=x86_64-pc-windows-msvc -O1 -Wall -Wextra -Werror
        -ffreestanding -fno-builtin -fno-stack-protector -fno-exceptions -I "$R")
CXXFLAGS=(--target=x86_64-pc-windows-msvc -O1 -Wall -Wextra -Werror
          -ffreestanding -fno-builtin -fno-stack-protector -fexceptions -fno-rtti -I "$R")
LINK_EXE=(/entry:entry /subsystem:console /nodefaultlib /machine:x64
          /dynamicbase /nxcompat /timestamp:0)

# Import libraries: one stub DLL per module, built from our own sources.
for module in kernel32 user32 d3d12; do
    "$CLANG" "${CFLAGS[@]}" -c "$R/stub_$module.c" -o "$OUT_DIR/stub_$module.obj"
    "$LLD_LINK" /dll /noentry /machine:x64 /timestamp:0 \
        "/implib:$OUT_DIR/$module.lib" "/out:$OUT_DIR/$module.dll" \
        "$OUT_DIR/stub_$module.obj"
done
LIBS=("$OUT_DIR/kernel32.lib" "$OUT_DIR/user32.lib" "$OUT_DIR/d3d12.lib")

# Every image carries one anchor relocation (see rung_reloc.c).
"$CLANG" "${CFLAGS[@]}" -c "$R/rung_reloc.c" -o "$OUT_DIR/rung_reloc.obj"
ANCHOR=("$OUT_DIR/rung_reloc.obj")

build_c() {  # $1 = rung letter, $2 = source stem
    "$CLANG" "${CFLAGS[@]}" -c "$R/$2.c" -o "$OUT_DIR/$2.obj"
    "$LLD_LINK" "${LINK_EXE[@]}" "/out:$OUT_DIR/rung_$1_$2.exe" \
        "$OUT_DIR/$2.obj" "${ANCHOR[@]}" "${LIBS[@]}"
}
build_c b bootloop
build_c c assetload
build_c d gpucompute
build_c e threads
build_c g titlelike

# Rung F is C++ with exceptions: the freestanding EH stubs live in
# cxxthrow_runtime.c until P1 lands the vcruntime path.
"$CLANG" "${CFLAGS[@]}" -c "$R/cxxthrow_runtime.c" -o "$OUT_DIR/cxxthrow_runtime.obj"
"$CLANG" "${CXXFLAGS[@]}" -c "$R/cxxthrow.cpp" -o "$OUT_DIR/cxxthrow.obj"
"$LLD_LINK" "${LINK_EXE[@]}" "/out:$OUT_DIR/rung_f_cxxthrow.exe" \
    "$OUT_DIR/cxxthrow.obj" "$OUT_DIR/cxxthrow_runtime.obj" "${ANCHOR[@]}" "${LIBS[@]}"

# Assets for rungs C and G, generated here: byte i == (i * 7 + 3) & 0xFF.
python3 - "$OUT_DIR/assets" <<'PY'
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
for name, size in (("rung_c.bin", 4096), ("rung_g.bin", 256)):
    data = bytes(((i * 7 + 3) & 0xFF) for i in range(size))
    (out / name).write_bytes(data)
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    print(f"{name}: {size} bytes, fnv1a & 0xFF = {h & 0xFF}")
PY

(cd "$OUT_DIR" && sha256sum rung_*.exe > SHA256SUMS.txt)
printf 'Built M12 rung fixtures in %s\n' "$OUT_DIR"
cat "$OUT_DIR/SHA256SUMS.txt"
