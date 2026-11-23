#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/build/m11-samples}"
CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
MINGW_CXX="${MINGW_CXX:-x86_64-w64-mingw32-g++}"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
export SOURCE_DATE_EPOCH=0

for tool in "$CLANG" "$LLD_LINK" sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: required tool not found: $tool" >&2
        exit 1
    }
done

COMMON_CLANG_FLAGS=(
    --target=x86_64-pc-windows-msvc
    -O1 -Wall -Wextra -Werror
    -ffreestanding -fno-builtin -fno-stack-protector -fno-exceptions
)

"$CLANG" "${COMMON_CLANG_FLAGS[@]}" -c \
    "$ROOT/samples/m11/kernel32_imports.c" \
    -o "$OUT_DIR/kernel32_imports.obj"
"$LLD_LINK" /dll /noentry /machine:x64 /timestamp:0 \
    "/implib:$OUT_DIR/kernel32.lib" "/out:$OUT_DIR/kernel32.dll" \
    "$OUT_DIR/kernel32_imports.obj"

"$CLANG" "${COMMON_CLANG_FLAGS[@]}" -c \
    "$ROOT/samples/m11/freestanding.c" \
    -o "$OUT_DIR/freestanding.obj"
"$CLANG" --target=x86_64-pc-windows-msvc -c \
    "$ROOT/samples/m11/tls_directory.s" \
    -o "$OUT_DIR/tls_directory.obj"
"$LLD_LINK" /entry:entry /subsystem:console /nodefaultlib /machine:x64 \
    /dynamicbase /nxcompat /timestamp:0 \
    "/out:$OUT_DIR/m11_freestanding.exe" \
    "$OUT_DIR/freestanding.obj" "$OUT_DIR/tls_directory.obj" \
    "$OUT_DIR/kernel32.lib"

if [[ "${M11_SKIP_CPP:-0}" != "1" ]]; then
    command -v "$MINGW_CXX" >/dev/null 2>&1 || {
        echo "error: $MINGW_CXX is required for the C++ exception fixture" >&2
        exit 1
    }
    "$MINGW_CXX" -std=c++20 -O1 -g0 -Wall -Wextra -Werror \
        -fexceptions -fasynchronous-unwind-tables -fno-omit-frame-pointer \
        -frandom-seed=m11-cpp-exceptions \
        -Wl,--no-insert-timestamp -Wl,--dynamicbase -Wl,--nxcompat \
        -Wl,--subsystem,console \
        -o "$OUT_DIR/m11_cpp_exceptions.exe" \
        "$ROOT/samples/m11/cpp_exceptions.cpp"
fi

{
    echo "source_date_epoch=0"
    echo "clang=$($CLANG --version | head -n 1)"
    echo "lld_link=$($LLD_LINK --version | head -n 1)"
    if [[ "${M11_SKIP_CPP:-0}" != "1" ]]; then
        echo "mingw_cxx=$($MINGW_CXX --version | head -n 1)"
    else
        echo "mingw_cxx=SKIPPED (M11_SKIP_CPP=1)"
    fi
    echo
    (cd "$ROOT" && sha256sum \
        samples/m11/kernel32_imports.c \
        samples/m11/freestanding.c \
        samples/m11/tls_directory.s \
        samples/m11/cpp_exceptions.cpp)
    (cd "$OUT_DIR" && sha256sum m11_freestanding.exe)
    if [[ -f "$OUT_DIR/m11_cpp_exceptions.exe" ]]; then
        (cd "$OUT_DIR" && sha256sum m11_cpp_exceptions.exe)
    fi
} > "$OUT_DIR/SHA256SUMS.txt"

printf 'Built M11 PE fixtures in %s\n' "$OUT_DIR"
cat "$OUT_DIR/SHA256SUMS.txt"
