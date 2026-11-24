#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${1:-build/m11-samples}"
CLI="${2:-$ROOT/build/tools/xbox2pc}"
GOLDEN_DIR="$ROOT/samples/m11/golden"

if [[ "$BIN_DIR" == "$ROOT/"* ]]; then
    BIN_DIR="${BIN_DIR#"$ROOT/"}"
fi
if [[ "$BIN_DIR" == /* ]]; then
    echo "error: sample directory must be inside the repository for stable golden paths" >&2
    exit 1
fi
if [[ "$CLI" != /* ]]; then
    CLI="$ROOT/$CLI"
fi

[[ -x "$CLI" ]] || { echo "error: xbox2pc CLI not executable: $CLI" >&2; exit 1; }
[[ -f "$ROOT/$BIN_DIR/m11_freestanding.exe" ]] || {
    echo "error: build the M11 PE samples first: $ROOT/$BIN_DIR" >&2
    exit 1
}
[[ -f "$ROOT/$BIN_DIR/m11_cpp_exceptions.exe" ]] || {
    echo "error: C++ exception sample missing: $ROOT/$BIN_DIR/m11_cpp_exceptions.exe" >&2
    exit 1
}

mkdir -p "$GOLDEN_DIR"
cd "$ROOT"
for name in m11_freestanding m11_cpp_exceptions; do
    sample="$BIN_DIR/$name.exe"
    "$CLI" inspect "$sample" > "$GOLDEN_DIR/$name.inspect.txt"
    "$CLI" validate-pe "$sample" --json \
        "$GOLDEN_DIR/$name.validate-pe.json" > /dev/null
    "$CLI" compat-report "$sample" --json \
        "$GOLDEN_DIR/$name.compat-report.json" > /dev/null
done

echo "Captured M11 static-analysis goldens in $GOLDEN_DIR"
