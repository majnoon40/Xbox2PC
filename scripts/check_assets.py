#!/usr/bin/env python3
"""Asset-policy checker: enforces docs/input-policy.md on what gets committed.

Rejected everywhere in the repository:

  * executables, objects, shared libraries and core dumps (PE, ELF, Mach-O,
    WASM);
  * archives, compressed containers, disk images and installers;
  * bitmap images;
  * binary data with no known magic (anything that contains NUL bytes
    or is not UTF-8 text);
  * files larger than MAX_FILE_BYTES;
  * symlinks and submodule (gitlink) entries.

The single exception is the fixture root.  A binary may be tracked under
tests/fixtures/ only when its repository-relative path and SHA-256 are
listed in tests/fixtures/SHA256SUMS.txt, each entry under a provenance
line saying what the file is and why it is not built from source.
Generated programs should not be committed at all: CI and scripts build
them from source.

Files are classified by content, never by name.  In the git modes the content
is the staged blob, not the working-tree copy, so a file edited after
`git add` cannot slip a different version through.

  scripts/check_assets.py --staged     what the next commit would record
  scripts/check_assets.py --all        every file in the index
  scripts/check_assets.py PATH...      explicit working-tree files

Exit status: 0 = clean, 1 = violations found, 2 = usage or policy error.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys

MAX_FILE_BYTES = 1024 * 1024
FIXTURE_ROOT = "tests/fixtures/"
FIXTURE_MANIFEST = "tests/fixtures/SHA256SUMS.txt"
POLICY_DOC = "docs/input-policy.md"
# Bytes inspected for a magic; the whole blob is hashed when a manifest
# match has to be confirmed (blobs over the size limit are never read whole).
HEAD_BYTES = 64 * 1024

EXIT_CLEAN, EXIT_VIOLATION, EXIT_ERROR = 0, 1, 2


class PolicyError(Exception):
    """The policy itself could not be applied (bad invocation, bad manifest)."""


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# (group, magic, offset).  First match wins; ELF and PE need extra decoding
# and are handled before this table.
_MAGIC = [
    ("executables and objects", b"\xcf\xfa\xed\xfe", 0x00),  # Mach-O 64
    ("executables and objects", b"\xfe\xed\xfa\xcf", 0x00),
    ("executables and objects", b"\xce\xfa\xed\xfe", 0x00),  # Mach-O 32
    ("executables and objects", b"\xfe\xed\xfa\xce", 0x00),
    ("executables and objects", b"\xca\xfe\xba\xbe", 0x00),  # Mach-O universal
    ("executables and objects", b"\xbe\xba\xfe\xca", 0x00),
    ("executables and objects", b"\xca\xfe\xba\xbf", 0x00),
    ("executables and objects", b"\x00asm", 0x00),
    ("archives and containers", b"PK\x03\x04", 0x00),        # zip (also jar)
    ("archives and containers", b"PK\x05\x06", 0x00),        # empty zip
    ("archives and containers", b"PK\x07\x08", 0x00),        # spanned zip
    ("archives and containers", b"7z\xbc\xaf\x27\x1c", 0x00),
    ("archives and containers", b"Rar!\x1a\x07", 0x00),
    ("archives and containers", b"\x1f\x8b", 0x00),          # gzip
    ("archives and containers", b"\xfd7zXZ\x00", 0x00),      # xz
    ("archives and containers", b"\x28\xb5\x2f\xfd", 0x00),  # zstd
    ("archives and containers", b"\x04\x22\x4d\x18", 0x00),  # lz4 frame
    ("archives and containers", b"!<arch>\n", 0x00),         # ar (.a, .lib)
    ("archives and containers", b"MSCF\x00\x00\x00\x00", 0x00),  # cab
    ("archives and containers", b"ustar", 0x101),            # tar
    ("archives and containers", b"070701", 0x00),            # cpio
    ("archives and containers", b"070702", 0x00),
    ("archives and containers", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0x00),  # OLE/MSI
    ("disk images", b"CD001", 0x8001),                       # ISO 9660
    ("images", b"\x89PNG\r\n\x1a\n", 0x00),
    ("images", b"\xff\xd8\xff", 0x00),                       # JPEG
    ("images", b"GIF87a", 0x00),
    ("images", b"GIF89a", 0x00),
]

_LABELS = {
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit executable",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit executable (byte-swapped)",
    b"\xce\xfa\xed\xfe": "Mach-O executable",
    b"\xfe\xed\xfa\xce": "Mach-O executable (byte-swapped)",
    b"\xca\xfe\xba\xbe": "Mach-O universal binary",
    b"\xbe\xba\xfe\xca": "Mach-O universal binary (byte-swapped)",
    b"\xca\xfe\xba\xbf": "Mach-O universal 64-bit binary",
    b"\x00asm": "WebAssembly module",
    b"PK\x03\x04": "zip archive",
    b"PK\x05\x06": "zip archive",
    b"PK\x07\x08": "zip archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"\x1f\x8b": "gzip archive",
    b"\xfd7zXZ\x00": "xz archive",
    b"\x28\xb5\x2f\xfd": "zstd archive",
    b"\x04\x22\x4d\x18": "lz4 archive",
    b"!<arch>\n": "ar archive (.a / .lib)",
    b"MSCF\x00\x00\x00\x00": "Microsoft cabinet",
    b"ustar": "tar archive",
    b"070701": "cpio archive",
    b"070702": "cpio archive",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "OLE compound container",
    b"CD001": "ISO 9660 image",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
}


def _has(data: bytes, offset: int, magic: bytes) -> bool:
    return len(data) >= offset + len(magic) and data[offset:offset + len(magic)] == magic


def classify(data: bytes) -> tuple[str, str] | None:
    """Return (group, label) when the bytes are a known binary, else None."""
    if _has(data, 0, b"\x7fELF"):
        e_type = int.from_bytes(data[0x10:0x12], "little") if len(data) >= 0x12 else 0
        if e_type == 4:  # ET_CORE
            return "core dumps", "ELF core dump"
        kinds = {1: "relocatable object", 2: "executable", 3: "shared object"}
        return "executables and objects", "ELF " + kinds.get(e_type, "file")
    if _has(data, 0, b"MZ") and len(data) >= 0x40:
        pe = int.from_bytes(data[0x3C:0x40], "little")
        if _has(data, pe, b"PE\x00\x00"):
            return "executables and objects", "PE image (Windows executable, DLL or driver)"
    for group, magic, offset in _MAGIC:
        if _has(data, offset, magic):
            return group, _LABELS[magic]
    if _has(data, 0, b"RIFF") and _has(data, 8, b"WEBP"):
        return "images", "WebP image"
    if _has(data, 0, b"BM") and _has(data, 6, b"\x00\x00\x00\x00"):
        return "images", "BMP image"
    if _has(data, 0, b"BZh") and len(data) > 3 and 0x31 <= data[3] <= 0x39:
        return "archives and containers", "bzip2 archive"
    if b"\x00" in data:
        return "unidentified binaries", "binary data with no known magic (contains NUL bytes)"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        # Compressed or encrypted content can be free of both NUL bytes and
        # any magic we know; a few dozen such bytes are never valid UTF-8.
        return "unidentified binaries", "binary data with no known magic (not UTF-8 text)"
    return None


# ---------------------------------------------------------------------------
# Policy inputs
# ---------------------------------------------------------------------------

_PROVENANCE = "# provenance:"


def _parse_manifest(text: str) -> dict[str, str]:
    """repository-relative path -> sha256, from the fixture manifest.

    Every checksum line must be preceded by its own provenance line:

        # provenance: <what it is; how it was produced; why it is not built
        # from source in CI or a script>
        <sha256>  tests/fixtures/<name>

    A hash says what a binary is, not why it may be tracked; the provenance
    line is what a reviewer reads, so an entry without one is a policy error.
    """
    entries: dict[str, str] = {}
    vouched = False
    for number, line in enumerate(text.split("\n"), 1):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if line.startswith("#"):
            vouched = line.startswith(_PROVENANCE) and bool(line[len(_PROVENANCE):].strip())
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if match is None:
            raise PolicyError(
                f"{FIXTURE_MANIFEST}:{number}: not in sha256sum format "
                "'<sha256>  <repository-relative path>'")
        if not vouched:
            raise PolicyError(
                f"{FIXTURE_MANIFEST}:{number}: '{match.group(2)}' has no provenance; put a line "
                f"'{_PROVENANCE} <what it is; how it was produced; why it is not built "
                "from source>' directly above each entry")
        vouched = False  # one provenance line vouches for exactly one entry
        entries[match.group(2)] = match.group(1).lower()
    return entries


def load_manifest(root: str | None, staged: bool = False) -> dict[str, str]:
    """repository-relative path -> sha256, from the fixture manifest.

    `staged` reads the manifest from the index, the same source the blobs come
    from, so an unstaged manifest edit cannot vouch for a staged binary.
    """
    if root is None:
        return {}
    if staged:
        present = subprocess.run(
            ["git", "-C", root, "cat-file", "-e", ":" + FIXTURE_MANIFEST],
            capture_output=True)
        if present.returncode != 0:
            return {}
        raw = _git(root, ["cat-file", "blob", ":" + FIXTURE_MANIFEST])
        return _parse_manifest(raw.decode("utf-8", "surrogateescape"))
    path = os.path.join(root, *FIXTURE_MANIFEST.split("/"))
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        return _parse_manifest(handle.read())


def judge(path: str, mode: str, data: bytes, size: int,
          manifest: dict[str, str]) -> list[str]:
    """Policy verdicts for one file.  `data` is the whole blob, or only its
    first HEAD_BYTES when `size` reports something over the size limit."""
    problems: list[str] = []
    if mode == "120000":
        problems.append(f"symlink -> {data.decode('utf-8', 'replace')}: symlinks are not tracked")
    elif mode == "160000":
        problems.append("submodule entry: submodules are not tracked")
    elif mode not in ("100644", "100755"):
        problems.append(f"git mode {mode}: only regular files are tracked")

    found = classify(data)
    described = f"{found[1]}, " if found else ""
    if size > MAX_FILE_BYTES:
        problems.append(f"{described}{size} bytes: over the {MAX_FILE_BYTES}-byte limit")
        return problems
    if found:
        digest = hashlib.sha256(data).hexdigest()
        listed = manifest.get(path)
        if not path.startswith(FIXTURE_ROOT):
            why = f"binaries are only tracked under {FIXTURE_ROOT}"
        elif listed is None:
            why = f"not listed in {FIXTURE_MANIFEST}"
        elif listed != digest:
            why = f"content differs from its {FIXTURE_MANIFEST} entry"
        else:
            why = ""
        if why:
            problems.append(
                f"{found[1]} ({size} bytes): {why}. Build programs from source "
                f"in CI or scripts; see {POLICY_DOC}.")
    return problems


# ---------------------------------------------------------------------------
# Content sources
# ---------------------------------------------------------------------------

def _git(root: str | None, args: list[str]) -> bytes:
    command = ["git"] + (["-C", root] if root is not None else []) + args
    proc = subprocess.run(command, capture_output=True)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise PolicyError(f"{' '.join(command)} failed: {detail}")
    return proc.stdout


def repo_root() -> str | None:
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "surrogateescape").strip() or None


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape").replace(os.sep, "/")


def staged_entries(root: str) -> list[tuple[str, str]]:
    """(mode, path) of every file the next commit would add, change or change
    the type of (a file replaced by a symlink is a type change)."""
    out = _git(root, ["diff", "--cached", "--raw", "-z", "--no-renames",
                      "--diff-filter=ACMRT"])
    fields = out.split(b"\0")
    entries: list[tuple[str, str]] = []
    position = 0
    while position < len(fields) and fields[position]:
        if position + 1 >= len(fields) or not fields[position].startswith(b":"):
            raise PolicyError("unexpected `git diff --cached --raw` record")
        parts = fields[position][1:].split(b" ")
        if len(parts) != 5:
            raise PolicyError("unexpected `git diff --cached --raw` header")
        entries.append((parts[1].decode("ascii"), _decode(fields[position + 1])))
        position += 2
    return entries


def index_entries(root: str) -> list[tuple[str, str]]:
    """(mode, path) of every file in the index."""
    entries: list[tuple[str, str]] = []
    for record in _git(root, ["ls-files", "-s", "-z"]).split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        entries.append((meta.split(b" ")[0].decode("ascii"), _decode(path)))
    return entries


def read_blob(root: str, path: str) -> tuple[bytes, int]:
    """(content, size) of the staged blob.  A blob over the size limit is
    returned as its first HEAD_BYTES only."""
    size = int(_git(root, ["cat-file", "-s", ":" + path]).strip())
    if size <= MAX_FILE_BYTES:
        return _git(root, ["cat-file", "blob", ":" + path]), size
    proc = subprocess.Popen(["git", "-C", root, "cat-file", "blob", ":" + path],
                            stdout=subprocess.PIPE)
    head = proc.stdout.read(HEAD_BYTES) if proc.stdout else b""
    proc.kill()
    proc.wait()
    return head, size


def read_working_file(path: str) -> tuple[str, bytes, int]:
    """(git mode, content, size) of a file on disk."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        return "120000", target.encode("utf-8", "surrogateescape"), len(target.encode())
    if not stat.S_ISREG(info.st_mode):
        return "160000", b"", 0  # anything that is not a file or a symlink
    with open(path, "rb") as handle:
        if info.st_size <= MAX_FILE_BYTES:
            return "100644", handle.read(), info.st_size
        return "100644", handle.read(HEAD_BYTES), info.st_size


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def check_git(root: str, entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    manifest = load_manifest(root, staged=True)
    violations: list[tuple[str, str]] = []
    for mode, path in entries:
        if mode in ("160000",):  # no blob to read for a gitlink
            data, size = b"", 0
        else:
            data, size = read_blob(root, path)
        for problem in judge(path, mode, data, size, manifest):
            violations.append((path, problem))
    return violations


def check_paths(root: str | None, paths: list[str]) -> list[tuple[str, str]]:
    manifest = load_manifest(root)
    violations: list[tuple[str, str]] = []
    for given in paths:
        absolute = os.path.abspath(given)
        if root is not None and (absolute == root or absolute.startswith(root + os.sep)):
            name = os.path.relpath(absolute, root).replace(os.sep, "/")
        else:
            name = given.replace(os.sep, "/")
        if not os.path.lexists(given):
            violations.append((name, "file does not exist"))
            continue
        mode, data, size = read_working_file(given)
        if mode == "160000":
            violations.append((name, "only regular files and symlinks can be checked"))
            continue
        for problem in judge(name, mode, data, size, manifest):
            violations.append((name, problem))
    return violations


def report(violations: list[tuple[str, str]], checked: int, annotations: bool) -> int:
    for path, message in violations:
        print(f"{path}: {message}")
        if annotations:
            print(f"::error file={path}::{message}")
    outcome = "rejected" if violations else "clean"
    print(f"asset policy: {checked} file(s) checked, {len(violations)} violation(s), {outcome}")
    if violations:
        print(f"see {POLICY_DOC}; to allow a generated test fixture, add its sha256 to "
              f"{FIXTURE_MANIFEST} under {FIXTURE_ROOT}")
    return EXIT_VIOLATION if violations else EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_assets.py",
        description="Reject binaries, archives and oversized files outside the fixture root.")
    parser.add_argument("--staged", action="store_true",
                        help="check files staged for the next commit")
    parser.add_argument("--all", action="store_true", help="check every file in the index")
    parser.add_argument("--annotations", action="store_true",
                        help="also print GitHub Actions ::error annotations")
    parser.add_argument("paths", nargs="*", help="explicit working-tree files")
    options = parser.parse_args(argv)

    if options.staged and options.all:
        parser.error("--staged and --all are mutually exclusive")
    if (options.staged or options.all) and options.paths:
        parser.error("--staged / --all cannot be combined with explicit paths")
    if not (options.staged or options.all or options.paths):
        parser.error("pass --staged, --all, or explicit paths")

    try:
        if options.staged or options.all:
            root = repo_root()
            if root is None:
                print("error: --staged / --all must run inside a git work tree", file=sys.stderr)
                return EXIT_ERROR
            entries = staged_entries(root) if options.staged else index_entries(root)
            violations = check_git(root, entries)
        else:
            violations = check_paths(repo_root(), options.paths)
            entries = options.paths
    except PolicyError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    return report(violations, len(entries), options.annotations)


if __name__ == "__main__":
    sys.exit(main())
