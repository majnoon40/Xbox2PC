#!/usr/bin/env python3
"""Parse a .torrent metadata file, verify its info hash, and dump a full inventory.

Usage: python3 parse_torrent.py <path-to.torrent> <expected-info-hex>
"""
import sys
import hashlib
import libtorrent as lt

MAGNET_BTIH = "465d6a0eac381e68ca77115f44f19f0c968b9590"


def raw_info_slice(data: bytes) -> bytes:
    """Extract the raw bencoded `info` value bytes from the file, byte-exact.

    A naive bdecode/re-encode may not reproduce the original bytes, so we scan
    the raw file for the `4:infod` boundary and track nesting depth to find
    the end of the info dictionary.
    """
    key = b"4:infod"
    start = data.find(key)
    if start < 0:
        raise ValueError("no info dict found")
    i = start + len(key) - 1  # position of the 'd' that opens the info dict
    depth = 0
    while i < len(data):
        c = data[i:i + 1]
        if c == b"d" or c == b"l":
            depth += 1
            i += 1
        elif c == b"i":
            j = data.index(b"e", i)
            i = j + 1
        elif c >= b"0" and c <= b"9":
            j = data.index(b":", i)
            length = int(data[i:j])
            i = j + 1 + length
        elif c == b"e":
            depth -= 1
            i += 1
            if depth == 0:
                # info value runs from the 'd' to this 'e' inclusive
                return data[start + len(key) - 1: i]
        else:
            raise ValueError(f"bad bencode byte at {i}: {c!r}")
    raise ValueError("unterminated info dict")


def human(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.2f} {u}" if u != "B" else f"{int(v)} B"
        v /= 1024
    return f"{n} B"


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/work/torrent-meta/meta_mirror.torrent"
    expected = (sys.argv[2] if len(sys.argv) > 2 else MAGNET_BTIH).lower()

    data = open(path, "rb").read()
    print(f"file: {path}")
    print(f"file size: {len(data)} bytes")

    # --- manual SHA-1 over the raw info slice (how btih v1 is computed) ---
    info_raw = raw_info_slice(data)
    sha1 = hashlib.sha1(info_raw).hexdigest()
    print(f"computed info-hash (SHA-1 of raw info dict): {sha1}")
    print(f"magnet btih:                              {expected}")
    print(f"hash match: {'YES' if sha1 == expected else 'NO — MISMATCH'}")
    print()

    # --- libtorrent view ---
    ti = lt.torrent_info(data if path.endswith(".torrent") else path)
    ih = ti.info_hashes()
    v1 = str(ih.v1) if str(ih.v1) != "00000000000000000000" else ""
    v2 = str(ih.v2) if str(ih.v2) != "00000000000000000000000000000000" else ""
    print(f"libtorrent info_hashes  v1={v1}  v2={v2 or '(none)'}")
    print(f"name: {ti.name()}")
    print(f"comment: {ti.comment()!r}")
    print(f"created by: {ti.creator()!r}")
    print(f"creation date: {ti.creation_date()} (unix)")
    print(f"piece length: {ti.piece_length()}  pieces: {ti.num_pieces()}")
    print(f"total size: {ti.total_size()} bytes ({human(ti.total_size())})")
    print(f"num files: {ti.num_files()}")
    print()

    fs = ti.files()
    print("=== TRACKERS ===")
    for t in ti.trackers():
        print(f"  {t.url}")
    print()

    print("=== FILE TREE ===")
    for i in range(fs.num_files()):
        f = fs.at(i)
        pad = "  [pad]" if f.pad_file else ""
        print(f"  {i:5d}  {human(f.size):>12}  {f.path}{pad}")


if __name__ == "__main__":
    main()
