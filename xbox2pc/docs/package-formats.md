# M5 — Package Formats & Evidence Grading

## Policy

M5's rule (spec §4.1): no fabricated headers, magic values, offsets or
algorithms. A format is parsed only when its structure is documented by a
source we can cite and verify. Formats that fail that bar are CLASSIFIED
with typed "unsupported-format" errors carrying their evidence grade.

## Xbox One/Xbox Series X|S container family

### XVC — Xbox Virtual Container

**Confirmed** (Microsoft GDK documentation,
https://learn.microsoft.com/en-us/gaming/gdk/docs/features/common/packaging/title-packaging-streaming-install-testing?view=gdk-2610):
- XVC is the binary packaged file produced by **MakePkg.exe** for title
  content ("Xbox Virtual Container");
- console packages use the `.xvc` extension, PC packages `.msixvc`;
  `_x` / `_xs` name suffixes distinguish Xbox One / Series X|S targets;
- packages are ENCRYPTED at rest (test key `/lt`, random key `/l`, or
  stable key `/lk` via LEKB key material); chunks and a "launch set"
  drive streaming installation;
- a Game OS image (`GameOs.xvd`) is embedded for console packages;
- Xbox Code Integrity signs binaries inside the package.

**Supported by partial evidence** (xvdtool project documentation,
https://github.com/emoose/xvdtool and its `xvd_info.md`):
- XVD ("Xbox Virtual Drive"/disc) holds system images; XVC is "a slightly
  modified variant of XVDs" used for game data;
- the header carries content ID / content type / sandbox ID / product ID
  and a header signature over the 0x0–0x200 (512-byte) region;
- integrity is a multi-level **SHA-256 hash tree** over data blocks
  (hash output "usually resized to 0x18 bytes");
- data is encrypted with a customized **AES-128-XTS** (XVC folds the
  region ID into the XTS tweak); the XVC payload filesystem is NTFS
  ("the only one observed so far");
- dev packages use a 256-bit ODK; XVC uses a 16-byte CIK (GUID + key).

**Unknown / proprietary** (explicitly stated by the same sources):
- the retail ODK is "still unknown";
- where XVC CIKs are stored "is currently unknown";
- no published source lists the magic constants or a complete
  field-by-field header/entry-table layout for XVD/XVC.

**xbox2pc decision:** XVC/XVD are **classified, never parsed**. The
`classify_bytes` probe identifies them only from a caller-supplied name
hint (`.xvc`/`.msixvc`/`.xvd`) — it explicitly does NOT claim byte-level
identification — and `parse_package` returns a typed
`PlatformUnsupported` whose message carries the evidence note. No
speculative parser, no invented fields.

### XPK — xbox2pc synthetic package (NOT an Xbox format)

Fully specified by this project (`include/xbox2pc/packages.hpp`) for
exercising the container interface, mounting and discovery with real
adversarial tests. Every artifact is labeled synthetic (`PackageInfo::
synthetic == true`; CLI output says so). Layout (all little-endian):

```
0    4   magic "XPK1"
4    2   version (1)
6    2   flags (reserved; must be 0)
8    4   entry_count
12   4   name_region_size
16   8   data_region_size
24   8   entry_table_offset (= 32 + name_region_size)
32   ..  name region ('/'-joined full paths, no NULs needed)
..   ..  entry table: entry_count × 32 bytes
         +0  8  name_offset (into name region)
         +8  2  name_length
         +10 2  flags (bit0 = directory)
         +12 4  path_depth
         +16 8  data_offset (into data region)
         +24 8  data_size
..   ..  data region (concatenated file payloads)
```

Validation (every rule adversarially tested — see
`XpkAdversarialTest` + the mutation fuzz): header floor 32 bytes;
regions must cover the file EXACTLY (no slack); table offset must equal
the post-name boundary; entry counts/names/sizes checked against
`PackageLimits` BEFORE allocation; checked-add everywhere (no overflow);
names validated (charset, length, no empty/'.'/'..' components);
path_depth must match the name; parents must be declared BEFORE children;
duplicate full paths rejected; file data spans must stay in-region and
must NOT overlap; reserved flag bits rejected; unsupported versions
rejected with the supported one stated.

The builder (`xpk_build`) canonifies input: implicit parent directories
are materialized as explicit directory entries (a draft emitted them
lazily, producing containers the parser rejected — found by the
benchmark fixture, fixed + regression-locked by
`XpkTest.Roundtrip`'s implicit-parent case).

## Parser safety architecture

`BoundedReader` (fixed buffer + position ceiling; every read/peek/seek
bounds-checked with wanted-vs-available messages) + `checked_add` for all
offset arithmetic + `PackageLimits` (max entries, name length, metadata
size, per-entry and total data size, nesting depth) enforced before any
allocation. Parsed packages own their buffers via `shared_ptr` so open
handles survive independently (POSIX-like).

## Other formats noted

- **XVD1/XVC1 magic claims** circulating in community tooling are NOT
  treated as verified (the sources we could open do not document them);
  xbox2pc does not encode them as identification bytes.
- XBFS (Xbox boot filesystem, original Xbox NAND) — out of scope (cited
  only as context in xvdtool).
- **XDVDFS/XISO** (original Xbox game discs, documented at
  https://xboxdevwiki.net/XDVDFS): different console generation; not
  implemented in M5, noted as a future candidate with REAL documentation
  available (512-byte header, FAT + 0x4000-byte clusters per the wiki).

## What M5 does NOT claim

No Xbox package is readable by xbox2pc today. The supported container is
our own synthetic XPK. The generic `ParsedPackage` interface, the bounded
reader, the limits framework and the read-only VFS mounting are the
foundation a future, evidence-backed XVC/XVD parser would plug into.
