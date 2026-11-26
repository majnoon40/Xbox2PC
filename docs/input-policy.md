# Input policy

This document says what may be used as test input for Xbox2PC and what the
repository may contain. It is the repository's statement of Rule 3 of the M12
plan, and it is enforced by `scripts/check_assets.py` (a pre-commit hook and a
CI job), described under [Enforcement](#enforcement).

## What may be used as test input

Only three kinds of program may be run, dissected, recorded or committed as a
test input:

1. **Our own programs, built from source.** The programs under `samples/`,
   the M12 rung fixtures, and every PE a test executes are written in this
   repository and compiled by a script or by CI. Their source is the artifact
   that gets committed; the binary never is.
2. **MIT-licensed public samples, built from source.** The Microsoft
   DirectX-Graphics-Samples repository may be used under the MIT License (its
   `LICENSE` file reads "The MIT License (MIT)", "Copyright (c) 2015
   Microsoft"; <https://github.com/microsoft/DirectX-Graphics-Samples/blob/master/LICENSE>,
   checked 2026-11-26). Only source is fetched, at a pinned commit, and only
   into a build directory. Public GDK PC samples may be used when the user
   installs the GDK themselves; the repository never vendors GDK files, and CI
   has no GDK, so a result from a GDK sample is reported as a local run.
3. **Artifacts we generate ourselves:** golden traces, validation reports,
   fuzz corpora produced by our own fuzzers, and fixture images assembled by
   `xbox2pc::test::PeBuilder`.

A fixture that needs an import library gets one generated from our own stub
DLL source (`samples/m11/kernel32_imports.c`), not from a Microsoft
library. The fixtures are freestanding: no Windows SDK or GDK header is
included.

## What is never allowed

- Retail binaries of any kind: executables, DLLs, drivers, system images.
- Retail packages, in any state: installed, extracted, decrypted or partial.
  Xbox2PC **classifies** XVC and XVD containers and never parses their
  contents (see [package-formats.md](package-formats.md)).
- Retail shaders, shader caches, assets, audio, video or text extracted from
  a product.
- Dumps derived from a binary we cannot redistribute: memory dumps,
  instruction dumps, string dumps, relocation dumps, disassembly listings,
  traces of a retail program.
- Title names in source, tests, docs, issues or commit messages, and
  title-specific patches or behavior switches.
- Code that decrypts, unpacks or otherwise circumvents the protection of
  retail content.
- Microsoft binaries or GDK files committed in any form.
- Code copied from a GPL project, including other emulators. Their public
  documentation is reading for concepts; everything here is reimplemented.

The rule does not depend on where a file came from or whether it was easy to
obtain. If it is not in the allowed list, it is not an input.

## Non-distribution stance

The repository is a source distribution. It contains no compiled programs, no
packages, no shaders, no dumps and no captures, and it links to none: an issue,
a document or a commit message must not point at a location that hosts retail
content. Every binary a test runs is built from source in the same CI job that
runs it, or by a script a developer runs locally into an ignored build
directory.

The only third-party code is source under a permissive license, recorded with
name, version, license and link mode in `docs/third-party.md`. Nothing in this
document is a license for Xbox2PC itself: the repository has no top-level
LICENSE file at the time of writing, and choosing one is the maintainer's
decision.

## Enforcement

`scripts/check_assets.py` decides by **content, never by name**. It rejects,
everywhere in the repository:

| Class | Detected by |
|---|---|
| PE images (executables, DLLs, drivers) | `MZ` header with a `PE\0\0` signature |
| ELF executables, shared objects, relocatable objects, core dumps | `\x7fELF`, `e_type` |
| Mach-O binaries, WebAssembly modules | magic |
| Archives and compressed containers: zip, 7z, RAR, gzip, bzip2, xz, zstd, lz4, ar (`.a`, `.lib`), cab, tar, cpio, MSI and other OLE compound containers | magic |
| Disk images (ISO 9660) | `CD001` at offset 0x8001 |
| Bitmap images: PNG, JPEG, GIF, WebP, BMP | magic or header fields |
| Binary data with no known magic | any NUL byte, or bytes that are not UTF-8 text |
| Files over 1 MiB | size |
| Symlinks and submodule entries | git mode |

The last content row exists because compressed and encrypted data can be free
of NUL bytes and of every magic we know; a few dozen such bytes are never
valid UTF-8. A side effect is that text in a legacy encoding (Latin-1) or with
a UTF-16 byte order mark is rejected as binary: convert it to UTF-8.

### The one exception

A binary may be tracked under `tests/fixtures/` only when two conditions hold:

1. its repository-relative path and SHA-256 are listed in
   `tests/fixtures/SHA256SUMS.txt`, and the staged content hashes to that
   value; and
2. the entry is preceded by a `# provenance:` line stating what the file is,
   how it was produced and why it is not built from source in CI.

The second condition is checked when the manifest is parsed; an entry without
it is a policy error. The manifest is an allowlist with a paper trail, not a
convenience: a binary belongs in it only when it genuinely cannot be produced
on a Linux CI runner. See [tests/fixtures/README.md](../tests/fixtures/README.md).

### Modes and exit status

| Invocation | Checks | Used by |
|---|---|---|
| `--staged` | what the next commit would add or change | the pre-commit hook |
| `--all` | every file in the index | CI, on every push and pull request |
| `PATH...` | the named working-tree files, ignored or not | by hand |

Exit status is 0 when clean, 1 when violations were found, and 2 for a usage
or policy error (a malformed manifest, no git work tree). In the git modes the
content examined is the **staged blob**, so editing a file after `git add`
cannot get a different version committed than the one that was checked, and
the manifest is read from the index for the same reason.

### Enabling the hook

Git does not install hooks from a repository, so each clone opts in once:

```sh
scripts/install-hooks.sh
```

That sets `core.hooksPath` to `scripts/hooks` in the clone's local config and
nothing else; `git config --unset core.hooksPath` turns it off. The hook
checks only the staged files, so its cost grows with the size of the commit:
36 ms with nothing staged, and 1.1 s for the whole 455-file tree on the
two-core machine this was measured on (M12 P0). `git commit --no-verify`
skips it, as it skips any hook, which is why CI runs `--all` over the whole
tree on every push and pull request: a change that gets past a local hook
still fails the `asset-policy` job.

### What the checker cannot do

- **It cannot recognise a dump written as text.** A hex listing, a string
  dump or a disassembly saved as text is text to the checker. The rule still
  forbids it; review is the only check.
- **It has no magic for XVC or XVD**, because none is published
  ([package-formats.md](package-formats.md)). Such a file is caught by the
  generic binary rows or by the size limit, which is one reason the limit
  applies everywhere.
- **It sees the index and named paths only.** An ignored file on disk is not
  reported; `.gitignore` keeps it out of `git add -A`, nothing more.
- **A hash proves identity, not origin.** A listed fixture is only as
  trustworthy as its provenance line.

## If a disallowed file was committed

Deleting it in a later commit is not enough: it stays in the history and in
every clone. Anyone who notices such a commit should stop and tell the
maintainer in the pull request, naming the commit, the path and what the file
is. Whether the history is rewritten is the maintainer's decision alone; a
contributor does not force-push. If the file contains a credential, revoke the
credential first, because rewriting history does not un-leak it.

## Related documents

- [package-formats.md](package-formats.md): why containers are classified and
  never parsed.
- [third-party.md](third-party.md): the register of third-party components.
- `samples/m11/README.md`: how the PE fixtures are built without any
  Microsoft file.
