# Test fixtures

`tests/fixtures/` is the only directory in which a binary may be tracked. It
is empty of binaries on purpose: every binary a test runs is built from source
in CI or by a script, into an ignored build directory. The M11 PE fixtures
follow that rule (`scripts/build-m11-samples.sh`, with their golden hashes in
`samples/m11/golden/SHA256SUMS.txt`), and the M12 rung fixtures do the same.

Commit a binary here only when it cannot be produced on a Linux CI runner. To
do so, both of these are required, and `scripts/check_assets.py` enforces them
in the pre-commit hook and in the `asset-policy` CI job:

1. Add a line to `SHA256SUMS.txt` in this directory with the file's SHA-256
   and its repository-relative path, in `sha256sum` format (two spaces), so
   `sha256sum --check tests/fixtures/SHA256SUMS.txt` passes from the
   repository root.
2. Put a provenance line directly above it:

   ```
   # provenance: <what the file is; how it was produced; why it is not built from source>
   <sha256>  tests/fixtures/<name>
   ```

One provenance line covers exactly one entry. An entry without one, a file
whose content does not match its hash, a renamed file, or a file outside this
directory is rejected. The limit of 1 MiB per file applies here too.

The hash tells a reviewer what the file is; the provenance line tells them why
it may be tracked. Before listing anything, read
[docs/input-policy.md](../../docs/input-policy.md): the file has to be a
program of ours, an MIT-licensed sample, or an artifact we generated, and it
may not be derived from a retail product.
