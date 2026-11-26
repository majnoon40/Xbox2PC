#!/usr/bin/env python3
"""Self-test for scripts/check_assets.py (stdlib unittest, no network).

The classifier is checked against crafted file headers.  The three modes
(--staged, --all, explicit paths) are checked against throwaway git
repositories, including the fixture-manifest rules.

    python3 scripts/check_assets_test.py [-v]

Exit status is unittest's: 0 when every test passes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_assets.py")

_SPEC = importlib.util.spec_from_file_location("check_assets", SCRIPT)
check_assets = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_assets)

LIMIT = check_assets.MAX_FILE_BYTES
MANIFEST = check_assets.FIXTURE_MANIFEST


def git(*args: str) -> None:
    subprocess.run(["git", *args], check=True, capture_output=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf(e_type: int = 2) -> bytes:
    # e_ident, then e_type (1 relocatable, 2 exec, 3 shared, 4 core), padding.
    return (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
            + e_type.to_bytes(2, "little") + bytes(48))


def pe() -> bytes:
    # DOS header with e_lfanew = 0x40, then the PE signature.
    return b"MZ" + bytes(0x3A) + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(64)


def tar() -> bytes:
    return bytes(0x101) + b"ustar" + bytes(200)


def iso() -> bytes:
    return bytes(0x8001) + b"CD001" + bytes(64)


def bmp() -> bytes:
    return b"BM" + bytes(12) + bytes(40)


def webp() -> bytes:
    return b"RIFF" + bytes(4) + b"WEBP" + bytes(16)


TEXT = b"plain text, nothing executable\n"
PROVENANCE = "# provenance: synthetic PE written by this self-test; never built or shipped"


def nul_free_noise(count: int = 256) -> bytes:
    """Deterministic bytes that look like compressed or encrypted content:
    no NUL bytes, none of the magics above, not UTF-8."""
    out = bytearray(b"\x01")  # not the first byte of any magic
    block = b"asset-policy self-test"
    while len(out) < count:
        block = hashlib.sha256(block).digest()
        out.extend(byte for byte in block if byte != 0)
    return bytes(out[:count])

KNOWN_HEADERS = {
    "ELF core dump": elf(4),
    "ELF executable": elf(2),
    "ELF relocatable object": elf(1),
    "ELF shared object": elf(3),
    "PE image (Windows executable, DLL or driver)": pe(),
    "Mach-O 64-bit executable": b"\xcf\xfa\xed\xfe" + bytes(64),
    "Mach-O executable": b"\xce\xfa\xed\xfe" + bytes(64),
    "Mach-O universal binary": b"\xca\xfe\xba\xbe" + bytes(64),
    "WebAssembly module": b"\x00asm" + bytes(16),
    "zip archive": b"PK\x03\x04" + bytes(30),
    "7-Zip archive": b"7z\xbc\xaf\x27\x1c" + bytes(24),
    "RAR archive": b"Rar!\x1a\x07\x01\x00" + bytes(24),
    "gzip archive": b"\x1f\x8b\x08\x00" + bytes(24),
    "bzip2 archive": b"BZh9" + bytes(24),
    "xz archive": b"\xfd7zXZ\x00" + bytes(24),
    "zstd archive": b"\x28\xb5\x2f\xfd" + bytes(24),
    "lz4 archive": b"\x04\x22\x4d\x18" + bytes(24),
    "ar archive (.a / .lib)": b"!<arch>\n" + bytes(24),
    "Microsoft cabinet": b"MSCF\x00\x00\x00\x00" + bytes(24),
    "tar archive": tar(),
    "cpio archive": b"070701" + bytes(24),
    "OLE compound container": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(24),
    "ISO 9660 image": iso(),
    "PNG image": b"\x89PNG\r\n\x1a\n" + bytes(24),
    "JPEG image": b"\xff\xd8\xff\xe0" + bytes(24),
    "GIF image": b"GIF89a" + bytes(24),
    "WebP image": webp(),
    "BMP image": bmp(),
}


class ClassifyTest(unittest.TestCase):
    def test_known_headers_are_named_by_content(self) -> None:
        for label, data in KNOWN_HEADERS.items():
            with self.subTest(label=label):
                found = check_assets.classify(data)
                self.assertIsNotNone(found, "not classified")
                assert found is not None
                self.assertEqual(found[1], label)

    def test_a_core_dump_is_not_reported_as_an_ordinary_executable(self) -> None:
        found = check_assets.classify(elf(4))
        assert found is not None
        self.assertEqual(found, ("core dumps", "ELF core dump"))

    def test_binary_without_known_magic_falls_back_to_nul_bytes(self) -> None:
        found = check_assets.classify(b"\x12\x34\x00\x00payload\x00")
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found[0], "unidentified binaries")

    def test_nul_free_binary_data_without_a_magic_is_still_binary(self) -> None:
        data = nul_free_noise()
        self.assertNotIn(0, data)
        found = check_assets.classify(data)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found[1], "binary data with no known magic (not UTF-8 text)")

    def test_text_in_a_legacy_encoding_is_rejected(self) -> None:
        # Latin-1 text has no NUL bytes but is not valid UTF-8, so it is
        # rejected: tracked text must be UTF-8 (see docs/input-policy.md).
        found = check_assets.classify("caf\xe9 latin-1\n".encode("latin-1"))
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found[1], "binary data with no known magic (not UTF-8 text)")

    def test_text_and_empty_input_are_clean(self) -> None:
        for data in (TEXT, b"", "unicode text: \u00e9\u4e2d\n".encode("utf-8"),
                     b"MZ is only two letters when no PE signature follows"):
            with self.subTest(data=data):
                self.assertIsNone(check_assets.classify(data))


class RepoCase(unittest.TestCase):
    """A throwaway git repository plus helpers to stage files and run the
    checker as a subprocess, exactly the way the hook and CI run it."""

    def setUp(self) -> None:
        self.repo = tempfile.mkdtemp(prefix="x2p-assets-")
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        git("init", "-q", self.repo)
        git("-C", self.repo, "config", "user.name", "asset-policy-test")
        git("-C", self.repo, "config", "user.email", "asset-policy-test@example.invalid")
        git("-C", self.repo, "config", "commit.gpgsign", "false")

    def write(self, relative: str, data: bytes) -> str:
        path = os.path.join(self.repo, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def stage(self, relative: str, data: bytes) -> None:
        self.write(relative, data)
        git("-C", self.repo, "add", "--force", "--", relative)

    def stage_manifest(self, *lines: str) -> None:
        self.stage(MANIFEST, ("\n".join(lines) + "\n").encode("utf-8"))

    def commit(self) -> None:
        git("-C", self.repo, "commit", "-q", "-m", "test")

    def check(self, *args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, SCRIPT, *args], cwd=cwd or self.repo,
                              capture_output=True, text=True)

    def assertRejected(self, result: subprocess.CompletedProcess, *fragments: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 violation(s)", result.stdout)
        for fragment in fragments:
            self.assertIn(fragment, result.stdout)

    def assertClean(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class StagedModeTest(RepoCase):
    def test_plain_text_passes(self) -> None:
        self.stage("notes.md", TEXT)
        result = self.check("--staged")
        self.assertClean(result)
        self.assertIn("1 file(s) checked, 0 violation(s), clean", result.stdout)

    def test_every_binary_kind_is_rejected(self) -> None:
        for label, data in KNOWN_HEADERS.items():
            with self.subTest(label=label):
                shutil.rmtree(os.path.join(self.repo, ".git"))
                git("init", "-q", self.repo)
                self.stage("staged.bin", data)
                result = self.check("--staged")
                self.assertEqual(result.returncode, 1, label + "\n" + result.stdout)
                self.assertIn(label, result.stdout)
                self.assertIn("binaries are only tracked under tests/fixtures/",
                              result.stdout)

    def test_a_name_does_not_make_a_file_safe(self) -> None:
        self.stage("looks-like-source.txt", pe())
        self.assertRejected(self.check("--staged"), "PE image")

    def test_compressed_or_encrypted_data_is_rejected_without_a_magic(self) -> None:
        self.stage("assets/chunk-0.bin", nul_free_noise())
        self.assertRejected(self.check("--staged"), "not UTF-8 text")

    def test_symlinks_are_rejected(self) -> None:
        self.stage("target.txt", TEXT)
        os.symlink("target.txt", os.path.join(self.repo, "link.txt"))
        git("-C", self.repo, "add", "--force", "--", "link.txt")
        self.assertRejected(self.check("--staged"), "symlink -> target.txt")

    def test_a_file_replaced_by_a_symlink_is_rejected(self) -> None:
        self.stage("notes.md", TEXT)
        self.commit()
        os.remove(os.path.join(self.repo, "notes.md"))
        os.symlink("/etc/passwd", os.path.join(self.repo, "notes.md"))
        git("-C", self.repo, "add", "--force", "--", "notes.md")
        self.assertRejected(self.check("--staged"), "symlink -> /etc/passwd")

    def test_deletions_are_not_reported(self) -> None:
        self.stage("old.bin", pe())
        self.commit()
        os.remove(os.path.join(self.repo, "old.bin"))
        git("-C", self.repo, "add", "-u", "--", "old.bin")
        self.assertClean(self.check("--staged"))


class StagedBlobTest(RepoCase):
    def test_the_index_blob_is_checked_not_the_working_copy(self) -> None:
        self.stage("program.exe", TEXT)
        self.write("program.exe", pe())  # edited after staging
        self.assertClean(self.check("--staged"))

    def test_a_later_text_edit_does_not_hide_a_staged_binary(self) -> None:
        self.stage("program.exe", pe())
        self.write("program.exe", TEXT)
        self.assertRejected(self.check("--staged"), "PE image")


class SizeLimitTest(RepoCase):
    def test_a_file_at_the_limit_passes_and_one_byte_more_fails(self) -> None:
        self.stage("at-limit.txt", b"x" * LIMIT)
        self.assertClean(self.check("--staged"))
        self.write("at-limit.txt", b"x" * (LIMIT + 1))
        git("-C", self.repo, "add", "--", "at-limit.txt")
        self.assertRejected(self.check("--staged"), f"{LIMIT + 1} bytes: over the {LIMIT}-byte limit")

    def test_an_oversized_binary_names_both_problems(self) -> None:
        self.stage("big.exe", pe() + bytes(LIMIT))
        self.assertRejected(self.check("--staged"),
                            f"PE image (Windows executable, DLL or driver), {len(pe()) + LIMIT} bytes: "
                            f"over the {LIMIT}-byte limit")

    def test_oversized_files_are_rejected_inside_the_fixture_root_too(self) -> None:
        self.stage("tests/fixtures/big.txt", b"x" * (LIMIT + 1))
        self.assertRejected(self.check("--staged"), "over the")


class FixtureManifestTest(RepoCase):
    def setUp(self) -> None:
        super().setUp()
        self.blob = pe()
        self.entry = f"{sha256(self.blob)}  tests/fixtures/tool.exe"

    def stage_manifest(self, *lines: str, provenance: bool = True) -> None:
        """Stage the fixture manifest.  Every checksum line gets the required
        provenance comment unless the line above it already is one; pass
        provenance=False to test the rule itself."""
        staged: list[str] = []
        for line in lines:
            if provenance and not line.startswith("#") and not (
                    staged and staged[-1].startswith(PROVENANCE)):
                staged.append(PROVENANCE)
            staged.append(line)
        super().stage_manifest(*staged)

    def test_a_fixture_binary_needs_a_manifest_entry(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.assertRejected(self.check("--staged"), f"not listed in {MANIFEST}")

    def test_a_listed_fixture_binary_with_the_right_hash_passes(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.stage_manifest("# generated by a tool that only runs on Windows", self.entry)
        self.assertClean(self.check("--staged"))

    def test_an_entry_without_provenance_is_a_policy_error(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.stage_manifest(self.entry, provenance=False)
        result = self.check("--staged")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("tests/fixtures/tool.exe' has no provenance", result.stderr)

    def test_a_bare_comment_is_not_provenance(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.stage_manifest("# added it for testing", self.entry, provenance=False)
        result = self.check("--staged")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("has no provenance", result.stderr)

    def test_one_provenance_line_vouches_for_one_entry(self) -> None:
        other = f"{sha256(elf(2))}  tests/fixtures/other.so"
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.stage("tests/fixtures/other.so", elf(2))
        self.stage_manifest(PROVENANCE, self.entry, other, provenance=False)
        result = self.check("--staged")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("tests/fixtures/other.so' has no provenance", result.stderr)

    @unittest.skipUnless(shutil.which("sha256sum"), "sha256sum not installed")
    def test_the_manifest_is_verifiable_with_sha256sum(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.stage_manifest(self.entry)
        verify = subprocess.run(["sha256sum", "--check", MANIFEST], cwd=self.repo,
                                capture_output=True, text=True)
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_a_changed_fixture_binary_is_rejected(self) -> None:
        self.stage_manifest(self.entry)
        self.stage("tests/fixtures/tool.exe", self.blob + b"\x90")
        self.assertRejected(self.check("--staged"), f"content differs from its {MANIFEST} entry")

    def test_a_manifest_entry_does_not_help_outside_the_fixture_root(self) -> None:
        self.stage_manifest(f"{sha256(self.blob)}  samples/tool.exe")
        self.stage("samples/tool.exe", self.blob)
        self.assertRejected(self.check("--staged"), "binaries are only tracked under tests/fixtures/")

    def test_a_prefix_shared_with_the_fixture_root_is_not_the_fixture_root(self) -> None:
        self.stage_manifest(f"{sha256(self.blob)}  tests/fixtures-extra/tool.exe")
        self.stage("tests/fixtures-extra/tool.exe", self.blob)
        self.assertRejected(self.check("--staged"), "binaries are only tracked under tests/fixtures/")

    def test_the_manifest_entry_must_be_staged_too(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.write(MANIFEST, f"{PROVENANCE}\n{self.entry}\n".encode("utf-8"))  # working tree only
        self.assertRejected(self.check("--staged"), f"not listed in {MANIFEST}")
        git("-C", self.repo, "add", "--", MANIFEST)
        self.assertClean(self.check("--staged"))

    def test_a_malformed_manifest_is_a_policy_error(self) -> None:
        self.stage_manifest("not-a-checksum-line")
        self.stage("tests/fixtures/tool.exe", self.blob)
        result = self.check("--staged")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("not in sha256sum format", result.stderr)

    def test_a_renamed_fixture_needs_a_new_manifest_entry(self) -> None:
        self.stage("tests/fixtures/tool.exe", self.blob)
        self.stage_manifest(self.entry)
        self.commit()
        git("-C", self.repo, "mv", "--", "tests/fixtures/tool.exe", "tests/fixtures/renamed.exe")
        self.assertRejected(self.check("--staged"), f"not listed in {MANIFEST}")


class AllModeTest(RepoCase):
    def test_all_covers_every_tracked_file(self) -> None:
        self.stage("a.txt", TEXT)
        self.stage("src/b.md", TEXT)
        self.commit()
        result = self.check("--all")
        self.assertClean(result)
        self.assertIn("2 file(s) checked, 0 violation(s), clean", result.stdout)

    def test_all_reports_a_binary_added_to_the_index(self) -> None:
        self.stage("a.txt", TEXT)
        self.commit()
        self.stage("later.bin", elf(4))
        self.assertRejected(self.check("--all"), "ELF core dump", "later.bin")

    def test_all_ignores_untracked_working_tree_files(self) -> None:
        self.stage("a.txt", TEXT)
        self.commit()
        self.write("untracked.bin", pe())
        self.assertClean(self.check("--all"))

    def test_all_needs_a_git_work_tree(self) -> None:
        bare = tempfile.mkdtemp(prefix="x2p-assets-bare-")
        self.addCleanup(shutil.rmtree, bare, ignore_errors=True)
        result = self.check("--all", cwd=bare)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("inside a git work tree", result.stderr)


class ExplicitPathsModeTest(RepoCase):
    def test_explicit_paths_are_checked_even_when_ignored(self) -> None:
        self.stage(".gitignore", b"*.bin\n")
        self.commit()
        self.write("ignored.bin", elf(2))
        self.assertRejected(self.check("ignored.bin"), "ELF executable")

    def test_explicit_text_paths_pass_from_any_directory(self) -> None:
        self.stage("docs/readme.md", TEXT)
        self.assertClean(self.check("docs/readme.md"))
        # Run from a directory that is not a git work tree: the repository is
        # found from the path, and the path still resolves to its
        # repository-relative name (so a manifest entry would match).
        elsewhere = tempfile.mkdtemp(prefix="x2p-assets-cwd-")
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        beside = os.path.join("..", os.path.basename(self.repo), "docs/readme.md")
        self.assertClean(self.check(beside, cwd=elsewhere))
        self.write("tests/fixtures/tool.exe", pe())
        rejected = self.check(os.path.join("..", os.path.basename(self.repo), "tests/fixtures/tool.exe"),
                              cwd=elsewhere)
        self.assertRejected(rejected, "tests/fixtures/tool.exe")

    def test_a_missing_path_is_reported(self) -> None:
        self.assertRejected(self.check("no-such-file.txt"), "file does not exist")

    def test_a_directory_is_reported(self) -> None:
        self.write("dir/.keep", b"")
        self.assertRejected(self.check("dir"), "only regular files and symlinks can be checked")


class CommandLineTest(RepoCase):
    def test_a_mode_is_required(self) -> None:
        for args in ((), ("--staged", "x.txt"), ("--all", "--staged")):
            with self.subTest(args=args):
                result = self.check(*args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_annotations_are_emitted_on_request(self) -> None:
        self.stage("bad.exe", pe())
        result = self.check("--staged", "--annotations")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("::error file=bad.exe::PE image", result.stdout)

    def test_help_describes_the_modes(self) -> None:
        result = self.check("--help")
        self.assertEqual(result.returncode, 0, result.stdout)
        for mode in ("--staged", "--all", "--annotations"):
            self.assertIn(mode, result.stdout)


if __name__ == "__main__":
    unittest.main()
