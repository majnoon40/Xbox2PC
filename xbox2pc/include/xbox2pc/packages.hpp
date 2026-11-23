#pragma once
// xbox2pc/packages.hpp — M5 package/container abstraction.
//
// Evidence grading (docs/package-formats.md — sources cited there):
//   * XVC (Xbox Virtual Container, MakePkg output) and XVD (system images)
//     are CONFIRMED to exist as Microsoft's package/container family
//     (Microsoft GDK docs; xvdtool project). Their BYTE-LEVEL layouts
//     (magic, header fields, entry tables) are NOT reliably published:
//     the best available source (xvdtool xvd_info.md) documents only the
//     0x0–0x200 signature region, SHA-256 hash trees, AES-128-XTS
//     encryption and an NTFS payload — and flags the retail key material
//     as unknown. We therefore do NOT implement an XVC/XVD parser: the
//     magic probe CLASSIFIES them and returns a typed
//     "unsupported-format" result with that evidence note. No speculative
//     parsing, no invented fields (M5 rule).
//   * XPK ("xbox2pc package", SYNTHETIC): a fully specified, obviously
//     synthetic format defined by this project for exercising the
//     container interface, mounting and discovery with real adversarial
//     tests. Every artifact is labeled synthetic; it is never presented
//     as an Xbox format.
//
// Parser safety: all parsers run through BoundedReader (fixed buffer +
// position ceiling; every read bounds-checked); declared counts/sizes are
// validated against arithmetic ceilings (no overflow: checked adds) and
// configurable PackageLimits before any allocation; entries are
// duplicate-checked; names validated (length, charset, no separators);
// regions checked for overlap where forbidden.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt {

// ── bounded reader ─────────────────────────────────────────────────────────

class BoundedReader {
public:
    // `data` must outlive the reader. size == the container's total size.
    BoundedReader(const std::uint8_t* data, std::uint64_t size);

    std::uint64_t position() const { return pos_; }
    std::uint64_t remaining() const { return size_ - pos_; }
    std::uint64_t size() const { return size_; }

    // Reads exactly `len` bytes; typed OutOfResources when past the end
    // (message says how much was wanted vs available).
    Result<void> read_exact(void* out, std::uint64_t len);
    // Reads up to `len` (returns byte count).
    Result<std::uint64_t> read_some(void* out, std::uint64_t len);
    // Bytes at offset..offset+len without moving (typed bounds check).
    Result<std::vector<std::uint8_t>> peek(std::uint64_t offset,
                                          std::uint64_t len) const;
    Result<void> seek(std::uint64_t position);

    // Little-endian fixed-width readers (bounds-checked).
    Result<std::uint16_t> u16le();
    Result<std::uint32_t> u32le();
    Result<std::uint64_t> u64le();

private:
    const std::uint8_t* data_;
    std::uint64_t size_ = 0;
    std::uint64_t pos_ = 0;
};

// Checked addition for offset arithmetic: fails typed on overflow.
Result<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b);

// ── limits ─────────────────────────────────────────────────────────────────

struct PackageLimits {
    std::uint32_t max_entries = 4096;
    std::uint32_t max_name_length = 255;
    std::uint64_t max_metadata_size = 64 * 1024;
    std::uint64_t max_entry_data_size = 256 * 1024 * 1024;
    std::uint64_t max_total_data_size = 512 * 1024 * 1024;
    std::uint32_t max_nesting_depth = 8;   // directory tree depth
};

// ── container interface ────────────────────────────────────────────────────

struct PackageEntry {
    std::string name;              // validated (charset/length, no '/')
    std::vector<std::string> path; // parent components (no ".."/".")
    bool is_directory = false;
    std::uint64_t offset = 0;      // within the container (files only)
    std::uint64_t size = 0;        // payload size (files only)
};

struct PackageInfo {
    std::string format_name;      // "xpk-synthetic" | classification label
    bool synthetic = true;        // true for xbox2pc-defined formats
    std::uint32_t version = 0;
    std::uint64_t entry_count = 0;
    std::vector<PackageEntry> entries;
};

// Parsed container: entry metadata + payload access. Implementations keep
// the source buffer alive (shared_ptr) so handles survive independently.
class ParsedPackage {
public:
    virtual ~ParsedPackage() = default;

    virtual const PackageInfo& info() const = 0;
    // Entry payload read (bounds-checked against the entry's size).
    virtual Result<std::vector<std::uint8_t>> read_entry_data(
        std::uint64_t entry_index) = 0;
};

// ── format identification (magic probe; no speculative parsing) ──────────
//
// Evidence-graded classification:
//   * XVC / XVD bytes → classified by label only; parse returns typed
//     UnsupportedFormat with the evidence note. We do NOT claim any
//     header structure beyond what the cited sources document (they
//     document none of the magic) — so even the probe is CONSERVATIVE:
//     it matches the well-known filename-extension/heuristic ONLY when a
//     caller explicitly supplies a label hint (e.g. ".xvc"), and states
//     that byte-level identification is not available.
struct FormatClassification {
    std::string label;            // "xvc" | "xvd" | "xpk-synthetic" | "unknown"
    bool parseable = false;       // a parser exists in this build
    std::string evidence_note;    // documented provenance/evidence grade
};

FormatClassification classify_bytes(const std::uint8_t* data, std::uint64_t size,
                                    const std::string& name_hint);

// Parse a container. Returns UnsupportedFormat for XVC/XVD (typed) with
// the evidence note; parses XPK fully.
Result<std::unique_ptr<ParsedPackage>> parse_package(
    const std::uint8_t* data, std::uint64_t size, const std::string& name_hint,
    const PackageLimits& limits = {});

// ── XPK (xbox2pc SYNTHETIC package format) ──────────────────────────────────
//
// Spec (project-defined; NOT an Xbox format — the magic is deliberately
// unlike any cited Xbox signature):
//
//   offset  size  field
//   0       4     magic "XPK1" (0x58 0x50 0x4B 0x31)
//   4       2     format version (1; reject others)
//   6       2     flags (bit0: reserved; must be 0)
//   8       4     entry_count (u32 LE; validated against limits)
//   12      4     name_region_size (u32 LE; bounds-checked)
//   16      8     data_region_size (u64 LE; ceiling-checked)
//   24      8     entry_table_offset (u64 LE; == 32 + name_region_size)
//   32      ..    name region (entry names, '/'-joined full paths)
//   ..      ..    entry table (entry_count * 32 bytes):
//                     0  8   name_offset (u64 LE, into name region)
//                     8  2   name_length (u16 LE)
//                     10 2   flags (bit0 = directory)
//                     12 4   path_depth (u32 LE; parent components)
//                     16 8   data_offset (u64 LE; into data region)
//                     24 8   data_size (u64 LE; files only)
//   ..      ..    data region (payloads, concatenated)
//
// Validation (all adversarially tested):
//   * header floor 32 bytes; total size covers every region;
//   * entry table fits; every entry's name offset/length lands in the name
//     region; names use the VFS charset (printable, no '/', no "..");
//   * path_depth bounds + parent names present (stored in name region
//     BEFORE their children — implied by table order; validated);
//   * file data_offset+size lands in the data region; no overlaps among
//     file data spans (forbidden by the format);
//   * duplicate full paths rejected; directory/file type conflicts rejected;
//   * count/size limits enforced BEFORE allocation.

constexpr std::uint32_t kXpkVersion = 1;

// Serializes entries into an XPK container (fixture building in tests and
// the CLI demo; clearly labeled synthetic).
struct XpkBuildEntry {
    std::string path;      // "a/b/file.bin" ('/'-separated)
    bool is_directory = false;
    std::string data;      // file payload
};
std::vector<std::uint8_t> xpk_build(const std::vector<XpkBuildEntry>& entries);

// XPK parser (used by parse_package).
class XpkPackage : public ParsedPackage {
public:
    // Takes shared ownership of the buffer.
    static Result<std::unique_ptr<ParsedPackage>> parse(
        std::shared_ptr<std::vector<std::uint8_t>> buffer,
        const PackageLimits& limits);

    const PackageInfo& info() const override { return info_; }
    Result<std::vector<std::uint8_t>> read_entry_data(
        std::uint64_t entry_index) override;

private:
    XpkPackage() = default;
    PackageInfo info_;
    std::shared_ptr<std::vector<std::uint8_t>> buf_;
};

}  // namespace xbox2pc::rt
