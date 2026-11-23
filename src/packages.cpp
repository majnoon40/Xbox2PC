// packages.cpp — M5 package abstraction: bounded reader, classification,
// XPK (synthetic) parser/builder. Adversarial validation throughout.

#include "xbox2pc/packages.hpp"

#include <cstring>
#include <iterator>
#include <map>
#include <set>
#include <utility>

namespace xbox2pc::rt {

// ── checked arithmetic ─────────────────────────────────────────────────────

Result<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) {
    if (a > UINT64_MAX - b) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "integer overflow in offset arithmetic");
    }
    return Result<std::uint64_t>(a + b);
}

// ── BoundedReader ─────────────────────────────────────────────────────────

BoundedReader::BoundedReader(const std::uint8_t* data, std::uint64_t size)
    : data_(data), size_(size) {}

Result<void> BoundedReader::read_exact(void* out, std::uint64_t len) {
    if (len == 0) return Result<void>::ok_result();
    if (out == nullptr || data_ == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "null bounded-reader buffer");
    }
    if (len > remaining()) {
        return Result<void>(RuntimeErrc::OutOfResources,
                            "read past end: want " + std::to_string(len) +
                                " bytes, have " + std::to_string(remaining()));
    }
    std::memcpy(out, data_ + pos_, static_cast<std::size_t>(len));
    pos_ += len;
    return Result<void>::ok_result();
}

Result<std::uint64_t> BoundedReader::read_some(void* out, std::uint64_t len) {
    const std::uint64_t n = len < remaining() ? len : remaining();
    if (n == 0) return Result<std::uint64_t>(0);
    if (out == nullptr || data_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "null bounded-reader buffer");
    }
    std::memcpy(out, data_ + pos_, static_cast<std::size_t>(n));
    pos_ += n;
    return Result<std::uint64_t>(n);
}

Result<std::vector<std::uint8_t>> BoundedReader::peek(std::uint64_t offset,
                                                      std::uint64_t len) const {
    auto end = checked_add(offset, len);
    if (!end.ok()) {
        return Result<std::vector<std::uint8_t>>(end.errc(), end.context());
    }
    if (end.value() > size_) {
        return Result<std::vector<std::uint8_t>>(
            RuntimeErrc::OutOfResources,
            "peek out of bounds: [" + std::to_string(offset) + ", " +
                std::to_string(end.value()) + ") vs size " +
                std::to_string(size_));
    }
    if (len == 0) return Result<std::vector<std::uint8_t>>(std::vector<std::uint8_t>{});
    if (data_ == nullptr) {
        return Result<std::vector<std::uint8_t>>(
            RuntimeErrc::InvalidArgument, "null bounded-reader buffer");
    }
    std::vector<std::uint8_t> out(
        data_ + offset, data_ + offset + len);
    return Result<std::vector<std::uint8_t>>(std::move(out));
}

Result<void> BoundedReader::seek(std::uint64_t position) {
    if (position > size_) {
        return Result<void>(RuntimeErrc::InvalidArgument, "seek past end");
    }
    pos_ = position;
    return Result<void>::ok_result();
}

Result<std::uint16_t> BoundedReader::u16le() {
    std::uint8_t b[2];
    auto r = read_exact(b, 2);
    if (!r.ok()) return Result<std::uint16_t>(r.errc(), r.context());
    return Result<std::uint16_t>(
        static_cast<std::uint16_t>(b[0]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[1]) << 8));
}

Result<std::uint32_t> BoundedReader::u32le() {
    std::uint8_t b[4];
    auto r = read_exact(b, 4);
    if (!r.ok()) return Result<std::uint32_t>(r.errc(), r.context());
    return Result<std::uint32_t>(
        static_cast<std::uint32_t>(b[0]) |
        (static_cast<std::uint32_t>(b[1]) << 8) |
        (static_cast<std::uint32_t>(b[2]) << 16) |
        (static_cast<std::uint32_t>(b[3]) << 24));
}

Result<std::uint64_t> BoundedReader::u64le() {
    std::uint8_t b[8];
    auto r = read_exact(b, 8);
    if (!r.ok()) return Result<std::uint64_t>(r.errc(), r.context());
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | b[i];
    }
    return Result<std::uint64_t>(v);
}

// ── classification (conservative, evidence-graded) ─────────────────────────

FormatClassification classify_bytes(const std::uint8_t* data, std::uint64_t size,
                                     const std::string& name_hint) {
    FormatClassification c;
    if (data == nullptr) {
        c.label = "unknown";
        c.parseable = false;
        c.evidence_note = "null input buffer";
        return c;
    }
    // XPK: fully specified by this project → parseable.
    if (size >= 4 && data[0] == 'X' && data[1] == 'P' && data[2] == 'K' &&
        data[3] == '1') {
        c.label = "xpk-synthetic";
        c.parseable = true;
        c.evidence_note = "xbox2pc-defined synthetic format (NOT an Xbox "
                          "format); full spec in include/xbox2pc/packages.hpp";
        return c;
    }
    // XVC/XVD: byte-level identification is NOT available from published
    // sources (docs/package-formats.md). We classify ONLY from the
    // caller-supplied name hint and never claim byte-level recognition.
    const std::string lower = [&] {
        std::string s = name_hint;
        for (char& ch : s) {
            if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        }
        return s;
    }();
    const auto ends_with = [&](const char* suffix) {
        const std::string suf = suffix;
        return lower.size() >= suf.size() &&
               lower.compare(lower.size() - suf.size(), suf.size(), suf) == 0;
    };
    if (ends_with(".xvc") || ends_with(".msixvc")) {
        c.label = "xvc";
        c.parseable = false;
        c.evidence_note =
            "XVC = Xbox Virtual Container (Microsoft GDK docs: created by "
            "MakePkg for title content). Byte-level layout is not reliably "
            "published (see docs/package-formats.md): xvdtool's xvd_info.md "
            "documents the 0x0-0x200 signature region, SHA-256 hash trees, "
            "AES-128-XTS encryption and an NTFS payload, but no magic values "
            "or header/entry field layout; retail key material is unknown. "
            "xbox2pc refuses speculative parsing of XVC.";
        return c;
    }
    if (ends_with(".xvd")) {
        c.label = "xvd";
        c.parseable = false;
        c.evidence_note =
            "XVD = Xbox system-image container (xvdtool: 'secured file "
            "format used by the Xbox One to store data'; XVC is a variant). "
            "Same evidence gap as XVC: no published magic/header layout; "
            "see docs/package-formats.md. xbox2pc refuses speculative "
            "parsing of XVD.";
        return c;
    }
    c.label = "unknown";
    c.parseable = false;
    c.evidence_note =
        "No known container signature matched; no speculative identification";
    return c;
}

// ── parse_package ──────────────────────────────────────────────────────────

Result<std::unique_ptr<ParsedPackage>> parse_package(
    const std::uint8_t* data, std::uint64_t size, const std::string& name_hint,
    const PackageLimits& limits) {
    if (data == nullptr && size != 0) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::InvalidArgument, "null data with nonzero size");
    }
    if (size < 4) {
        // Even classification needs 4 bytes; the classification itself
        // still runs below via classify_bytes (which handles short input).
        const auto cls = classify_bytes(data, size, name_hint);
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::OutOfResources,
            "container too small (" + std::to_string(size) +
                " bytes) for any known format; classified '" + cls.label + "'");
    }
    const auto cls = classify_bytes(data, size, name_hint);
    if (cls.label == "xpk-synthetic") {
        auto buffer = std::make_shared<std::vector<std::uint8_t>>(data, data + size);
        return XpkPackage::parse(std::move(buffer), limits);
    }
    // XVC/XVD/unknown: typed unsupported-format with the evidence note.
    // Distinct errc so CLI shows a clear "unsupported format" message.
    return Result<std::unique_ptr<ParsedPackage>>(
        RuntimeErrc::PlatformUnsupported,
        "unsupported container format '" + cls.label + "': " + cls.evidence_note);
}

// ── XPK parser ─────────────────────────────────────────────────────────────

namespace {

constexpr std::uint64_t kXpkHeaderSize = 32;       // fixed header floor
constexpr std::uint64_t kXpkEntrySize = 32;       // entry table record

bool xpk_name_char_ok(char c) {
    // '/' is ALLOWED here: names are full '/'-joined paths; components
    // are validated after the split (empty/./.. rejection below).
    const auto uc = static_cast<unsigned char>(c);
    return uc >= 0x20 && uc != 0x7F && c != '\\';
}

}  // namespace

Result<std::unique_ptr<ParsedPackage>> XpkPackage::parse(
    std::shared_ptr<std::vector<std::uint8_t>> buffer,
    const PackageLimits& limits) {
    if (buffer == nullptr || buffer->empty()) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::InvalidArgument, "empty buffer");
    }
    BoundedReader r(buffer->data(), buffer->size());

    // Header (fixed fields; magic already matched by the caller).
    (void)r.seek(4);
    const auto version = r.u16le();
    if (!version.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(version.errc(),
                                                      version.context());
    }
    if (version.value() != kXpkVersion) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::InvalidArgument,
            "unsupported XPK version " + std::to_string(version.value()) +
                " (supported: " + std::to_string(kXpkVersion) + ")");
    }
    const auto flags = r.u16le();
    if (!flags.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(flags.errc(),
                                                      flags.context());
    }
    if ((flags.value() & 0x0001) != 0) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::InvalidArgument, "reserved flag bit0 set");
    }
    const auto entry_count = r.u32le();
    if (!entry_count.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(entry_count.errc(),
                                                      entry_count.context());
    }
    const auto name_region_size = r.u32le();
    if (!name_region_size.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(name_region_size.errc(),
                                                      name_region_size.context());
    }
    const auto data_region_size = r.u64le();
    if (!data_region_size.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(data_region_size.errc(),
                                                      data_region_size.context());
    }
    const auto entry_table_offset = r.u64le();
    if (!entry_table_offset.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(entry_table_offset.errc(),
                                                      entry_table_offset.context());
    }

    // Limit enforcement BEFORE any allocation (never trust metadata).
    if (entry_count.value() > limits.max_entries) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::OutOfResources,
            "entry count " + std::to_string(entry_count.value()) +
                " exceeds limit " + std::to_string(limits.max_entries));
    }
    if (name_region_size.value() > limits.max_metadata_size) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::OutOfResources,
            "name region " + std::to_string(name_region_size.value()) +
                " exceeds metadata limit");
    }
    if (data_region_size.value() > limits.max_total_data_size) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::OutOfResources,
            "data region " + std::to_string(data_region_size.value()) +
                " exceeds total-data limit");
    }

    // Region bounds: header floor + regions must cover the whole file
    // EXACTLY (no unaccounted slack — truncated OR padded files rejected).
    const std::uint64_t k = kXpkHeaderSize;
    auto name_end = checked_add(k, name_region_size.value());
    if (!name_end.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(name_end.errc(),
                                                      name_end.context());
    }
    auto table_end = checked_add(entry_table_offset.value(),
                                 entry_count.value() * kXpkEntrySize);
    if (!table_end.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(table_end.errc(),
                                                      table_end.context());
    }
    auto data_end = checked_add(table_end.value(), data_region_size.value());
    if (!data_end.ok()) {
        return Result<std::unique_ptr<ParsedPackage>>(data_end.errc(),
                                                      data_end.context());
    }
    if (data_end.value() != buffer->size()) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::InvalidArgument,
            "regions do not cover the file exactly (computed end " +
                std::to_string(data_end.value()) + " vs size " +
                std::to_string(buffer->size()) + ")");
    }
    // Layout order: header | names | table | data (entry_table_offset must
    // equal the post-name boundary).
    if (entry_table_offset.value() != name_end.value()) {
        return Result<std::unique_ptr<ParsedPackage>>(
            RuntimeErrc::InvalidArgument,
            "entry table offset must follow the name region");
    }

    // Parse entries.
    std::vector<PackageEntry> entries;
    entries.reserve(entry_count.value());
    // Parent-tracking: table order must list a directory before its
    // children (format invariant — validated).
    std::set<std::string> known_paths;
    std::set<std::string> dir_paths;
    // Overlap tracking for file data spans (forbidden by the format).
    std::map<std::uint64_t, std::uint64_t> spans;  // start -> exclusive end
    std::uint64_t data_cursor = table_end.value();  // data region base

    for (std::uint32_t i = 0; i < entry_count.value(); ++i) {
        (void)r.seek(entry_table_offset.value() + i * kXpkEntrySize);
        const auto name_off = r.u64le();
        if (!name_off.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(name_off.errc(),
                                                          name_off.context());
        }
        const auto name_len = r.u16le();
        if (!name_len.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(name_len.errc(),
                                                          name_len.context());
        }
        const auto eflags = r.u16le();
        if (!eflags.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(eflags.errc(),
                                                          eflags.context());
        }
        if ((eflags.value() & ~0x0001) != 0) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::InvalidArgument, "entry flags use reserved bits");
        }
        const bool is_dir = (eflags.value() & 0x0001) != 0;
        const auto depth = r.u32le();
        if (!depth.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(depth.errc(),
                                                          depth.context());
        }
        if (depth.value() > limits.max_nesting_depth) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::OutOfResources,
                "entry path depth " + std::to_string(depth.value()) +
                    " exceeds nesting limit");
        }
        const auto data_off = r.u64le();
        if (!data_off.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(data_off.errc(),
                                                          data_off.context());
        }
        const auto data_size = r.u64le();
        if (!data_size.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(data_size.errc(),
                                                          data_size.context());
        }
        if (!is_dir && data_size.value() > limits.max_entry_data_size) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::OutOfResources,
                "entry data size " + std::to_string(data_size.value()) +
                    " exceeds per-entry limit");
        }

        // Name region access (bounds-checked via checked_add).
        auto name_abs = checked_add(k + 0, name_off.value());
        if (!name_abs.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(name_abs.errc(),
                                                          name_abs.context());
        }
        auto name_end_abs = checked_add(name_abs.value(), name_len.value());
        if (!name_end_abs.ok()) {
            return Result<std::unique_ptr<ParsedPackage>>(name_end_abs.errc(),
                                                          name_end_abs.context());
        }
        if (name_end_abs.value() > k + name_region_size.value()) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::InvalidArgument,
                "entry name out of the name region");
        }
        if (name_len.value() == 0) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::InvalidArgument, "entry name is empty");
        }
        if (name_len.value() > limits.max_name_length) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::OutOfResources,
                "entry name length exceeds limit");
        }
        // Reconstruct the name's components: the name region stores the
        // FULL path of this entry ('/'-joined, same charset rules).
        const std::string raw_name(
            reinterpret_cast<const char*>(buffer->data()) + name_abs.value(),
            name_len.value());
        for (char c : raw_name) {
            if (!xpk_name_char_ok(c)) {
                return Result<std::unique_ptr<ParsedPackage>>(
                    RuntimeErrc::InvalidArgument,
                    "entry name contains an invalid character");
            }
        }
        // Split into components; empty segments are forbidden.
        std::vector<std::string> comps;
        std::string cur;
        for (char c : raw_name) {
            if (c == '/') {
                if (cur.empty()) {
                    return Result<std::unique_ptr<ParsedPackage>>(
                        RuntimeErrc::InvalidArgument, "empty path component");
                }
                comps.push_back(std::move(cur));
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) comps.push_back(cur);
        else {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::InvalidArgument, "entry name ends with '/'");
        }
        if (comps.size() != depth.value() + 1) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::InvalidArgument,
                "declared path depth does not match the name");
        }
        for (const auto& c : comps) {
            if (c == "." || c == "..") {
                return Result<std::unique_ptr<ParsedPackage>>(
                    RuntimeErrc::InvalidArgument, "reserved path component");
            }
        }
        // Parent must exist as a known DIRECTORY (table order invariant).
        if (depth.value() > 0) {
            std::string parent_key;
            for (std::size_t j = 0; j + 1 < comps.size(); ++j) {
                if (j > 0) parent_key.push_back('/');
                parent_key.append(comps[j]);
            }
            if (dir_paths.count(parent_key) == 0) {
                return Result<std::unique_ptr<ParsedPackage>>(
                    RuntimeErrc::InvalidArgument,
                    "parent directory not declared before its child: " +
                        parent_key);
            }
        }
        // Duplicate full-path rejection (files AND directories).
        std::string full_key;
        for (const auto& c : comps) {
            if (!full_key.empty()) full_key.push_back('/');
            full_key.append(c);
        }
        if (!known_paths.insert(full_key).second) {
            return Result<std::unique_ptr<ParsedPackage>>(
                RuntimeErrc::AlreadyExists, "duplicate entry path: " + full_key);
        }

        PackageEntry e;
        if (comps.size() > 1) {
            e.path.assign(comps.begin(), comps.end() - 1);
        }
        e.name = comps.back();
        e.is_directory = is_dir;
        if (!is_dir) {
            // Data span: offset relative to the DATA region.
            auto abs_off = checked_add(data_cursor, data_off.value());
            if (!abs_off.ok()) {
                return Result<std::unique_ptr<ParsedPackage>>(abs_off.errc(),
                                                              abs_off.context());
            }
            auto abs_end = checked_add(abs_off.value(), data_size.value());
            if (!abs_end.ok()) {
                return Result<std::unique_ptr<ParsedPackage>>(abs_end.errc(),
                                                              abs_end.context());
            }
            if (abs_end.value() > data_end.value()) {
                return Result<std::unique_ptr<ParsedPackage>>(
                    RuntimeErrc::InvalidArgument,
                    "entry data span out of the data region");
            }
            // O(log n) overlap check. A linear scan here made a valid
            // package with many tiny files quadratic to parse (CPU DoS).
            if (data_size.value() != 0) {
                const auto next = spans.lower_bound(abs_off.value());
                if (next != spans.end() && abs_end.value() > next->first) {
                    return Result<std::unique_ptr<ParsedPackage>>(
                        RuntimeErrc::InvalidArgument,
                        "entry data spans overlap (forbidden by the format)");
                }
                if (next != spans.begin()) {
                    const auto prev = std::prev(next);
                    if (prev->second > abs_off.value()) {
                        return Result<std::unique_ptr<ParsedPackage>>(
                            RuntimeErrc::InvalidArgument,
                            "entry data spans overlap (forbidden by the format)");
                    }
                }
                spans.emplace(abs_off.value(), abs_end.value());
            }
            e.offset = abs_off.value();
            e.size = data_size.value();
        }
        entries.push_back(std::move(e));
        if (is_dir) {
            dir_paths.insert(full_key);
        }
    }

    auto out = std::unique_ptr<XpkPackage>(new XpkPackage());
    out->buf_ = buffer;
    out->info_.format_name = "xpk-synthetic";
    out->info_.synthetic = true;
    out->info_.version = kXpkVersion;
    out->info_.entry_count = entries.size();
    out->info_.entries = std::move(entries);
    return Result<std::unique_ptr<ParsedPackage>>(
        std::unique_ptr<ParsedPackage>(out.release()));
}

Result<std::vector<std::uint8_t>> XpkPackage::read_entry_data(
    std::uint64_t entry_index) {
    if (entry_index >= info_.entries.size()) {
        return Result<std::vector<std::uint8_t>>(
            RuntimeErrc::NotFound,
            "entry index " + std::to_string(entry_index) + " out of range");
    }
    const PackageEntry& e = info_.entries[static_cast<std::size_t>(entry_index)];
    if (e.is_directory) {
        return Result<std::vector<std::uint8_t>>(
            RuntimeErrc::InvalidArgument, "entry is a directory");
    }
    auto end = checked_add(e.offset, e.size);
    if (!end.ok() || end.value() > buf_->size()) {
        return Result<std::vector<std::uint8_t>>(
            RuntimeErrc::InvalidArgument, "entry data out of bounds");
    }
    std::vector<std::uint8_t> out(buf_->data() + e.offset,
                                  buf_->data() + e.offset + e.size);
    return Result<std::vector<std::uint8_t>>(std::move(out));
}

// ── XPK builder (fixtures; clearly synthetic) ──────────────────────────────

namespace {
void put_u16le(std::vector<std::uint8_t>& v, std::uint16_t x) {
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
    v.push_back(static_cast<std::uint8_t>(x >> 8));
}
void put_u32le(std::vector<std::uint8_t>& v, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
    }
}
void put_u64le(std::vector<std::uint8_t>& v, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
    }
}
}  // namespace

std::vector<std::uint8_t> xpk_build(const std::vector<XpkBuildEntry>& raw_entries) {
    // Canonify first: EVERY parent directory gets an explicit directory
    // entry (parents emitted before their children — the format's table
    // invariant requires it; the builder never relies on the caller
    // pre-declaring them). Duplicate directory entries collapse.
    std::vector<XpkBuildEntry> entries;
    std::set<std::string> seen_dirs;
    // Pass 1: directories, in path order (parents first).
    for (const auto& e : raw_entries) {
        // Every ancestor of e.path AND e.path itself (when marked dir).
        std::vector<std::string> comps;
        std::string cur;
        for (char c : e.path) {
            if (c == '/') { comps.push_back(std::move(cur)); cur.clear(); }
            else cur.push_back(c);
        }
        comps.push_back(std::move(cur));
        std::string prefix;
        const std::size_t depth = e.is_directory ? comps.size() : comps.size() - 1;
        for (std::size_t i = 0; i < depth; ++i) {
            if (!prefix.empty()) prefix.push_back('/');
            prefix.append(comps[i]);
            if (seen_dirs.insert(prefix).second) {
                entries.push_back({prefix, true, ""});
            }
        }
    }
    // Pass 2: the caller's entries (dirs were materialized above; keep the
    // caller's own dir entries only if not already emitted — file
    // duplicates remain the caller's responsibility; parse rejects them).
    for (const auto& e : raw_entries) {
        if (!e.is_directory) entries.push_back(e);
    }
    // Stable order requirement: the format's table invariant is
    // parent-before-child for FILES; directories were all emitted in
    // pass 1 (sorted by construction order per pass-1 path order) — the
    // file entries follow, so parents always precede children.
    // Canonical build: all paths ('/'-joined names), then the entry
    // table, then concatenated file data (given order, no overlaps).
    std::vector<std::uint8_t> out;
    out.insert(out.end(), {'X', 'P', 'K', '1'});
    put_u16le(out, kXpkVersion);
    put_u16le(out, 0);  // flags
    put_u32le(out, static_cast<std::uint32_t>(entries.size()));
    // Names region length: sum of (path length) bytes.
    std::uint64_t name_bytes = 0;
    for (const auto& e : entries) {
        name_bytes += e.path.size();
    }
    put_u32le(out, static_cast<std::uint32_t>(name_bytes));
    // Data size + table offset filled after lengths are known.
    std::uint64_t data_bytes = 0;
    for (const auto& e : entries) {
        if (!e.is_directory) data_bytes += e.data.size();
    }
    put_u64le(out, data_bytes);
    const std::uint64_t table_offset = kXpkHeaderSize + name_bytes;
    put_u64le(out, table_offset);
    // Names region.
    std::map<std::string, std::uint64_t> name_offsets;  // path -> offset
    std::uint64_t name_cursor = 0;
    for (const auto& e : entries) {
        name_offsets[e.path] = name_cursor;
        out.insert(out.end(), e.path.begin(), e.path.end());
        name_cursor += e.path.size();
    }
    // Entry table.
    std::uint64_t data_cursor = 0;
    std::map<std::string, std::uint64_t> data_offsets;  // path -> data off
    for (const auto& e : entries) {
        if (!e.is_directory) {
            data_offsets[e.path] = data_cursor;
            data_cursor += e.data.size();
        }
    }
    for (const auto& e : entries) {
        std::vector<std::string> comps;
        {
            std::string cur;
            for (char c : e.path) {
                if (c == '/') {
                    comps.push_back(std::move(cur));
                    cur.clear();
                } else {
                    cur.push_back(c);
                }
            }
            comps.push_back(std::move(cur));
        }
        put_u64le(out, name_offsets[e.path]);
        put_u16le(out, static_cast<std::uint16_t>(e.path.size()));
        put_u16le(out, e.is_directory ? 1 : 0);
        put_u32le(out, static_cast<std::uint32_t>(comps.size() - 1));
        put_u64le(out, e.is_directory ? 0 : data_offsets[e.path]);
        put_u64le(out, e.is_directory ? 0 : e.data.size());
    }
    // Data region.
    for (const auto& e : entries) {
        if (!e.is_directory) {
            out.insert(out.end(), e.data.begin(), e.data.end());
        }
    }
    return out;
}

}  // namespace xbox2pc::rt
