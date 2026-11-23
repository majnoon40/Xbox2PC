// package_vfs.cpp — M5 package mounting backend + discovery.

#include "xbox2pc/package_vfs.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "xbox2pc/packages.hpp"

namespace xbox2pc::rt {

// ── PackageFileHandle ─────────────────────────────────────────────────────

PackageFileHandle::PackageFileHandle(std::shared_ptr<std::vector<std::uint8_t>> buffer,
                                     std::uint64_t offset, std::uint64_t size)
    : buf_(std::move(buffer)), offset_(offset), size_(size) {
    valid_ = buf_ && offset_ <= buf_->size() &&
             size_ <= static_cast<std::uint64_t>(buf_->size()) - offset_;
}

Result<std::uint64_t> PackageFileHandle::read(void* buf, std::uint64_t len) {
    if (!valid_) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "package file range is invalid");
    }
    if (len == 0) return Result<std::uint64_t>(0);
    if (buf == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "null read buffer");
    }
    std::lock_guard lock(lock_);
    if (pos_ >= size_) return Result<std::uint64_t>(0);
    const std::uint64_t avail = std::min<std::uint64_t>(len, size_ - pos_);
    std::memcpy(buf, buf_->data() + static_cast<std::size_t>(offset_ + pos_),
                static_cast<std::size_t>(avail));
    pos_ += avail;
    return Result<std::uint64_t>(avail);
}

Result<std::uint64_t> PackageFileHandle::write(const void*, std::uint64_t) {
    return Result<std::uint64_t>(RuntimeErrc::LockNotOwned,
                                  "package mounts are read-only");
}

Result<std::uint64_t> PackageFileHandle::seek(std::uint64_t position) {
    if (!valid_) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "package file range is invalid");
    }
    std::lock_guard lock(lock_);
    if (position > size_) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "seek beyond entry size");
    }
    pos_ = position;
    return Result<std::uint64_t>(pos_);
}

std::uint64_t PackageFileHandle::position() const {
    std::lock_guard lock(lock_);
    return pos_;
}

// ── PackageVfsBackend ──────────────────────────────────────────────────────

namespace {

// Canonical entry path key: 'a/b/c'.
std::string entry_key(const PackageEntry& e) {
    std::string k;
    for (const auto& p : e.path) {
        k.append(p);
        k.push_back('/');
    }
    k.append(e.name);
    return k;
}

}  // namespace

PackageVfsBackend::PackageVfsBackend(std::unique_ptr<ParsedPackage> pkg)
    : pkg_(std::move(pkg)) {
    // Build the path index once (deterministic iteration over entries).
    const PackageInfo& info = pkg_->info();
    for (std::uint64_t i = 0; i < info.entries.size(); ++i) {
        index_[entry_key(info.entries[static_cast<std::size_t>(i)])] = i;
    }
}

PackageVfsBackend::~PackageVfsBackend() = default;

Result<std::uint64_t> PackageVfsBackend::entry_index_for(const VfsPath& rel) const {
    std::string key;
    for (const auto& c : rel.components()) {
        key.append(c);
        key.push_back('/');
    }
    if (!key.empty()) key.pop_back();
    const auto it = index_.find(key);
    if (it == index_.end()) {
        return Result<std::uint64_t>(RuntimeErrc::NotFound,
                                     "no such entry: " + key);
    }
    return Result<std::uint64_t>(it->second);
}

Result<VfsStat> PackageVfsBackend::stat(const VfsPath& rel) {
    auto idx = entry_index_for(rel);
    if (!idx.ok()) {
        // Root of the mount = the package itself (a directory).
        if (rel.is_root()) {
            return Result<VfsStat>(VfsStat{true, true, 0});
        }
        return Result<VfsStat>(idx.errc(), idx.context());
    }
    const PackageEntry& e =
        pkg_->info().entries[static_cast<std::size_t>(idx.value())];
    VfsStat s;
    s.exists = true;
    s.is_directory = e.is_directory;
    s.size = e.is_directory ? 0 : e.size;
    return Result<VfsStat>(s);
}

Result<std::unique_ptr<IVfsFileHandle>> PackageVfsBackend::open(const VfsPath& rel,
                                                                bool write) {
    if (write) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::LockNotOwned, "package mounts are read-only");
    }
    auto idx = entry_index_for(rel);
    if (!idx.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(idx.errc(), idx.context());
    }
    const PackageEntry& e =
        pkg_->info().entries[static_cast<std::size_t>(idx.value())];
    if (e.is_directory) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::InvalidArgument, "entry is a directory");
    }
    // The XpkPackage buffer is shared-ownership; PackageFileHandle keeps
    // it alive (safe against backend destruction — the handle outlives
    // the mount while open; the namespace's open tracking covers unmount).
    auto data = pkg_->read_entry_data(idx.value());
    if (!data.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(data.errc(),
                                                       data.context());
    }
    // Copy into a self-owned buffer: parsed packages keep the ORIGINAL
    // buffer; a self-owned copy decouples handle lifetime cleanly.
    auto owned = std::make_shared<std::vector<std::uint8_t>>(std::move(data.value()));
    const std::uint64_t size = owned->size();
    return Result<std::unique_ptr<IVfsFileHandle>>(
        std::unique_ptr<IVfsFileHandle>(
            new PackageFileHandle(std::move(owned), 0, size)));
}

Result<void> PackageVfsBackend::create_file(const VfsPath&) {
    return Result<void>(RuntimeErrc::LockNotOwned, "package mounts are read-only");
}
Result<void> PackageVfsBackend::delete_file(const VfsPath&) {
    return Result<void>(RuntimeErrc::LockNotOwned, "package mounts are read-only");
}
Result<void> PackageVfsBackend::create_directory(const VfsPath&) {
    return Result<void>(RuntimeErrc::LockNotOwned, "package mounts are read-only");
}
Result<void> PackageVfsBackend::delete_directory(const VfsPath&) {
    return Result<void>(RuntimeErrc::LockNotOwned, "package mounts are read-only");
}

Result<std::vector<VfsDirEntry>> PackageVfsBackend::list(const VfsPath& rel) {
    // Children: entries whose parent == rel (or direct children of the
    // package root when rel is the mount root).
    std::map<std::string, VfsDirEntry> merged;
    const PackageInfo& info = pkg_->info();
    for (const auto& e : info.entries) {
        const auto& comps = e.path;
        const bool direct_child =
            rel.is_root() ? comps.empty()
                          : (comps.size() == rel.components().size() &&
                             [&] {
                                 for (std::size_t i = 0;
                                      i < rel.components().size(); ++i) {
                                     if (comps[i] != rel.components()[i]) {
                                         return false;
                                     }
                                 }
                                 return true;
                             }());
        if (!direct_child) continue;
        VfsDirEntry out;
        out.name = e.name;
        out.is_directory = e.is_directory;
        out.size = e.is_directory ? 0 : e.size;
        merged[e.name] = std::move(out);
    }
    std::vector<VfsDirEntry> out;
    out.reserve(merged.size());
    for (auto& [name, e] : merged) out.push_back(std::move(e));
    return Result<std::vector<VfsDirEntry>>(std::move(out));
}

// ── discovery ─────────────────────────────────────────────────────────────

const char* discovered_kind_to_name(DiscoveredKind k) {
    switch (k) {
        case DiscoveredKind::Directory: return "directory";
        case DiscoveredKind::PeModule: return "pe-module";
        case DiscoveredKind::InvalidPe: return "invalid-pe";
        case DiscoveredKind::KnownAsset: return "known-asset";
        case DiscoveredKind::UnknownFile: return "unknown";
    }
    return "?";
}

namespace {

// CITED binary-signature set (docs/asset-discovery.md). Deliberately tiny:
// only signatures whose layout is publicly documented AND trivially
// verifiable. No extension-based guessing.
struct AssetSignature {
    const char* name;
    const char* label;
    std::uint32_t offset;  // probe offset
    const char* bytes;     // NUL-terminated magic (memcmp over its strlen)
};
const AssetSignature kAssetSignatures[] = {
    // PNG: magic documented at png-CRC position — 89 50 4E 47 0D 0A 1A 0A
    // https://www.w3.org/TR/PNG/#5PNG-file-signature
    {"png", "image/png", 0, "\x89PNG\r\n\x1a\n"},
    // JPEG/JFIF APP0 marker documented in ISO/IEC 10918-1 / libjpeg docs.
    // SOI (FFD8) followed by APP0 (FFE0) at offset 2 — "JFIF\0" at 6.
    // https://www.w3.org/Graphics/JPEG/jfif3.pdf (§)
    {"jpeg", "image/jpeg", 0, "\xff\xd8\xff"},
};

}  // namespace

Result<DiscoveryResult> discover_in_namespace(VfsNamespace& ns,
                                               const VfsPath& root,
                                               std::uint64_t max_entries) {
    // Bounded walk (typed OutOfResources when exceeded).
    auto files = ns.walk(root, max_entries);
    if (!files.ok()) {
        return Result<DiscoveryResult>(files.errc(), files.context());
    }
    DiscoveryResult res;
    for (const auto& path_str : files.value()) {
        auto p = VfsPath::parse(path_str, ns.policy());
        if (!p.ok()) continue;  // walk output is canonical; skip impossible
        auto st = ns.stat(p.value());
        if (!st.ok()) continue;
        DiscoveredFile f;
        f.path = path_str;
        f.size = st.value().size;
        if (st.value().is_directory) {
            f.kind = DiscoveredKind::Directory;
            ++res.directories;
            res.files.push_back(std::move(f));
            continue;
        }
        // Read the head (files only) for signature probing + PE parsing.
        auto fh = ns.open(p.value(), false);
        if (!fh.ok()) {
            f.kind = DiscoveredKind::UnknownFile;
            ++res.unknown_files;
            res.files.push_back(std::move(f));
            continue;
        }
        std::uint8_t head[4096];
        const auto got = fh.value()->read(head, sizeof(head));
        std::uint64_t head_len = got.ok() ? got.value() : 0;
        if (head_len == 0) {
            f.kind = DiscoveredKind::UnknownFile;
            ++res.unknown_files;
            res.files.push_back(std::move(f));
            continue;
        }
        // PE check FIRST (MZ at 0): the M1 parser decides with real
        // headers; extension never matters. Hard parse failures throw
        // pe::ParseError → InvalidPe classification (never dropped).
        if (head[0] == 'M' && head[1] == 'Z') {
            std::vector<std::uint8_t> full(head, head + head_len);
            std::uint8_t chunk[8192];
            for (;;) {
                auto n = fh.value()->read(chunk, sizeof(chunk));
                if (!n.ok() || n.value() == 0) break;
                full.insert(full.end(), chunk, chunk + n.value());
                if (full.size() > 512ull * 1024 * 1024) break;  // hard cap
            }
            const std::string module_name = p.value().components().back();
            try {
                diag::Diagnostics diags;
                const pe::PeImage img =
                    pe::parse(full.data(), full.size(), module_name, diags);
                f.kind = DiscoveredKind::PeModule;
                f.module_name = module_name;
                f.size_of_image = img.opt.size_of_image;
                for (const auto& imp : img.imports.entries) {
                    f.imports.push_back(imp.dll_name);
                }
                ++res.pe_modules;
            } catch (const pe::ParseError& e) {
                f.kind = DiscoveredKind::InvalidPe;
                f.pe_note = e.what();
                ++res.invalid_pe;
            }
            res.files.push_back(std::move(f));
            continue;
        }
        // Known asset signatures (cited set only).
        bool matched_asset = false;
        for (const auto& sig : kAssetSignatures) {
            const std::size_t mlen = std::strlen(sig.bytes);
            if (head_len >= sig.offset + mlen &&
                std::memcmp(head + sig.offset, sig.bytes, mlen) == 0) {
                f.kind = DiscoveredKind::KnownAsset;
                f.pe_note = sig.label;
                ++res.known_assets;
                matched_asset = true;
                break;
            }
        }
        if (matched_asset) {
            res.files.push_back(std::move(f));
            continue;
        }
        // Unknown: honestly unclassified (never guessed).
        f.kind = DiscoveredKind::UnknownFile;
        ++res.unknown_files;
        res.files.push_back(std::move(f));
    }
    return Result<DiscoveryResult>(std::move(res));
}

}  // namespace xbox2pc::rt
