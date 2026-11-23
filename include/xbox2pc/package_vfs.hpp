#pragma once
// xbox2pc/package_vfs.hpp — M5 package mounting + discovery.
//
// PackageVfsBackend: an IVfsBackend VIEW over a ParsedPackage (read-only,
// entry payloads served from the shared buffer). The backend holds the
// ParsedPackage by unique_ptr and serves stat/list/open from its entry
// table. Because ParsedPackage implementations own their buffers via
// shared_ptr, file handles stay valid even across backend mutation
// (none exists — backends are immutable snapshots).
//
// PackageDiscovery: walks a VfsNamespace and classifies every file:
//   * PE32+ modules (M1 parse → M2 dependency report → M3/M4
//     ModuleDescriptor) — actual DOS/PE headers decide, NEVER the filename;
//   * known asset categories by BINARY signature probe only where the
//     runtime can verify (documented: current set is PE32+ plus a
//     deliberately tiny, cited set — anything else is "unknown", never
//     guessed by extension);
//   * directories; invalid PE (parse error) → "invalid-pe" classification
//     (not silently dropped).

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/vfs.hpp"

namespace xbox2pc::rt {

class ParsedPackage;

// ── package-backed read-only backend ──────────────────────────────────────

class PackageVfsBackend : public IVfsBackend {
public:
    // Takes ownership of the parsed package (read-only view).
    explicit PackageVfsBackend(std::unique_ptr<ParsedPackage> pkg);
    ~PackageVfsBackend() override;

    const char* backend_name() const override { return "package"; }
    bool read_only() const override { return true; }

    Result<VfsStat> stat(const VfsPath& rel) override;
    Result<std::unique_ptr<IVfsFileHandle>> open(const VfsPath& rel,
                                                 bool write) override;
    Result<void> create_file(const VfsPath& rel) override;          // denied
    Result<void> delete_file(const VfsPath& rel) override;          // denied
    Result<void> create_directory(const VfsPath& rel) override;    // denied
    Result<void> delete_directory(const VfsPath& rel) override;    // denied
    Result<std::vector<VfsDirEntry>> list(const VfsPath& rel) override;

    const ParsedPackage& package() const { return *pkg_; }

private:
    // Entry index for a relative path (folded compare over components).
    Result<std::uint64_t> entry_index_for(const VfsPath& rel) const;

    std::unique_ptr<ParsedPackage> pkg_;
    // Path key -> entry index (built once in the ctor).
    std::map<std::string, std::uint64_t> index_;
};

// Read-only handle over one package entry's payload (shared buffer view).
class PackageFileHandle : public IVfsFileHandle {
public:
    PackageFileHandle(std::shared_ptr<std::vector<std::uint8_t>> buffer,
                      std::uint64_t offset, std::uint64_t size);
    ~PackageFileHandle() override = default;

    Result<std::uint64_t> read(void* buf, std::uint64_t len) override;
    Result<std::uint64_t> write(const void* buf, std::uint64_t len) override;  // denied
    Result<std::uint64_t> seek(std::uint64_t position) override;
    std::uint64_t position() const override;
    std::uint64_t size() const override { return size_; }

private:
    std::shared_ptr<std::vector<std::uint8_t>> buf_;
    std::uint64_t offset_ = 0;
    std::uint64_t size_ = 0;
    std::uint64_t pos_ = 0;
    bool valid_ = false;
    mutable std::mutex lock_;
};

// ── discovery ─────────────────────────────────────────────────────────────

enum class DiscoveredKind {
    Directory,
    PeModule,     // valid PE32+ parsed by M1
    InvalidPe,    // looked like PE (MZ) but failed to parse
    KnownAsset,   // matched a CITED binary signature (see kAssetSignatures)
    UnknownFile,  // deliberately unclassified — never guessed
};

const char* discovered_kind_to_name(DiscoveredKind k);

struct DiscoveredFile {
    std::string path;               // canonical VFS path
    std::uint64_t size = 0;
    DiscoveredKind kind = DiscoveredKind::UnknownFile;
    // PeModule/InvalidPe only:
    std::string pe_note;            // parse error text for InvalidPe
    // PeModule only (module metadata + unresolved dependencies reported,
    // never resolved — M5 exclusion):
    std::string module_name;
    std::uint64_t size_of_image = 0;
    std::vector<std::string> imports;      // unresolved DLL names
};

struct DiscoveryResult {
    std::vector<DiscoveredFile> files;
    std::uint32_t pe_modules = 0;
    std::uint32_t invalid_pe = 0;
    std::uint32_t known_assets = 0;
    std::uint32_t unknown_files = 0;
    std::uint32_t directories = 0;
};

// Discover over a namespace (bounded walk via walk()).
Result<DiscoveryResult> discover_in_namespace(VfsNamespace& ns,
                                               const VfsPath& root,
                                               std::uint64_t max_entries);

}  // namespace xbox2pc::rt
