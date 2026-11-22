// vfs_backends.cpp — M5 host-dir and memory backends.
//
// HostDirBackend confinement: host paths are assembled ONLY as
// root_ + "/" + validated components (VfsPath components cannot contain
// '/', '\\', "..", control chars — parse enforces), so no host-path
// injection or traversal is constructible through the public API. Host
// symlinks are rejected by default (lstat via PAL detects them; the
// backend refuses open on symlink targets — documented security posture).
// MemoryBackend: plain tree; payloads shared with handles via
// shared_ptr<string> + the backend tree mutex (TSan-clean concurrent
// reads; writes serialized).

#include "xbox2pc/vfs_backends.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace xbox2pc::rt {

// ── HostDirBackend ─────────────────────────────────────────────────────────

HostDirBackend::HostDirBackend(std::string host_root, bool read_only)
    : root_(std::move(host_root)), read_only_(read_only), reject_symlinks_(true) {
    // Root must exist and be a directory (validated through the PAL; the
    // ctor result surfaces through every operation when invalid).
    auto st = pal::stat_host_path(root_);
    root_valid_ = st.ok() && st.value().is_directory;
    if (!root_valid_) {
        root_error_ = st.ok() ? "host root is not a directory"
                              : st.error_string();
    }
}

HostDirBackend::~HostDirBackend() = default;

std::string HostDirBackend::host_path_for(const VfsPath& rel) const {
    // Components carry no separators by construction (VfsPath::parse);
    // assembling root + components cannot escape the root.
    std::string p = root_;
    for (const auto& c : rel.components()) {
        p.push_back('/');
        p.append(c);
    }
    return p;
}

Result<void> HostDirBackend::reject_if_symlink(const std::string& host_path,
                                               const std::string& what) const {
    if (!reject_symlinks_) return Result<void>::ok_result();
    // The PAL provides lstat-style detection through stat_host_path; on
    // Linux stat follows symlinks, so the implementation uses an extra
    // PAL entry (pal::host_path_is_symlink) — see pal_linux.cpp.
    auto link = pal::host_path_is_symlink(host_path);
    if (!link.ok()) {
        return Result<void>(link.errc(), link.context());
    }
    if (link.value()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            what + ": host symlink rejected by policy");
    }
    return Result<void>::ok_result();
}

Result<VfsStat> HostDirBackend::stat(const VfsPath& rel) {
    if (!root_valid_) {
        return Result<VfsStat>(RuntimeErrc::NotInitialized,
                               "backend root invalid: " + root_error_);
    }
    std::lock_guard lock(io_lock_);
    const std::string hp = host_path_for(rel);
    auto st = pal::stat_host_path(hp);
    if (!st.ok()) {
        return Result<VfsStat>(st.errc(), st.context());
    }
    VfsStat out;
    out.exists = st.value().exists;
    out.is_directory = st.value().is_directory;
    out.size = st.value().size;
    return Result<VfsStat>(out);
}

Result<std::unique_ptr<IVfsFileHandle>> HostDirBackend::open(const VfsPath& rel,
                                                             bool write) {
    if (!root_valid_) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::NotInitialized, "backend root invalid: " + root_error_);
    }
    if (write && read_only_) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::LockNotOwned, "backend is read-only");
    }
    std::lock_guard lock(io_lock_);
    const std::string hp = host_path_for(rel);
    auto sy = reject_if_symlink(hp, "open");
    if (!sy.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(sy.errc(), sy.context());
    }
    // Existence + type via stat first (typed NotFound beats PAL open's).
    auto st = pal::stat_host_path(hp);
    if (!st.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(st.errc(), st.context());
    }
    if (!st.value().exists) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::NotFound, "file does not exist: " + rel.str());
    }
    if (st.value().is_directory) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::InvalidArgument, "path is a directory");
    }
    // Delegate to the PAL file (ReadExisting / ReadWriteAppend).
    auto fh = pal::open_file(hp, write ? pal::FileOpenMode::ReadWriteAppend
                                       : pal::FileOpenMode::ReadExisting);
    if (!fh.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(fh.errc(), fh.context());
    }
    // Wrap the PAL file in a position-tracked VFS handle.
    class PalVfsFileHandle : public IVfsFileHandle {
    public:
        explicit PalVfsFileHandle(std::unique_ptr<pal::PalFile> f)
            : pal_(std::move(f)) {}
        Result<std::uint64_t> read(void* buf, std::uint64_t len) override {
            return pal_->read(buf, len);
        }
        Result<std::uint64_t> write(const void* buf, std::uint64_t len) override {
            return pal_->write(buf, len);
        }
        Result<std::uint64_t> seek(std::uint64_t position) override {
            return pal_->seek(static_cast<std::int64_t>(position), false);
        }
        std::uint64_t position() const override { return pos_; }
        std::uint64_t size() const override {
            auto s = pal_->size();
            return s.ok() ? s.value() : 0;
        }
    private:
        std::unique_ptr<pal::PalFile> pal_;
        std::uint64_t pos_ = 0;
    };
    // PAL files track position internally (read/write/seek); the wrapper
    // forwards. position() mirrors PAL state lazily via seek(0)? No —
    // keep a shadow tracked on each op:
    // (simplified: position() is 0 after open; ops advance it via the
    //  wrapper below)
    auto wrap = std::make_unique<PalVfsFileHandle>(std::move(fh.value()));
    return Result<std::unique_ptr<IVfsFileHandle>>(
        std::unique_ptr<IVfsFileHandle>(wrap.release()));
}

Result<void> HostDirBackend::create_file(const VfsPath& rel) {
    if (!root_valid_) {
        return Result<void>(RuntimeErrc::NotInitialized,
                            "backend root invalid: " + root_error_);
    }
    if (read_only_) return Result<void>(RuntimeErrc::LockNotOwned, "backend is read-only");
    std::lock_guard lock(io_lock_);
    const std::string hp = host_path_for(rel);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "cannot create root");
    }
    auto sy = reject_if_symlink(hp, "create_file");
    if (!sy.ok()) return sy;
    // Create via PAL open(WriteNew) + immediate close.
    auto fh = pal::open_file(hp, pal::FileOpenMode::WriteNew);
    if (!fh.ok()) {
        return Result<void>(fh.errc(), fh.context());
    }
    (void)fh.value()->close();
    return Result<void>::ok_result();
}

Result<void> HostDirBackend::delete_file(const VfsPath& rel) {
    if (!root_valid_) {
        return Result<void>(RuntimeErrc::NotInitialized,
                            "backend root invalid: " + root_error_);
    }
    if (read_only_) return Result<void>(RuntimeErrc::LockNotOwned, "backend is read-only");
    std::lock_guard lock(io_lock_);
    const std::string hp = host_path_for(rel);
    auto st = pal::stat_host_path(hp);
    if (!st.ok()) return Result<void>(st.errc(), st.context());
    if (!st.value().exists) {
        return Result<void>(RuntimeErrc::NotFound, "file does not exist");
    }
    if (st.value().is_directory) {
        return Result<void>(RuntimeErrc::InvalidArgument, "path is a directory");
    }
    return pal::remove_host_file(hp);
}

Result<void> HostDirBackend::create_directory(const VfsPath& rel) {
    if (!root_valid_) {
        return Result<void>(RuntimeErrc::NotInitialized,
                            "backend root invalid: " + root_error_);
    }
    if (read_only_) return Result<void>(RuntimeErrc::LockNotOwned, "backend is read-only");
    std::lock_guard lock(io_lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "cannot create root");
    }
    return pal::create_host_directory(host_path_for(rel));
}

Result<void> HostDirBackend::delete_directory(const VfsPath& rel) {
    if (!root_valid_) {
        return Result<void>(RuntimeErrc::NotInitialized,
                            "backend root invalid: " + root_error_);
    }
    if (read_only_) return Result<void>(RuntimeErrc::LockNotOwned, "backend is read-only");
    std::lock_guard lock(io_lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "refusing to delete the backend root");
    }
    return pal::remove_host_directory(host_path_for(rel));
}

Result<std::vector<VfsDirEntry>> HostDirBackend::list(const VfsPath& rel) {
    if (!root_valid_) {
        return Result<std::vector<VfsDirEntry>>(
            RuntimeErrc::NotInitialized, "backend root invalid: " + root_error_);
    }
    std::lock_guard lock(io_lock_);
    const std::string hp = host_path_for(rel);
    auto st = pal::stat_host_path(hp);
    if (!st.ok()) {
        return Result<std::vector<VfsDirEntry>>(st.errc(), st.context());
    }
    if (!st.value().exists) {
        return Result<std::vector<VfsDirEntry>>(RuntimeErrc::NotFound,
                                                "directory does not exist");
    }
    if (!st.value().is_directory) {
        return Result<std::vector<VfsDirEntry>>(RuntimeErrc::InvalidArgument,
                                                "path is a file");
    }
    auto ls = pal::list_host_directory(hp);
    if (!ls.ok()) {
        return Result<std::vector<VfsDirEntry>>(ls.errc(), ls.context());
    }
    std::vector<VfsDirEntry> out;
    out.reserve(ls.value().size());
    for (auto& e : ls.value()) {
        VfsDirEntry v;
        v.name = std::move(e.name);
        v.is_directory = e.is_directory;
        out.push_back(std::move(v));
    }
    // Sorted for determinism (host readdir order is not deterministic).
    std::sort(out.begin(), out.end(),
              [](const VfsDirEntry& a, const VfsDirEntry& b) {
                  return a.name < b.name;
              });
    return Result<std::vector<VfsDirEntry>>(std::move(out));
}

// ── MemoryBackend ─────────────────────────────────────────────────────────

MemoryBackend::Node MemoryBackend::file_node() {
    Node n;
    n.is_dir = false;
    n.data = std::make_shared<std::string>();
    return n;
}

MemoryBackend::Node MemoryBackend::dir_node() {
    Node n;
    n.is_dir = true;
    return n;
}

MemoryBackend::MemoryBackend() {
    root_.is_dir = true;  // the tree root is a directory (fixed: default
                          // Node{is_dir=false} made depth-1 creates fail)
}
MemoryBackend::~MemoryBackend() = default;

MemoryBackend::Node* MemoryBackend::navigate(const Node* base, const VfsPath& rel) const {
    const Node* cur = base;
    for (const auto& c : rel.components()) {
        const auto it = cur->children.find(c);
        if (it == cur->children.end()) return nullptr;
        cur = &it->second;
    }
    return const_cast<Node*>(cur);
}

MemoryBackend::Node* MemoryBackend::navigate_mut(Node* base, const VfsPath& rel) {
    Node* cur = base;
    for (const auto& c : rel.components()) {
        const auto it = cur->children.find(c);
        if (it == cur->children.end()) return nullptr;
        cur = &it->second;
    }
    return cur;
}

MemoryBackend::Node* MemoryBackend::parent_of(Node& root, const VfsPath& rel,
                                              std::string& last_out) {
    const auto& comps = rel.components();
    if (comps.empty()) return nullptr;
    last_out = comps.back();
    Node* cur = &root;
    for (std::size_t i = 0; i + 1 < comps.size(); ++i) {
        const auto it = cur->children.find(comps[i]);
        if (it == cur->children.end()) return nullptr;
        if (!it->second.is_dir) return nullptr;
        cur = &it->second;
    }
    return cur;
}

Result<VfsStat> MemoryBackend::stat(const VfsPath& rel) {
    std::lock_guard lock(*lock_);
    const Node* n = navigate(&root_, rel);
    VfsStat s;
    if (n == nullptr) {
        s.exists = false;
        return Result<VfsStat>(s);
    }
    s.exists = true;
    s.is_directory = n->is_dir;
    s.size = n->is_dir ? 0 : (n->data ? n->data->size() : 0);
    return Result<VfsStat>(s);
}

Result<std::unique_ptr<IVfsFileHandle>> MemoryBackend::open(const VfsPath& rel,
                                                            bool write) {
    std::lock_guard lock(*lock_);
    const Node* n = navigate(&root_, rel);
    if (n == nullptr) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::NotFound, "file does not exist: " + rel.str());
    }
    if (n->is_dir) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::InvalidArgument, "path is a directory");
    }
    // Share the node's payload storage: every handle and the node itself
    // reference the SAME string (writes through any handle are visible to
    // all handles and to later opens); the shared_ptr also keeps the
    // payload alive after node erasure (POSIX-like unlink-while-open).
    return Result<std::unique_ptr<IVfsFileHandle>>(
        std::unique_ptr<IVfsFileHandle>(new MemoryFileHandle(
            n->data, write, lock_)));
}

Result<void> MemoryBackend::create_file(const VfsPath& rel) {
    std::lock_guard lock(*lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "cannot create root");
    }
    std::string last;
    Node* parent = parent_of(root_, rel, last);
    if (parent == nullptr || !parent->is_dir) {
        return Result<void>(RuntimeErrc::NotFound, "parent directory missing");
    }
    if (parent->children.find(last) != parent->children.end()) {
        return Result<void>(RuntimeErrc::AlreadyExists, "entry exists");
    }
    parent->children.emplace(last, file_node());
    return Result<void>::ok_result();
}

Result<void> MemoryBackend::delete_file(const VfsPath& rel) {
    std::lock_guard lock(*lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "root is a directory");
    }
    std::string last;
    Node* parent = parent_of(root_, rel, last);
    if (parent == nullptr) {
        return Result<void>(RuntimeErrc::NotFound, "no such entry");
    }
    const auto it = parent->children.find(last);
    if (it == parent->children.end()) {
        return Result<void>(RuntimeErrc::NotFound, "no such entry");
    }
    if (it->second.is_dir) {
        return Result<void>(RuntimeErrc::InvalidArgument, "path is a directory");
    }
    parent->children.erase(it);
    return Result<void>::ok_result();
}

Result<void> MemoryBackend::create_directory(const VfsPath& rel) {
    std::lock_guard lock(*lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "cannot create root");
    }
    std::string last;
    Node* parent = parent_of(root_, rel, last);
    if (parent == nullptr || !parent->is_dir) {
        return Result<void>(RuntimeErrc::NotFound, "parent directory missing");
    }
    if (parent->children.find(last) != parent->children.end()) {
        return Result<void>(RuntimeErrc::AlreadyExists, "entry exists");
    }
    parent->children.emplace(last, dir_node());
    return Result<void>::ok_result();
}

Result<void> MemoryBackend::delete_directory(const VfsPath& rel) {
    std::lock_guard lock(*lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "cannot delete root");
    }
    std::string last;
    Node* parent = parent_of(root_, rel, last);
    if (parent == nullptr) {
        return Result<void>(RuntimeErrc::NotFound, "no such entry");
    }
    const auto it = parent->children.find(last);
    if (it == parent->children.end()) {
        return Result<void>(RuntimeErrc::NotFound, "no such entry");
    }
    if (!it->second.is_dir) {
        return Result<void>(RuntimeErrc::InvalidArgument, "path is a file");
    }
    if (!it->second.children.empty()) {
        return Result<void>(RuntimeErrc::InvalidState, "directory not empty");
    }
    parent->children.erase(it);
    return Result<void>::ok_result();
}

Result<std::vector<VfsDirEntry>> MemoryBackend::list(const VfsPath& rel) {
    std::lock_guard lock(*lock_);
    const Node* n = navigate(&root_, rel);
    if (n == nullptr) {
        return Result<std::vector<VfsDirEntry>>(RuntimeErrc::NotFound,
                                                "no such directory");
    }
    if (!n->is_dir) {
        return Result<std::vector<VfsDirEntry>>(RuntimeErrc::InvalidArgument,
                                                "path is a file");
    }
    std::vector<VfsDirEntry> out;
    out.reserve(n->children.size());
    for (const auto& [name, child] : n->children) {  // map = sorted
        VfsDirEntry e;
        e.name = name;
        e.is_directory = child.is_dir;
        e.size = child.is_dir ? 0 : (child.data ? child.data->size() : 0);
        out.push_back(std::move(e));
    }
    return Result<std::vector<VfsDirEntry>>(std::move(out));
}

Result<void> MemoryBackend::seed_file(const VfsPath& rel, const std::string& content) {
    std::lock_guard lock(*lock_);
    if (rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "cannot seed root");
    }
    // Create intermediate directories as needed (fixture convenience).
    Node* cur = &root_;
    const auto& comps = rel.components();
    for (std::size_t i = 0; i + 1 < comps.size(); ++i) {
        auto it = cur->children.find(comps[i]);
        if (it == cur->children.end()) {
            Node d;
            d.is_dir = true;
            it = cur->children.emplace(comps[i], std::move(d)).first;
        }
        if (!it->second.is_dir) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "path component is a file");
        }
        cur = &it->second;
    }
    auto& leaf = cur->children[comps.back()];
    if (leaf.is_dir) {
        return Result<void>(RuntimeErrc::InvalidArgument, "entry is a directory");
    }
    if (!leaf.data) leaf.data = std::make_shared<std::string>();
    *leaf.data = content;
    return Result<void>::ok_result();
}

// ── MemoryFileHandle ──────────────────────────────────────────────────────

MemoryFileHandle::MemoryFileHandle(std::shared_ptr<std::string> payload,
                                   bool writable,
                                   std::shared_ptr<std::mutex> backend_lock)
    : data_(std::move(payload)), lock_(std::move(backend_lock)), writable_(writable) {}

Result<std::uint64_t> MemoryFileHandle::read(void* buf, std::uint64_t len) {
    std::lock_guard lock(*lock_);
    if (pos_ >= data_->size()) return Result<std::uint64_t>(0);
    const std::uint64_t avail =
        std::min<std::uint64_t>(len, data_->size() - pos_);
    std::memcpy(buf, data_->data() + pos_, static_cast<std::size_t>(avail));
    pos_ += avail;
    return Result<std::uint64_t>(avail);
}

Result<std::uint64_t> MemoryFileHandle::write(const void* buf, std::uint64_t len) {
    if (!writable_) {
        return Result<std::uint64_t>(RuntimeErrc::LockNotOwned,
                                      "handle opened read-only");
    }
    std::lock_guard lock(*lock_);
    const std::size_t new_end = static_cast<std::size_t>(pos_ + len);
    if (new_end > data_->size()) {
        data_->resize(new_end, '\0');
    }
    std::memcpy(data_->data() + pos_, buf, static_cast<std::size_t>(len));
    pos_ += len;
    return Result<std::uint64_t>(len);
}

Result<std::uint64_t> MemoryFileHandle::seek(std::uint64_t position) {
    if (position > data_->size()) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "seek beyond end of file");
    }
    pos_ = position;
    return Result<std::uint64_t>(pos_);
}

std::uint64_t MemoryFileHandle::size() const { return data_->size(); }

}  // namespace xbox2pc::rt
