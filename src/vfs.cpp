// vfs.cpp — M5 virtual filesystem: path model + namespace/mounts.
//
// Security-critical (docs/virtual-filesystem.md): path parsing rejects
// traversal (".." above root), NUL/control chars, over-long paths; mount
// resolution NEVER escapes the chosen backend (remount-relative lookups);
// unmount refuses while open files exist. Fuzzed (tests/vfs_fuzz.cpp).

#include "xbox2pc/vfs.hpp"

#include <algorithm>
#include <atomic>
#include <utility>

namespace xbox2pc::rt {

// ── VfsPath ───────────────────────────────────────────────────────────────

namespace {
bool is_path_char(char c) {
    // Reject control chars (0x00–0x1F) and DEL; the runtime naming rule.
    const auto uc = static_cast<unsigned char>(c);
    return uc >= 0x20 && uc != 0x7F;
}
}  // namespace

Result<VfsPath> VfsPath::parse(const std::string& raw, const VfsPathPolicy& policy) {
    if (raw.empty()) {
        return Result<VfsPath>(RuntimeErrc::InvalidArgument, "empty path");
    }
    if (raw.size() > policy.max_total_length) {
        return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                               "path exceeds max length " +
                                   std::to_string(policy.max_total_length));
    }
    // Reject '\' unless the policy allows it as a separator (then treat as
    // '/'; the canonical form is always '/').
    std::string norm = raw;
    if (policy.allow_backslash_separator) {
        for (char& c : norm) {
            if (c == '\\') c = '/';
        }
    } else {
        for (char c : norm) {
            if (c == '\\') {
                return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                                       "backslash not allowed in VFS path");
            }
        }
    }
    // Split on '/'; process "." and ".." with a component stack.
    std::vector<std::string> comps;
    std::string cur;
    const auto flush = [&]() {
        if (!cur.empty()) {
            if (cur == ".") {
                // "." disappears
            } else if (cur == "..") {
                if (comps.empty()) {
                    // traversal above root: REJECTED (security boundary)
                    return false;
                }
                comps.pop_back();
            } else {
                comps.push_back(cur);
            }
            cur.clear();
        }
        return true;
    };
    for (char c : norm) {
        if (!is_path_char(c)) {
            return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                                   "invalid control character in path");
        }
        if (c == '/') {
            if (!flush()) {
                return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                                       "path traversal above root ('..')");
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!flush()) {
        return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                               "path traversal above root ('..')");
    }
    // Component validation: length + depth.
    if (comps.size() > policy.max_depth) {
        return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                               "path depth exceeds " +
                                   std::to_string(policy.max_depth));
    }
    for (const auto& c : comps) {
        if (c.size() > policy.max_component_length) {
            return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                                   "component exceeds " +
                                       std::to_string(policy.max_component_length));
        }
        if (c == "." || c == "..") {
            // Unreachable given the folding above; kept as a guard.
            return Result<VfsPath>(RuntimeErrc::InvalidArgument,
                                   "reserved component name");
        }
    }
    return Result<VfsPath>(VfsPath::from_components(std::move(comps)));
}

VfsPath VfsPath::from_components(std::vector<std::string> components) {
    VfsPath p;
    p.comps_ = std::move(components);
    return p;
}

std::string VfsPath::str() const {
    if (comps_.empty()) return "/";
    std::string out;
    std::size_t total = 0;
    for (const auto& c : comps_) total += c.size() + 1;
    out.reserve(total);
    for (const auto& c : comps_) {
        out.push_back('/');
        out.append(c);
    }
    return out;
}

VfsPath VfsPath::parent() const {
    if (comps_.empty()) return *this;  // root's parent is root
    auto p = comps_;
    p.pop_back();
    return VfsPath::from_components(std::move(p));
}

VfsPath VfsPath::child(const std::string& name) const {
    auto p = comps_;
    p.push_back(name);
    return VfsPath::from_components(std::move(p));
}

std::string VfsPath::fold_key() const {
    // ASCII-lowercased canonical string for case-insensitive matching.
    std::string s = str();
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// ── VfsNamespace ───────────────────────────────────────────────────────────

namespace {
std::atomic<std::uint64_t> g_next_mount_id{1};
}

struct VfsNamespace::Impl {
    struct Mount {
        std::uint64_t id = 0;
        VfsPath path;                    // canonical mount path
        std::string fold;                // fold key for case-insensitive hits
        IVfsBackend* backend = nullptr;  // NOT owned
        bool read_only = false;
        std::int64_t precedence = 0;
        std::uint64_t order = 0;         // mount sequence (tie-break)
        std::uint64_t open_files = 0;     // live file handles on this mount
    };

    mutable std::mutex lock;
    std::vector<Mount> mounts;           // kept sorted for lookup
    std::uint64_t next_order = 0;
    VfsPathPolicy policy;

    // Longest-prefix match + precedence/order tie-break. The mount at the
    // path itself (exact) beats deeper paths. Caller holds the lock.
    const Mount* find_mount_for(const VfsPath& path, VfsPath& rel_out) const {
        const Mount* best = nullptr;
        VfsPath best_rel;
        const bool fold = false;  // mount matching is exact-path (see below)
        (void)fold;
        for (const Mount& m : mounts) {
            // m.path must be a prefix of `path` (component-wise).
            const auto& mc = m.path.components();
            const auto& pc = path.components();
            if (mc.size() > pc.size()) continue;
            bool prefix = true;
            for (std::size_t i = 0; i < mc.size(); ++i) {
                if (mc[i] != pc[i]) { prefix = false; break; }
            }
            if (!prefix) continue;
            // Candidate; compare against the current best.
            if (best == nullptr || better(m, *best)) {
                best = &m;
                best_rel = VfsPath::from_components(
                    std::vector<std::string>(pc.begin() + static_cast<long>(mc.size()),
                                             pc.end()));
            }
        }
        rel_out = best_rel;
        return best;
    }

    // Ordering: longer mount path wins (more specific); then precedence
    // (higher); then later mount order.
    static bool better(const Mount& a, const Mount& b) {
        if (a.path.components().size() != b.path.components().size()) {
            return a.path.components().size() > b.path.components().size();
        }
        if (a.precedence != b.precedence) return a.precedence > b.precedence;
        return a.order > b.order;
    }

    // Caller holds the lock.
    const Mount* by_id(std::uint64_t id) const {
        for (const auto& m : mounts) {
            if (m.id == id) return &m;
        }
        return nullptr;
    }
    Mount* by_id_mut(std::uint64_t id) {
        for (auto& m : mounts) {
            if (m.id == id) return &m;
        }
        return nullptr;
    }
};

VfsNamespace::VfsNamespace() : impl_(std::make_shared<Impl>()) {}
VfsNamespace::~VfsNamespace() = default;

const VfsPathPolicy& VfsNamespace::policy() const { return impl_->policy; }
void VfsNamespace::set_policy(const VfsPathPolicy& p) {
    std::lock_guard lock(impl_->lock);
    impl_->policy = p;
}

Result<std::uint64_t> VfsNamespace::mount(const VfsPath& mount_path,
                                          IVfsBackend& backend, bool read_only,
                                          std::int64_t precedence) {
    if (mount_path.is_root()) {
        // Root mounts are allowed (they cover everything) but must be the
        // least-specific by construction; multiple root mounts stack by
        // precedence as with any other path.
    }
    std::lock_guard lock(impl_->lock);
    const std::uint64_t id = g_next_mount_id.fetch_add(1, std::memory_order_acq_rel);
    Impl::Mount m;
    m.id = id;
    m.path = mount_path;
    m.fold = mount_path.fold_key();
    m.backend = &backend;
    m.read_only = read_only || backend.read_only();
    m.precedence = precedence;
    m.order = impl_->next_order++;
    impl_->mounts.push_back(m);
    return Result<std::uint64_t>(id);
}

Result<void> VfsNamespace::unmount(std::uint64_t mount_id) {
    std::lock_guard lock(impl_->lock);
    for (auto it = impl_->mounts.begin(); it != impl_->mounts.end(); ++it) {
        if (it->id == mount_id) {
            if (it->open_files > 0) {
                return Result<void>(
                    RuntimeErrc::InvalidState,
                    "unmount refused: " + std::to_string(it->open_files) +
                        " open file(s) on this mount");
            }
            impl_->mounts.erase(it);
            return Result<void>::ok_result();
        }
    }
    return Result<void>(RuntimeErrc::NotFound,
                        "mount id " + std::to_string(mount_id) + " not found");
}

std::vector<VfsMountInfo> VfsNamespace::list_mounts() const {
    std::lock_guard lock(impl_->lock);
    std::vector<VfsMountInfo> out;
    out.reserve(impl_->mounts.size());
    for (const auto& m : impl_->mounts) {
        VfsMountInfo info;
        info.mount_path = m.path.str();
        info.backend_name = m.backend->backend_name();
        info.read_only = m.read_only;
        info.precedence = m.precedence;
        info.mount_id = m.id;
        out.push_back(std::move(info));
    }
    return out;
}

Result<VfsNamespace::Resolved> VfsNamespace::resolve(const VfsPath& path) const {
    std::lock_guard lock(impl_->lock);
    VfsPath rel;
    const Impl::Mount* m = impl_->find_mount_for(path, rel);
    if (m == nullptr) {
        // No mount serves this path (also the root-mount-absent case).
        return Result<Resolved>(RuntimeErrc::NotFound,
                                "no mount covers " + path.str());
    }
    Resolved r;
    r.mount_id = m->id;
    r.rel = rel;
    r.read_only = m->read_only;
    r.case_insensitive = m->backend->case_insensitive();
    return Result<Resolved>(std::move(r));
}

Result<VfsStat> VfsNamespace::stat(const VfsPath& path) const {
    auto res = resolve(path);
    if (!res.ok()) {
        // Unmounted areas read as missing (not a filesystem error).
        if (res.errc() == RuntimeErrc::NotFound) {
            VfsStat missing;
            missing.exists = false;
            return Result<VfsStat>(missing);
        }
        return Result<VfsStat>(res.errc(), res.context());
    }
    // The mount root itself is always a directory that exists.
    if (res.value().rel.is_root()) {
        return Result<VfsStat>(VfsStat{true, true, 0});
    }
    std::lock_guard lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) {
        return Result<VfsStat>(RuntimeErrc::NotFound, "mount vanished");
    }
    return m->backend->stat(res.value().rel);
}

Result<std::vector<VfsDirEntry>> VfsNamespace::list(const VfsPath& path) const {
    auto res = resolve(path);
    if (!res.ok()) {
        return Result<std::vector<VfsDirEntry>>(res.errc(), res.context());
    }
    std::lock_guard lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) {
        return Result<std::vector<VfsDirEntry>>(RuntimeErrc::NotFound, "mount vanished");
    }
    // Merge: entries from EVERY mount whose path is a DIRECT child of
    // `path` (sub-mounts appear as directories), plus the backend's own
    // listing.
    std::map<std::string, VfsDirEntry> merged;  // name -> entry (sorted)
    if (res.value().rel.is_root() || true) {
        // Backend listing (rel is relative to the mount root; root of the
        // mount when the resolved path IS the mount path).
        auto bl = m->backend->list(res.value().rel);
        if (!bl.ok()) {
            return Result<std::vector<VfsDirEntry>>(bl.errc(), bl.context());
        }
        for (const auto& e : bl.value()) merged[e.name] = e;
    }
    // Sub-mounts at exactly one level below `path`.
    for (const auto& sub : impl_->mounts) {
        const auto& sc = sub.path.components();
        const auto& pc = path.components();
        if (sc.size() == pc.size() + 1) {
            bool prefix = true;
            for (std::size_t i = 0; i < pc.size(); ++i) {
                if (sc[i] != pc[i]) { prefix = false; break; }
            }
            if (prefix) {
                VfsDirEntry e;
                e.name = sc.back();
                e.is_directory = true;
                merged[e.name] = std::move(e);
            }
        }
    }
    std::vector<VfsDirEntry> out;
    out.reserve(merged.size());
    for (auto& [name, e] : merged) out.push_back(std::move(e));
    return Result<std::vector<VfsDirEntry>>(std::move(out));
}

Result<std::vector<std::string>> VfsNamespace::walk(const VfsPath& root,
                                                    std::uint64_t max_entries) const {
    std::vector<std::string> out;
    if (max_entries == 0) {
        return Result<std::vector<std::string>>(
            RuntimeErrc::InvalidArgument, "max_entries must be > 0");
    }
    // Iterative DFS with a sorted-explicit stack for determinism.
    std::vector<VfsPath> stack;
    stack.push_back(root);
    while (!stack.empty()) {
        const VfsPath dir = stack.back();
        stack.pop_back();
        auto listing = list(dir);
        if (!listing.ok() && listing.errc() != RuntimeErrc::NotFound) {
            return Result<std::vector<std::string>>(listing.errc(),
                                                     listing.context());
        }
        if (!listing.ok()) continue;
        // Children in sorted order: files first-line, then dirs deeper.
        std::vector<VfsDirEntry> children = listing.value();
        std::sort(children.begin(), children.end(),
                  [](const VfsDirEntry& a, const VfsDirEntry& b) {
                      return a.name < b.name;
                  });
        // Push dirs in REVERSE so the alphabetically-first pops first.
        for (auto it = children.rbegin(); it != children.rend(); ++it) {
            const VfsPath child = dir.child(it->name);
            if (it->is_directory) {
                stack.push_back(child);
            }
            out.push_back(child.str());
            if (out.size() >= max_entries) {
                return Result<std::vector<std::string>>(
                    RuntimeErrc::OutOfResources,
                    "walk exceeded max_entries " + std::to_string(max_entries));
            }
        }
    }
    return Result<std::vector<std::string>>(std::move(out));
}

Result<void> VfsNamespace::create_file(const VfsPath& path) {
    auto res = resolve(path);
    if (!res.ok()) return Result<void>(res.errc(), res.context());
    if (res.value().rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "cannot create file at a mount root");
    }
    std::lock_guard lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) return Result<void>(RuntimeErrc::NotFound, "mount vanished");
    if (m->read_only) {
        return Result<void>(RuntimeErrc::LockNotOwned,
                            "mount is read-only");
    }
    return m->backend->create_file(res.value().rel);
}

Result<void> VfsNamespace::create_directory(const VfsPath& path) {
    auto res = resolve(path);
    if (!res.ok()) return Result<void>(res.errc(), res.context());
    if (res.value().rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "cannot create directory at a mount root");
    }
    std::lock_guard lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) return Result<void>(RuntimeErrc::NotFound, "mount vanished");
    if (m->read_only) {
        return Result<void>(RuntimeErrc::LockNotOwned, "mount is read-only");
    }
    return m->backend->create_directory(res.value().rel);
}

Result<void> VfsNamespace::delete_file(const VfsPath& path) {
    auto res = resolve(path);
    if (!res.ok()) return Result<void>(res.errc(), res.context());
    if (res.value().rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "mount root is not a file");
    }
    std::lock_guard lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) return Result<void>(RuntimeErrc::NotFound, "mount vanished");
    if (m->read_only) {
        return Result<void>(RuntimeErrc::LockNotOwned, "mount is read-only");
    }
    return m->backend->delete_file(res.value().rel);
}

Result<void> VfsNamespace::delete_directory(const VfsPath& path) {
    auto res = resolve(path);
    if (!res.ok()) return Result<void>(res.errc(), res.context());
    if (res.value().rel.is_root()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "cannot delete a mount root through the FS API");
    }
    std::lock_guard lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) return Result<void>(RuntimeErrc::NotFound, "mount vanished");
    if (m->read_only) {
        return Result<void>(RuntimeErrc::LockNotOwned, "mount is read-only");
    }
    // Refuse to delete a directory that carries sub-mounts.
    for (const auto& sub : impl_->mounts) {
        const auto& sc = sub.path.components();
        const auto& pc = path.components();
        if (sc.size() > pc.size()) {
            bool prefix = true;
            for (std::size_t i = 0; i < pc.size(); ++i) {
                if (sc[i] != pc[i]) { prefix = false; break; }
            }
            if (prefix) {
                return Result<void>(RuntimeErrc::InvalidState,
                                    "directory has an active sub-mount");
            }
        }
    }
    return m->backend->delete_directory(res.value().rel);
}

namespace {
// Open-tracking wrapper: decrements the mount's open-file count when the
// handle dies (balances VfsNamespace::open's increment exactly once).
class TrackedFileHandle : public IVfsFileHandle {
public:
    TrackedFileHandle(std::unique_ptr<IVfsFileHandle> inner,
                      std::shared_ptr<void> token, std::uint64_t mount_id)
        : inner_(std::move(inner)), token_(std::move(token)), mount_(mount_id) {}
    ~TrackedFileHandle() override {
        VfsNamespace::decrement_impl_mount(token_, mount_);
    }
    Result<std::uint64_t> read(void* buf, std::uint64_t len) override {
        return inner_->read(buf, len);
    }
    Result<std::uint64_t> write(const void* buf, std::uint64_t len) override {
        return inner_->write(buf, len);
    }
    Result<std::uint64_t> seek(std::uint64_t position) override {
        return inner_->seek(position);
    }
    std::uint64_t position() const override { return inner_->position(); }
    std::uint64_t size() const override { return inner_->size(); }

private:
    std::unique_ptr<IVfsFileHandle> inner_;
    std::shared_ptr<void> token_;
    std::uint64_t mount_;
};
}  // namespace

Result<std::unique_ptr<IVfsFileHandle>> VfsNamespace::open(const VfsPath& path,
                                                          bool write) {
    auto res = resolve(path);
    if (!res.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(res.errc(), res.context());
    }
    if (res.value().rel.is_root()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::InvalidArgument, "mount root is a directory");
    }
    std::unique_lock lock(impl_->lock);
    const Impl::Mount* m = impl_->by_id(res.value().mount_id);
    if (m == nullptr) {
        return Result<std::unique_ptr<IVfsFileHandle>>(RuntimeErrc::NotFound,
                                                       "mount vanished");
    }
    if (write && m->read_only) {
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::LockNotOwned, "mount is read-only");
    }
    IVfsBackend* backend = m->backend;
    const std::uint64_t mount_id = m->id;
    lock.unlock();
    auto fh = backend->open(res.value().rel, write);
    if (!fh.ok()) {
        return Result<std::unique_ptr<IVfsFileHandle>>(fh.errc(), fh.context());
    }
    lock.lock();
    // Re-find (unmount may have raced; if gone, fail cleanly).
    Impl::Mount* mm = impl_->by_id_mut(mount_id);
    if (mm == nullptr) {
        lock.unlock();
        return Result<std::unique_ptr<IVfsFileHandle>>(
            RuntimeErrc::NotFound, "mount unmounted during open");
    }
    ++mm->open_files;
    lock.unlock();
    // Tracked wrapper: the handle's DEATH balances the increment (the M5
    // fix: raw backend handles previously never decremented — unmount
    // stayed refused forever after any open).
    return Result<std::unique_ptr<IVfsFileHandle>>(
        std::unique_ptr<IVfsFileHandle>(
            new TrackedFileHandle(std::move(fh.value()), impl_token(), mount_id)));
}

void VfsNamespace::decrement_impl_mount(const std::shared_ptr<void>& token,
                                         std::uint64_t mount_id) {
    // Static helper: operates on the Impl token directly (type-erased in
    // the header; Impl is complete in this TU). Teardown-order
    // independent: usable after the owning session's destruction.
    if (token == nullptr) return;
    auto* impl = static_cast<Impl*>(token.get());
    std::lock_guard lock(impl->lock);
    if (Impl::Mount* m = impl->by_id_mut(mount_id)) {
        if (m->open_files > 0) --m->open_files;
    }
}

void VfsNamespace::close_open(IVfsFileHandle* handle) {
    // Kept for API compatibility: the open-file accounting is per MOUNT
    // and is balanced by decrement_mount_open (called from
    // VfsFileObject::on_destroy with the mount id recorded at open time).
    (void)handle;
}

void VfsNamespace::decrement_mount_open(std::uint64_t mount_id) {
    std::lock_guard lock(impl_->lock);
    if (Impl::Mount* m = impl_->by_id_mut(mount_id)) {
        if (m->open_files > 0) --m->open_files;
    }
}

// ── VfsFileObject ─────────────────────────────────────────────────────────

VfsFileObject::VfsFileObject(std::unique_ptr<IVfsFileHandle> fh,
                             VfsNamespace& space, std::string canonical_path,
                             bool writable)
    : RuntimeObject(TypeId::File),
      fh_(std::move(fh)),
      space_(space),
      impl_keep_(space.impl_token()),
      path_(std::move(canonical_path)),
      writable_(writable) {
    set_name(path_);
}

VfsFileObject::~VfsFileObject() = default;

Result<std::uint64_t> VfsFileObject::read(void* buf, std::uint64_t len) {
    std::lock_guard lock(io_lock_);
    return fh_->read(buf, len);
}

Result<std::uint64_t> VfsFileObject::write(const void* buf, std::uint64_t len) {
    if (!writable_) {
        return Result<std::uint64_t>(RuntimeErrc::LockNotOwned,
                                      "file opened read-only");
    }
    std::lock_guard lock(io_lock_);
    return fh_->write(buf, len);
}

Result<std::uint64_t> VfsFileObject::seek(std::uint64_t position) {
    std::lock_guard lock(io_lock_);
    return fh_->seek(position);
}

Result<std::uint64_t> VfsFileObject::position() const {
    return Result<std::uint64_t>(fh_->position());
}

Result<std::uint64_t> VfsFileObject::size() const {
    return Result<std::uint64_t>(fh_->size());
}

void VfsFileObject::on_destroy() {
    // Release the backend handle. The open-count decrement happens inside
    // the TrackedFileHandle's destructor (the wrapper the namespace
    // handed us) — a single, guaranteed decrement per open.
    fh_.reset();
}

}  // namespace xbox2pc::rt
