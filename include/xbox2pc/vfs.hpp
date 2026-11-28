#pragma once
// xbox2pc/vfs.hpp — M5 virtual filesystem.
//
// Design (docs/virtual-filesystem.md):
//   1. Path model: canonical VFS paths are '/'-separated, rooted ("/"),
//      no drive letters, no symlinks (the runtime's own naming rule —
//      documented Xbox-agnostic). All public entry points normalize
//      through VfsPath::parse, which rejects: empty components kept, ".."
//      escaping the root, NUL/control chars, over-long components, and
//      backslash-injection (converted or rejected per policy below).
//   2. Case policy: VFS paths are CASE-SENSITIVE by default; each
//      filesystem/mount may declare case-insensitive matching (matching
//      then folds ASCII case on lookup only — the stored form stays
//      as-is; documented deviation vs both FAT (insensitive) and NTFS
//      (configurable)). Xbox's own rule is NOT known — we do not claim it.
//   3. Backends implement IVfsBackend (open/read/write/create/...) and own
//      their storage; the VFS never touches the host directly — host
//      access lives in the PAL + HostDirBackend (wraps the PAL calls and
//      enforces root confinement via VfsPath resolution).
//   4. Mounts: a VfsNamespace is a mount TREE: each mount maps a VFS
//      directory to a backend at a precedence value; lookups walk the
//      mount points from LONGEST matching path (most specific) first;
//      equal paths resolve by precedence (higher wins), then by mount
//      order (deterministic). Mounts can be read-only (writes typed
//      PermissionDenied). Every process can own a private namespace
//      (isolation); namespaces are plain objects under the object model.
//   5. File objects: VfsFileObject (RuntimeObject, TypeId::File) with
//      generation-protected handles from the EXISTING M4 manager (no
//      second handle system); rights enforce read/write; process
//      termination closes its table (existing M4 cleanup path).
//
// Xbox framing: this is xbox2pc infrastructure with NO claim of Xbox
// filesystem internals; docs separate confirmed host facts from design
// decisions.

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/platform.hpp"
#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt {

// ── path policy + errors ───────────────────────────────────────────────────

struct VfsPathPolicy {
    std::uint32_t max_component_length = 255;  // per component
    std::uint32_t max_depth = 64;              // components
    std::uint32_t max_total_length = 4096;     // canonical string length
    bool allow_backslash_separator = false;    // reject '\' (default: Xbox-agnostic strict)
    bool case_insensitive = false;             // per-mount override exists
};

// ── parsed path ────────────────────────────────────────────────────────────
//
// A normalized, validated path: components only (no ".", no "..", no
// trailing separators). "" is the root ("/").
class VfsPath {
public:
    // Parse + normalize a user path. Handles: leading '/', repeated '/',
    // interior "/./", trailing "/", and ".." cancellation — ".." above the
    // root is REJECTED (traversal). Backslashes are separators only when
    // the policy allows; otherwise they are invalid characters.
    static Result<VfsPath> parse(const std::string& raw,
                                  const VfsPathPolicy& policy = {});

    // Build from already-clean components (no validation of separators).
    static VfsPath from_components(std::vector<std::string> components);

    const std::vector<std::string>& components() const { return comps_; }
    // Canonical string form: "/" + join('/') ; root is "/".
    std::string str() const;
    // Parent path (root's parent is the root).
    VfsPath parent() const;
    // Child path with one appended component (component NOT re-validated).
    VfsPath child(const std::string& name) const;
    // Depth = component count; root depth 0.
    std::size_t depth() const { return comps_.size(); }
    bool is_root() const { return comps_.empty(); }

    // Case-folding key for case-insensitive matching ('/' + lower(ascii)).
    std::string fold_key() const;

    bool operator==(const VfsPath& o) const { return comps_ == o.comps_; }
    bool operator!=(const VfsPath& o) const { return !(*this == o); }
    bool operator<(const VfsPath& o) const { return comps_ < o.comps_; }

    VfsPath() = default;

private:
    std::vector<std::string> comps_;
};

// ── file handle (backend-side) ─────────────────────────────────────────────
//
// One open file instance. Position tracking is the BACKEND's (host files
// track in the PAL; in-memory/files track internally). Thread safety:
// implementations must tolerate concurrent read() from multiple threads
// (the VFS layer allows concurrent read handles); writes are serialized
// by the implementation.
class IVfsFileHandle {
public:
    virtual ~IVfsFileHandle() = default;

    // Read up to len bytes at the current position; returns bytes read
    // (0 = EOF). Advances the position.
    virtual Result<std::uint64_t> read(void* buf, std::uint64_t len) = 0;
    // Write at the current position; returns bytes written.
    virtual Result<std::uint64_t> write(const void* buf, std::uint64_t len) = 0;
    // Absolute seek (InvalidArgument beyond size for reads).
    virtual Result<std::uint64_t> seek(std::uint64_t position) = 0;
    // Current position.
    virtual std::uint64_t position() const = 0;
    virtual std::uint64_t size() const = 0;
};

// ── backend interface ─────────────────────────────────────────────────────
//
// A filesystem implementation. Paths arriving here are ALREADY canonical
// and RELATIVE TO THE MOUNT POINT (the namespace strips the mount prefix).
// Backends never see host paths (HostDirBackend is the only host toucher
// and it confines through the PAL with a validated root).
struct VfsStat {
    bool is_directory = false;
    bool exists = false;
    std::uint64_t size = 0;   // bytes, files only
};

struct VfsDirEntry {
    std::string name;        // base name
    bool is_directory = false;
    std::uint64_t size = 0;
};

class IVfsBackend {
public:
    virtual ~IVfsBackend() = default;

    virtual const char* backend_name() const = 0;
    virtual bool read_only() const = 0;
    // Case-insensitive matching (per-backend policy; VfsPath::fold_key).
    virtual bool case_insensitive() const { return false; }

    virtual Result<VfsStat> stat(const VfsPath& rel) = 0;

    // Open a file for reading/writing. `write` requests write access;
    // backends that cannot honor it return typed errors.
    virtual Result<std::unique_ptr<IVfsFileHandle>> open(const VfsPath& rel,
                                                         bool write) = 0;

    // Mutations (typed PermissionDenied on read-only backends).
    virtual Result<void> create_file(const VfsPath& rel) = 0;
    virtual Result<void> delete_file(const VfsPath& rel) = 0;
    virtual Result<void> create_directory(const VfsPath& rel) = 0;
    virtual Result<void> delete_directory(const VfsPath& rel) = 0;  // empty only

    // One-level enumeration; entries sorted by name (deterministic).
    virtual Result<std::vector<VfsDirEntry>> list(const VfsPath& rel) = 0;
};

// ── mounts ─────────────────────────────────────────────────────────────────

struct VfsMountInfo {
    std::string mount_path;      // canonical VFS path ("/Game")
    std::string backend_name;
    bool read_only = false;
    std::int64_t precedence = 0; // higher wins on equal mount paths
    std::uint64_t mount_id = 0;
};

// ── namespace ─────────────────────────────────────────────────────────────
//
// A mount tree over backends. Owns nothing but mount registrations (the
// caller keeps backends alive — typically as RuntimeObjects).
class VfsNamespace {
public:
    VfsNamespace();
    ~VfsNamespace();

    VfsNamespace(const VfsNamespace&) = delete;
    VfsNamespace& operator=(const VfsNamespace&) = delete;

    // Mount `backend` at `mount_path` (a directory; must not be an
    // existing FILE). Same-path remounts stack by precedence (higher
    // wins), ties by later-mount-wins. Read-only enforced when
    // `read_only` or the backend itself is read-only.
    Result<std::uint64_t> mount(const VfsPath& mount_path, IVfsBackend& backend,
                               bool read_only, std::int64_t precedence);
    // Unmount by id (typed NotFound). Refuses when open files exist on
    // that mount (Busy-style InvalidState).
    Result<void> unmount(std::uint64_t mount_id);
    std::vector<VfsMountInfo> list_mounts() const;

    // ── filesystem operations (mount-aware) ──
    Result<VfsStat> stat(const VfsPath& path) const;
    Result<std::vector<VfsDirEntry>> list(const VfsPath& path) const;
    // Enumerate RECURSIVELY (depth-first, sorted); bounded by
    // max_entries (typed OutOfResources when exceeded — resource safety).
    Result<std::vector<std::string>> walk(const VfsPath& root,
                                          std::uint64_t max_entries) const;
    Result<void> create_file(const VfsPath& path);
    Result<void> create_directory(const VfsPath& path);
    Result<void> delete_file(const VfsPath& path);
    Result<void> delete_directory(const VfsPath& path);

    // Open a file → backend handle. The namespace tracks open handles
    // per mount (unmount safety) — the caller wraps the result in a
    // VfsFileObject and owns closing it via close_open().
    Result<std::unique_ptr<IVfsFileHandle>> open(const VfsPath& path,
                                                bool write);
    // Called by VfsFileObject::on_destroy (tracks the mount's open count).
    void close_open(IVfsFileHandle* handle);

    // Policy accessors.
    const VfsPathPolicy& policy() const;
    void set_policy(const VfsPathPolicy& p);

    // Mount resolution for the given path: fills the mount that serves
    // it (and the relative remainder). Public for diagnostics/tests.
    struct Resolved {
        std::uint64_t mount_id = 0;
        VfsPath rel;              // relative to the mount root
        bool read_only = false;
        bool case_insensitive = false;
    };
    Result<Resolved> resolve(const VfsPath& path) const;

    // Internal (used by VfsFileObject::on_destroy): drop the mount's
    // open-file count so unmount safety stays exact.
    void decrement_mount_open(std::uint64_t mount_id);

    // Opaque keep-alive token type (VfsNamespace::Impl, type-erased).
    // Public: the open-tracking wrapper (anonymous-namespace class in
    // vfs.cpp) calls the static below through the token; users should
    // treat it as opaque.
    static void decrement_impl_mount(const std::shared_ptr<void>& token,
                                     std::uint64_t mount_id);

private:
    friend class VfsFileObject;

    struct Impl;
    // shared_ptr: VfsFileObject instances hold a keep-alive token to the
    // SAME Impl (M5 use-after-free fix: file objects may outlive the
    // owning session during manager teardown; the Impl stays alive until
    // the last file object releases it — see VfsFileObject::impl_keep_).
    std::shared_ptr<Impl> impl_;

    const Impl* impl() const { return impl_.get(); }
    Impl* impl() { return impl_.get(); }

public:
    // Keep-alive token for file objects (internal).
    std::shared_ptr<Impl> impl_token() { return impl_; }
};

// ── runtime file object (handle-integrated) ────────────────────────────────
//
// Wraps one open VFS file as a RuntimeObject: handles from the M4
// manager, rights enforced at the object boundary, cleanup on destroy.
class VfsNamespace;

class VfsFileObject : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(VfsFileObject, File)

    // The object takes ownership of `fh`; `space` tracks it for unmount
    // (the object keeps the namespace's Impl alive — teardown-order safe).
    VfsFileObject(std::unique_ptr<IVfsFileHandle> fh, VfsNamespace& space,
                  std::string canonical_path, bool writable);
    ~VfsFileObject() override;

    Result<std::uint64_t> read(void* buf, std::uint64_t len);
    Result<std::uint64_t> write(const void* buf, std::uint64_t len);
    Result<std::uint64_t> seek(std::uint64_t position);
    Result<std::uint64_t> position() const;
    Result<std::uint64_t> size() const;

    bool writable() const { return writable_; }
    const std::string& canonical_path() const { return path_; }

private:
    void on_destroy() override;  // notifies the namespace (open tracking)

    std::unique_ptr<IVfsFileHandle> fh_;
    [[maybe_unused]] VfsNamespace& space_;   // bound at construction (namespace lifetime intent)
    // Keep-alive to the namespace Impl (outlives the session if the
    // manager destroys the session first — the M5 UAF fix). Opaque type:
    // VfsNamespace::Impl (vfs.cpp defines both; the fwd struct aliases it).
    std::shared_ptr<void> impl_keep_;
    const std::string path_;
    const bool writable_;
    mutable std::mutex io_lock_;  // serializes position-mutating IO
};

// ── process-scoped namespaces (M4 integration) ────────────────────────────
//
// ManagedProcess extension: every process owns a VfsNamespace created at
// process creation; the ProcessManager exposes mount/unmount/open/etc per
// process handle; termination runs the namespace's cleanup (closes open
// files via handle-table close_all → objects destroyed → on_destroy).
// The integration lives in process_management (see vfs_process.hpp).

}  // namespace xbox2pc::rt
