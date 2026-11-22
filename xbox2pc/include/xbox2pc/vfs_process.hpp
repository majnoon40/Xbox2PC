#pragma once
// xbox2pc/vfs_process.hpp — M5 VFS ⇄ M4 process integration.
//
// Design (docs/virtual-filesystem.md §namespaces):
//   * VfsSession is a RuntimeObject (user type "VfsSession") owning ONE
//     VfsNamespace + its backends' lifetimes as objects. It is attached to
//     a ManagedProcess at creation; the process's table issues file
//     handles; termination closes the table (M4 ordering step c) → the
//     VfsFileObjects are destroyed → their on_destroy balances namespace
//     open-file counts. No second handle system, no bespoke cleanup path.
//   * ProcessManager gains mount/open/read/... bridges that resolve the
//     owning process by handle (rights checks ride the M4 rights layer).
//   * Every session starts EMPTY (no mounts): isolation is the default;
//     sharing happens only by explicitly mounting the same backend object
//     into two sessions (caller's choice, documented).

#include <memory>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/vfs.hpp"

namespace xbox2pc::rt {

// ── session object ─────────────────────────────────────────────────────────

class VfsSession : public RuntimeObject {
public:
    static TypeId static_type_id();  // registered user type

    explicit VfsSession(std::string name);
    ~VfsSession() override;

    VfsNamespace& namespace_() { return ns_; }
    const VfsNamespace& namespace_() const { return ns_; }

    // Mount a backend owned by this session (registered in the object
    // manager so it stays alive until the session dies). Returns the
    // mount id.
    Result<std::uint64_t> mount_backend(std::unique_ptr<IVfsBackend> backend,
                                        const std::string& mount_path,
                                        bool read_only, std::int64_t precedence);
    Result<void> unmount(std::uint64_t mount_id);
    std::vector<VfsMountInfo> mounts() const;

private:
    void on_destroy() override;  // unmounts everything (open files must be 0
                                 // — process termination closes handles first)
    VfsNamespace ns_;
    // Registered backend object ids (the manager owns the IVfsBackend
    // wrappers; kept for teardown diagnostics).
    std::vector<std::uint64_t> backend_ids_;
    // Fallback ownership when NO object manager is installed (bare tests).
    std::vector<std::unique_ptr<IVfsBackend>> backends_fallback_;
};

// IVfsBackend lifetime wrapper: a RuntimeObject holding a backend.
class VfsBackendObject : public RuntimeObject {
public:
    static TypeId static_type_id();

    VfsBackendObject(std::unique_ptr<IVfsBackend> backend, std::string name);
    ~VfsBackendObject() override;

    IVfsBackend& backend() { return *backend_; }
    const IVfsBackend& backend() const { return *backend_; }

private:
    std::unique_ptr<IVfsBackend> backend_;
};

// ── typed VFS file-handle view (for handle-based access) ──────────────────
//
// Opening a file through the process bridge yields an M4 HANDLE bound to
// a VfsFileObject; this helper resolves + validates the type once.
Result<VfsFileObject*> resolve_vfs_file(ObjectManager& mgr, Handle h);

// ── ProcessManager bridges ─────────────────────────────────────────────────
//
// Mounted through a process's OWN session only. All operations resolve the
// process by handle first (M4 handle validation), then the session.
// Termination of the process runs the M4 ordering; the session's backends
// die with the session object when the process's objects are destroyed.

Result<std::uint64_t> proc_mount_memory(Handle process, const std::string& mount_path,
                                        std::int64_t precedence);
Result<std::uint64_t> proc_mount_host_dir(Handle process, const std::string& host_root,
                                         const std::string& mount_path, bool read_only,
                                         std::int64_t precedence);
Result<void> proc_unmount(Handle process, std::uint64_t mount_id);
Result<std::vector<VfsMountInfo>> proc_mounts(Handle process);
Result<std::vector<VfsDirEntry>> proc_list(Handle process, const std::string& path);
Result<VfsStat> proc_stat(Handle process, const std::string& path);
Result<void> proc_create_file(Handle process, const std::string& path);
Result<void> proc_create_directory(Handle process, const std::string& path);
Result<void> proc_delete_file(Handle process, const std::string& path);
Result<void> proc_delete_directory(Handle process, const std::string& path);
// Open through the process's handle table (M4 handle + rights).
Result<Handle> proc_open_file(Handle process, const std::string& path,
                             bool write);
Result<std::uint64_t> vfs_read(ObjectManager& mgr, Handle file, void* buf,
                               std::uint64_t len);
Result<std::uint64_t> vfs_write(ObjectManager& mgr, Handle file, const void* buf,
                                std::uint64_t len);
Result<std::uint64_t> vfs_seek(ObjectManager& mgr, Handle file,
                               std::uint64_t position);

// Full path strings are parsed with the session policy inside the bridges;
// typed InvalidArgument carries the parse failure.

// Create a process WITH an attached VFS session (records the session id in
// the process's metadata; the bridges above resolve it). Kept in the M5
// layer so the M4 process library gains no VFS dependency.
Result<Handle> create_process_with_vfs(ProcessManager& pm, ObjectManager& mgr,
                                      const std::string& image_name);

}  // namespace xbox2pc::rt
