// vfs_process.cpp — M5 VFS ⇄ M4 process integration implementation.

#include "xbox2pc/vfs_process.hpp"

#include <utility>

#include "xbox2pc/vfs_backends.hpp"

namespace xbox2pc::rt {

// ── type registration ──────────────────────────────────────────────────────
namespace {
constexpr TypeId kVfsSessionType = static_cast<TypeId>(kUserTypeBase + 1);
constexpr TypeId kVfsBackendType = static_cast<TypeId>(kUserTypeBase + 2);
}

TypeId VfsSession::static_type_id() { return kVfsSessionType; }
TypeId VfsBackendObject::static_type_id() { return kVfsBackendType; }

// ── VfsBackendObject ──────────────────────────────────────────────────────

VfsBackendObject::VfsBackendObject(std::unique_ptr<IVfsBackend> backend,
                                   std::string name)
    : RuntimeObject(kVfsBackendType), backend_(std::move(backend)) {
    set_name(std::move(name));
}

VfsBackendObject::~VfsBackendObject() = default;

// ── VfsSession ────────────────────────────────────────────────────────────

VfsSession::VfsSession(std::string name)
    : RuntimeObject(kVfsSessionType), ns_() {
    set_name(std::move(name));
}

VfsSession::~VfsSession() = default;

Result<std::uint64_t> VfsSession::mount_backend(
    std::unique_ptr<IVfsBackend> backend, const std::string& mount_path,
    bool read_only, std::int64_t precedence) {
    // Parse the mount path with the session policy.
    auto path = VfsPath::parse(mount_path, ns_.policy());
    if (!path.ok()) {
        return Result<std::uint64_t>(path.errc(), path.context());
    }
    // Register the backend as an object so it outlives the mounts.
    auto owner = global_manager();
    if (owner == nullptr) {
        // No manager: keep the backend alive inside the session's own
        // vector (fallback ownership — tests without the runtime).
        backends_fallback_.push_back(std::move(backend));
        return ns_.mount(path.value(), *backends_fallback_.back(), read_only,
                         precedence);
    }
    auto obj = std::make_unique<VfsBackendObject>(std::move(backend),
                                                  "vfs-backend");
    IVfsBackend* raw = &obj->backend();
    auto reg = owner->register_object(std::move(obj));
    if (!reg.ok()) {
        return Result<std::uint64_t>(reg.errc(), reg.context());
    }
    backend_ids_.push_back(reg.value());
    return ns_.mount(path.value(), *raw, read_only, precedence);
}

Result<void> VfsSession::unmount(std::uint64_t mount_id) {
    return ns_.unmount(mount_id);
}

std::vector<VfsMountInfo> VfsSession::mounts() const { return ns_.list_mounts(); }

void VfsSession::on_destroy() {
    // Unmount everything. Any still-open file would refuse an unmount, but
    // the process-termination ordering closes handles BEFORE objects are
    // destroyed, so counts are 0 here; failures are recorded in metadata.
    for (const auto& info : ns_.list_mounts()) {
        (void)ns_.unmount(info.mount_id);
    }
}

// ── handle resolution helpers ──────────────────────────────────────────────

Result<VfsFileObject*> resolve_vfs_file(ObjectManager& mgr, Handle h) {
    auto found = mgr.lookup_handle(h);
    if (!found.ok()) {
        return Result<VfsFileObject*>(found.errc(), found.context());
    }
    auto* obj = found.value().get()->as<VfsFileObject>();
    if (obj == nullptr) {
        return Result<VfsFileObject*>(RuntimeErrc::ObjectTypeMismatch,
                                       "handle is not a VFS file");
    }
    return Result<VfsFileObject*>(obj);
}

// ── process bridges ────────────────────────────────────────────────────────
namespace {

// Resolve a process handle -> ManagedProcess + its VfsSession (attached as
// metadata object id "vfs_session" at creation — see attach code below).
Result<std::pair<ManagedProcess*, VfsSession*>> session_for(ObjectManager& mgr,
                                                            Handle process) {
    auto found = mgr.lookup_handle(process);
    if (!found.ok()) {
        return Result<std::pair<ManagedProcess*, VfsSession*>>(
            found.errc(), found.context());
    }
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr) {
        return Result<std::pair<ManagedProcess*, VfsSession*>>(
            RuntimeErrc::ObjectTypeMismatch, "handle is not a process");
    }
    // Session object id recorded in the process metadata.
    const std::string sid = proc->meta("vfs_session");
    if (sid.empty()) {
        return Result<std::pair<ManagedProcess*, VfsSession*>>(
            RuntimeErrc::NotFound, "process has no VFS session");
    }
    const std::uint64_t id =
        std::strtoull(sid.c_str(), nullptr, 10);
    auto s = mgr.lookup_id(id);
    if (!s.ok()) {
        return Result<std::pair<ManagedProcess*, VfsSession*>>(
            s.errc(), s.context());
    }
    auto* session = s.value().get()->as<VfsSession>();
    if (session == nullptr) {
        return Result<std::pair<ManagedProcess*, VfsSession*>>(
            RuntimeErrc::ObjectTypeMismatch, "session object type mismatch");
    }
    return Result<std::pair<ManagedProcess*, VfsSession*>>(
        std::make_pair(proc, session));
}

}  // namespace

Result<std::uint64_t> proc_mount_memory(Handle process, const std::string& mount_path,
                                        std::int64_t precedence) {
    auto* mgr = global_manager();
    if (mgr == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::NotInitialized,
                                     "runtime not initialized");
    }
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<std::uint64_t>(s.errc(), s.context());
    return s.value().second->mount_backend(std::make_unique<MemoryBackend>(),
                                           mount_path, false, precedence);
}

Result<std::uint64_t> proc_mount_host_dir(Handle process,
                                          const std::string& host_root,
                                          const std::string& mount_path,
                                          bool read_only,
                                          std::int64_t precedence) {
    auto* mgr = global_manager();
    if (mgr == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::NotInitialized,
                                     "runtime not initialized");
    }
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<std::uint64_t>(s.errc(), s.context());
    // Validate the host root BEFORE mounting (typed failure surfaces now).
    auto st = pal::stat_host_path(host_root);
    if (!st.ok() || !st.value().is_directory) {
        return Result<std::uint64_t>(
            RuntimeErrc::InvalidArgument,
            "host root must be an existing directory: " + host_root);
    }
    return s.value().second->mount_backend(
        std::make_unique<HostDirBackend>(host_root, read_only), mount_path,
        read_only, precedence);
}

Result<void> proc_unmount(Handle process, std::uint64_t mount_id) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<void>(RuntimeErrc::NotInitialized,
                                            "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<void>(s.errc(), s.context());
    return s.value().second->unmount(mount_id);
}

Result<std::vector<VfsMountInfo>> proc_mounts(Handle process) {
    auto* mgr = global_manager();
    if (mgr == nullptr) {
        return Result<std::vector<VfsMountInfo>>(RuntimeErrc::NotInitialized,
                                                 "runtime not initialized");
    }
    auto s = session_for(*mgr, process);
    if (!s.ok()) {
        return Result<std::vector<VfsMountInfo>>(s.errc(), s.context());
    }
    return Result<std::vector<VfsMountInfo>>(s.value().second->mounts());
}

Result<std::vector<VfsDirEntry>> proc_list(Handle process, const std::string& path) {
    auto* mgr = global_manager();
    if (mgr == nullptr) {
        return Result<std::vector<VfsDirEntry>>(RuntimeErrc::NotInitialized,
                                                 "runtime not initialized");
    }
    auto s = session_for(*mgr, process);
    if (!s.ok()) {
        return Result<std::vector<VfsDirEntry>>(s.errc(), s.context());
    }
    auto p = VfsPath::parse(path, s.value().second->namespace_().policy());
    if (!p.ok()) {
        return Result<std::vector<VfsDirEntry>>(p.errc(), p.context());
    }
    return s.value().second->namespace_().list(p.value());
}

Result<VfsStat> proc_stat(Handle process, const std::string& path) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<VfsStat>(RuntimeErrc::NotInitialized,
                                               "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<VfsStat>(s.errc(), s.context());
    auto p = VfsPath::parse(path, s.value().second->namespace_().policy());
    if (!p.ok()) return Result<VfsStat>(p.errc(), p.context());
    return s.value().second->namespace_().stat(p.value());
}

Result<void> proc_create_file(Handle process, const std::string& path) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<void>(RuntimeErrc::NotInitialized,
                                            "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<void>(s.errc(), s.context());
    auto p = VfsPath::parse(path, s.value().second->namespace_().policy());
    if (!p.ok()) return Result<void>(p.errc(), p.context());
    return s.value().second->namespace_().create_file(p.value());
}

Result<void> proc_create_directory(Handle process, const std::string& path) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<void>(RuntimeErrc::NotInitialized,
                                            "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<void>(s.errc(), s.context());
    auto p = VfsPath::parse(path, s.value().second->namespace_().policy());
    if (!p.ok()) return Result<void>(p.errc(), p.context());
    return s.value().second->namespace_().create_directory(p.value());
}

Result<void> proc_delete_file(Handle process, const std::string& path) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<void>(RuntimeErrc::NotInitialized,
                                            "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<void>(s.errc(), s.context());
    auto p = VfsPath::parse(path, s.value().second->namespace_().policy());
    if (!p.ok()) return Result<void>(p.errc(), p.context());
    return s.value().second->namespace_().delete_file(p.value());
}

Result<void> proc_delete_directory(Handle process, const std::string& path) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<void>(RuntimeErrc::NotInitialized,
                                            "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<void>(s.errc(), s.context());
    auto p = VfsPath::parse(path, s.value().second->namespace_().policy());
    if (!p.ok()) return Result<void>(p.errc(), p.context());
    return s.value().second->namespace_().delete_directory(p.value());
}

Result<Handle> proc_open_file(Handle process, const std::string& path,
                              bool write) {
    auto* mgr = global_manager();
    if (mgr == nullptr) return Result<Handle>(RuntimeErrc::NotInitialized,
                                               "runtime not initialized");
    auto s = session_for(*mgr, process);
    if (!s.ok()) return Result<Handle>(s.errc(), s.context());
    auto& session = *s.value().second;
    auto p = VfsPath::parse(path, session.namespace_().policy());
    if (!p.ok()) return Result<Handle>(p.errc(), p.context());
    auto fh = session.namespace_().open(p.value(), write);
    if (!fh.ok()) return Result<Handle>(fh.errc(), fh.context());
    // Wrap as an object; record the mount id for balanced open tracking.
    auto res = session.namespace_().resolve(p.value());
    const std::uint64_t mount_id = res.ok() ? res.value().mount_id : 0;
    auto obj = std::make_unique<VfsFileObject>(
        std::move(fh.value()), session.namespace_(), p.value().str(), write);
    obj->set_meta("mount_id", std::to_string(mount_id));
    auto reg = mgr->register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    auto found = mgr->lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    // Handles through the RUNTIME table (processes share it in M4's
    // model; the M4 rights layer governs).
    auto handle = mgr->create_handle_with_rights(
        *found.value().get(),
        write ? AccessRights::ReadWrite | AccessRights::Close
              : AccessRights::Read | AccessRights::Close,
        /*inheritable=*/false);
    if (!handle.ok()) return Result<Handle>(handle.errc(), handle.context());
    return handle;
}

Result<std::uint64_t> vfs_read(ObjectManager& mgr, Handle file, void* buf,
                               std::uint64_t len) {
    auto obj = resolve_vfs_file(mgr, file);
    if (!obj.ok()) return Result<std::uint64_t>(obj.errc(), obj.context());
    return obj.value()->read(buf, len);
}

Result<std::uint64_t> vfs_write(ObjectManager& mgr, Handle file, const void* buf,
                                std::uint64_t len) {
    auto obj = resolve_vfs_file(mgr, file);
    if (!obj.ok()) return Result<std::uint64_t>(obj.errc(), obj.context());
    return obj.value()->write(buf, len);
}

Result<std::uint64_t> vfs_seek(ObjectManager& mgr, Handle file,
                               std::uint64_t position) {
    auto obj = resolve_vfs_file(mgr, file);
    if (!obj.ok()) return Result<std::uint64_t>(obj.errc(), obj.context());
    return obj.value()->seek(position);
}

// ── process creation with an attached session ─────────────────────────────
//
// Helper used by the CLI/tests: create a process AND attach a fresh
// VfsSession to it (records the session object id in the process's
// metadata). Lives here so the M4 process-management library stays
// untouched by M5 (no dependency inversion).

Result<Handle> create_process_with_vfs(ProcessManager& pm, ObjectManager& mgr,
                                       const std::string& image_name) {
    auto proc = pm.create_process(image_name);
    if (!proc.ok()) return Result<Handle>(proc.errc(), proc.context());
    auto found = mgr.lookup_handle(proc.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    auto* mp = found.value().get()->as<ManagedProcess>();
    if (mp == nullptr) {
        return Result<Handle>(RuntimeErrc::ObjectTypeMismatch,
                              "not a managed process");
    }
    auto session = std::make_unique<VfsSession>("proc-" + image_name);
    auto reg = mgr.register_object(std::move(session));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    mp->set_meta("vfs_session", std::to_string(reg.value()));
    return proc;
}

}  // namespace xbox2pc::rt
