// process_management.cpp — M4 ManagedProcess + ProcessManager.

#include "xbox2pc/process_management.hpp"

#include <algorithm>
#include <utility>

namespace xbox2pc::rt {

// ── ManagedProcess ─────────────────────────────────────────────────────────

ManagedProcess::ManagedProcess(std::uint64_t pid, std::string image_name,
                               std::uint64_t space_capacity,
                               std::uint64_t xbox_base)
    : RtProcess(image_name),  // M3 base keeps its own naming/registry
      pid_(pid),
      image_name_(std::move(image_name)),
      space_(std::make_unique<AddressSpace>(space_capacity, xbox_base,
                                             "proc-" + std::to_string(pid))) {}

ManagedProcess::~ManagedProcess() = default;

Result<void> ManagedProcess::add_module_descriptor(const ModuleDescriptor& mod) {
    std::lock_guard lock(detail_lock_);
    modules_.push_back(mod);
    return Result<void>::ok_result();
}

std::vector<ModuleDescriptor> ManagedProcess::module_descriptors() const {
    std::lock_guard lock(detail_lock_);
    return modules_;
}

Result<void> ManagedProcess::attach_thread(std::uint64_t thread_obj_id) {
    std::lock_guard lock(detail_lock_);
    for (std::uint64_t t : threads_) {
        if (t == thread_obj_id) {
            return Result<void>(RuntimeErrc::AlreadyExists, "thread already attached");
        }
    }
    threads_.push_back(thread_obj_id);
    return Result<void>::ok_result();
}

Result<void> ManagedProcess::detach_thread(std::uint64_t thread_obj_id) {
    std::lock_guard lock(detail_lock_);
    const auto it = std::remove(threads_.begin(), threads_.end(), thread_obj_id);
    if (it == threads_.end()) {
        return Result<void>(RuntimeErrc::NotFound, "thread not attached");
    }
    threads_.erase(it, threads_.end());
    return Result<void>::ok_result();
}

std::vector<std::uint64_t> ManagedProcess::thread_ids() const {
    std::lock_guard lock(detail_lock_);
    return threads_;
}

ResourceStats ManagedProcess::stats() const {
    ResourceStats s;
    {
        const AddressSpace::Stats ms = space_->stats();
        s.reserved_bytes = ms.reserved_bytes;
        s.committed_bytes = ms.committed_bytes;
        s.region_count = ms.region_count;
    }
    std::lock_guard lock(detail_lock_);
    s.thread_count = static_cast<std::uint32_t>(threads_.size());
    s.module_count = static_cast<std::uint32_t>(modules_.size());
    s.handle_count = handle_table().live_count();
    return s;
}

void ManagedProcess::set_memory_limits(const MemoryLimits& limits) {
    space_->set_limits(limits);
}

// ── ProcessManager ────────────────────────────────────────────────────────

ProcessManager::ProcessManager(ObjectManager& objects) : objects_(objects) {}

ProcessManager::~ProcessManager() {
    // Snapshot ids under the map lock; never index pid_to_object_id_ after
    // releasing it. Drain every host thread before releasing its address
    // space, because a cooperative thread may still be executing guest code.
    std::vector<std::uint64_t> object_ids;
    {
        std::lock_guard lock(lock_);
        object_ids.reserve(pid_to_object_id_.size());
        for (const auto& [pid, id] : pid_to_object_id_) object_ids.push_back(id);
    }
    for (const std::uint64_t id : object_ids) {
        auto found = objects_.lookup_id(id);
        if (!found.ok() || found.value().get() == nullptr) continue;
        auto* proc = found.value().get()->as<ManagedProcess>();
        if (proc == nullptr) continue;
        const auto tids = proc->thread_ids();
        for (const auto tid : tids) {
            auto t = objects_.lookup_id(tid);
            if (t.ok() && t.value().get() != nullptr) {
                if (auto* thread = t.value().get()->as<RtThread>()) {
                    thread->request_stop();
                }
            }
        }
        for (const auto tid : tids) {
            auto t = objects_.lookup_id(tid);
            if (t.ok() && t.value().get() != nullptr) {
                if (auto* thread = t.value().get()->as<RtThread>()) {
                    auto joined = thread->join_ns(pal::kInfiniteTimeout);
                    if (!joined.ok() &&
                        joined.errc() != RuntimeErrc::InvalidState) {
                        // A manager cannot safely free memory while a host
                        // thread might still touch it; do not force detach.
                        continue;
                    }
                }
            }
        }
        (void)proc->handle_table().close_all();
        (void)proc->address_space().release_all();
        for (const auto tid : tids) (void)proc->detach_thread(tid);
        (void)proc->terminate(0);
    }
}

Result<Handle> ProcessManager::create_process(const std::string& image_name,
                                              std::uint64_t space_capacity) {
    if (image_name.empty()) {
        return Result<Handle>(RuntimeErrc::InvalidArgument, "empty image name");
    }
    std::lock_guard lock(lock_);
    if (limits_.max_processes != 0 &&
        pid_to_object_id_.size() + 1 > limits_.max_processes) {
        return Result<Handle>(RuntimeErrc::OutOfResources, "process limit");
    }
    const std::uint64_t pid = next_pid_.fetch_add(1, std::memory_order_acq_rel);
    // Xbox-address base for the process space (design choice documented:
    // 0x10000000 per process; distinct from typical host mappings).
    auto proc = std::make_unique<ManagedProcess>(pid, image_name, space_capacity,
                                                 0x10000000ull * ((pid % 256) + 1));
    auto reg = objects_.register_object(std::move(proc));
    if (!reg.ok()) {
        return Result<Handle>(reg.errc(), reg.context());
    }
    pid_to_object_id_[pid] = reg.value();
    // Issue the runtime-table handle for the process object.
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) {
        pid_to_object_id_.erase(pid);
        (void)objects_.destroy(reg.value());  // rollback registration
        return Result<Handle>(found.errc(), found.context());
    }
    auto handle = objects_.create_handle(*found.value().get());
    if (!handle.ok()) {
        pid_to_object_id_.erase(pid);
        (void)objects_.destroy(reg.value());  // rollback: no partial leaks
        return Result<Handle>(handle.errc(), handle.context());
    }
    return handle;
}

Result<void> ProcessManager::initialize_process(Handle process,
                                                const ModuleDescriptor& main,
                                                const RuntimeConfig& config) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // Delegate to the M3 state machine (Initializing); on failure the M3
    // machine leaves Created — and we drop any module descriptors added
    // (documented rollback: init failure must not leak metadata).
    auto r = proc->initialize(main, config);
    if (!r.ok()) {
        return r;
    }
    auto add = proc->add_module_descriptor(main);
    if (!add.ok()) {
        // Rollback: fail the process (state machine offers fail()) and
        // clear the space (partial init must not leak).
        (void)proc->fail("initialize: module descriptor rejected");
        (void)proc->address_space().release_all();
        return add;
    }
    return Result<void>::ok_result();
}

Result<void> ProcessManager::start_process(Handle process) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // M3 machine: Initializing -> Running. Created (uninitialized) start
    // is an InvalidTransition (typed) — required by the tests.
    return proc->run();
}

Result<void> ProcessManager::suspend_process(Handle process) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    auto r = proc->suspend();
    if (!r.ok()) return r;
    // Cooperative suspension across owned threads: request stop so their
    // safe points observe it (never forced).
    for (std::uint64_t tid : proc->thread_ids()) {
        auto t = objects_.lookup_id(tid);
        if (t.ok() && t.value().get() != nullptr) {
            if (auto* thread = t.value().get()->as<RtThread>()) {
                thread->request_stop();
            }
        }
    }
    return Result<void>::ok_result();
}

Result<void> ProcessManager::resume_process(Handle process) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    auto r = proc->resume();
    if (!r.ok()) return r;
    for (std::uint64_t tid : proc->thread_ids()) {
        auto t = objects_.lookup_id(tid);
        if (t.ok() && t.value().get() != nullptr) {
            if (auto* thread = t.value().get()->as<RtThread>()) {
                // Clear the cooperative stop for resumable threads.
                (void)thread->resume();
            }
        }
    }
    return Result<void>::ok_result();
}

Result<void> ProcessManager::terminate_process(Handle process,
                                               std::uint64_t exit_code) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // Stop all threads first, then join them before touching process-owned
    // handles or guest memory. A timeout leaves the process resources intact;
    // callers can retry termination after the cooperative thread exits.
    const auto tids = proc->thread_ids();
    for (const std::uint64_t tid : tids) {
        auto t = objects_.lookup_id(tid);
        if (t.ok() && t.value().get() != nullptr) {
            if (auto* thread = t.value().get()->as<RtThread>()) {
                thread->request_stop();
            }
        }
    }
    for (const std::uint64_t tid : tids) {
        auto t = objects_.lookup_id(tid);
        if (!t.ok() || t.value().get() == nullptr) continue;
        if (auto* thread = t.value().get()->as<RtThread>()) {
            auto joined = thread->join_ns(50ull * 1000 * 1000);
            if (!joined.ok() && joined.errc() != RuntimeErrc::InvalidState) {
                return Result<void>(joined.errc(),
                                    "process termination deferred: thread " +
                                        std::to_string(tid) + " has not exited: " +
                                        joined.context());
            }
        }
    }
    auto closed = proc->handle_table().close_all();
    if (!closed.ok()) return closed;
    auto released = proc->address_space().release_all();
    if (!released.ok()) return released;
    for (const std::uint64_t tid : tids) {
        auto detached = proc->detach_thread(tid);
        if (!detached.ok() && detached.errc() != RuntimeErrc::NotFound) {
            return detached;
        }
    }
    return proc->terminate(exit_code);
}

Result<Handle> ProcessManager::spawn_thread(Handle process,
                                            RtThread::ThreadMain main, void* arg,
                                            const std::string& name) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<Handle>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // Thread limits (global).
    if (limits_.max_threads_total != 0) {
        std::uint32_t total = 0;
        for (const auto& [pid, id] : pid_to_object_id_) {
            auto p = objects_.lookup_id(id);
            if (p.ok() && p.value().get() != nullptr) {
                total += p.value().get()->as<ManagedProcess>()
                             ->thread_ids()
                             .size();
            }
        }
        if (total + 1 > limits_.max_threads_total) {
            return Result<Handle>(RuntimeErrc::OutOfResources, "thread limit");
        }
    }
    auto thread = std::make_unique<RtThread>(main, arg, name);
    auto reg = objects_.register_object(std::move(thread));
    if (!reg.ok()) {
        return Result<Handle>(reg.errc(), reg.context());
    }
    auto attach = proc->attach_thread(reg.value());
    if (!attach.ok()) {
        (void)objects_.destroy(reg.value());  // rollback: no partial leaks
        return Result<Handle>(attach.errc(), attach.context());
    }
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) {
        (void)proc->detach_thread(reg.value());
        (void)objects_.destroy(reg.value());
        return Result<Handle>(found.errc(), found.context());
    }
    auto* rt_thread = found.value().get()->as<RtThread>();
    auto start = rt_thread->start();
    if (!start.ok()) {
        (void)proc->detach_thread(reg.value());
        (void)objects_.destroy(reg.value());
        return Result<Handle>(start.errc(), start.context());
    }
    auto handle = objects_.create_handle(*found.value().get());
    if (!handle.ok()) {
        (void)proc->detach_thread(reg.value());
        (void)objects_.destroy(reg.value());
        return Result<Handle>(handle.errc(), handle.context());
    }
    return handle;
}

// ── memory management per process ───────────────────────────────────────

Result<std::uint64_t> ProcessManager::reserve_region(Handle process,
                                                    std::uint64_t size,
                                                    const std::string& name) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // Global reserved-bytes limit check (sum of live spaces).
    if (limits_.max_reserved_bytes_total != 0) {
        std::uint64_t total = 0;
        for (const auto& [pid, id] : pid_to_object_id_) {
            auto p = objects_.lookup_id(id);
            if (p.ok() && p.value().get() != nullptr) {
                total += p.value().get()->as<ManagedProcess>()
                             ->address_space()
                             .stats()
                             .reserved_bytes;
            }
        }
        const std::uint64_t aligned =
            (size + pal::host_page_size() - 1) / pal::host_page_size() *
            pal::host_page_size();
        if (total + aligned > limits_.max_reserved_bytes_total) {
            return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                         "global reserved-bytes limit");
        }
    }
    return proc->address_space().reserve_region_auto(size, name);
}

Result<void> ProcessManager::commit_region(Handle process, std::uint64_t xbox_va) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    if (limits_.max_committed_bytes_total != 0) {
        std::uint64_t total = 0;
        for (const auto& [pid, id] : pid_to_object_id_) {
            auto p = objects_.lookup_id(id);
            if (p.ok() && p.value().get() != nullptr) {
                total += p.value().get()->as<ManagedProcess>()
                             ->address_space()
                             .stats()
                             .committed_bytes;
            }
        }
        auto region = proc->address_space().find_region(xbox_va);
        if (!region.ok()) {
            return Result<void>(region.errc(), region.context());
        }
        if (total + region.value().size > limits_.max_committed_bytes_total) {
            return Result<void>(RuntimeErrc::OutOfResources,
                                "global committed-bytes limit");
        }
    }
    return proc->address_space().commit_region(xbox_va);
}

Result<void> ProcessManager::protect_region(Handle process, std::uint64_t xbox_va,
                                            MemProtect prot,
                                            const ResourceLimits& global) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // W^X discipline: RWX (Full) requires the global allow_wx_pages opt-in.
    if (prot == MemProtect::Full && !global.allow_wx_pages) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "RWX protection requires allow_wx_pages (W^X discipline)");
    }
    return proc->address_space().protect_region(xbox_va, prot);
}

Result<void> ProcessManager::release_region(Handle process, std::uint64_t xbox_va) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::InvalidHandle, "process not found");
    }
    return proc->address_space().release_region(xbox_va);
}

std::vector<VmRegion> ProcessManager::list_regions(Handle process) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) return {};
    return proc->address_space().list_regions();
}

// ── lookup + accounting ──────────────────────────────────────────────────

Result<RefGuard> ProcessManager::find_process(Handle process) const {
    return objects_.lookup_handle(process);
}

Result<std::uint64_t> ProcessManager::resolve_pid(Handle process) const {
    auto found = objects_.lookup_handle(process);
    if (!found.ok()) {
        return Result<std::uint64_t>(found.errc(), found.context());
    }
    if (auto* proc = found.value().get()->as<ManagedProcess>()) {
        return Result<std::uint64_t>(proc->pid_value());
    }
    return Result<std::uint64_t>(RuntimeErrc::ObjectTypeMismatch, "not a process");
}

ResourceStats ProcessManager::global_stats() const {
    std::lock_guard lock(lock_);
    ResourceStats s;
    for (const auto& [pid, id] : pid_to_object_id_) {
        auto p = objects_.lookup_id(id);
        if (!p.ok() || p.value().get() == nullptr) continue;
        auto* proc = p.value().get()->as<ManagedProcess>();
        if (proc == nullptr) continue;
        const ResourceStats ps = proc->stats();
        s.reserved_bytes += ps.reserved_bytes;
        s.committed_bytes += ps.committed_bytes;
        s.region_count += ps.region_count;
        s.thread_count += ps.thread_count;
        s.module_count += ps.module_count;
        s.handle_count += ps.handle_count;
        ++s.process_count;
        ++s.address_space_count;
    }
    s.object_count = static_cast<std::uint32_t>(objects_.object_count());
    return s;
}

ResourceStats ProcessManager::process_stats(Handle process) const {
    RefGuard guard;
    const ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) return {};
    return proc->stats();
}

void ProcessManager::set_limits(const ResourceLimits& limits) {
    std::lock_guard lock(lock_);
    limits_ = limits;
}

std::size_t ProcessManager::process_count() const {
    std::lock_guard lock(lock_);
    return pid_to_object_id_.size();
}

std::vector<ProcessManager::ProcessInfo> ProcessManager::list_processes() const {
    std::lock_guard lock(lock_);
    std::vector<ProcessInfo> out;
    for (const auto& [pid, id] : pid_to_object_id_) {
        auto p = objects_.lookup_id(id);
        if (!p.ok() || p.value().get() == nullptr) continue;
        auto* proc = p.value().get()->as<ManagedProcess>();
        if (proc == nullptr) continue;
        ProcessInfo info;
        info.pid = pid;
        info.image_name = proc->image_name();
        info.state = proc->state();
        info.exit_code = proc->exit_code();
        info.stats = proc->stats();
        out.push_back(std::move(info));
    }
    return out;
}

ManagedProcess* ProcessManager::find_locked(Handle process, RefGuard& guard_out) const {
    auto found = objects_.lookup_handle(process);
    if (!found.ok()) return nullptr;
    guard_out = std::move(found.value());
    if (guard_out.get() == nullptr) return nullptr;
    return guard_out.get()->as<ManagedProcess>();
}

}  // namespace xbox2pc::rt
