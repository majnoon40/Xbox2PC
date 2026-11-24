// process_management.cpp — M4 ManagedProcess + ProcessManager.

#include "xbox2pc/process_management.hpp"

#include <algorithm>
#include <exception>
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

Result<IXMemAllocator*> ManagedProcess::ensure_xmem_allocator(
    std::uint64_t arena_size, std::uint64_t max_bytes) {
    std::lock_guard lock(detail_lock_);
    const auto current = state();
    if (current == ProcessState::Terminating ||
        current == ProcessState::Terminated || current == ProcessState::Failed) {
        return Result<IXMemAllocator*>(RuntimeErrc::ProcessTerminated,
                                       "cannot create XMem allocator for a terminating process");
    }
    if (xmem_allocator_ != nullptr)
        return Result<IXMemAllocator*>(xmem_allocator_.get());

    auto created = GuestXMemAllocator::create(
        *space_, arena_size, "proc-" + std::to_string(pid_) + "-xmem",
        max_bytes);
    if (!created.ok())
        return Result<IXMemAllocator*>(created.errc(), created.context());
    xmem_allocator_ = std::move(created.value());
    return Result<IXMemAllocator*>(xmem_allocator_.get());
}

Result<void> ManagedProcess::add_module_descriptor(const ModuleDescriptor& mod) {
    std::lock_guard lock(detail_lock_);
    const ProcessState cur = state();
    if (cur == ProcessState::Terminating || cur == ProcessState::Terminated ||
        cur == ProcessState::Failed) {
        return Result<void>(RuntimeErrc::ProcessTerminated, "process is terminating");
    }
    modules_.push_back(mod);
    return Result<void>::ok_result();
}

std::vector<ModuleDescriptor> ManagedProcess::module_descriptors() const {
    std::lock_guard lock(detail_lock_);
    return modules_;
}

Result<void> ManagedProcess::begin_termination() {
    std::lock_guard lock(detail_lock_);
    return RtProcess::begin_termination();
}

Result<void> ManagedProcess::finish_termination(std::uint64_t exit_code) {
    std::lock_guard lock(detail_lock_);
    return RtProcess::finish_termination(exit_code);
}

Result<void> ManagedProcess::attach_thread(std::uint64_t thread_obj_id) {
    std::lock_guard lock(detail_lock_);
    const ProcessState cur = state();
    if (cur == ProcessState::Terminating || cur == ProcessState::Terminated ||
        cur == ProcessState::Failed) {
        return Result<void>(RuntimeErrc::ProcessTerminated, "process is terminating");
    }
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
    {
        std::lock_guard lock(lock_);
        exit_observers_.clear();
    }
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
                        // ProcessManager destruction from one of its own
                        // managed threads is unsupported: continuing would
                        // free memory still reachable by that host thread.
                        std::terminate();
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
    // Suspend each owned live thread through its resumable gate. This is
    // deliberately not request_stop(): stop is terminal cancellation.
    std::vector<RefGuard> suspended;
    std::vector<std::uint64_t> suspended_ids;
    for (const std::uint64_t tid : proc->thread_ids()) {
        auto t = objects_.lookup_id(tid);
        if (!t.ok() || t.value().get() == nullptr) continue;
        auto* thread = t.value().get()->as<RtThread>();
        if (thread == nullptr) continue;
        const auto state = thread->state();
        if (state == ThreadState::Suspended || state == ThreadState::Terminated ||
            state == ThreadState::Failed || state == ThreadState::Created) continue;
        auto paused = thread->suspend();
        if (!paused.ok()) {
            for (auto it = suspended.rbegin(); it != suspended.rend(); ++it) {
                auto* previous = it->get()->as<RtThread>();
                if (previous != nullptr) (void)previous->resume();
            }
            (void)proc->resume();
            return Result<void>(paused.errc(),
                                "process suspension rolled back: " + paused.context());
        }
        suspended_ids.push_back(tid);
        suspended.push_back(std::move(t.value()));
    }
    {
        std::lock_guard detail_guard(proc->detail_lock_);
        proc->process_suspended_threads_ = std::move(suspended_ids);
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
    std::vector<std::uint64_t> suspended_ids;
    {
        std::lock_guard detail_guard(proc->detail_lock_);
        suspended_ids = proc->process_suspended_threads_;
    }
    std::vector<RefGuard> resumed;
    for (const std::uint64_t tid : suspended_ids) {
        auto t = objects_.lookup_id(tid);
        if (!t.ok() || t.value().get() == nullptr) continue;
        auto* thread = t.value().get()->as<RtThread>();
        if (thread == nullptr || thread->state() != ThreadState::Suspended) continue;
        auto running = thread->resume();
        if (!running.ok()) {
            for (auto it = resumed.rbegin(); it != resumed.rend(); ++it) {
                auto* previous = it->get()->as<RtThread>();
                if (previous != nullptr) (void)previous->suspend();
            }
            (void)proc->suspend();
            return Result<void>(running.errc(),
                                "process resume rolled back: " + running.context());
        }
        resumed.push_back(std::move(t.value()));
    }
    {
        std::lock_guard detail_guard(proc->detail_lock_);
        proc->process_suspended_threads_.clear();
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
    auto begun = proc->begin_termination();
    if (!begun.ok()) return begun;
    if (proc->state() == ProcessState::Terminated) return Result<void>::ok_result();
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
    const std::uint64_t pid = proc->pid_value();
    auto finished = proc->finish_termination(exit_code);
    if (!finished.ok()) return finished;

    {
        // Serialize callback execution with observer removal. This ensures
        // service shutdown cannot destroy a target while its callback is active.
        // Observers must not re-enter ProcessManager (see the public contract).
        std::lock_guard lock(lock_);
        for (const auto& [observer_id, observer] : exit_observers_) {
            (void)observer_id;
            try { observer(pid); } catch (...) {
                // A notification cannot undo or escape successful teardown.
            }
        }
    }
    return Result<void>::ok_result();
}

Result<std::uint64_t> ProcessManager::add_process_exit_observer(
    ProcessExitObserver observer) {
    if (!observer) return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                                "empty process-exit observer");
    std::lock_guard lock(lock_);
    if (next_exit_observer_ == 0 || next_exit_observer_ == ~std::uint64_t{0}) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "process-exit observer ID space exhausted");
    }
    const std::uint64_t id = next_exit_observer_++;
    exit_observers_.emplace(id, std::move(observer));
    return Result<std::uint64_t>(id);
}

Result<void> ProcessManager::remove_process_exit_observer(std::uint64_t observer_id) {
    if (observer_id == 0) return Result<void>(RuntimeErrc::InvalidArgument,
                                               "zero process-exit observer ID");
    std::lock_guard lock(lock_);
    if (exit_observers_.erase(observer_id) == 0) {
        return Result<void>(RuntimeErrc::NotFound, "process-exit observer not registered");
    }
    return Result<void>::ok_result();
}

Result<Handle> ProcessManager::spawn_thread(Handle process,
                                            RtThread::ThreadMain main, void* arg,
                                            const std::string& name) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<Handle>(RuntimeErrc::InvalidHandle, "process not found");
    }
    // Reserve one global thread slot under the manager lock. The reservation
    // closes the race where concurrent spawns all pass the same count check.
    {
        std::lock_guard lock(lock_);
        if (pending_threads_ == ~0ull) {
            return Result<Handle>(RuntimeErrc::OutOfResources,
                                  "pending thread count exhausted");
        }
        if (limits_.max_threads_total != 0) {
            std::uint64_t total = pending_threads_;
            for (const auto& [pid, id] : pid_to_object_id_) {
                auto p = objects_.lookup_id(id);
                if (p.ok() && p.value().get() != nullptr) {
                    auto* managed = p.value().get()->as<ManagedProcess>();
                    if (managed != nullptr) {
                        const auto count = managed->thread_ids().size();
                        total = count > (~0ull) - total ? ~0ull : total + count;
                    }
                }
            }
            if (total >= limits_.max_threads_total) {
                return Result<Handle>(RuntimeErrc::OutOfResources, "thread limit");
            }
        }
        ++pending_threads_;
    }
    bool pending_active = true;
    auto release_pending = [&]() {
        if (!pending_active) return;
        std::lock_guard lock(lock_);
        if (pending_threads_ != 0) --pending_threads_;
        pending_active = false;
    };
    struct PendingRelease {
        decltype(release_pending)& release;
        ~PendingRelease() { release(); }
    } pending_release{release_pending};

    auto thread = std::make_unique<RtThread>(main, arg, name, proc->pid_value());
    auto reg = objects_.register_object(std::move(thread));
    if (!reg.ok()) {
        return Result<Handle>(reg.errc(), reg.context());
    }
    auto attach = proc->attach_thread(reg.value());
    if (!attach.ok()) {
        (void)objects_.destroy(reg.value());  // rollback: no partial leaks
        return Result<Handle>(attach.errc(), attach.context());
    }
    // From this point the thread is visible in the process list, so it is
    // counted there rather than in pending_threads_.
    release_pending();
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
    // Serialize global accounting and the reservation itself; otherwise
    // parallel processes can both pass the same quota check.
    std::lock_guard lock(lock_);
    const std::uint64_t page = pal::host_page_size();
    if (page == 0 || size > (~0ull) - (page - 1)) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "reservation size alignment overflow");
    }
    const std::uint64_t aligned = ((size + page - 1) / page) * page;
    if (limits_.max_reserved_bytes_total != 0) {
        std::uint64_t total = 0;
        for (const auto& [pid, id] : pid_to_object_id_) {
            auto p = objects_.lookup_id(id);
            if (p.ok() && p.value().get() != nullptr) {
                auto* managed = p.value().get()->as<ManagedProcess>();
                if (managed != nullptr) {
                    const auto used = managed->address_space().stats().reserved_bytes;
                    total = used > (~0ull) - total ? ~0ull : total + used;
                }
            }
        }
        if (total > limits_.max_reserved_bytes_total ||
            aligned > limits_.max_reserved_bytes_total - total) {
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
    std::lock_guard lock(lock_);
    auto region = proc->address_space().find_region(xbox_va);
    if (!region.ok()) return Result<void>(region.errc(), region.context());
    if (region.value().state == RegionState::Committed) {
        return proc->address_space().commit_region(xbox_va);
    }
    if (limits_.max_committed_bytes_total != 0) {
        std::uint64_t total = 0;
        for (const auto& [pid, id] : pid_to_object_id_) {
            auto p = objects_.lookup_id(id);
            if (p.ok() && p.value().get() != nullptr) {
                auto* managed = p.value().get()->as<ManagedProcess>();
                if (managed != nullptr) {
                    const auto used = managed->address_space().stats().committed_bytes;
                    total = used > (~0ull) - total ? ~0ull : total + used;
                }
            }
        }
        if (total > limits_.max_committed_bytes_total ||
            region.value().size > limits_.max_committed_bytes_total - total) {
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


Result<std::uint64_t> ProcessManager::reserve_region_by_pid(
    std::uint64_t pid, std::uint64_t size, const std::string& name) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<std::uint64_t>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated, "guest process is not running");
    std::lock_guard lock(lock_);
    const auto page = proc->address_space().page_size();
    if (size == 0 || page == 0 || size > (~0ull) - (page - 1))
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "invalid guest reservation size");
    const auto aligned = ((size + page - 1) / page) * page;
    if (limits_.max_reserved_bytes_total != 0) {
        std::uint64_t total = 0;
        for (const auto& [other_pid, id] : pid_to_object_id_) {
            (void)other_pid;
            auto object = objects_.lookup_id(id);
            if (!object.ok() || object.value().get() == nullptr) continue;
            auto* managed = object.value().get()->as<ManagedProcess>();
            if (managed == nullptr) continue;
            const auto used = managed->address_space().stats().reserved_bytes;
            total = used > (~0ull) - total ? ~0ull : total + used;
        }
        if (total > limits_.max_reserved_bytes_total || aligned > limits_.max_reserved_bytes_total - total)
            return Result<std::uint64_t>(RuntimeErrc::OutOfResources, "global reserved-bytes limit");
    }
    return proc->address_space().reserve_region_auto(size, name);
}

Result<std::uint64_t> ProcessManager::reserve_region_at_by_pid(
    std::uint64_t pid, std::uint64_t xbox_va, std::uint64_t size,
    const std::string& name) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<std::uint64_t>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated,
                                     "guest process is not running");
    std::lock_guard lock(lock_);
    const auto page = proc->address_space().page_size();
    if (xbox_va == 0 || size == 0 || page == 0 ||
        size > (~0ull) - (page - 1)) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "invalid fixed guest reservation");
    }
    const auto aligned = ((size + page - 1) / page) * page;
    if (limits_.max_reserved_bytes_total != 0) {
        std::uint64_t total = 0;
        for (const auto& [other_pid, id] : pid_to_object_id_) {
            (void)other_pid;
            auto object = objects_.lookup_id(id);
            if (!object.ok() || object.value().get() == nullptr) continue;
            auto* managed = object.value().get()->as<ManagedProcess>();
            if (managed == nullptr) continue;
            const auto used = managed->address_space().stats().reserved_bytes;
            total = used > (~0ull) - total ? ~0ull : total + used;
        }
        if (total > limits_.max_reserved_bytes_total ||
            aligned > limits_.max_reserved_bytes_total - total) {
            return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                         "global reserved-bytes limit");
        }
    }
    return proc->address_space().reserve_region(xbox_va, size, name);
}

Result<void> ProcessManager::set_allocation_protection_by_pid(
    std::uint64_t pid, std::uint64_t xbox_va, MemProtect protection) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<void>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<void>(RuntimeErrc::ProcessTerminated,
                            "guest process is not running");
    std::lock_guard lock(lock_);
    return proc->address_space().set_allocation_protection(xbox_va, protection);
}

Result<void> ProcessManager::commit_region_by_pid(
    std::uint64_t pid, std::uint64_t xbox_va, std::uint64_t size,
    MemProtect protection) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<void>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<void>(RuntimeErrc::ProcessTerminated, "guest process is not running");
    std::lock_guard lock(lock_);
    if (protection == MemProtect::Full && !limits_.allow_wx_pages)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "RWX protection requires allow_wx_pages");
    const auto page = proc->address_space().page_size();
    if (size == 0 || page == 0 || xbox_va % page != 0 ||
        size > (~0ull) - (page - 1))
        return Result<void>(RuntimeErrc::InvalidArgument, "invalid guest commit range");
    const auto aligned = ((size + page - 1) / page) * page;
    if (xbox_va > (~0ull) - aligned)
        return Result<void>(RuntimeErrc::InvalidArgument, "guest commit range overflows");
    const auto region = proc->address_space().find_containing(xbox_va);
    if (!region.ok()) return Result<void>(region.errc(), region.context());
    const auto allocation = region.value().allocation_base;
    if (allocation == 0 || xbox_va < allocation)
        return Result<void>(RuntimeErrc::InvalidArgument, "commit range is outside its reservation");

    std::uint64_t newly_committed = 0;
    const auto range_end = xbox_va + aligned;
    for (const auto& segment : proc->address_space().list_regions()) {
        const auto segment_end = segment.xbox_va + segment.size;
        if (segment_end <= xbox_va || segment.xbox_va >= range_end) continue;
        if (segment.allocation_base != allocation)
            return Result<void>(RuntimeErrc::InvalidState,
                                "commit range crosses reservation boundaries");
        if (segment.state == RegionState::Reserved) {
            const auto begin = std::max(xbox_va, segment.xbox_va);
            const auto finish = std::min(range_end, segment_end);
            const auto bytes = finish - begin;
            newly_committed = bytes > (~0ull) - newly_committed
                ? ~0ull : newly_committed + bytes;
        }
    }
    if (limits_.max_committed_bytes_total != 0 && newly_committed != 0) {
        std::uint64_t total = 0;
        for (const auto& [other_pid, id] : pid_to_object_id_) {
            (void)other_pid;
            auto object = objects_.lookup_id(id);
            if (!object.ok() || object.value().get() == nullptr) continue;
            auto* managed = object.value().get()->as<ManagedProcess>();
            if (managed == nullptr) continue;
            const auto used = managed->address_space().stats().committed_bytes;
            total = used > (~0ull) - total ? ~0ull : total + used;
        }
        if (total > limits_.max_committed_bytes_total ||
            newly_committed > limits_.max_committed_bytes_total - total)
            return Result<void>(RuntimeErrc::OutOfResources, "global committed-bytes limit");
    }
    return proc->address_space().commit_range(xbox_va, aligned, protection);
}

Result<void> ProcessManager::decommit_region_by_pid(
    std::uint64_t pid, std::uint64_t xbox_va, std::uint64_t size) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<void>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<void>(RuntimeErrc::ProcessTerminated, "guest process is not running");
    std::lock_guard lock(lock_);
    const auto page = proc->address_space().page_size();
    if (size == 0 || page == 0 || xbox_va % page != 0 ||
        size > (~0ull) - (page - 1))
        return Result<void>(RuntimeErrc::InvalidArgument, "invalid guest decommit range");
    const auto aligned = ((size + page - 1) / page) * page;
    return proc->address_space().decommit_range(xbox_va, aligned);
}

Result<MemProtect> ProcessManager::protect_region_by_pid(
    std::uint64_t pid, std::uint64_t xbox_va, std::uint64_t size, MemProtect prot) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<MemProtect>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<MemProtect>(RuntimeErrc::ProcessTerminated, "guest process is not running");
    std::lock_guard lock(lock_);
    if (prot == MemProtect::Full && !limits_.allow_wx_pages)
        return Result<MemProtect>(RuntimeErrc::InvalidArgument, "RWX protection requires allow_wx_pages");
    const auto page = proc->address_space().page_size();
    if (size == 0 || page == 0 || xbox_va % page != 0 ||
        size > (~0ull) - (page - 1))
        return Result<MemProtect>(RuntimeErrc::InvalidArgument, "invalid guest protection range");
    const auto aligned = ((size + page - 1) / page) * page;
    return proc->address_space().protect_range(xbox_va, aligned, prot);
}

Result<void> ProcessManager::release_region_by_pid(std::uint64_t pid, std::uint64_t xbox_va) {
    auto found = find_process_by_pid(pid);
    if (!found.ok()) return Result<void>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr || proc->state() != ProcessState::Running)
        return Result<void>(RuntimeErrc::ProcessTerminated, "guest process is not running");
    std::lock_guard lock(lock_);
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

Result<RefGuard> ProcessManager::find_process_by_pid(std::uint64_t pid) const {
    if (pid == 0) return Result<RefGuard>(RuntimeErrc::InvalidArgument, "process ID zero is not a guest process");
    std::lock_guard lock(lock_);
    const auto it = pid_to_object_id_.find(pid);
    if (it == pid_to_object_id_.end()) return Result<RefGuard>(RuntimeErrc::NotFound, "unknown or terminated process ID");
    return objects_.lookup_id(it->second);
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
