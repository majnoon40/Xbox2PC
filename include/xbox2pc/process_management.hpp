#pragma once
// xbox2pc/process_management.hpp — M4 process management layer.
//
// Design (docs/process-management.md, docs/address-spaces.md,
// docs/resource-accounting.md):
//   1. ProcessManager owns the PROCESS lifecycle end-to-end: creation
//      (with ModuleDescriptor from M1/M2), startup, suspension
//      abstraction, termination with EXACT cleanup ordering, and failure
//      rollback during initialization (no leaked partial resources).
//   2. Each managed process owns an AddressSpace (isolated virtual
//      memory model — regions never resolve in another process's space;
//      space_id validation on every lookup path).
//   3. Resource accounting: per-process + global snapshots of virtual
//      memory (reserved/committed), threads, handles, objects, module
//      descriptors; limits with typed enforcement.
//   4. Cleanup ordering on termination (documented, tested):
//      a. request_stop on all owned threads (cooperative; never kill)
//      b. drain: wait bounded for thread exit (join completed threads)
//      c. process handle table close_all (every handle dies together)
//      d. address space release_all (memory gone)
//      e. threads unregister; objects destroyed via the object manager
//      f. accounting updated; state Terminated
//   5. NO execution of PE images (M4 exclusion): startup transitions
//      state and wires metadata only.

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/process_model.hpp"
#include "xbox2pc/thread_model.hpp"

namespace xbox2pc::rt {

// ── resource accounting ───────────────────────────────────────────────────

struct ResourceStats {
    // Memory (per space or aggregate).
    std::uint64_t reserved_bytes = 0;
    std::uint64_t committed_bytes = 0;
    std::uint32_t region_count = 0;
    // Objects.
    std::uint32_t thread_count = 0;
    std::uint32_t handle_count = 0;
    std::uint32_t object_count = 0;
    std::uint32_t module_count = 0;
    std::uint32_t process_count = 0;
    std::uint64_t address_space_count = 0;
};

// Global runtime-wide limits (documented: xbox2pc design, NOT Xbox limits).
struct ResourceLimits {
    std::uint64_t max_committed_bytes_total = 0;   // 0 = unlimited
    std::uint64_t max_reserved_bytes_total = 0;
    std::uint32_t max_threads_total = 0;
    std::uint32_t max_processes = 0;
    std::uint64_t max_address_spaces = 0;
    bool allow_wx_pages = false;  // W^X discipline: RWX regions off by default
};

// ── managed process ────────────────────────────────────────────────────────
//
// Extends RtProcess with the M4 management surface: its address space,
// owned thread list (object ids), module descriptors, and per-process
// resource stats. The RtProcess state machine from M3 stays authoritative
// (validated transitions); ProcessManager drives it.
class ManagedProcess : public RtProcess {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(ManagedProcess, Process)

    ManagedProcess(std::uint64_t pid, std::string image_name,
                   std::uint64_t space_capacity, std::uint64_t xbox_base);
    ~ManagedProcess() override;

    AddressSpace& address_space() { return *space_; }
    const AddressSpace& address_space() const { return *space_; }

    // Modules (M1/M2 descriptors).
    Result<void> add_module_descriptor(const ModuleDescriptor& mod);
    std::vector<ModuleDescriptor> module_descriptors() const;

    // Threads (registered by ProcessManager; ids are object ids).
    Result<void> begin_termination();
    Result<void> finish_termination(std::uint64_t exit_code);
    Result<void> attach_thread(std::uint64_t thread_obj_id);
    Result<void> detach_thread(std::uint64_t thread_obj_id);
    std::vector<std::uint64_t> thread_ids() const;

    // Per-process stats (consistent snapshot under one lock).
    ResourceStats stats() const;

    // Per-process memory limits pass-through.
    void set_memory_limits(const MemoryLimits& limits);

    const std::string& image_name() const { return image_name_; }
    std::uint64_t pid_value() const { return pid_; }

private:
    friend class ProcessManager;
    const std::uint64_t pid_;
    const std::string image_name_;
    std::unique_ptr<AddressSpace> space_;
    mutable std::mutex detail_lock_;
    std::vector<ModuleDescriptor> modules_;
    std::vector<std::uint64_t> threads_;
};

// ── process manager ────────────────────────────────────────────────────────

class ProcessManager {
public:
    explicit ProcessManager(ObjectManager& objects);
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    // ── lifecycle ──
    // create_process: registers the object, allocates the address space;
    // failure rolls back registration (no partial leaks). State Created.
    Result<Handle> create_process(const std::string& image_name,
                                  std::uint64_t space_capacity = 16ull << 20);
    // initialize_process: feeds the M1/M2 module descriptor + config;
    // failure rolls the process back to Created (space + threads kept
    // intact, descriptors dropped) — the documented rollback contract.
    Result<void> initialize_process(Handle process, const ModuleDescriptor& main,
                                    const RuntimeConfig& config);
    // start_process: Created/Initializing -> Running.
    Result<void> start_process(Handle process);
    // suspend/resume abstractions (state transitions on all threads:
    // request_stop on suspend, clear on resume — cooperative).
    Result<void> suspend_process(Handle process);
    Result<void> resume_process(Handle process);
    // terminate_process: drives the EXACT cleanup ordering (header top).
    // exit status recorded; idempotent.
    Result<void> terminate_process(Handle process, std::uint64_t exit_code);

    // ── thread management per process ──
    // spawn_thread: creates an RtThread object owned by this process,
    // registers it in the process's list, starts the host thread. The
    // thread's main receives (self, arg). Exception containment applies
    // (trampoline). Returns the thread HANDLE (runtime table).
    Result<Handle> spawn_thread(Handle process, RtThread::ThreadMain main,
                                void* arg, const std::string& name);

    // ── memory management per process ──
    Result<std::uint64_t> reserve_region(Handle process, std::uint64_t size,
                                         const std::string& name);
    Result<void> commit_region(Handle process, std::uint64_t xbox_va);
    Result<void> protect_region(Handle process, std::uint64_t xbox_va,
                                MemProtect prot, const ResourceLimits& global);
    Result<void> release_region(Handle process, std::uint64_t xbox_va);
    std::vector<VmRegion> list_regions(Handle process);

    // ── lookup ──
    Result<RefGuard> find_process(Handle process) const;
    Result<std::uint64_t> resolve_pid(Handle process) const;

    // ── accounting ──
    // Snapshot: consistent view (manager lock held) across all processes.
    ResourceStats global_stats() const;
    ResourceStats process_stats(Handle process) const;
    void set_limits(const ResourceLimits& limits);
    const ResourceLimits& limits() const { return limits_; }

    std::size_t process_count() const;
    // Listing (CLI process-info).
    struct ProcessInfo {
        std::uint64_t pid;
        std::string image_name;
        ProcessState state;
        std::uint64_t exit_code;
        ResourceStats stats;
    };
    std::vector<ProcessInfo> list_processes() const;

private:
    ManagedProcess* find_locked(Handle process, RefGuard& guard_out) const;

    ObjectManager& objects_;
    mutable std::mutex lock_;
    std::map<std::uint64_t, std::uint64_t> pid_to_object_id_;  // pid -> obj id
    std::atomic<std::uint64_t> next_pid_{1};
    ResourceLimits limits_;
    // Spawn reservations counted while a thread is being registered/attached.
    // Protected by lock_ so concurrent spawns cannot bypass the global limit.
    std::uint64_t pending_threads_ = 0;
    // Global totals maintained incrementally for fast limit checks.
    mutable std::atomic<std::uint64_t> committed_total_{0};
    mutable std::atomic<std::uint64_t> reserved_total_{0};
};

}  // namespace xbox2pc::rt
