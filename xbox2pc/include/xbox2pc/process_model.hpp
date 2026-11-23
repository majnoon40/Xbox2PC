#pragma once
// xbox2pc/process_model.hpp — M3 abstract process representation.
//
// Design (docs/process-thread-model.md):
//   - RtProcess is a runtime object aggregating: unique pid, lifecycle
//     state machine, executable image metadata (from the M1 PE parser via
//     ModuleDescriptor), runtime configuration, a memory-space interface
//     (region collection), a thread collection (registered threads),
//     its OWN handle table, loaded-module metadata, and per-process
//     runtime services.
//   - States: Created -> Initializing -> Running -> {Suspended ->
//     Running} -> Terminating -> Terminated; Failed reachable from any
//     non-terminal state. All transitions validated (table in .cpp).
//   - Interaction with the object manager: process-owned objects live in
//     the process's handle table; the GLOBAL manager keeps process
//     objects themselves. Destroying a process closes its handle table
//     and terminates (cooperatively) its registered threads.
//   - NO executable execution: image metadata is DATA ONLY (M3 exclusion).
//
// Module descriptor (M1/M2 integration, non-duplicating):
//   - ModuleDescriptor copies the *summary* fields of a parsed PeImage
//     and the DependencyReport into plain metadata vectors; the parser
//     and analyzer stay authoritative (no re-parsing here).

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::rt {

// ── process states ────────────────────────────────────────────────────────
enum class ProcessState {
    Created,
    Initializing,
    Running,
    Suspended,
    Terminating,
    Terminated,
    Failed,
};

const char* process_state_to_name(ProcessState s);

// ── executable/runtime configuration ──────────────────────────────────────

struct RuntimeConfig {
    std::uint32_t subsystem = 0;             // PE subsystem value (data)
    std::uint64_t image_base = 0;            // preferred base (data only)
    std::uint32_t image_size = 0;            // SizeOfImage (data only)
    bool break_on_module_load_failure = false;
    std::size_t max_handle_table_slots = 1u << 20;  // per-process cap
};

// ── module descriptor (M1/M2 metadata integration) ────────────────────────
//
// Summarizes one parsed executable (main image or a dependency module):
// header facts, section names, imported DLLs + functions, classification.
struct ModuleDescriptor {
    std::string module_name;            // file name / display name
    bool is_valid_pe = false;
    bool is_pe32plus = false;
    std::uint16_t machine = 0;
    std::string machine_name;
    std::uint64_t entry_point_rva = 0;
    std::uint64_t image_base = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t subsystem = 0;
    std::vector<std::string> section_names;
    std::vector<std::string> imported_dlls;             // distinct, in order
    std::vector<std::string> delay_loaded_dlls;
    std::vector<std::string> forwarded_exports;
    // Classification summary (from the M2 analyzer, per DLL).
    struct DllClass {
        std::string dll;
        std::string category;
        bool classified;
    };
    std::vector<DllClass> dll_classes;

    // Build from a parsed image + analyzed report (metadata copy only).
    static ModuleDescriptor from_image(const pe::PeImage& img,
                                        const deps::DependencyReport& rep,
                                        std::string display_name);
};

// ── process object ─────────────────────────────────────────────────────────

class RtProcess : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtProcess, Process)

    RtProcess(std::string image_name);
    ~RtProcess() override;

    // ── lifecycle ──
    Result<void> initialize(const ModuleDescriptor& main_module,
                             RuntimeConfig config);
    Result<void> run();                  // Initializing -> Running
    Result<void> suspend();
    Result<void> resume();
    Result<void> terminate(std::uint64_t exit_code);  // -> Terminating/Terminated
    Result<void> fail(std::string reason);

    ProcessState state() const { return state_.load(std::memory_order_acquire); }
    std::uint64_t pid() const { return pid_; }
    std::uint64_t exit_code() const;
    std::string fail_reason() const;

    // ── metadata ──
    const ModuleDescriptor* main_module() const;   // null until initialize()
    Result<void> add_loaded_module(ModuleDescriptor mod);  // dependency modules
    std::vector<ModuleDescriptor> loaded_modules() const;
    const RuntimeConfig& config() const { return config_; }

    // ── memory-space interface ──
    // Registers a region object in the process (memory manager owns the
    // region objects themselves; the process tracks them by object id).
    Result<void> attach_region(std::uint64_t region_obj_id, std::string label);
    Result<void> detach_region(std::uint64_t region_obj_id);
    std::vector<std::pair<std::uint64_t, std::string>> regions() const;

    // ── thread collection ──
    Result<void> register_thread(std::uint64_t thread_obj_id);
    Result<void> unregister_thread(std::uint64_t thread_obj_id);
    std::vector<std::uint64_t> threads() const;

    // ── per-process handle table ──
    HandleTable& handle_table() { return table_; }
    const HandleTable& handle_table() const { return table_; }

    // ── process-local runtime services (name -> object id) ──
    Result<void> set_service(const std::string& name, std::uint64_t obj_id);
    Result<std::uint64_t> get_service(const std::string& name) const;
    std::vector<std::pair<std::string, std::uint64_t>> services() const;

    // Resolve a handle through this process's table (object manager does
    // the id -> object resolution; process owns the table only).
    Result<RefGuard> lookup_handle(Handle h, const ObjectManager& manager) const;

private:
    void on_destroy() override;  // close table + terminate threads

    const std::uint64_t pid_;
    std::atomic<ProcessState> state_{ProcessState::Created};
    std::string image_name_;
    std::unique_ptr<ModuleDescriptor> main_module_;
    RuntimeConfig config_;
    std::uint64_t exit_code_ = 0;
    std::string fail_reason_;
    HandleTable table_;  // NOTE: ObjectManager back-reference is the runtime's

    // Guarded collections (internal mutex; const methods lock it too).
    mutable std::mutex collections_lock_;
    std::vector<ModuleDescriptor> modules_;
    std::vector<std::pair<std::uint64_t, std::string>> region_list_;
    std::vector<std::uint64_t> thread_list_;
    std::map<std::string, std::uint64_t> service_map_;

    static std::uint64_t next_pid();
};

// ── validated process transitions (exposed for tests) ────────────────────
bool process_transition_valid(ProcessState from, ProcessState to);

}  // namespace xbox2pc::rt
