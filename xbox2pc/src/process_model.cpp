// process_model.cpp — RtProcess + ModuleDescriptor implementation.

#include "xbox2pc/process_model.hpp"

#include <algorithm>
#include <atomic>
#include <utility>

namespace xbox2pc::rt {
namespace {

std::atomic<std::uint64_t> g_next_pid{1};

// ── validated process transition table ───────────────────────────────────
//
// Legal transitions (architectural model — inferred, documented):
//   Created      -> Initializing, Failed
//   Initializing -> Running, Failed
//   Running      -> Suspended, Terminating, Failed
//   Suspended    -> Running, Terminating, Failed
//   Terminating  -> Terminated, Failed
//   Terminated/Failed terminal (Terminated -> Terminated idempotent).
constexpr bool kTrans[7][7] = {
    // to:       Created Init Running Suspended Term-inate Term-ined Failed
    /* Created */ {false, true, false, false, true, false, true},
    /* Init */ {false, false, true, false, true, false, true},
    /* Running */ {false, false, false, true, true, false, true},
    /* Suspended */ {false, false, true, false, true, false, true},
    /* Terminating */ {false, false, false, false, false, true, true},
    /* Terminated */ {false, false, false, false, false, true, false},
    /* Failed */ {false, false, false, false, false, false, true},
};
// M4 change (documented in docs/process-management.md): Created and
// Initializing may now transition to Terminating — M4 requires that ANY
// pre-terminal process be terminable (deterministic cleanup of partially
// initialized processes is a milestone requirement; the M3 table only
// allowed termination from Running/Suspended). process_transition_valid()
// tests updated accordingly.

int idx(ProcessState s) {
    switch (s) {
        case ProcessState::Created: return 0;
        case ProcessState::Initializing: return 1;
        case ProcessState::Running: return 2;
        case ProcessState::Suspended: return 3;
        case ProcessState::Terminating: return 4;
        case ProcessState::Terminated: return 5;
        case ProcessState::Failed: return 6;
    }
    return 6;
}

}  // namespace

bool process_transition_valid(ProcessState from, ProcessState to) {
    return kTrans[idx(from)][idx(to)];
}

const char* process_state_to_name(ProcessState s) {
    switch (s) {
        case ProcessState::Created: return "created";
        case ProcessState::Initializing: return "initializing";
        case ProcessState::Running: return "running";
        case ProcessState::Suspended: return "suspended";
        case ProcessState::Terminating: return "terminating";
        case ProcessState::Terminated: return "terminated";
        case ProcessState::Failed: return "failed";
    }
    return "?";
}

std::uint64_t RtProcess::next_pid() {
    return g_next_pid.fetch_add(1, std::memory_order_acq_rel);
}

// ── ModuleDescriptor ──────────────────────────────────────────────────────

ModuleDescriptor ModuleDescriptor::from_image(const pe::PeImage& img,
                                               const deps::DependencyReport& rep,
                                               std::string display_name) {
    ModuleDescriptor d;
    d.module_name = std::move(display_name);
    d.is_valid_pe = true;  // the parser throws on invalid images; reaching
                           // here means the parse succeeded.
    d.is_pe32plus = img.opt.is_pe32plus;
    d.machine = img.coff.machine;
    d.machine_name = img.machine_name();
    d.entry_point_rva = img.opt.address_of_entry_point;
    d.image_base = img.opt.image_base;
    d.size_of_image = img.opt.size_of_image;
    d.subsystem = img.opt.subsystem;
    for (const auto& s : img.sections) d.section_names.push_back(s.name);
    for (const auto& dep : rep.dependencies) {
        if (dep.delay_import) d.delay_loaded_dlls.push_back(dep.dll_name);
        else d.imported_dlls.push_back(dep.dll_name);
        DllClass c;
        c.dll = dep.dll_name;
        c.category = dep.category_name;
        c.classified = dep.classified;
        d.dll_classes.push_back(std::move(c));
    }
    for (const auto& f : rep.forwarded_exports) {
        d.forwarded_exports.push_back(f.forwarder);
    }
    return d;
}

// ── RtProcess lifecycle ─────────────────────────────────────────────────────

RtProcess::RtProcess(std::string image_name)
    : RuntimeObject(TypeId::Process),
      pid_(next_pid()),
      image_name_(std::move(image_name)),
      table_(*global_manager()) {
    // The per-process handle table resolves ids through the runtime's
    // GLOBAL ObjectManager (install_global_manager must have been called;
    // lookups before that return NotInitialized).
}

RtProcess::~RtProcess() = default;

Result<void> RtProcess::initialize(const ModuleDescriptor& main_module,
                                    RuntimeConfig config) {
    std::lock_guard lock(collections_lock_);
    const ProcessState cur = state_.load(std::memory_order_acquire);
    if (!process_transition_valid(cur, ProcessState::Initializing)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "initialize() from " +
                                std::string(process_state_to_name(cur)));
    }
    main_module_ = std::make_unique<ModuleDescriptor>(main_module);
    config_ = config;
    state_.store(ProcessState::Initializing, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtProcess::run() {
    const ProcessState cur = state_.load(std::memory_order_acquire);
    if (!process_transition_valid(cur, ProcessState::Running)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "run() from " + std::string(process_state_to_name(cur)));
    }
    state_.store(ProcessState::Running, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtProcess::suspend() {
    const ProcessState cur = state_.load(std::memory_order_acquire);
    if (!process_transition_valid(cur, ProcessState::Suspended)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "suspend() from " +
                                std::string(process_state_to_name(cur)));
    }
    state_.store(ProcessState::Suspended, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtProcess::resume() {
    // resume() is exclusively the inverse of suspend(): only a Suspended
    // process may resume (run() covers Initializing -> Running).
    const ProcessState cur = state_.load(std::memory_order_acquire);
    if (cur != ProcessState::Suspended) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "resume() from " +
                                std::string(process_state_to_name(cur)) +
                                " (only suspended processes resume)");
    }
    state_.store(ProcessState::Running, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtProcess::terminate(std::uint64_t exit_code) {
    {
        std::lock_guard lock(collections_lock_);
        const ProcessState cur = state_.load(std::memory_order_acquire);
        if (!process_transition_valid(cur, ProcessState::Terminating)) {
            // Terminated -> Terminated is the idempotent case.
            if (cur == ProcessState::Terminated) {
                return Result<void>::ok_result();
            }
            return Result<void>(RuntimeErrc::InvalidTransition,
                                "terminate() from " +
                                    std::string(process_state_to_name(cur)));
        }
        state_.store(ProcessState::Terminating, std::memory_order_release);
        // Close the per-process handle table (all handles die together).
        table_.close_all();
        state_.store(ProcessState::Terminated, std::memory_order_release);
        exit_code_ = exit_code;
    }
    return Result<void>::ok_result();
}

Result<void> RtProcess::fail(std::string reason) {
    {
        std::lock_guard lock(collections_lock_);
        const ProcessState cur = state_.load(std::memory_order_acquire);
        if (!process_transition_valid(cur, ProcessState::Failed)) {
            return Result<void>(RuntimeErrc::InvalidTransition,
                                "fail() from " +
                                    std::string(process_state_to_name(cur)));
        }
        state_.store(ProcessState::Failed, std::memory_order_release);
        fail_reason_ = std::move(reason);
    }
    return Result<void>::ok_result();
}

std::uint64_t RtProcess::exit_code() const { return exit_code_; }

std::string RtProcess::fail_reason() const {
    std::lock_guard lock(collections_lock_);
    return fail_reason_;
}

const ModuleDescriptor* RtProcess::main_module() const {
    std::lock_guard lock(collections_lock_);
    return main_module_.get();
}

Result<void> RtProcess::add_loaded_module(ModuleDescriptor mod) {
    if (state_.load(std::memory_order_acquire) == ProcessState::Terminated) {
        return Result<void>(RuntimeErrc::ProcessTerminated, "process terminated");
    }
    std::lock_guard lock(collections_lock_);
    modules_.push_back(std::move(mod));
    return Result<void>::ok_result();
}

std::vector<ModuleDescriptor> RtProcess::loaded_modules() const {
    std::lock_guard lock(collections_lock_);
    return modules_;
}

Result<void> RtProcess::attach_region(std::uint64_t region_obj_id, std::string label) {
    std::lock_guard lock(collections_lock_);
    for (const auto& r : region_list_) {
        if (r.first == region_obj_id) {
            return Result<void>(RuntimeErrc::AlreadyExists, "region already attached");
        }
    }
    region_list_.emplace_back(region_obj_id, std::move(label));
    return Result<void>::ok_result();
}

Result<void> RtProcess::detach_region(std::uint64_t region_obj_id) {
    std::lock_guard lock(collections_lock_);
    const auto it = std::remove_if(region_list_.begin(), region_list_.end(),
                                   [region_obj_id](const auto& p) {
                                       return p.first == region_obj_id;
                                   });
    if (it == region_list_.end()) {
        return Result<void>(RuntimeErrc::NotFound, "region not attached");
    }
    region_list_.erase(it, region_list_.end());
    return Result<void>::ok_result();
}

std::vector<std::pair<std::uint64_t, std::string>> RtProcess::regions() const {
    std::lock_guard lock(collections_lock_);
    return region_list_;
}

Result<void> RtProcess::register_thread(std::uint64_t thread_obj_id) {
    std::lock_guard lock(collections_lock_);
    for (std::uint64_t t : thread_list_) {
        if (t == thread_obj_id) {
            return Result<void>(RuntimeErrc::AlreadyExists, "thread already registered");
        }
    }
    thread_list_.push_back(thread_obj_id);
    return Result<void>::ok_result();
}

Result<void> RtProcess::unregister_thread(std::uint64_t thread_obj_id) {
    std::lock_guard lock(collections_lock_);
    const auto it = std::remove(thread_list_.begin(), thread_list_.end(),
                                thread_obj_id);
    if (it == thread_list_.end()) {
        return Result<void>(RuntimeErrc::NotFound, "thread not registered");
    }
    thread_list_.erase(it, thread_list_.end());
    return Result<void>::ok_result();
}

std::vector<std::uint64_t> RtProcess::threads() const {
    std::lock_guard lock(collections_lock_);
    return thread_list_;
}

Result<void> RtProcess::set_service(const std::string& name, std::uint64_t obj_id) {
    if (name.empty()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "empty service name");
    }
    std::lock_guard lock(collections_lock_);
    service_map_[name] = obj_id;
    return Result<void>::ok_result();
}

Result<std::uint64_t> RtProcess::get_service(const std::string& name) const {
    std::lock_guard lock(collections_lock_);
    const auto it = service_map_.find(name);
    if (it == service_map_.end()) {
        return Result<std::uint64_t>(RuntimeErrc::NotFound, "service '" + name + "'");
    }
    return Result<std::uint64_t>(it->second);
}

std::vector<std::pair<std::string, std::uint64_t>> RtProcess::services() const {
    std::lock_guard lock(collections_lock_);
    return {service_map_.begin(), service_map_.end()};
}

Result<RefGuard> RtProcess::lookup_handle(Handle h,
                                           const ObjectManager& manager) const {
    (void)manager;
    return table_.lookup(h);
}

void RtProcess::on_destroy() {
    // Teardown: close the table; terminate is user-driven, so if the
    // process is still non-terminal here we record it (never silent).
    if (state_.load(std::memory_order_acquire) != ProcessState::Terminated) {
        set_meta("destroyed-without-terminate", "true");
    }
    table_.close_all();
}

}  // namespace xbox2pc::rt
