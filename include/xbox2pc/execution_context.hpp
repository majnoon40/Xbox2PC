#pragma once
// xbox2pc/execution_context.hpp — M8 per-thread guest execution context
// + M6 loader integration + TLS callback scheduling.
//
// Design (docs/execution-architecture.md):
//   ExecutionContext — a per-(process, thread) guest execution context:
//   owns a CpuState, binds the process's AddressSpace (guest memory),
//   the M7 ApiRegistry (dispatch association), the ABI config, the
//   guest stack (allocated IN the process address space through M4 —
//   not host memory), and entry-point preparation. Registered as an
//   M3 RuntimeObject so handles/generation protection and process
//   termination cleanup apply exactly like every other runtime object.
//
//   Lifecycle: Created -> Initialized -> Executing -> Stopped ->
//   (re-Initialized or) Destroyed. Invalid transitions return typed
//   errors; cross-process use is rejected (the context validates its
//   process's generation on every use). Contexts never share mutable
//   CPU state; the engine itself holds no global mutable guest state.
//
//   M6 integration: prepare_entry() receives a SUCCESSFULLY PREPARED
//   LoadedImageObject (state Prepared), validates the entry point
//   (executable region, inside the image), allocates the guest stack,
//   prepares the ABI call frame for the entry point, associates the
//   TLS index (M7), and produces a VALIDATED ExecutionRequest — no
//   unchecked host pointers anywhere (entry/stack are guest VAs).
//
//   TLS callbacks: validated + scheduled, EXECUTED only when the
//   request's callback programs are run through the engine (the
//   deterministic backend executes them like any other guest code —
//   through the documented callback ABI: RCX=DllMain-style reason,
//   RDX=Reserved, R8=Reserved per the documented callback signature
//   void CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)).
//   Recursion guard + count limit enforced; failures reported; partial
//   initialization cleaned up. Callback programs that need real
//   instruction execution run on the engine; anything beyond the
//   subset reports UnsupportedInstruction honestly.
//
//   Entry-point invocation: invoke_entry() runs the engine on the
//   prepared request and returns a structured ExecutionResult. The
//   runtime NEVER claims a real Xbox executable "runs" — it runs what
//   the engine can execute, and reports the rest.

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/guest_exceptions.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/runtime_object.hpp"
#include "xbox2pc/service_registry.hpp"

namespace xbox2pc::rt::exec {

// ── context lifecycle states ──────────────────────────────────────────────

enum class ContextState : std::uint8_t {
    Created = 0,     // registered, no CPU/stack yet
    Initialized = 1,  // stack + CPU + associations bound
    Executing = 2,    // an engine run holds it
    Stopped = 3,      // run finished (or faulted) — reusable
    Destroyed = 4,    // terminal
};
const char* context_state_to_name(ContextState s);

// ── the context object ────────────────────────────────────────────────────

class ExecutionContext : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(ExecutionContext, RuntimeService)
    // NOTE: type id reuses the RuntimeService slot (the 9-bit handle
    // type field only round-trips built-in ids; as<T> double-validates
    // the dynamic type — the same discipline LoadedImageObject uses).

    // Creation info for reports.
    struct Info {
        std::uint64_t process_id = 0;
        std::uint64_t thread_id = 0;
        std::uint32_t tls_index = 0;
        std::uint64_t stack_top = 0;
        std::uint64_t stack_size = 0;
        std::uint64_t entry_va = 0;
        std::string image_name;
    };

    ExecutionContext(std::uint64_t process_id, std::uint64_t thread_id,
                     AddressSpace& space, api::ApiRegistry& api_reg,
                     ExecutionConfig cfg, std::string name);
    // Managed-thread constructor: derives both guest identities and binds
    // the thread's cooperative gate, preventing caller-supplied TID drift.
    ExecutionContext(RtThread& thread, AddressSpace& space,
                     api::ApiRegistry& api_reg, ExecutionConfig cfg,
                     std::string name);
    ~ExecutionContext() override;

    // ── lifecycle ──
    // Created -> Initialized: allocates the guest stack (M4 region,
    // RW, config-capped), resets the CPU, binds the ABI config.
    Result<void> initialize();

    // Initialized/Stopped -> (entry preparation + validated request).
    // Receives a Prepared image; validates entry (exec + inside image);
    // associates TLS (M7 index for the image); builds the request.
    Result<ExecutionRequest> prepare_entry(const loader::LoadedImageObject& image,
                                           std::uint32_t tls_index,
                                           const std::vector<abi::ArgValue>& args,
                                           const abi::CallSpec& spec);

    // Run the engine on a request (Initialized/Stopped -> Executing ->
    // Stopped). The CPU state travels in the context (per-context
    // mutable state; two contexts never share it).
    Result<ExecutionResult> invoke(const ExecutionRequest& req,
                                   IExecutionEngine& engine,
                                   const std::atomic<bool>& interrupted);

    // Attach the owning managed thread's shared cooperative gate. When a
    // request has no explicit control, invoke() supplies this gate to the
    // backend automatically.
    Result<void> bind_thread_control(std::shared_ptr<ExecutionControl> control);

    // Single-step (engine supports it): one instruction.
    Result<std::uint64_t> step(const ExecutionRequest& req,
                               IExecutionEngine& engine);

    // Terminate the context (any state -> Destroyed): releases the
    // stack region (M4), drops associations. Idempotent after destroy.
    Result<void> destroy();

    // ── introspection ──
    ContextState context_state() const { return state_; }
    const Info& info() const { return info_; }
    const cpu::CpuState& cpu() const { return cpu_; }
    cpu::CpuState& cpu_mut() { return cpu_; }
    const ExecutionConfig& config() const { return cfg_; }
    guest::GuestMemory& memory() { return mem_; }
    std::shared_ptr<ExecutionControl> execution_control() const;
    std::uint32_t run_count() const { return runs_; }

private:
    std::uint64_t process_id_;
    std::uint64_t thread_id_;
    AddressSpace& space_;
    api::ApiRegistry& api_reg_;
    ExecutionConfig cfg_;
    guest::GuestMemory mem_;
    cpu::CpuState cpu_;
    Info info_;
    ContextState state_ = ContextState::Created;
    std::uint64_t stack_region_va_ = 0;
    std::uint32_t runs_ = 0;
    std::string ctx_name_;
    // M9: true once initialize() acquired a ContextLimiter slot (the
    // destructor releases only what was acquired — no counter underflow).
    bool counted_ = false;
    std::shared_ptr<ExecutionControl> execution_control_;
    mutable std::mutex lock_;
};

// ── M6 loader integration ────────────────────────────────────────────────

// Entry-point validation over a prepared image (public for tests):
// entry must be inside the image's mapped extent and executable.
Result<std::uint64_t> validate_entry_point(const loader::ExecDescription& exec,
                                           AddressSpace& space);

// ── TLS callback scheduling ──────────────────────────────────────────────

// One validated callback slot.
struct TlsCallback {
    std::uint64_t va = 0;    // callback entry (exec-validated)
    std::uint32_t order = 0; // document order (array order)
};

// Validate the callback array of a loaded image: reads the callback VA
// array from the mapped image (guest memory), bounds-checks the count
// against the config limit, validates every VA lands in executable
// mapped regions, preserves order, and reports problems typed.
struct TlsCallbackPlan {
    std::vector<TlsCallback> callbacks;
    std::uint32_t rejected_count = 0;   // invalid entries dropped
    std::string note;                    // validation summary
};
Result<TlsCallbackPlan> plan_tls_callbacks(guest::GuestMemory& mem,
                                           const loader::TlsInfo& tls,
                                           const ExecutionConfig& cfg);

// Execute a callback plan through an engine (documented callback ABI:
// RCX=handle, RDX=reason DLL_PROCESS_ATTACH(1), R8=reserved). Returns
// per-callback results; a callback failure is reported, NOT silently
// ignored; recursion is impossible (one pass, plan-level guard), and
// partial failure still completes the remaining cleanup.
struct TlsCallbackResult {
    std::uint32_t executed = 0;
    std::uint32_t failed = 0;
    std::optional<GuestException> first_failure;
};
Result<TlsCallbackResult> execute_tls_callbacks(
    ExecutionContext& ctx, const TlsCallbackPlan& plan,
    IExecutionEngine& engine, std::uint64_t image_handle_va);

// ── limits registry (runtime-wide, thread-safe) ─────────────────────────

// Counts live contexts against the config cap (advisory; creation
// sites call this before registering).
class ContextLimiter {
public:
    static Result<void> acquire();
    static void release();
    static std::uint32_t live();
};

}  // namespace xbox2pc::rt::exec
