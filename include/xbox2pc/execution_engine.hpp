#pragma once
// xbox2pc/execution_engine.hpp — M8 execution engine interface, the API
// marshalling bridge, and the deterministic test backend.
//
// Design (docs/execution-engine.md + docs/api-marshalling.md):
//
//   IExecutionEngine — the abstract engine boundary. The runtime is
//   NEVER permanently coupled to one CPU implementation; native-host and
//   emulator backends register behind this interface and are explicitly
//   distinguished (engine_kind(): "deterministic-test" vs
//   "native-host" vs future "emulated"). A test backend is labeled a
//   test backend — nothing here claims to be an x86-64 emulator.
//
//   DeterministicBackend — the working backend M8 ships: it executes a
//   DOCUMENTED, bounded instruction subset (see below) against the
//   CpuState + GuestMemory models. It is a real interpreter for that
//   subset — not a mock — and it reports UnsupportedInstruction for
//   everything outside the subset. Executed subset (all bounds-checked
//   through guest memory):
//       MOV r64, imm64              (B8+r io)
//       MOV r64, r64                (89/8B with REX.W; both encodings)
//       ADD r64, imm32(sext)        (81 /0 id)
//       SUB r64, imm32(sext)        (81 /5 id)
//       XOR r64, r64                (31 /r)
//       CMP r64, imm32(sext)        (81 /7 id)
//       RET                         (C3)
//       CALL rel32                  (E8)
//       JMP rel32                   (E9)
//       PUSH r64 / POP r64          (50+r / 58+r)
//       MOV r64, [r64+disp8]        (8B /r with REX.W; load)
//       MOV [r64+disp8], r64        (89 /r with REX.W; store)
//       NOP                         (90)
//   Flags updated: CMP sets ZF/SF/OF/CF; ADD/SUB set CF/ZF/SF/OF.
//   This subset is sufficient for the synthetic guest programs the tests
//   execute (compute, call/ret through a chain, load/store stack slots,
//   and imported-API calls through the bridge).
//
//   The imported-API path: when RIP lands on a synthetic dispatch
//   binding value issued by M7's ApiResolver (bit pattern 0x5100xxxx),
//   the engine enters the marshalling bridge: marshal_and_dispatch()
//   extracts arguments per the M8 ABI from the guest CPU state, reads
//   pointer/string/buffer arguments through GuestMemory (validated),
//   dispatches the M7 ApiRegistry call, writes outputs back through
//   GuestMemory, converts the result into guest return state (RAX/XMM0,
//   RSP frame pop per [MS-X64CC]), and returns control to the engine,
//   which resumes at the guest return address. NO host function
//   pointers are exposed to guest code; no arbitrary guest address is
//   dereferenced outside GuestMemory.
//
//   ExecutionOutcome — the result contract: Completed (hit an exit
//   sentinel), Returned (entry-point style return), Interrupted,
//   Terminated, GuestException (populated record, never a silent
//   success), UnsupportedInstruction, BudgetExceeded, InvalidState.
//
//   ExecutionConfig — validated limits (stack size, context count,
//   TLS callback count, dispatch nesting, guest op size, instruction
//   budget, diagnostic cap). Overflow-safe construction.
//
// Layering: this header is the top of the M8 stack — depends on
// rt_cpu, rt_abi, rt_guestmem, M7 rt_api, M3/M4 through the context.
// Nothing below links upward.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/guest_cpu_state.hpp"
#include "xbox2pc/guest_exceptions.hpp"
#include "xbox2pc/guest_memory.hpp"
#include "xbox2pc/runtime_error.hpp"
#include "xbox2pc/thread_model.hpp"
#include "xbox2pc/xbox_abi.hpp"

namespace xbox2pc::rt::exec {

// ── configuration + limits ────────────────────────────────────────────────

struct ExecutionConfig {
    // Maximum guest stack size per context (bytes; 16-aligned).
    std::uint64_t max_stack_bytes = 256 * 1024;
    // Maximum concurrent execution contexts (runtime-wide).
    std::uint32_t max_contexts = 256;
    // Maximum TLS callbacks per image (validation + scheduling).
    std::uint32_t max_tls_callbacks = 64;
    // Maximum nested API dispatches per engine call.
    std::uint32_t max_dispatch_depth = 64;
    // Maximum single guest memory operation (must be <= guest cap).
    std::uint64_t max_guest_op_bytes = guest::kMaxGuestOpBytes;
    // Maximum executed instructions per engine call (0 = no budget).
    std::uint64_t max_instructions = 1'000'000;
    // Maximum diagnostic text per exception record.
    std::uint32_t max_diagnostic_bytes = 1024;

    // Overflow-safe validation (rejects absurd values).
    Result<void> validate() const;
    // Clamp helper: an explicit small-delta builder for tests.
    static Result<ExecutionConfig> default_validated();
};

// ── execution outcomes ────────────────────────────────────────────────────

enum class Outcome : std::uint8_t {
    Completed = 0,   // ran to the documented completion sentinel
    Returned = 1,    // guest returned from the entry call
    Interrupted = 2, // stopped by request (cancellation observed)
    Terminated = 3,  // process/thread termination interrupted execution
    Faulted = 4,     // guest exception raised (record populated)
};
const char* outcome_to_name(Outcome o);

struct ExecutionResult {
    Outcome outcome = Outcome::Completed;
    std::uint64_t instructions_executed = 0;
    std::uint64_t final_rip = 0;
    std::uint64_t return_value = 0;   // RAX when Returned/Completed
    std::optional<GuestException> exception;   // populated iff Faulted
    // CPU state at the end (snapshot; always consistent).
    cpu::CpuSnapshot cpu;
    // Registered-API calls marshalled during this run.
    std::uint32_t api_calls = 0;
};

// ── the engine interface ──────────────────────────────────────────────────

// A prepared guest call to run (from the execution context). Carries
// NO raw host pointers: entry + stack are guest VAs; the API side
// resolves through the registry.
struct ApiBindingInfo {
    std::uint64_t value = 0;
    std::string library;
    std::string export_name;
    bool by_ordinal = false;
    std::uint32_t ordinal = 0;
};

// Alias the M3-managed-thread gate for execution requests and backends.
using ExecutionControl = CooperativeExecutionGate;

struct ExecutionRequest {
    std::uint64_t entry_va = 0;
    std::uint64_t stack_top_va = 0;     // 16-aligned free stack top
    std::uint64_t stack_size = 0;       // guard floor = top - size
    // Imported-API binding values the image's IAT entries hold (M7
    // ApiResolver-issued); retained for diagnostics and compatibility.
    // Dispatch requires a matching exact ApiBindingInfo below.
    std::vector<std::uint64_t> api_binding_values;
    // Exact import identity for every resolved binding. This is the
    // authoritative dispatch map; binding-range addresses alone are not.
    std::vector<ApiBindingInfo> api_bindings;
    // Completion sentinel: executing a `RET` with the sentinel address
    // as the return target completes the run (documented contract).
    std::uint64_t completion_va = 0;
    // Optional entry arguments (prepared via the ABI by the context).
    std::vector<abi::ArgValue> entry_args;
    abi::CallSpec entry_spec;
    // Optional cooperative suspend/resume control shared with the owning thread.
    std::shared_ptr<ExecutionControl> control;
};

class IExecutionEngine {
public:
    virtual ~IExecutionEngine() = default;

    // Backend identity — honest labels (see header top).
    virtual const char* engine_kind() const = 0;
    virtual const char* engine_description() const = 0;

    // Run one request to completion / fault / budget. `interrupted`
    // is polled between instructions: setting it yields Outcome::
    // Interrupted (cancellation is observable).
    // Bind the identity and address space of the guest context before each
    // run/step. Backends that dispatch guest APIs must override this hook.
    // The default preserves compatibility for backends that do not yet
    // consume runtime context.
    virtual Result<void> bind_execution_context(std::uint64_t process_id,
                                                std::uint64_t thread_id,
                                                AddressSpace& space) {
        (void)process_id;
        (void)thread_id;
        (void)space;
        return Result<void>::ok_result();
    }
    virtual Result<void> bind_execution_context(std::uint64_t process_id,
                                                std::uint64_t thread_id,
                                                AddressSpace& space,
                                                GuestThreadEnvironment* thread_environment) {
        (void)thread_environment;
        return bind_execution_context(process_id, thread_id, space);
    }

    virtual ExecutionResult run(const ExecutionRequest& req,
                                cpu::CpuState& io_cpu,
                                const std::atomic<bool>& interrupted) = 0;

    // Optional single-step support (deterministic backend: yes).
    virtual bool supports_single_step() const = 0;
    virtual Result<std::uint64_t> single_step(cpu::CpuState& io_cpu,
                                              const ExecutionRequest& req) = 0;
};

// ── the deterministic backend ─────────────────────────────────────────────

// Real interpreter for the documented subset (header top). Config caps
// instruction budget; the marshalling bridge dispatches M7 APIs.
class DeterministicBackend : public IExecutionEngine {
public:
    // The bridge needs the registry + per-process identity for
    // marshalling (process id rides the ApiContext).
    DeterministicBackend(api::ApiRegistry& registry, ExecutionConfig cfg);
    ~DeterministicBackend() override;   // defined in the .cpp (Impl)

    const char* engine_kind() const override { return "deterministic-test"; }
    const char* engine_description() const override {
        return "bounded-subset x86-64 interpreter (test backend; "
               "explicitly NOT a general emulator)";
    }

    // NOTE: guest memory access is provided per-run via the context's
    // process address space. ExecutionContext invokes bind_execution_context
    // automatically before run/step/callback execution.
    void bind_space(AddressSpace& space) { mem_ = std::make_unique<guest::GuestMemory>(space); }
    void bind_process(std::uint64_t pid, std::uint64_t tid) {
        pid_ = pid;
        tid_ = tid;
    }
    Result<void> bind_execution_context(std::uint64_t process_id,
                                        std::uint64_t thread_id,
                                        AddressSpace& space) override {
        return bind_execution_context(process_id, thread_id, space, nullptr);
    }
    Result<void> bind_execution_context(std::uint64_t process_id,
                                        std::uint64_t thread_id,
                                        AddressSpace& space,
                                        GuestThreadEnvironment* thread_environment) override {
        if (process_id == 0 || thread_id == 0) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "guest process and thread identities must be nonzero");
        }
        bind_space(space);
        bind_process(process_id, thread_id);
        thread_environment_ = thread_environment;
        return Result<void>::ok_result();
    }

    ExecutionResult run(const ExecutionRequest& req,
                       cpu::CpuState& io_cpu,
                       const std::atomic<bool>& interrupted) override;

    bool supports_single_step() const override { return true; }
    Result<std::uint64_t> single_step(cpu::CpuState& io_cpu,
                                      const ExecutionRequest& req) override;

    const ExecutionConfig& config() const { return cfg_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    api::ApiRegistry& registry_;
    ExecutionConfig cfg_;
    std::unique_ptr<guest::GuestMemory> mem_;
    std::uint64_t pid_ = 0;
    std::uint64_t tid_ = 0;
    GuestThreadEnvironment* thread_environment_ = nullptr;
};

// First native-host execution slice. This backend is intentionally narrow:
// x86-64 Linux, up to four integer-like register arguments (RCX/RDX/R8/R9),
// no pointer/FP/stack arguments, imports, GS, or SEH, and a bounded child
// process lifetime. The child contains host faults; it is NOT a security
// sandbox and must only be used with trusted, unencumbered test code.
class NativeExecutionBackend final : public IExecutionEngine {
public:
    explicit NativeExecutionBackend(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));
    const char* engine_kind() const override { return "native-host"; }
    const char* engine_description() const override {
        return "x86-64 Linux native entry execution in a fault-contained child process "
               "(no imports, GS/TLS, SEH, or persistent guest writes)";
    }
    Result<void> bind_execution_context(std::uint64_t process_id,
                                        std::uint64_t thread_id,
                                        AddressSpace& space) override;
    Result<void> bind_execution_context(std::uint64_t process_id,
                                        std::uint64_t thread_id,
                                        AddressSpace& space,
                                        GuestThreadEnvironment* thread_environment) override;
    ExecutionResult run(const ExecutionRequest& req, cpu::CpuState& io_cpu,
                        const std::atomic<bool>& interrupted) override;
    bool supports_single_step() const override { return false; }
    Result<std::uint64_t> single_step(cpu::CpuState& io_cpu,
                                      const ExecutionRequest& req) override;
private:
    AddressSpace* space_ = nullptr;
    std::uint64_t pid_ = 0;
    std::uint64_t tid_ = 0;
    std::chrono::milliseconds timeout_;
};

// ── the marshalling bridge ────────────────────────────────────────────────

// Argument marshalling metadata for one imported API: how to extract
// the documented parameters from the guest ABI and how to write the
// documented result back. Authored per-API from the M7 descriptor's
// documented signature (never inferred from names alone).
struct MarshalPlan {
    std::string library;      // M7 registry identity
    std::string export_name;
    abi::CallSpec call;       // documented parameter kinds + return
    // For pointer outputs: which argument INDEX is an out buffer whose
    // bytes the bridge writes from the ApiCallResult out_value slot.
    std::vector<std::uint32_t> out_buffer_args;
    struct PointerArrayArg { std::uint32_t pointer_arg = 0; std::uint32_t count_arg = 0; std::uint32_t max_count = 0; std::uint32_t element_size = 0; };
    std::vector<PointerArrayArg> pointer_array_args;
    // String input argument indexes (read as guest C strings).
    std::vector<std::uint32_t> string_args;
};

// Build the marshal plan for a REGISTERED M7 descriptor from its
// documented signature text (param_count + known kinds for the 16
// built-ins). Unknown APIs yield a typed error — the bridge never
// guesses layouts.
Result<MarshalPlan> plan_for_descriptor(const api::ApiDescriptor& d);

// Extract args -> validate pointers -> dispatch -> write back.
// Fills a GuestException on any marshalling rejection (MarshalFailure)
// and returns the ApiCallResult + the post-call CPU state via
// write_return. Execution continues at the guest return address.
struct MarshalResult {
    bool dispatched = false;
    api::ApiCallResult api_result;
    std::uint32_t depth_used = 0;
};
Result<MarshalResult> marshal_and_dispatch(cpu::CpuState& io_cpu,
                                           guest::GuestMemory& mem,
                                           api::ApiRegistry& registry,
                                           const MarshalPlan& plan,
                                           std::uint64_t pid,
                                           std::uint32_t depth,
                                           std::uint32_t max_depth,
                                           std::uint64_t tid = 0,
                                           const api::GuestCallbackInvoker& invoke_callback = {},
                                           GuestThreadEnvironment* thread_environment = nullptr,
                                           const std::function<bool()>& cancellation_requested = {});

// ── completion sentinel + binding range ──────────────────────────────────

inline constexpr std::uint64_t kBindingBase = 0x51000000ull;
inline constexpr std::uint64_t kBindingRange = 0x00020000ull;
inline constexpr std::uint64_t kCompletionSentinel = 0x5100FFFFull;
inline bool is_api_binding(std::uint64_t va) {
    return va >= kBindingBase && va < kBindingBase + kBindingRange &&
           va != kCompletionSentinel;
}

}  // namespace xbox2pc::rt::exec
