#pragma once
// xbox2pc/guest_exceptions.hpp — M8 structured guest exception model.
//
// Design (docs/guest-exceptions.md): one exception record type covers
// every guest-execution fault class the runtime can report, carrying
// the identity + fault context + recoverability classification. Guest
// exceptions NEVER silently convert into successful returns: every
// execution outcome is either a normal completion or carries an
// optional-but-populated GuestException. A failure in one execution
// context cannot corrupt another (per-context state; engine holds no
// global mutable guest state).

#include <cstdint>
#include <optional>
#include <string>

namespace xbox2pc::rt::exec {

// ── exception codes (stable, machine-readable) ────────────────────────────

enum class GuestFault : std::uint16_t {
    InvalidAccess = 0,        // unmapped guest memory touched
    PermissionRead = 1,       // read from a non-readable region
    PermissionWrite = 2,      // write to a read-only region
    PermissionExec = 3,       // execution from non-executable memory
    InvalidInstruction = 4,  // decoded but architecturally invalid
    UnsupportedInstruction = 5, // valid x64 but not implemented by backend
    StackOverflow = 6,        // RSP fell below the stack guard/floor
    InvalidState = 7,         // execution requested on an invalid context
    MarshalFailure = 8,       // API marshalling rejected (args/pointers)
    GuestTerminated = 9,      // process/thread termination interrupted exec
    BudgetExceeded = 10,      // instruction/time budget exhausted
    Internal = 11,            // engine-internal error (bug class)
    DivideError = 12,         // DIV/IDIV by zero or quotient overflow
};
const char* guest_fault_to_name(GuestFault f);
std::optional<GuestFault> guest_fault_from_name(const std::string& n);

// Access classification for memory faults.
enum class AccessType : std::uint8_t { None = 0, Read, Write, Execute };
const char* access_type_to_name(AccessType a);

// Recoverability: can execution continue in this context after the
// fault was raised (with corrective action), or is the context dead?
enum class Recoverability : std::uint8_t {
    Recoverable = 0,   // engine stopped cleanly; context reusable
    Fatal = 1,         // context must be destroyed
};
const char* recoverability_to_name(Recoverability r);

// ── the record ─────────────────────────────────────────────────────────────

struct GuestException {
    GuestFault fault = GuestFault::InvalidAccess;
    std::uint64_t rip = 0;            // guest instruction address
    AccessType access = AccessType::None;
    std::uint64_t fault_address = 0;   // guest VA where applicable (else 0)
    std::uint64_t process_id = 0;
    std::uint64_t thread_id = 0;
    Recoverability recoverability = Recoverability::Fatal;
    std::string detail;                // bounded diagnostic text

    // Bound: detail is capped by the execution config's
    // max_diagnostic_bytes; longer engine detail is truncated before
    // the record is surfaced (no unbounded diagnostic growth).
    void clamp_detail(std::size_t max_bytes) {
        if (detail.size() > max_bytes) detail.resize(max_bytes);
    }
};

// Human-readable one-liner (reporting/CLI).
std::string format_exception(const GuestException& e);

}  // namespace xbox2pc::rt::exec
