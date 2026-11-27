// xbox2pc/src/guest_exceptions.cpp — M8 guest exception model impl.

#include "xbox2pc/guest_exceptions.hpp"

namespace xbox2pc::rt::exec {

const char* guest_fault_to_name(GuestFault f) {
    switch (f) {
        case GuestFault::InvalidAccess: return "invalid-access";
        case GuestFault::PermissionRead: return "permission-read";
        case GuestFault::PermissionWrite: return "permission-write";
        case GuestFault::PermissionExec: return "permission-exec";
        case GuestFault::InvalidInstruction: return "invalid-instruction";
        case GuestFault::UnsupportedInstruction: return "unsupported-instruction";
        case GuestFault::StackOverflow: return "stack-overflow";
        case GuestFault::InvalidState: return "invalid-state";
        case GuestFault::MarshalFailure: return "marshal-failure";
        case GuestFault::GuestTerminated: return "guest-terminated";
        case GuestFault::BudgetExceeded: return "budget-exceeded";
        case GuestFault::Internal: return "internal";
        case GuestFault::DivideError: return "divide-error";
        case GuestFault::UnimplementedApi: return "unimplemented-api";
    }
    return "?";
}

std::optional<GuestFault> guest_fault_from_name(const std::string& n) {
    if (n == "invalid-access") return GuestFault::InvalidAccess;
    if (n == "permission-read") return GuestFault::PermissionRead;
    if (n == "permission-write") return GuestFault::PermissionWrite;
    if (n == "permission-exec") return GuestFault::PermissionExec;
    if (n == "invalid-instruction") return GuestFault::InvalidInstruction;
    if (n == "unsupported-instruction") return GuestFault::UnsupportedInstruction;
    if (n == "stack-overflow") return GuestFault::StackOverflow;
    if (n == "invalid-state") return GuestFault::InvalidState;
    if (n == "marshal-failure") return GuestFault::MarshalFailure;
    if (n == "guest-terminated") return GuestFault::GuestTerminated;
    if (n == "budget-exceeded") return GuestFault::BudgetExceeded;
    if (n == "internal") return GuestFault::Internal;
    if (n == "divide-error") return GuestFault::DivideError;
    if (n == "unimplemented-api") return GuestFault::UnimplementedApi;
    return std::nullopt;
}

const char* access_type_to_name(AccessType a) {
    switch (a) {
        case AccessType::None: return "none";
        case AccessType::Read: return "read";
        case AccessType::Write: return "write";
        case AccessType::Execute: return "execute";
    }
    return "?";
}

const char* recoverability_to_name(Recoverability r) {
    switch (r) {
        case Recoverability::Recoverable: return "recoverable";
        case Recoverability::Fatal: return "fatal";
    }
    return "?";
}

std::string format_exception(const GuestException& e) {
    std::string out = std::string(guest_fault_to_name(e.fault)) +
                     " rip=0x" + std::to_string(e.rip);
    if (e.access != AccessType::None) {
        out += std::string(" (") + access_type_to_name(e.access) + ")";
    }
    if (e.fault_address != 0) {
        out += " addr=0x" + std::to_string(e.fault_address);
    }
    out += " pid=" + std::to_string(e.process_id) +
           " tid=" + std::to_string(e.thread_id) +
           " [" + recoverability_to_name(e.recoverability) + "]";
    if (!e.detail.empty()) {
        out += ": " + e.detail;
    }
    return out;
}

}  // namespace xbox2pc::rt::exec
