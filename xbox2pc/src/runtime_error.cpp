// xbox2pc/runtime_error.cpp — error code naming.

#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt {

const char* errc_to_name(RuntimeErrc e) {
    switch (e) {
        case RuntimeErrc::Ok: return "ok";
        case RuntimeErrc::InvalidArgument: return "invalid_argument";
        case RuntimeErrc::NotFound: return "not_found";
        case RuntimeErrc::AlreadyExists: return "already_exists";
        case RuntimeErrc::OutOfResources: return "out_of_resources";
        case RuntimeErrc::NotInitialized: return "not_initialized";
        case RuntimeErrc::AlreadyInitialized: return "already_initialized";
        case RuntimeErrc::InvalidState: return "invalid_state";
        case RuntimeErrc::ShutdownInProgress: return "shutdown_in_progress";
        case RuntimeErrc::ObjectDestroyed: return "object_destroyed";
        case RuntimeErrc::ObjectTypeMismatch: return "object_type_mismatch";
        case RuntimeErrc::ObjectRegistryFull: return "object_registry_full";
        case RuntimeErrc::InvalidHandle: return "invalid_handle";
        case RuntimeErrc::HandleStale: return "handle_stale";
        case RuntimeErrc::HandleClosed: return "handle_closed";
        case RuntimeErrc::HandleTableFull: return "handle_table_full";
        case RuntimeErrc::InvalidTransition: return "invalid_transition";
        case RuntimeErrc::ProcessTerminated: return "process_terminated";
        case RuntimeErrc::ThreadTerminated: return "thread_terminated";
        case RuntimeErrc::Timeout: return "timeout";
        case RuntimeErrc::LockNotOwned: return "lock_not_owned";
        case RuntimeErrc::MissingDependency: return "missing_dependency";
        case RuntimeErrc::CircularDependency: return "circular_dependency";
        case RuntimeErrc::ServiceFailed: return "service_failed";
        case RuntimeErrc::PlatformUnsupported: return "platform_unsupported";
        case RuntimeErrc::PlatformError: return "platform_error";
        case RuntimeErrc::IoError: return "io_error";
    }
    return "unknown_errc";
}

std::string errc_to_string(RuntimeErrc e) {
    return std::string(errc_to_name(e));
}

}  // namespace xbox2pc::rt
