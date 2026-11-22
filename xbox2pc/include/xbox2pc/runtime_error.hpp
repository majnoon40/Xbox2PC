#pragma once
// xbox2pc/runtime_error.hpp — M3 runtime error model.
//
// Layer rules (see docs/architecture.md):
//   1. Runtime code never throws across layer boundaries except via this
//      typed error; recoverable outcomes use `Result`/status codes.
//   2. Hard bugs (contract violations) throw RuntimeError; ordinary
//      operational failures (stale handle, invalid transition, duplicate
//      registration) return Result<T> with a RuntimeErrc code so callers
//      can branch without exceptions.
//   3. Errors carry the failing component name for diagnostics; they are
//      never silently discarded (documentation rule).

#include <cassert>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace xbox2pc::rt {

// ── error codes ───────────────────────────────────────────────────────────
enum class RuntimeErrc {
    // generic
    Ok = 0,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    OutOfResources,
    NotInitialized,
    AlreadyInitialized,
    InvalidState,
    ShutdownInProgress,
    // objects
    ObjectDestroyed,
    ObjectTypeMismatch,
    ObjectRegistryFull,
    // handles
    InvalidHandle,
    HandleStale,
    HandleClosed,
    HandleTableFull,
    // process/thread
    InvalidTransition,
    ProcessTerminated,
    ThreadTerminated,
    // synchronization
    Timeout,
    LockNotOwned,
    // services
    MissingDependency,
    CircularDependency,
    ServiceFailed,
    // platform
    PlatformUnsupported,
    PlatformError,
    IoError,
};

const char* errc_to_name(RuntimeErrc e);
std::string errc_to_string(RuntimeErrc e);

// ── Result ───────────────────────────────────────────────────────────────
//
// A minimal status-or-value type: operations that fail for representable
// reasons return Result<T> instead of throwing. Assertions use asserts for
// programmer errors only.
template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), errc_(RuntimeErrc::Ok) {}
    Result(RuntimeErrc e, std::string context)
        : errc_(e), context_(std::move(context)) {}

    bool ok() const { return errc_ == RuntimeErrc::Ok; }
    explicit operator bool() const { return ok(); }

    const T& value() const& {
        assert(ok());
        return *value_;
    }
    T& value() & {
        assert(ok());
        return *value_;
    }
    T value() && {
        assert(ok());
        return std::move(*value_);
    }

    RuntimeErrc errc() const { return errc_; }
    const std::string& context() const { return context_; }
    // Full human-readable error ("handle_stale: generation 4 != 5").
    std::string error_string() const {
        return errc_to_string(errc_) +
               (context_.empty() ? std::string() : ": " + context_);
    }

private:
    std::optional<T> value_;
    RuntimeErrc errc_ = RuntimeErrc::Ok;
    std::string context_;
};

// Void specialization for status-only operations.
template <>
class Result<void> {
public:
    Result() : errc_(RuntimeErrc::Ok) {}
    Result(RuntimeErrc e, std::string context)
        : errc_(e), context_(std::move(context)) {}

    bool ok() const { return errc_ == RuntimeErrc::Ok; }
    explicit operator bool() const { return ok(); }
    RuntimeErrc errc() const { return errc_; }
    const std::string& context() const { return context_; }
    std::string error_string() const {
        return errc_to_string(errc_) +
               (context_.empty() ? std::string() : ": " + context_);
    }

    static Result<void> ok_result() { return Result<void>(); }

private:
    RuntimeErrc errc_;
    std::string context_;
};

// ── hard error ────────────────────────────────────────────────────────────
//
// Thrown only for contract violations the caller cannot reasonably handle
// (using a destroyed registry, calling into a half-initialized core).
class RuntimeError : public std::runtime_error {
public:
    RuntimeError(RuntimeErrc e, std::string context)
        : std::runtime_error(errc_to_string(e) + ": " + context), errc_(e) {}
    RuntimeErrc errc() const { return errc_; }

private:
    RuntimeErrc errc_;
};

}  // namespace xbox2pc::rt
