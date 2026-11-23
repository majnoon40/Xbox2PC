#pragma once
// xbox2pc/diagnostics.hpp — logging, warnings and error reporting.
//
// Every parse/analysis function reports problems through this component:
//   - fatal parse errors   -> std::system_error / ParseError (checked by callers)
//   - recoverable problems -> Diagnostics::warning (kept, printed, non-fatal)
// This keeps "did it work" decidable from one place and makes the tool's
// output reproducible for tests.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace xbox2pc::diag {

enum class Severity {
    Info,
    Warning,
    Error,
};

// One recorded diagnostic: severity, message, optional location (file offset
// or RVA depending on producer).
struct Diagnostic {
    Severity severity = Severity::Info;
    std::string message;
    std::uint64_t offset = 0;  // byte offset / RVA the problem was found at
    bool has_offset = false;

    Diagnostic(Severity s, std::string msg) : severity(s), message(std::move(msg)) {}
    Diagnostic(Severity s, std::string msg, std::uint64_t off)
        : severity(s), message(std::move(msg)), offset(off), has_offset(true) {}

    std::string to_string() const;
};

// Collects diagnostics for one parse/analysis run. Not thread-safe by
// design: one instance per file being processed.
class Diagnostics {
public:
    void info(std::string msg) { entries_.emplace_back(Severity::Info, std::move(msg)); }
    void warning(std::string msg) { entries_.emplace_back(Severity::Warning, std::move(msg)); }
    void warning(std::string msg, std::uint64_t off) {
        entries_.emplace_back(Severity::Warning, std::move(msg), off);
    }
    void error(std::string msg) { entries_.emplace_back(Severity::Error, std::move(msg)); }
    void error(std::string msg, std::uint64_t off) {
        entries_.emplace_back(Severity::Error, std::move(msg), off);
    }

    const std::vector<Diagnostic>& entries() const { return entries_; }

    std::size_t count(Severity s) const;

    // True when any Error-severity diagnostic was recorded.
    bool has_errors() const { return count(Severity::Error) != 0; }
    // True when any Warning-severity diagnostic was recorded.
    bool has_warnings() const { return count(Severity::Warning) != 0; }

    // Render all diagnostics as lines ("[warning] ... (offset 0x...)").
    std::vector<std::string> lines() const;

    void clear() { entries_.clear(); }

private:
    std::vector<Diagnostic> entries_;
};

// Simple leveled logger for the CLI/tools. Writes to stderr by default so
// structured tool output on stdout stays clean.
class Logger {
public:
    enum class Level { Quiet = 0, Error = 1, Warn = 2, Info = 3, Debug = 4 };

    explicit Logger(Level lvl = Level::Warn) : level_(lvl) {}

    void set_level(Level lvl) { level_ = lvl; }
    Level level() const { return level_; }

    void log(Level lvl, const std::string& msg) const;
    void error(const std::string& msg) const { log(Level::Error, msg); }
    void warn(const std::string& msg) const { log(Level::Warn, msg); }
    void info(const std::string& msg) const { log(Level::Info, msg); }
    void debug(const std::string& msg) const { log(Level::Debug, msg); }

private:
    Level level_;
};

}  // namespace xbox2pc::diag
