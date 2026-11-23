#include "xbox2pc/diagnostics.hpp"

#include <cstdio>

namespace xbox2pc::diag {

std::string Diagnostic::to_string() const {
    const char* sev = "info";
    switch (severity) {
        case Severity::Info: sev = "info"; break;
        case Severity::Warning: sev = "warning"; break;
        case Severity::Error: sev = "error"; break;
    }
    std::string out = "[" + std::string(sev) + "] " + message;
    if (has_offset) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), " (offset 0x%llx)",
                      static_cast<unsigned long long>(offset));
        out += buf;
    }
    return out;
}

std::size_t Diagnostics::count(Severity s) const {
    std::size_t n = 0;
    for (const auto& d : entries_) {
        if (d.severity == s) ++n;
    }
    return n;
}

std::vector<std::string> Diagnostics::lines() const {
    std::vector<std::string> out;
    out.reserve(entries_.size());
    for (const auto& d : entries_) out.push_back(d.to_string());
    return out;
}

void Logger::log(Level lvl, const std::string& msg) const {
    if (static_cast<int>(lvl) > static_cast<int>(level_)) return;
    const char* tag = "debug";
    switch (lvl) {
        case Level::Quiet: break;
        case Level::Error: tag = "error"; break;
        case Level::Warn: tag = "warn"; break;
        case Level::Info: tag = "info"; break;
        case Level::Debug: tag = "debug"; break;
    }
    std::fprintf(stderr, "[xbox2pc:%s] %s\n", tag, msg.c_str());
}

}  // namespace xbox2pc::diag
