#pragma once
// xbox2pc/telemetry.hpp — M12 P0.4 run telemetry shared by both backends.
//
// The last 64 imported-API identities of a run (the plan's "last 64 provider
// trace records"; there is no graphics provider in the run path yet, so API
// calls are what is traced) and XBOX2PC_WATCH: guest u32s logged when their
// value changes. Both backends sample at imported-API call boundaries; a
// per-instruction watch is P1 work and is not claimed here.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/guest_memory.hpp"

namespace xbox2pc::rt::exec::telemetry {

constexpr std::size_t kApiTraceRecords = 64;

// Appends `identity` ("dll!name"), keeping the newest kApiTraceRecords.
inline void record_api_call(ExecutionResult& result, const std::string& identity) {
    if (result.api_trace.size() >= kApiTraceRecords)
        result.api_trace.erase(result.api_trace.begin());
    result.api_trace.push_back(identity);
}

// XBOX2PC_WATCH=<rva>,... : RVAs (decimal or 0x-hex) of guest u32s, relative
// to the image base bound into the request's unwind context. A malformed
// item is skipped, never fatal.
inline std::vector<std::uint32_t> parse_watch_rvas(const char* text) {
    std::vector<std::uint32_t> out;
    if (text == nullptr) return out;
    const char* p = text;
    while (*p != '\0') {
        char* end = nullptr;
        const unsigned long value = std::strtoul(p, &end, 0);
        if (end == p) {
            while (*p != '\0' && *p != ',') ++p;
        } else if (value <= 0xFFFFFFFFul) {
            out.push_back(static_cast<std::uint32_t>(value));
        }
        p = end;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == ',') ++p;
        else if (*p != '\0') { while (*p != '\0' && *p != ',') ++p; if (*p == ',') ++p; }
    }
    return out;
}

// Logs every change of the watched u32s to stderr as
//   watch: rva 0x00001234: 0x0000002a (api call 3)
// The first sample of each value is a change (it has no predecessor).
class WatchLog {
public:
    explicit WatchLog(std::vector<std::uint32_t> rvas)
        : rvas_(std::move(rvas)), last_(rvas_.size(), std::pair<bool, std::uint32_t>(false, 0)) {}

    void sample(guest::GuestMemory& memory, std::uint64_t image_base, std::uint64_t api_call_index) {
        for (std::size_t i = 0; i < rvas_.size(); ++i) {
            const auto value = memory.read_u32(image_base + rvas_[i]);
            if (!value.ok()) continue;
            if (!last_[i].first || last_[i].second != value.value()) {
                std::fprintf(stderr, "watch: rva 0x%08x: 0x%08x (api call %llu)\n",
                             rvas_[i], value.value(),
                             static_cast<unsigned long long>(api_call_index));
                last_[i].first = true;
                last_[i].second = value.value();
            }
        }
    }

private:
    std::vector<std::uint32_t> rvas_;
    std::vector<std::pair<bool, std::uint32_t>> last_;
};

}  // namespace xbox2pc::rt::exec::telemetry
