#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace xbox2pc::validation {

enum class StageStatus : std::uint8_t { Passed, Warning, Failed, NotTested };

struct Stage {
    std::string name;
    StageStatus status = StageStatus::NotTested;
    std::vector<std::string> findings;
};

struct BinaryReport {
    std::string source;
    std::uint64_t file_size = 0;
    bool parsed = false;
    bool is_pe32_plus_amd64 = false;
    std::vector<Stage> stages;

    // True only when parsing succeeded and no performed structural check failed.
    // NOT_TESTED stages do not imply runtime or Xbox compatibility.
    bool structurally_valid() const;
};

const char* status_name(StageStatus status);

// Structural-only validation. Input is inspected in place and is never mapped
// into guest memory or executed.
BinaryReport validate_pe(const std::uint8_t* data, std::size_t size,
                         const std::string& source_name);

}  // namespace xbox2pc::validation
