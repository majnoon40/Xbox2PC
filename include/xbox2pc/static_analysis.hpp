#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace xbox2pc::analysis {

struct InstructionRecord {
    std::string section;
    std::uint64_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint8_t length = 0;
    std::string bytes_hex;
    std::string text;
};

struct Region {
    std::string section;
    std::uint64_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::string reason;
};

struct SegmentUse {
    std::string section;
    std::uint64_t rva = 0;
    std::string segment;
    std::string instruction;
};

struct AnalysisReport {
    std::string source;
    bool parsed = false;
    bool is_pe32_plus_amd64 = false;
    std::vector<InstructionRecord> confirmed_instructions;
    // Invalid byte sequences are only candidates for embedded data, never
    // asserted to be data without control-flow or relocation evidence.
    std::vector<Region> candidate_embedded_data;
    std::vector<Region> unsupported_instructions;
    std::vector<Region> uncertain_regions;
    std::vector<SegmentUse> fs_gs_uses;
    std::vector<std::string> notes;
};

// Linear, heuristic scan of file-backed executable sections only. This is not
// control-flow recovery and does not infer that every decoded byte is reached.
AnalysisReport analyze_pe(const std::uint8_t* data, std::size_t size,
                          const std::string& source_name);

}  // namespace xbox2pc::analysis
