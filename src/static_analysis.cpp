#include "xbox2pc/static_analysis.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/x64_decoder.hpp"
#include "xbox2pc/x86_interpreter.hpp"

namespace xbox2pc::analysis {
namespace {

constexpr std::size_t kMaxInstructionRecords = 1'000'000;

bool fits(std::uint64_t start, std::uint64_t length, std::uint64_t limit) {
    return start <= limit && length <= limit - start;
}

std::string hex_bytes(const std::uint8_t* bytes, std::size_t length) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < length; ++i) {
        if (i != 0) out << ' ';
        out << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return out.str();
}

void append_region(std::vector<Region>& regions, const std::string& section,
                   std::uint64_t rva, std::uint64_t file_offset,
                   std::uint64_t size, const std::string& reason) {
    if (size == 0) return;
    if (!regions.empty()) {
        Region& last = regions.back();
        if (last.section == section && last.reason == reason &&
            last.rva + last.size == rva &&
            last.file_offset + last.size == file_offset) {
            last.size += size;
            return;
        }
    }
    regions.push_back(Region{section, rva, file_offset, size, reason});
}

}  // namespace

AnalysisReport analyze_pe(const std::uint8_t* data, std::size_t size,
                          const std::string& source_name) {
    AnalysisReport report;
    report.source = source_name;
    if (data == nullptr || size == 0) {
        report.notes.push_back("input buffer is null or empty");
        return report;
    }

    xbox2pc::diag::Diagnostics diagnostics;
    xbox2pc::pe::PeImage image;
    try {
        image = xbox2pc::pe::parse(data, size, source_name, diagnostics);
        report.parsed = true;
    } catch (const std::exception& error) {
        report.notes.push_back(std::string("PE parse failed: ") + error.what());
        return report;
    }

    report.is_pe32_plus_amd64 = image.opt.is_pe32plus &&
        image.coff.machine == xbox2pc::pe::kMachineAmd64;
    for (const auto& diagnostic : diagnostics.lines()) {
        report.notes.push_back(diagnostic);
    }
    if (!report.is_pe32_plus_amd64) {
        report.notes.push_back(
            "static instruction scan requires a PE32+ AMD64 image; no sections scanned");
        return report;
    }

    std::size_t instruction_count = 0;
    for (const auto& section : image.sections) {
        if ((section.characteristics & xbox2pc::pe::sect_flags::kExecutable) == 0) {
            continue;
        }
        if (!section.has_raw_data || section.size_of_raw_data == 0) {
            report.notes.push_back(
                "executable section " + section.name + " has no file-backed bytes");
            continue;
        }
        const std::uint64_t file_offset = section.raw_data_offset;
        const std::uint64_t section_size = section.size_of_raw_data;
        if (!fits(file_offset, section_size, size)) {
            report.notes.push_back(
                "executable section " + section.name + " has an out-of-file raw range");
            append_region(report.uncertain_regions, section.name,
                          section.virtual_address, file_offset, section_size,
                          "raw section range failed bounds validation");
            continue;
        }

        std::uint64_t offset = 0;
        while (offset < section_size) {
            if (instruction_count >= kMaxInstructionRecords) {
                append_region(report.uncertain_regions, section.name,
                              static_cast<std::uint64_t>(section.virtual_address) + offset,
                              file_offset + offset, section_size - offset,
                              "analysis instruction cap reached");
                report.notes.push_back("analysis stopped at the instruction safety cap");
                return report;
            }

            const auto remaining = static_cast<std::size_t>(section_size - offset);
            const std::uint64_t rva =
                static_cast<std::uint64_t>(section.virtual_address) + offset;
            const std::uint64_t absolute_file_offset = file_offset + offset;
            const auto decoded = xbox2pc::rt::x64::decode(
                data + static_cast<std::size_t>(absolute_file_offset), remaining, rva);

            if (decoded.status == xbox2pc::rt::x64::DecodeStatus::Ok &&
                decoded.ins.length != 0 && decoded.ins.length <= remaining) {
                const auto* instruction_bytes =
                    data + static_cast<std::size_t>(absolute_file_offset);
                InstructionRecord record;
                record.section = section.name;
                record.rva = rva;
                record.file_offset = absolute_file_offset;
                record.length = decoded.ins.length;
                record.bytes_hex = hex_bytes(instruction_bytes, decoded.ins.length);
                record.text = xbox2pc::rt::x64::format_instruction(decoded.ins);
                record.interpreter_supported =
                    xbox2pc::rt::x86::Interpreter::supports(decoded.ins.mnem);
                if (!record.interpreter_supported) {
                    append_region(report.unsupported_execution, section.name, rva,
                                  absolute_file_offset, decoded.ins.length,
                                  "decoder-recognized instruction is outside the current interpreter support matrix: " +
                                      record.text);
                }
                report.confirmed_instructions.push_back(std::move(record));
                ++instruction_count;

                for (std::uint8_t i = 0; i < decoded.ins.op_count; ++i) {
                    const auto& operand = decoded.ins.ops[i];
                    if (operand.kind != xbox2pc::rt::x64::OpKind::Mem) continue;
                    if (operand.seg == xbox2pc::rt::x64::Segment::Fs ||
                        operand.seg == xbox2pc::rt::x64::Segment::Gs) {
                        report.fs_gs_uses.push_back(SegmentUse{
                            section.name, rva,
                            operand.seg == xbox2pc::rt::x64::Segment::Fs ? "FS" : "GS",
                            xbox2pc::rt::x64::format_instruction(decoded.ins)});
                    }
                }
                offset += decoded.ins.length;
                continue;
            }

            if (decoded.status == xbox2pc::rt::x64::DecodeStatus::Unsupported) {
                const std::uint64_t consumed =
                    std::max<std::uint64_t>(decoded.consumed, 1);
                const std::uint64_t span = std::min(consumed, section_size - offset);
                append_region(report.unsupported_instructions, section.name, rva,
                              absolute_file_offset, span,
                              std::string(xbox2pc::rt::x64::reject_class_name(decoded.reject)) +
                                  ": " + decoded.reason + " [bytes: " +
                                  hex_bytes(data + static_cast<std::size_t>(absolute_file_offset),
                                            static_cast<std::size_t>(span)) + "]");
                offset += span;
                continue;
            }

            if (decoded.status == xbox2pc::rt::x64::DecodeStatus::Truncated) {
                append_region(report.uncertain_regions, section.name, rva,
                              absolute_file_offset, section_size - offset,
                              std::string("truncated instruction or incomplete tail: ") +
                                  decoded.reason);
                break;
            }

            const std::uint64_t consumed =
                std::max<std::uint64_t>(decoded.consumed, 1);
            const std::uint64_t span = std::min(consumed, section_size - offset);
            append_region(report.candidate_embedded_data, section.name, rva,
                          absolute_file_offset, span,
                          std::string("invalid encoding; possible embedded data: ") +
                              decoded.reason);
            offset += span;
        }
    }

    report.notes.push_back(
        "linear scan only: confirmed means decoder-recognized, not reachable or executed");
    report.notes.push_back(
        "candidate embedded-data regions are heuristic; no complete CFG is claimed");
    return report;
}

}  // namespace xbox2pc::analysis
