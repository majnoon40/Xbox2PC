#include "xbox2pc/binary_validation.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>
#include <utility>

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::validation {
namespace {

Stage make_stage(const char* name, StageStatus status, std::string finding = {}) {
    Stage stage;
    stage.name = name;
    stage.status = status;
    if (!finding.empty()) stage.findings.push_back(std::move(finding));
    return stage;
}

bool fits(std::uint64_t start, std::uint64_t length, std::uint64_t limit) {
    return start <= limit && length <= limit - start;
}

}  // namespace

const char* status_name(StageStatus status) {
    switch (status) {
        case StageStatus::Passed: return "PASSED";
        case StageStatus::Warning: return "WARNING";
        case StageStatus::Failed: return "FAILED";
        case StageStatus::NotTested: return "NOT_TESTED";
    }
    return "NOT_TESTED";
}

bool BinaryReport::structurally_valid() const {
    return parsed && std::none_of(stages.begin(), stages.end(),
        [](const Stage& stage) { return stage.status == StageStatus::Failed; });
}

BinaryReport validate_pe(const std::uint8_t* data, std::size_t size,
                         const std::string& source_name) {
    BinaryReport report;
    report.source = source_name;
    report.file_size = static_cast<std::uint64_t>(size);

    if (data == nullptr || size == 0) {
        report.stages.push_back(make_stage(
            "identification", StageStatus::Failed, "input buffer is null or empty"));
        return report;
    }

    xbox2pc::diag::Diagnostics diagnostics;
    xbox2pc::pe::PeImage image;
    try {
        image = xbox2pc::pe::parse(data, size, source_name, diagnostics);
        report.parsed = true;
    } catch (const xbox2pc::pe::ParseError& error) {
        report.stages.push_back(make_stage("pe-structure", StageStatus::Failed, error.what()));
        report.stages.push_back(make_stage("imports", StageStatus::NotTested));
        report.stages.push_back(make_stage("relocations", StageStatus::NotTested));
        report.stages.push_back(make_stage("tls", StageStatus::NotTested));
        report.stages.push_back(make_stage("memory-layout", StageStatus::NotTested));
        return report;
    } catch (const std::exception& error) {
        report.stages.push_back(make_stage(
            "pe-structure", StageStatus::Failed,
            std::string("parser exception: ") + error.what()));
        return report;
    }

    auto directory_pair_valid = [&](std::uint16_t index) {
        if (index >= image.directories.size()) return true;
        const auto& directory = image.directories[index];
        return (directory.rva == 0) == (directory.size == 0);
    };

    report.is_pe32_plus_amd64 = image.opt.is_pe32plus &&
        image.coff.machine == xbox2pc::pe::kMachineAmd64;

    report.stages.push_back(make_stage(
        "identification", StageStatus::Passed, "PE signature and headers parsed"));

    Stage structure = make_stage("pe-structure", StageStatus::Passed);
    const auto loader_validation =
        xbox2pc::rt::loader::validate_image(image, data, size);
    for (const auto& issue : loader_validation.issues) {
        structure.status = StageStatus::Failed;
        structure.findings.push_back(issue.code + ": " + issue.message);
    }
    if (diagnostics.has_warnings()) {
        if (structure.status != StageStatus::Failed) {
            structure.status = StageStatus::Warning;
        }
        for (const auto& line : diagnostics.lines()) {
            structure.findings.push_back(line);
        }
    }
    for (std::size_t i = 0; i < image.directories.size(); ++i) {
        const auto& directory = image.directories[i];
        if ((directory.rva == 0) != (directory.size == 0)) {
            structure.status = StageStatus::Failed;
            structure.findings.push_back(
                directory.name + " directory has an inconsistent RVA/size pair");
        }
    }
    if (!image.opt.is_pe32plus) {
        structure.status = StageStatus::Failed;
        structure.findings.push_back("image is not PE32+");
    }
    if (image.coff.machine != xbox2pc::pe::kMachineAmd64) {
        structure.status = StageStatus::Failed;
        structure.findings.push_back("machine is not AMD64");
    }

    for (std::size_t i = 0; i < image.sections.size(); ++i) {
        const auto& current = image.sections[i];
        const std::uint64_t current_span =
            std::max(current.virtual_size, current.size_of_raw_data);

        if (!fits(current.virtual_address, current_span, image.opt.size_of_image)) {
            structure.status = StageStatus::Failed;
            structure.findings.push_back(
                "section " + current.name + " exceeds SizeOfImage");
        }
        if (current.has_raw_data &&
            !fits(current.raw_data_offset, current.size_of_raw_data, size)) {
            structure.status = StageStatus::Failed;
            structure.findings.push_back(
                "section " + current.name + " raw bytes exceed file");
        }
        if ((current.characteristics & xbox2pc::pe::sect_flags::kWritable) != 0 &&
            (current.characteristics & xbox2pc::pe::sect_flags::kExecutable) != 0) {
            if (structure.status != StageStatus::Failed) {
                structure.status = StageStatus::Warning;
            }
            structure.findings.push_back(
                "section " + current.name + " is writable and executable");
        }

        for (std::size_t j = i + 1; j < image.sections.size(); ++j) {
            const auto& other = image.sections[j];
            const std::uint64_t other_span =
                std::max(other.virtual_size, other.size_of_raw_data);
            const std::uint64_t current_end =
                static_cast<std::uint64_t>(current.virtual_address) + current_span;
            const std::uint64_t other_end =
                static_cast<std::uint64_t>(other.virtual_address) + other_span;
            if (current_span != 0 && other_span != 0 &&
                current.virtual_address < other_end &&
                other.virtual_address < current_end) {
                structure.status = StageStatus::Failed;
                structure.findings.push_back(
                    "virtual sections overlap: " + current.name + " and " + other.name);
            }
        }
    }

    if (image.opt.address_of_entry_point != 0) {
        const auto entry = image.opt.address_of_entry_point;
        const auto section = std::find_if(
            image.sections.begin(), image.sections.end(),
            [entry](const xbox2pc::pe::Section& candidate) {
                const std::uint64_t span =
                    std::max(candidate.virtual_size, candidate.size_of_raw_data);
                return entry >= candidate.virtual_address &&
                    entry - candidate.virtual_address < span;
            });

        if (section == image.sections.end()) {
            structure.status = StageStatus::Failed;
            structure.findings.push_back("entry point is outside all sections");
        } else if ((section->characteristics &
                    xbox2pc::pe::sect_flags::kExecutable) == 0) {
            structure.status = StageStatus::Failed;
            structure.findings.push_back("entry point section is not executable");
        }
    } else if ((image.coff.characteristics & 0x2000u) == 0 &&
               structure.status == StageStatus::Passed) {
        structure.status = StageStatus::Warning;
        structure.findings.push_back("executable image has no entry point");
    }

    if (structure.findings.empty()) {
        structure.findings.push_back("header, section and entry-point checks passed");
    }
    report.stages.push_back(std::move(structure));

    bool import_validation_failed = false;
    for (const auto& issue : loader_validation.issues) {
        if (issue.code == xbox2pc::rt::loader::vcode::kImportDirectory) {
            import_validation_failed = true;
        }
    }
    import_validation_failed =
        import_validation_failed ||
        !directory_pair_valid(xbox2pc::pe::kDirImport) ||
        !directory_pair_valid(xbox2pc::pe::kDirDelayImport);
    Stage imports = make_stage(
        "imports",
        import_validation_failed ? StageStatus::Failed :
            diagnostics.has_warnings() ? StageStatus::Warning : StageStatus::Passed,
        std::to_string(image.imports.entries.size()) +
            " regular import descriptor(s) parsed; symbol resolution not tested");
    if (import_validation_failed) {
        imports.findings.push_back("M6 import-directory validation reported a failure");
    }
    if (image.delay_imports.present) {
        imports.findings.push_back(
            std::to_string(image.delay_imports.entries.size()) +
            " delay-import descriptor(s) parsed");
    }
    report.stages.push_back(std::move(imports));

    Stage relocations = make_stage(
        "relocations", StageStatus::Passed,
        "relocation blocks decoded; relocation application not performed");
    if (!directory_pair_valid(xbox2pc::pe::kDirReloc)) {
        relocations.status = StageStatus::Failed;
        relocations.findings.push_back("relocation directory has an inconsistent RVA/size pair");
    }
    const auto relocation_blocks = xbox2pc::rt::loader::decode_relocations(
        image, data, size, xbox2pc::rt::loader::kMaxRelocEntries);
    if (!directory_pair_valid(xbox2pc::pe::kDirReloc)) {
        // The directory-pair failure above is authoritative; do not reinterpret
        // the zero-sized directory as a valid empty relocation table.
    } else if (!relocation_blocks.ok()) {
        relocations.status = StageStatus::Failed;
        relocations.findings.push_back(relocation_blocks.error_string());
    } else {
        std::uint64_t entries = 0;
        for (const auto& block : relocation_blocks.value()) {
            entries += block.entries.size();
        }
        relocations.findings.push_back(
            std::to_string(relocation_blocks.value().size()) +
            " relocation block(s), " + std::to_string(entries) +
            " entry/entries decoded; no relocations applied");
    }
    report.stages.push_back(std::move(relocations));

    Stage tls = make_stage(
        "tls", StageStatus::Passed,
        "TLS metadata decoded; callbacks are never executed by validation");
    xbox2pc::rt::loader::LoadDiagnostics tls_diagnostics;
    if (!directory_pair_valid(xbox2pc::pe::kDirTls)) {
        tls.status = StageStatus::Failed;
        tls.findings.push_back("TLS directory has an inconsistent RVA/size pair");
    }
    const auto tls_info = xbox2pc::rt::loader::decode_tls(
        image, data, size, tls_diagnostics);
    if (!directory_pair_valid(xbox2pc::pe::kDirTls)) {
        // Do not reinterpret a malformed zero-sized directory as absent TLS.
    } else if (!tls_info.ok()) {
        tls.status = StageStatus::Failed;
        tls.findings.push_back(tls_info.error_string());
    } else if (!tls_info.value().has_value()) {
        tls.findings.push_back("no TLS directory");
    } else {
        tls.findings.push_back(
            std::to_string(tls_info.value()->callback_count) +
            " TLS callback(s) validated; execution not tested");
        tls.findings.push_back(
            "TLS template size " +
            std::to_string(tls_info.value()->template_size) + " bytes");
    }
    report.stages.push_back(std::move(tls));

    report.stages.push_back(make_stage(
        "memory-layout", StageStatus::NotTested,
        "no guest address space is created; W^X is statically reported only"));

    return report;
}

}  // namespace xbox2pc::validation
