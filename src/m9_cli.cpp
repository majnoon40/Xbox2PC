#include "xbox2pc/m9_cli.hpp"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "xbox2pc/binary_validation.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/json_writer.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/static_analysis.hpp"
#include "xbox2pc/x64_decoder.hpp"

namespace xbox2pc::cli {
namespace {

using xbox2pc::json::Json;

std::optional<std::vector<std::uint8_t>> read_binary(const std::string& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) return std::nullopt;
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > (512ull << 20)) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    input.seekg(0, std::ios::beg);
    if (!bytes.empty() &&
        !input.read(reinterpret_cast<char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()))) {
        return std::nullopt;
    }
    return bytes;
}

bool write_json(const std::optional<std::string>& output, const Json& value) {
    const std::string serialized = value.serialize() + "\n";
    if (!output.has_value()) {
        std::fwrite(serialized.data(), 1, serialized.size(), stdout);
        return true;
    }
    std::ofstream file(*output, std::ios::binary | std::ios::trunc);
    if (!file) return false;
    file.write(serialized.data(), static_cast<std::streamsize>(serialized.size()));
    return file.good();
}

Json strings(const std::vector<std::string>& values) {
    Json out = Json::array();
    for (const auto& value : values) out.push_back(value);
    return out;
}

Json stage_json(const xbox2pc::validation::Stage& stage) {
    Json out = Json::object();
    out.set("name", stage.name);
    out.set("status", xbox2pc::validation::status_name(stage.status));
    out.set("findings", strings(stage.findings));
    return out;
}

Json validation_json(const xbox2pc::validation::BinaryReport& report) {
    Json out = Json::object();
    out.set("source", report.source);
    out.set("file_size", report.file_size);
    out.set("parsed", report.parsed);
    out.set("pe32_plus_amd64", report.is_pe32_plus_amd64);
    out.set("structurally_valid", report.structurally_valid());
    Json stages = Json::array();
    for (const auto& stage : report.stages) stages.push_back(stage_json(stage));
    out.set("stages", std::move(stages));
    return out;
}

Json analysis_json(const xbox2pc::analysis::AnalysisReport& report) {
    Json out = Json::object();
    out.set("source", report.source);
    out.set("parsed", report.parsed);
    out.set("pe32_plus_amd64", report.is_pe32_plus_amd64);
    Json instructions = Json::array();
    for (const auto& item : report.confirmed_instructions) {
        Json row = Json::object();
        row.set("section", item.section);
        row.set("rva", item.rva);
        row.set("file_offset", item.file_offset);
        row.set("length", static_cast<std::uint64_t>(item.length));
        row.set("bytes", item.bytes_hex);
        row.set("instruction", item.text);
        row.set("interpreter_supported", item.interpreter_supported);
        instructions.push_back(std::move(row));
    }
    out.set("confirmed_instructions", std::move(instructions));

    auto regions = [](const std::vector<xbox2pc::analysis::Region>& input) {
        Json result = Json::array();
        for (const auto& item : input) {
            Json row = Json::object();
            row.set("section", item.section);
            row.set("rva", item.rva);
            row.set("file_offset", item.file_offset);
            row.set("size", item.size);
            row.set("reason", item.reason);
            result.push_back(std::move(row));
        }
        return result;
    };
    out.set("candidate_embedded_data", regions(report.candidate_embedded_data));
    out.set("unsupported_instructions", regions(report.unsupported_instructions));
    out.set("unsupported_execution", regions(report.unsupported_execution));
    out.set("uncertain_regions", regions(report.uncertain_regions));

    Json segments = Json::array();
    for (const auto& item : report.fs_gs_uses) {
        Json row = Json::object();
        row.set("section", item.section);
        row.set("rva", item.rva);
        row.set("segment", item.segment);
        row.set("instruction", item.instruction);
        segments.push_back(std::move(row));
    }
    out.set("fs_gs_uses", std::move(segments));
    out.set("notes", strings(report.notes));
    out.set("analysis_model", "linear heuristic scan; no complete CFG recovery");
    return out;
}

Json directory_json(const xbox2pc::pe::PeImage& image, std::uint16_t index) {
    Json out = Json::object();
    if (index >= image.directories.size()) {
        out.set("present", false);
        out.set("status", "NOT_TESTED");
        out.set("note", "directory entry is absent from the optional header");
        return out;
    }
    const auto& directory = image.directories[index];
    const bool present = directory.rva != 0 || directory.size != 0;
    out.set("name", directory.name);
    out.set("present", present);
    out.set("rva", directory.rva);
    out.set("size", directory.size);
    out.set("status", "NOT_TESTED");
    out.set("note", "directory-specific semantic validation/application is not implemented");
    return out;
}

Json sections_json(const xbox2pc::pe::PeImage& image) {
    Json out = Json::array();
    for (const auto& section : image.sections) {
        Json row = Json::object();
        row.set("name", section.name);
        row.set("virtual_address", section.virtual_address);
        row.set("virtual_size", section.virtual_size);
        row.set("raw_offset", section.raw_data_offset);
        row.set("raw_size", section.size_of_raw_data);
        row.set("has_raw_data", section.has_raw_data);
        row.set("readable", (section.characteristics & xbox2pc::pe::sect_flags::kReadable) != 0);
        row.set("writable", (section.characteristics & xbox2pc::pe::sect_flags::kWritable) != 0);
        row.set("executable", (section.characteristics & xbox2pc::pe::sect_flags::kExecutable) != 0);
        out.push_back(std::move(row));
    }
    return out;
}

Json imports_json(const xbox2pc::pe::PeImage& image) {
    Json out = Json::object();
    out.set("regular_import_directory_present", image.imports.present);
    Json regular = Json::array();
    for (const auto& entry : image.imports.entries) {
        Json row = Json::object();
        row.set("dll", entry.dll_name);
        row.set("int_rva", entry.int_rva);
        row.set("iat_rva", entry.iat_rva);
        row.set("bound", entry.bound);
        Json functions = Json::array();
        for (const auto& function : entry.functions) functions.push_back(function);
        row.set("functions", std::move(functions));
        Json ordinals = Json::array();
        for (const auto ordinal : entry.ordinal_only) ordinals.push_back(ordinal);
        row.set("ordinals", std::move(ordinals));
        regular.push_back(std::move(row));
    }
    out.set("regular_imports", std::move(regular));
    out.set("delay_import_directory_present", image.delay_imports.present);
    Json delay = Json::array();
    for (const auto& entry : image.delay_imports.entries) {
        Json row = Json::object();
        row.set("dll", entry.dll_name);
        row.set("va_addressed", entry.va_addressed);
        Json functions = Json::array();
        for (const auto& function : entry.functions) functions.push_back(function);
        row.set("functions", std::move(functions));
        Json ordinals = Json::array();
        for (const auto ordinal : entry.ordinal_only) ordinals.push_back(ordinal);
        row.set("ordinals", std::move(ordinals));
        delay.push_back(std::move(row));
    }
    out.set("delay_imports", std::move(delay));
    out.set("resolution_status", "NOT_TESTED");
    return out;
}

Json binary_info_json(const xbox2pc::pe::PeImage& image,
                      const std::vector<std::uint8_t>& bytes) {
    Json out = Json::object();
    out.set("source", image.source_name);
    out.set("file_size", static_cast<std::uint64_t>(bytes.size()));
    out.set("machine", image.machine_name());
    out.set("machine_code", image.coff.machine);
    out.set("pe_format", image.opt.is_pe32plus ? "PE32+" :
                         image.opt.is_pe32 ? "PE32" : "unknown");
    out.set("pe32_plus_amd64",
            image.opt.is_pe32plus && image.coff.machine == xbox2pc::pe::kMachineAmd64);
    out.set("subsystem", image.subsystem_name());
    out.set("entry_point_rva", image.opt.address_of_entry_point);
    out.set("image_base", image.opt.image_base);
    out.set("size_of_image", image.opt.size_of_image);
    out.set("section_count", static_cast<std::uint64_t>(image.sections.size()));
    return out;
}

Json compatibility_json(const xbox2pc::pe::PeImage& image,
                        const std::vector<std::uint8_t>& bytes,
                        const xbox2pc::validation::BinaryReport& validation,
                        const xbox2pc::analysis::AnalysisReport& analysis) {
    Json out = Json::object();
    out.set("schema", "xbox2pc.binary-compatibility");
    out.set("schema_version", 1);
    out.set("source", image.source_name);
    out.set("file_size", static_cast<std::uint64_t>(bytes.size()));

    Json architecture = Json::object();
    const bool amd64 = image.opt.is_pe32plus &&
        image.coff.machine == xbox2pc::pe::kMachineAmd64;
    architecture.set("status", amd64 ? "SUPPORTED" : "UNSUPPORTED");
    architecture.set("machine", image.machine_name());
    architecture.set("pe32_plus", image.opt.is_pe32plus);
    out.set("architecture", std::move(architecture));

    Json platform = Json::object();
    platform.set("status", "UNKNOWN");
    platform.set("evidence", "No Xbox target-platform provenance has been established by these checks.");
    out.set("xbox_platform", std::move(platform));

    Json import_status = Json::object();
    import_status.set("status", "UNKNOWN");
    import_status.set("regular_descriptor_count",
                      static_cast<std::uint64_t>(image.imports.entries.size()));
    import_status.set("delay_descriptor_count",
                      static_cast<std::uint64_t>(image.delay_imports.entries.size()));
    import_status.set("resolution", "NOT_TESTED");
    out.set("imports", std::move(import_status));

    auto checked_directory = [&](std::uint16_t index, std::size_t stage_index,
                                  const char* unperformed_operation) {
        Json directory = directory_json(image, index);
        const bool present = index < image.directories.size() &&
            (image.directories[index].rva != 0 || image.directories[index].size != 0);
        const char* status = "NOT_TESTED";
        if (present && stage_index < validation.stages.size()) {
            switch (validation.stages[stage_index].status) {
                case xbox2pc::validation::StageStatus::Passed: status = "SUPPORTED"; break;
                case xbox2pc::validation::StageStatus::Warning: status = "PARTIALLY_SUPPORTED"; break;
                case xbox2pc::validation::StageStatus::Failed: status = "INVALID"; break;
                case xbox2pc::validation::StageStatus::NotTested: status = "NOT_TESTED"; break;
            }
        }
        directory.set("status", status);
        directory.set("unperformed_operation", unperformed_operation);
        return directory;
    };
    out.set("relocations", checked_directory(
        xbox2pc::pe::kDirReloc, 3, "base relocation application"));
    out.set("tls", checked_directory(
        xbox2pc::pe::kDirTls, 4, "TLS callback execution"));
    out.set("exception_metadata", directory_json(image, xbox2pc::pe::kDirException));

    Json instructions = Json::object();
    const bool has_unsupported = !analysis.unsupported_instructions.empty() ||
        !analysis.unsupported_execution.empty();
    const bool has_uncertain = !analysis.uncertain_regions.empty();
    const char* instruction_status = !analysis.parsed ? "NOT_TESTED" :
        (!amd64 ? "NOT_TESTED" :
         (has_unsupported ? "PARTIALLY_SUPPORTED" : "UNKNOWN"));
    instructions.set("status", instruction_status);
    instructions.set("confirmed_decode_count",
                     static_cast<std::uint64_t>(analysis.confirmed_instructions.size()));
    instructions.set("unsupported_region_count",
                     static_cast<std::uint64_t>(analysis.unsupported_instructions.size()));
    instructions.set("interpreter_unsupported_count",
                     static_cast<std::uint64_t>(analysis.unsupported_execution.size()));
    instructions.set("uncertain_region_count",
                     static_cast<std::uint64_t>(analysis.uncertain_regions.size()));
    instructions.set("embedded_data_candidates",
                     static_cast<std::uint64_t>(analysis.candidate_embedded_data.size()));
    instructions.set("model", "linear heuristic decode; not reachability or CFG proof");
    instructions.set("limitations", strings(analysis.notes));
    if (!has_unsupported && !has_uncertain) {
        instructions.set("status_note", "No unsupported encoding was observed in scanned bytes; completeness is not established.");
    }
    out.set("instruction_support", std::move(instructions));

    Json execution = Json::object();
    execution.set("status", "NOT_TESTED");
    execution.set("note", "Static inspection does not execute this image.");
    out.set("execution", std::move(execution));

    Json summary = Json::object();
    summary.set("status", "UNKNOWN");
    summary.set("note", "No overall Xbox compatibility verdict is inferred from partial static evidence.");
    summary.set("structural_validation_passed", validation.structurally_valid());
    out.set("overall", std::move(summary));

    Json limitations = Json::array();
    for (const char* item : {
        "No Xbox-specific platform provenance verified",
        "Import resolution and runtime API behavior not tested",
        "Relocation application not tested",
        "TLS callback validation or execution not tested",
        "Static instruction scan is linear and does not recover a complete control-flow graph",
        "No real Xbox executable has been tested"
    }) limitations.push_back(item);
    out.set("limitations", std::move(limitations));
    return out;
}

}  // namespace

int run_m9_binary_cli(int argc, char** argv) {
    if (argc < 2) return -1;
    const std::string command = argv[1];
    const std::vector<std::string> commands = {
        "binary-analyze", "binary-info", "binary-sections", "binary-imports",
        "binary-relocations", "binary-tls", "binary-instructions",
        "binary-compat", "binary-report"
    };
    bool recognized = false;
    for (const auto& candidate : commands) {
        if (candidate == command) { recognized = true; break; }
    }
    if (!recognized) return -1;

    std::string path;
    std::optional<std::string> json_path;
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: --json requires an output path\n");
                return 2;
            }
            json_path = argv[++i];
        } else if (path.empty()) {
            path = argv[i];
        } else {
            std::fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
            return 2;
        }
    }
    if (path.empty()) {
        std::fprintf(stderr, "error: %s requires a PE file\n", command.c_str());
        return 2;
    }

    auto bytes = read_binary(path);
    if (!bytes) {
        std::fprintf(stderr, "error: cannot read '%s' (missing, unreadable, or over 512 MiB)\n",
                     path.c_str());
        return 1;
    }
    xbox2pc::diag::Diagnostics diagnostics;
    xbox2pc::pe::PeImage image;
    try {
        image = xbox2pc::pe::parse(bytes->data(), bytes->size(), path, diagnostics);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: PE parse failed: %s\n", error.what());
        return 1;
    }

    const auto validation =
        xbox2pc::validation::validate_pe(bytes->data(), bytes->size(), path);
    const auto analysis =
        xbox2pc::analysis::analyze_pe(bytes->data(), bytes->size(), path);

    Json result = Json::object();
    result.set("tool", "xbox2pc");
    result.set("command", command);
    if (command == "binary-info") {
        result = binary_info_json(image, *bytes);
    } else if (command == "binary-sections") {
        result = Json::object();
        result.set("source", path);
        result.set("sections", sections_json(image));
    } else if (command == "binary-imports") {
        result = imports_json(image);
    } else if (command == "binary-relocations") {
        result = Json::object();
        auto decoded = xbox2pc::rt::loader::decode_relocations(
            image, bytes->data(), bytes->size(),
            xbox2pc::rt::loader::kMaxRelocEntries);
        result.set("status", decoded.ok() ? "PASSED" : "FAILED");
        if (!decoded.ok()) {
            result.set("error", decoded.error_string());
        } else {
            Json blocks = Json::array();
            std::uint64_t entry_count = 0;
            for (const auto& block : decoded.value()) {
                Json row = Json::object();
                row.set("page_rva", block.page_rva);
                row.set("block_size", block.block_size);
                Json entries = Json::array();
                for (const auto& entry : block.entries) {
                    Json item = Json::object();
                    item.set("type", xbox2pc::rt::loader::reloc_type_to_name(entry.type));
                    item.set("page_rva", entry.page_rva);
                    item.set("target_rva", entry.target_rva);
                    entries.push_back(std::move(item));
                    ++entry_count;
                }
                row.set("entries", std::move(entries));
                blocks.push_back(std::move(row));
            }
            result.set("blocks", std::move(blocks));
            result.set("entry_count", entry_count);
            result.set("application", "NOT_TESTED");
        }
    } else if (command == "binary-tls") {
        result = Json::object();
        xbox2pc::rt::loader::LoadDiagnostics tls_diagnostics;
        auto decoded = xbox2pc::rt::loader::decode_tls(
            image, bytes->data(), bytes->size(), tls_diagnostics);
        result.set("status", decoded.ok() ? "PASSED" : "FAILED");
        if (!decoded.ok()) {
            result.set("error", decoded.error_string());
        } else if (!decoded.value().has_value()) {
            result.set("present", false);
        } else {
            const auto& tls = *decoded.value();
            result.set("present", true);
            result.set("template_rva", tls.template_rva);
            result.set("template_size", tls.template_size);
            result.set("zero_fill_size", tls.zero_fill_size);
            result.set("index_slot_rva", tls.index_slot_rva);
            result.set("callbacks_va", tls.callbacks_va);
            result.set("callback_count", tls.callback_count);
            result.set("callback_execution", "NOT_TESTED");
        }
    } else if (command == "binary-instructions") {
        result = analysis_json(analysis);
    } else if (command == "binary-compat") {
        result = compatibility_json(image, *bytes, validation, analysis);
    } else {
        result.set("binary_info", binary_info_json(image, *bytes));
        result.set("validation", validation_json(validation));
        result.set("instruction_analysis", analysis_json(analysis));
        result.set("compatibility", compatibility_json(image, *bytes, validation, analysis));
        Json diagnostics_json = Json::array();
        for (const auto& line : diagnostics.lines()) diagnostics_json.push_back(line);
        result.set("parser_diagnostics", std::move(diagnostics_json));
        if (command == "binary-analyze") {
            result.set("analysis_scope", "static inspection only; no mapping or execution");
        }
    }

    if (!write_json(json_path, result)) {
        std::fprintf(stderr, "error: cannot write JSON output\n");
        return 1;
    }
    return validation.structurally_valid() ? 0 : 1;
}

}  // namespace xbox2pc::cli
