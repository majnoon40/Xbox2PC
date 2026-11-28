// xbox2pc/src/census.cpp — `xbox2pc census` (see include/xbox2pc/census.hpp).

#include "xbox2pc/census.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <utility>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/json_reader.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace xbox2pc::census {
namespace {

namespace fs = std::filesystem;
using xbox2pc::json::Json;

bool ends_with_ci(const std::string& text, const char* suffix) {
    const std::size_t n = std::strlen(suffix);
    if (text.size() < n) return false;
    for (std::size_t i = 0; i < n; ++i) {
        if (std::tolower(static_cast<unsigned char>(text[text.size() - n + i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i]))) return false;
    }
    return true;
}

bool looks_like_pe(const fs::path& path) {
    if (ends_with_ci(path.filename().string(), ".exe") ||
        ends_with_ci(path.filename().string(), ".dll") ||
        ends_with_ci(path.filename().string(), ".sys")) return true;
    std::ifstream in(path, std::ios::binary);
    char magic[2] = {0, 0};
    in.read(magic, 2);
    return in.gcount() == 2 && magic[0] == 'M' && magic[1] == 'Z';
}

std::vector<std::string> collect(const std::vector<std::string>& paths) {
    std::vector<std::string> files;
    for (const auto& given : paths) {
        std::error_code ec;
        const fs::path path(given);
        if (fs::is_directory(path, ec)) {
            std::vector<fs::path> entries;
            for (const auto& entry : fs::directory_iterator(path, ec)) {
                if (entry.is_regular_file(ec) && looks_like_pe(entry.path()))
                    entries.push_back(entry.path());
            }
            std::sort(entries.begin(), entries.end());
            for (auto& entry : entries) files.push_back(entry.string());
        } else if (fs::is_regular_file(path, ec)) {
            files.push_back(path.string());
        }
    }
    return files;
}

Status classify(const rt::api::ApiDescriptor* d) {
    if (d == nullptr) return Status::Missing;
    switch (d->compat) {
        case rt::api::ApiStatus::NativeEquivalent:
        case rt::api::ApiStatus::FullyImplemented:
            return Status::Implemented;
        case rt::api::ApiStatus::PartiallyImplemented:
            return Status::Partial;
        case rt::api::ApiStatus::Stubbed:
            return Status::Stubbed;
        case rt::api::ApiStatus::Unsupported:
            return Status::Unsupported;
        case rt::api::ApiStatus::Unknown:
            return Status::Missing;
    }
    return Status::Missing;
}

std::string normalized_key(const std::string& dll, const std::string& name) {
    return registry::normalize_module_name(dll) + "!" + name;
}

// "kernel32.dll!ExitProcess" (a run report's first_unimplemented) -> key.
std::string key_from_identity(const std::string& identity) {
    const auto bang = identity.find('!');
    if (bang == std::string::npos) return {};
    return normalized_key(identity.substr(0, bang), identity.substr(bang + 1));
}

struct Aggregated {
    Import row;
    std::map<std::string, bool> importers;
};

}  // namespace

const char* status_name(Status s) {
    switch (s) {
        case Status::Implemented: return "implemented";
        case Status::Partial: return "partial";
        case Status::Stubbed: return "stubbed";
        case Status::Unsupported: return "unsupported";
        case Status::Missing: return "missing";
    }
    return "?";
}

Report run(const std::vector<std::string>& paths, const Options& options) {
    Report report;
    rt::api::ApiRegistry reg;
    std::map<std::string, Aggregated> rows;

    for (const auto& file : collect(paths)) {
        File entry;
        entry.path = file;
        std::ifstream in(file, std::ios::binary);
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                         std::istreambuf_iterator<char>());
        diag::Diagnostics diags;
        try {
            const auto img = pe::parse(bytes.data(), bytes.size(), fs::path(file).filename().string(), diags);
            if (diags.has_errors()) {
                entry.error = "parse diagnostics reported errors";
            } else {
                entry.parsed = true;
                for (const auto& dll : img.imports.entries) {
                    for (const auto& name : dll.functions) {
                        const std::string key = normalized_key(dll.dll_name, name);
                        auto& row = rows[key];
                        row.row.dll = registry::normalize_module_name(dll.dll_name);
                        row.row.name = name;
                        const rt::api::ApiDescriptor* d = reg.find(dll.dll_name, name);
                        if (row.row.descriptor_status.empty()) {
                            row.row.status = classify(d);
                            row.row.descriptor_status = d ? rt::api::api_status_to_name(d->compat) : "none";
                            row.row.implementation = d ? rt::api::api_status_to_name(d->impl) : "none";
                        }
                        row.importers[fs::path(file).filename().string()] = true;
                        ++entry.imports;
                        if (row.row.status != Status::Implemented) ++entry.not_implemented;
                    }
                    for (const std::uint32_t ordinal : dll.ordinal_only) {
                        const std::string name = "#" + std::to_string(ordinal);
                        const std::string key = normalized_key(dll.dll_name, name);
                        auto& row = rows[key];
                        row.row.dll = registry::normalize_module_name(dll.dll_name);
                        row.row.name = name;
                        const rt::api::ApiDescriptor* d = reg.find_ordinal(dll.dll_name, ordinal);
                        if (row.row.descriptor_status.empty()) {
                            row.row.status = classify(d);
                            row.row.descriptor_status = d ? rt::api::api_status_to_name(d->compat) : "none";
                            row.row.implementation = d ? rt::api::api_status_to_name(d->impl) : "none";
                        }
                        row.importers[fs::path(file).filename().string()] = true;
                        ++entry.imports;
                        if (row.row.status != Status::Implemented) ++entry.not_implemented;
                    }
                }
            }
        } catch (const pe::ParseError& error) {
            entry.error = error.what();
        }
        if (entry.parsed) ++report.parsed_files;
        report.files.push_back(std::move(entry));
    }

    // First reach: each run report names the first unimplemented import the
    // guest called; the reports are given in reach order.
    int rank = 0;
    for (const auto& trace : options.traces) {
        std::ifstream in(trace, std::ios::binary);
        if (!in.good()) {
            if (report.trace_error.empty()) report.trace_error = "cannot open " + trace;
            continue;
        }
        std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            const Json report_json = json::parse(text);
            const Json* first = report_json.find("first_unimplemented");
            if (first == nullptr || !first->is_string()) continue;
            const std::string key = key_from_identity(first->as_string());
            if (key.empty()) continue;
            auto it = rows.find(key);
            if (it == rows.end()) {
                // An import the static pass has not seen: record it so the
                // reach order stays complete.
                auto& row = rows[key];
                row.row.dll = key.substr(0, key.find('!'));
                row.row.name = key.substr(key.find('!') + 1);
                row.row.status = Status::Missing;
                row.row.descriptor_status = "none";
                row.row.implementation = "none";
                it = rows.find(key);
            }
            if (it->second.row.reach_rank == 0) it->second.row.reach_rank = ++rank;
        } catch (const json::JsonParseError& error) {
            if (report.trace_error.empty()) report.trace_error = trace + ": " + error.what();
        }
    }
    report.reached = static_cast<std::uint32_t>(rank);

    for (auto& [key, aggregated] : rows) {
        (void)key;
        aggregated.row.files = static_cast<std::uint32_t>(aggregated.importers.size());
        for (const auto& [name, seen] : aggregated.importers) {
            (void)seen;
            aggregated.row.importers.push_back(name);
        }
        report.imports.push_back(std::move(aggregated.row));
    }
    std::sort(report.imports.begin(), report.imports.end(), [](const Import& a, const Import& b) {
        const bool a_reached = a.reach_rank != 0;
        const bool b_reached = b.reach_rank != 0;
        if (a_reached != b_reached) return a_reached;
        if (a_reached && a.reach_rank != b.reach_rank) return a.reach_rank < b.reach_rank;
        if (a.files != b.files) return a.files > b.files;
        if (a.dll != b.dll) return a.dll < b.dll;
        return a.name < b.name;
    });
    if (options.missing_only) {
        report.imports.erase(std::remove_if(report.imports.begin(), report.imports.end(),
                                            [](const Import& row) { return row.status == Status::Implemented; }),
                             report.imports.end());
    }
    return report;
}

Json to_json(const Report& report, const Options& options) {
    (void)options;
    Json j = Json::object();
    Json files = Json::array();
    for (const auto& file : report.files) {
        Json f = Json::object();
        f.set("path", file.path);
        f.set("parsed", file.parsed);
        f.set("error", file.error);
        f.set("imports", file.imports);
        f.set("not_implemented", file.not_implemented);
        files.push_back(std::move(f));
    }
    j.set("files", std::move(files));
    Json imports = Json::array();
    std::uint32_t by_status[5] = {0, 0, 0, 0, 0};
    for (const auto& row : report.imports) {
        ++by_status[static_cast<std::size_t>(row.status)];
        Json r = Json::object();
        r.set("dll", row.dll);
        r.set("name", row.name);
        r.set("status", status_name(row.status));
        r.set("descriptor_status", row.descriptor_status);
        r.set("implementation", row.implementation);
        r.set("files", row.files);
        r.set("reach_rank", row.reach_rank);
        Json importers = Json::array();
        for (const auto& name : row.importers) importers.push_back(Json(name));
        r.set("importers", std::move(importers));
        imports.push_back(std::move(r));
    }
    j.set("imports", std::move(imports));
    Json summary = Json::object();
    summary.set("files", static_cast<std::uint64_t>(report.files.size()));
    summary.set("parsed_files", report.parsed_files);
    summary.set("imports", static_cast<std::uint64_t>(report.imports.size()));
    Json status_counts = Json::object();
    for (std::size_t s = 0; s < 5; ++s)
        status_counts.set(status_name(static_cast<Status>(s)), by_status[s]);
    summary.set("imports_by_status", std::move(status_counts));
    j.set("summary", std::move(summary));
    j.set("reached", report.reached);
    j.set("trace_error", report.trace_error);
    return j;
}

std::string to_text(const Report& report, const Options& options) {
    std::string out;
    out += "xbox2pc census: " + std::to_string(report.parsed_files) + " of " +
           std::to_string(report.files.size()) + " file(s) parsed, " +
           std::to_string(report.imports.size()) + " distinct import(s)";
    if (report.reached != 0) out += ", " + std::to_string(report.reached) + " ranked by first reach";
    out += "\n";
    if (!report.trace_error.empty()) out += "trace error: " + report.trace_error + "\n";
    for (const auto& file : report.files) {
        if (!file.parsed) out += "  (unparsed) " + file.path + ": " + file.error + "\n";
    }
    out += "\nSTATUS        FILES  REACH  IMPORT\n";
    for (const auto& row : report.imports) {
        const std::string status = status_name(row.status);
        const std::string reach = row.reach_rank ? std::to_string(row.reach_rank) : "-";
        out += status + std::string(status.size() < 13 ? 13 - status.size() : 1, ' ') +
               std::to_string(row.files) + "\t" + reach + "\t" + row.dll + "!" + row.name + "\n";
    }
    out += "\nWeekly triage (top " + std::to_string(options.triage) + " imports not yet implemented)\n";
    out += "| rank | import | status | files | first reach |\n";
    out += "| --- | --- | --- | --- | --- |\n";
    std::uint32_t shown = 0;
    for (const auto& row : report.imports) {
        if (row.status == Status::Implemented) continue;
        if (shown >= options.triage) break;
        ++shown;
        out += "| " + std::to_string(shown) + " | " + row.dll + "!" + row.name + " | " +
               status_name(row.status) + " | " + std::to_string(row.files) + " | " +
               (row.reach_rank ? std::to_string(row.reach_rank) : "-") + " |\n";
    }
    if (shown == 0) out += "| - | every import implemented | - | - | - |\n";
    return out;
}

int cli(int argc, char** argv) {
    const char* const usage =
        "usage: xbox2pc census <dir-or-file>... [--missing] [--trace <run.json>]...\n"
        "                                [--triage N] [--json <out>]\n"
        "  Reports, per imported dll!name, whether the registry implements it.\n"
        "  --trace   an `xbox2pc run --json` report; its first_unimplemented is the\n"
        "            first import the guest reached. Give several in reach order.\n"
        "  --missing keep only imports that are not implemented\n"
        "  --triage  rows in the weekly-triage block (default 10)\n"
        "  exit: 0 ran, 1 nothing parsed or a trace unreadable, 2 usage\n";
    if (argc < 3) {
        std::fprintf(stderr, "%s", usage);
        return 2;
    }
    Options options;
    std::vector<std::string> paths;
    std::optional<std::string> json_out;
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc) json_out = argv[++i];
        else if (std::strcmp(argv[i], "--trace") == 0 && i + 1 < argc) options.traces.push_back(argv[++i]);
        else if (std::strcmp(argv[i], "--missing") == 0) options.missing_only = true;
        else if (std::strcmp(argv[i], "--triage") == 0 && i + 1 < argc) {
            const long n = std::strtol(argv[++i], nullptr, 10);
            if (n < 0 || n > 1000) { std::fprintf(stderr, "error: --triage out of range\n"); return 2; }
            options.triage = static_cast<std::uint32_t>(n);
        } else if (std::strncmp(argv[i], "--", 2) == 0) {
            std::fprintf(stderr, "error: unknown census option '%s'\n%s", argv[i], usage);
            return 2;
        } else {
            paths.push_back(argv[i]);
        }
    }
    if (paths.empty()) {
        std::fprintf(stderr, "%s", usage);
        return 2;
    }
    const Report report = run(paths, options);
    if (json_out.has_value()) {
        std::ofstream out(*json_out, std::ios::binary | std::ios::trunc);
        if (!out) { std::fprintf(stderr, "error: cannot write %s\n", json_out->c_str()); return 1; }
        out << to_json(report, options).serialize() << "\n";
        std::printf("wrote %s\n", json_out->c_str());
    } else {
        std::fputs(to_text(report, options).c_str(), stdout);
    }
    if (report.parsed_files == 0) {
        std::fprintf(stderr, "error: no PE could be parsed under the given paths\n");
        return 1;
    }
    if (!report.trace_error.empty()) return 1;
    return 0;
}

}  // namespace xbox2pc::census
