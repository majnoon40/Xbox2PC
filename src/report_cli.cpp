// xbox2pc/src/report_cli.cpp — `xbox2pc report` (see include/xbox2pc/report_cli.hpp).

#include "xbox2pc/report_cli.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <utility>
#include <vector>

#include "xbox2pc/json_reader.hpp"

namespace xbox2pc::report {
namespace {

using xbox2pc::json::Json;

std::string site_of(const Json& record) {
    const Json* fault = record.find("fault");
    const Json* rva = record.find("rva");
    const Json* rip = record.find("rip");
    const std::string fault_name = fault != nullptr && fault->is_string() ? fault->as_string() : "unknown";
    if (rva != nullptr && rva->is_number()) {
        char buffer[32];
        std::snprintf(buffer, sizeof buffer, "%llx",
                      static_cast<unsigned long long>(rva->as_int()));
        return fault_name + " @ module+0x" + buffer;
    }
    if (rip != nullptr && rip->is_number()) {
        char buffer[32];
        std::snprintf(buffer, sizeof buffer, "%llx",
                      static_cast<unsigned long long>(rip->as_int()));
        return fault_name + " @ rip 0x" + buffer;
    }
    return fault_name + " @ ?";
}

void count(std::map<std::string, std::uint32_t>& table, const std::string& key,
           std::uint32_t by = 1) {
    if (key.empty()) return;
    table[key] += by;
}

std::vector<std::pair<std::string, std::uint32_t>> sorted_desc(
    const std::map<std::string, std::uint32_t>& table) {
    std::vector<std::pair<std::string, std::uint32_t>> rows(table.begin(), table.end());
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    return rows;
}

Json table_json(const std::map<std::string, std::uint32_t>& table) {
    Json j = Json::object();
    for (const auto& [key, value] : sorted_desc(table)) j.set(key, value);
    return j;
}

}  // namespace

bool aggregate_file(const std::string& path, Aggregates& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        error = "cannot open " + path;
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
        Json record;
        try {
            record = json::parse(line);
        } catch (const json::JsonParseError&) {
            ++out.malformed;
            continue;
        }
        if (!record.is_object()) { ++out.malformed; continue; }
        ++out.runs;
        const Json* outcome = record.find("outcome");
        const std::string outcome_name = outcome != nullptr && outcome->is_string()
            ? outcome->as_string() : std::string();
        if (outcome_name == "returned") ++out.returned;
        else if (outcome_name == "faulted") ++out.faulted;
        else ++out.other;
        if (record.find("fault") != nullptr) count(out.faults_by_site, site_of(record));
        const Json* first = record.find("first_unimplemented");
        const Json* unimplemented = record.find("unimplemented_calls");
        if (first != nullptr && first->is_string() && unimplemented != nullptr &&
            unimplemented->is_number()) {
            count(out.unimplemented_imports, first->as_string(),
                  static_cast<std::uint32_t>(unimplemented->as_int()));
        }
        const Json* trace = record.find("api_trace");
        if (trace != nullptr && trace->is_array()) {
            for (std::size_t i = 0; i < trace->size(); ++i) {
                if (trace->at(i).is_string()) count(out.api_histogram, trace->at(i).as_string());
            }
        }
    }
    return true;
}

json::Json to_json(const Aggregates& a) {
    Json j = Json::object();
    j.set("runs", a.runs);
    j.set("returned", a.returned);
    j.set("faulted", a.faulted);
    j.set("other", a.other);
    j.set("malformed", a.malformed);
    j.set("faults_by_site", table_json(a.faults_by_site));
    j.set("unimplemented_imports", table_json(a.unimplemented_imports));
    j.set("api_histogram", table_json(a.api_histogram));
    return j;
}

std::string to_text(const Aggregates& a) {
    std::string out;
    out += "xbox2pc report: " + std::to_string(a.runs) + " run(s): " +
           std::to_string(a.returned) + " returned, " + std::to_string(a.faulted) +
           " faulted, " + std::to_string(a.other) + " other";
    if (a.malformed != 0) out += ", " + std::to_string(a.malformed) + " malformed line(s) skipped";
    out += "\n\nFaults by site\n  runs  site\n";
    for (const auto& [site, runs] : sorted_desc(a.faults_by_site))
        out += "  " + std::to_string(runs) + "\t" + site + "\n";
    if (a.faults_by_site.empty()) out += "  -\n";
    out += "\nUnimplemented imports reached\n  calls  import\n";
    for (const auto& [identity, calls] : sorted_desc(a.unimplemented_imports))
        out += "  " + std::to_string(calls) + "\t" + identity + "\n";
    if (a.unimplemented_imports.empty()) out += "  -\n";
    out += "\nAPI trace histogram (top 20)\n  calls  import\n";
    std::uint32_t shown = 0;
    for (const auto& [identity, calls] : sorted_desc(a.api_histogram)) {
        if (shown++ >= 20) break;
        out += "  " + std::to_string(calls) + "\t" + identity + "\n";
    }
    if (a.api_histogram.empty()) out += "  -\n";
    return out;
}

int cli(int argc, char** argv) {
    const char* const usage =
        "usage: xbox2pc report <crashes.log> [--json <out>]\n"
        "  Aggregates the crash records written by `xbox2pc run` under\n"
        "  XBOX2PC_CRASH_SAVE: faults by site, unimplemented-import call counts,\n"
        "  and the API trace histogram.\n"
        "  exit: 0 read, 1 cannot open, 2 usage\n";
    if (argc < 3 || argc > 5) {
        std::fprintf(stderr, "%s", usage);
        return 2;
    }
    std::optional<std::string> json_out;
    if (argc == 5) {
        if (std::strcmp(argv[3], "--json") != 0) { std::fprintf(stderr, "%s", usage); return 2; }
        json_out = argv[4];
    } else if (argc == 4) {
        std::fprintf(stderr, "%s", usage);
        return 2;
    }
    Aggregates aggregates;
    std::string error;
    if (!aggregate_file(argv[2], aggregates, error)) {
        std::fprintf(stderr, "error: %s\n", error.c_str());
        return 1;
    }
    if (json_out.has_value()) {
        std::ofstream out(*json_out, std::ios::binary | std::ios::trunc);
        if (!out) { std::fprintf(stderr, "error: cannot write %s\n", json_out->c_str()); return 1; }
        out << to_json(aggregates).serialize() << "\n";
        std::printf("wrote %s\n", json_out->c_str());
    } else {
        std::fputs(to_text(aggregates).c_str(), stdout);
    }
    return 0;
}

}  // namespace xbox2pc::report
