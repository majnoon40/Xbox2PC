#pragma once
// xbox2pc/report_cli.hpp — `xbox2pc report`: aggregates crashes.log (M12 P0.4).
//
// crashes.log is written by `xbox2pc run` when XBOX2PC_CRASH_SAVE names a
// directory: one JSON object per run that executed and did not return
// normally. The report aggregates every record of a log into faults by site,
// unimplemented-import call counts and an API-trace histogram.

#include <cstdint>
#include <string>
#include <map>

#include "xbox2pc/json_writer.hpp"

namespace xbox2pc::report {

struct Aggregates {
    std::uint32_t runs = 0;
    std::uint32_t returned = 0;
    std::uint32_t faulted = 0;
    std::uint32_t other = 0;
    std::uint32_t malformed = 0;
    std::map<std::string, std::uint32_t> faults_by_site;        // "<fault> @ <site>" -> runs
    std::map<std::string, std::uint32_t> unimplemented_imports;  // "dll!name" -> calls
    std::map<std::string, std::uint32_t> api_histogram;          // "dll!name" -> calls
};

// Reads one JSON object per line. Blank lines are skipped; a line that does
// not parse counts as malformed and is skipped. False when the file cannot
// be opened (error says why).
bool aggregate_file(const std::string& path, Aggregates& out, std::string& error);

json::Json to_json(const Aggregates& aggregates);
std::string to_text(const Aggregates& aggregates);

// `xbox2pc report <crashes.log> [--json <out>]`
// Exit status: 0 when the log was read (even if empty); 1 when it could not
// be opened; 2 for a usage error.
int cli(int argc, char** argv);

}  // namespace xbox2pc::report
