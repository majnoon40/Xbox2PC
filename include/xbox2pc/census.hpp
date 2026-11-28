#pragma once
// xbox2pc/census.hpp — `xbox2pc census`: import coverage of a directory of
// PEs, ranked (M12 P0.3; plan section 3.3).
//
// Reads every PE under the given paths and reports, per imported
// dll!name, whether the registry implements it, partially implements it,
// stubs it, documents it as unsupported, or has no descriptor at all. Rows
// are ranked by first reach when run reports are given (--trace: each
// `xbox2pc run --json` report names the first unimplemented import the
// guest called), then by the number of files that import them.
//
// Used only on binaries we are allowed to use (docs/input-policy.md); the
// command inspects import tables, it executes nothing.

#include <cstdint>
#include <string>
#include <vector>

#include "xbox2pc/json_writer.hpp"

namespace xbox2pc::census {

enum class Status : std::uint8_t {
    Implemented = 0,   // documented behavior covered (native equivalent or fully implemented)
    Partial = 1,       // subset of the documented behavior
    Stubbed = 2,       // deterministic stub
    Unsupported = 3,   // documented as impossible here
    Missing = 4,       // no descriptor at all
};
const char* status_name(Status s);

struct Import {
    std::string dll;        // normalized module name (no .dll)
    std::string name;       // "#<ordinal>" for ordinal imports
    Status status = Status::Missing;
    std::string descriptor_status;   // registry compat status, verbatim
    std::string implementation;      // registry impl status, verbatim
    std::uint32_t files = 0;         // how many files import it
    std::vector<std::string> importers;   // file names, sorted
    int reach_rank = 0;              // 1-based when a trace reached it, else 0
};

struct File {
    std::string path;
    bool parsed = false;
    std::string error;
    std::uint32_t imports = 0;
    std::uint32_t not_implemented = 0;
};

struct Options {
    bool missing_only = false;            // keep only rows that are not Implemented
    std::vector<std::string> traces;      // run reports, in reach order
    std::uint32_t triage = 10;            // rows in the weekly-triage block
};

struct Report {
    std::vector<File> files;              // sorted by path
    std::vector<Import> imports;          // ranked
    std::uint32_t parsed_files = 0;
    std::uint32_t reached = 0;            // distinct imports ranked by the traces
    std::string trace_error;              // first unreadable or malformed trace, if any
};

// `paths` are files or directories (regular files with an .exe/.dll/.sys
// extension, or any file that starts with "MZ"). Nothing is executed.
Report run(const std::vector<std::string>& paths, const Options& options);
json::Json to_json(const Report& report, const Options& options);
// A table of the ranked rows followed by a markdown "Weekly triage" block.
std::string to_text(const Report& report, const Options& options);

// `xbox2pc census <path>... [--json <out>] [--missing] [--trace <run.json>]...
//                  [--triage N]`
// Exit status: 0 when at least one file was parsed; 1 when paths were given
// but none parsed, or a trace could not be read; 2 for a usage error.
int cli(int argc, char** argv);

}  // namespace xbox2pc::census
