#pragma once
// xbox2pc/run_cli.hpp — M11 Phase 9 `xbox2pc run <file>` entry point.
//
// Full integration path over a user-supplied PE: parse -> M4 process ->
// M6/M7 load with resolver -> M8 context -> prepare entry ->
// deterministic-backend execution -> exit code from RAX (mod 256,
// process-style). The deterministic backend is a subset interpreter,
// NOT a general emulator; this entry proves the end-to-end pipeline and
// reports a structured outcome either way.

#include <optional>
#include <string>

namespace xbox2pc::cli {

// Returns 0 when the program returned normally; 1 for a load/prepare/
// execution failure; 2 for usage/input errors (missing/unparseable
// file). When json_out is provided, a structured result object is
// written there (outcome, instructions, return_value, exit_code,
// api_calls, regions_after_terminate).
int run_file(const std::string& file, const std::optional<std::string>& json_out);

}  // namespace xbox2pc::cli
