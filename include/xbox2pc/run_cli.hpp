#pragma once
// xbox2pc/run_cli.hpp — `xbox2pc run <file>` entry point (M11 Phase 9,
// extended in M12 P0).
//
// Full integration path over a user-supplied PE: parse -> M4 process ->
// M6/M7 load with resolver -> M8 context -> prepare entry -> deterministic
// or native backend -> exit code from RAX (mod 256, process-style). The
// deterministic backend is a subset interpreter, NOT a general emulator.
//
// M12 P0: a JSON report is written on EVERY outcome once the input path is
// known (outcome, stage, every import with its status and the missing ones,
// API and unimplemented call counts), and `unimplemented` decides what an
// import without an implementation does (see api_compat.hpp).

#include <optional>
#include <string>

#include "xbox2pc/api_compat.hpp"

namespace xbox2pc::cli {

// Returns 0 when the program returned normally; 1 for a load, prepare or
// execution failure; 2 for usage or input errors (unknown backend, missing
// or unparseable file). With json_out, a report object is written for every
// outcome except an unknown backend, which is the caller's mistake:
//   file, backend, unimplemented, outcome, stage, error, detail, ran,
//   exit_code, return_value, instructions, api_calls, unimplemented_calls,
//   first_unimplemented, regions_after_terminate,
//   imports { total, resolved, unimplemented, unresolved, unsupported, invalid },
//   missing [ { dll, name, ordinal, status, note } ... ]
// outcome is a backend outcome (returned | completed | interrupted |
// terminated | faulted) or cannot_open | not_pe | load_failed | prepare_failed
// | error. stage is the last stage reached: read | parse | process | load |
// prepare | execute | teardown. exit_code is the guest's (RAX & 0xFF) and is
// 0 when no guest code ran; outcome and stage say which.
int run_file(const std::string& file, const std::optional<std::string>& json_out,
             const std::string& backend = "deterministic",
             rt::api::UnimplementedPolicy unimplemented = rt::api::UnimplementedPolicy::Strict);

}  // namespace xbox2pc::cli
