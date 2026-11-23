#pragma once

namespace xbox2pc::cli {

// Handles the M9 binary-inspection commands. Returns -1 when argv[1] is not
// one of those commands; otherwise returns the process exit code.
int run_m9_binary_cli(int argc, char** argv);

}  // namespace xbox2pc::cli
