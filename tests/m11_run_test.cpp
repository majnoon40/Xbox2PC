// tests/m11_run_test.cpp — M11 Phase 9 `xbox2pc run` integration and
// determinism suite.
//
// Integration: build a fixture PE with the project's own pe_builder,
// write it to a temp file, and execute it through the CLI's run path
// (cmd_run_file via the real main dispatcher where possible; the
// in-process entry is exercised directly because the CLI binary target
// is not exported to tests). Verifies the full pipeline: parse ->
// process -> load -> context -> prepare -> deterministic backend ->
// RAX-derived exit code -> teardown.
//
// Determinism: the SAME fixture run 100 consecutive times must produce
// byte-identical structured results (outcome, instruction count, return
// value, api-call count) — the PR #15 Phase 9 acceptance criterion.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/run_cli.hpp"

namespace {

using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

struct RunResult {
    bool ok = false;
    std::uint64_t instructions = 0;
    std::uint64_t return_value = 0;
    std::uint64_t api_calls = 0;
    std::string outcome;
};

// Build the fixture: entry computes 33 + 9 = 42 in RAX and returns.
std::vector<std::uint8_t> MakeFixtureImage() {
    PeBuildSpec spec;
    std::vector<std::uint8_t> code{0x48, 0xB8, 33, 0, 0, 0, 0, 0, 0, 0,
                                   0x48, 0x81, 0xC0, 9, 0, 0, 0, 0xC3};
    spec.text_payloads.push_back({0x1000, code});
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    return PeBuilder(spec).build();
}

std::filesystem::path WriteFixture(const std::filesystem::path& dir,
                                   const std::vector<std::uint8_t>& image) {
    const auto path = dir / "fixture.exe";
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(image.data()),
              static_cast<std::streamsize>(image.size()));
    out.close();
    return path;
}

std::string ReadAll(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

TEST(M11Run, FixtureLoadsAndReturns42) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("xbox2pc-m11-run-" + std::to_string(nonce));
    std::filesystem::create_directories(root);
    const auto fixture = WriteFixture(root, MakeFixtureImage());

    const auto json = root / "run.json";
    const int rc = xbox2pc::cli::run_file(fixture.string(), json.string());
    EXPECT_EQ(rc, 0) << "run command failed";

    const auto body = ReadAll(json);
    // The JSON writer emits "key": value with a space after the colon.
    EXPECT_NE(body.find("\"return_value\": 42"), std::string::npos) << body;
    EXPECT_NE(body.find("\"exit_code\": 42"), std::string::npos) << body;
    EXPECT_NE(body.find("\"outcome\": \"returned\""), std::string::npos) << body;
    EXPECT_NE(body.find("\"instructions\": 3"), std::string::npos) << body;
    EXPECT_NE(body.find("\"regions_after_terminate\": 0"), std::string::npos) << body;
    std::filesystem::remove_all(root);
}

TEST(M11Run, MissingFileFailsClosed) {
    const int rc = xbox2pc::cli::run_file("/nonexistent/xbox2pc-missing.exe",
                                          std::nullopt);
    EXPECT_EQ(rc, 2);
}

TEST(M11Run, HundredConsecutiveRunsAreDeterministic) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("xbox2pc-m11-det-" + std::to_string(nonce));
    std::filesystem::create_directories(root);
    const auto fixture = WriteFixture(root, MakeFixtureImage());

    std::string first;
    for (int i = 0; i < 100; ++i) {
        const auto json = root / ("run-" + std::to_string(i) + ".json");
        const int rc = xbox2pc::cli::run_file(fixture.string(), json.string());
        ASSERT_EQ(rc, 0) << "run " << i << " failed";
        const auto body = ReadAll(json);
        // Normalize the per-run file field so only behavioral fields
        // participate in the comparison.
        const auto file_pos = body.find("\"file\":");
        ASSERT_NE(file_pos, std::string::npos);
        const auto behavior = body.substr(0, file_pos) +
            body.substr(body.find(',', file_pos) + 1);
        if (i == 0) {
            first = behavior;
        } else {
            ASSERT_EQ(behavior, first)
                << "run " << i << " diverged from run 0:\n"
                << first << "\nvs\n" << behavior;
        }
        std::filesystem::remove(json);
    }
    std::filesystem::remove_all(root);
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
