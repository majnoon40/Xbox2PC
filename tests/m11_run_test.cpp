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
#include <cstring>
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

// ── M11 Phase 5: native-backend integration + determinism ─────────────────
// Compiled only when the experimental native path is enabled; the flag
// OFF build keeps the deterministic-only suite above.
#if XBOX2PC_NATIVE_EXECUTION_ENABLED

namespace {

// Parse the first descriptor's IAT RVA out of a built image (mirrors the
// samples generator: the builder appends import machinery after the
// payloads, so the displacement must be learned from a full-layout probe).
std::uint32_t FirstIatRva(const std::vector<std::uint8_t>& image) {
    std::uint32_t pe = 0;
    std::memcpy(&pe, image.data() + 0x3C, 4);
    std::uint32_t import_rva = 0;
    std::memcpy(&import_rva, image.data() + pe + 24 + 120, 4);
    const std::uint32_t off =
        import_rva >= 0x1000 ? import_rva - 0x1000 + 0x400 : import_rva;
    std::uint32_t iat_rva = 0;
    std::memcpy(&iat_rva, image.data() + off + 16, 4);
    return iat_rva;
}

// exit42: mov ecx,42; call [rip+disp]->ExitProcess; ret  (12 bytes).
std::vector<std::uint8_t> MakeExit42Image() {
    PeBuildSpec s;
    s.imports = {{"kernel32", {{"ExitProcess", 0}}}};
    s.reloc_blocks = {{0x2000, {{10, 0x2000, 0}}}};
    // Full-layout probe at the FINAL code size.
    std::vector<std::uint8_t> probe(12, 0xC3);
    s.text_payloads.push_back({0x1000, probe});
    const std::uint32_t iat = FirstIatRva(PeBuilder(s).build());
    const std::int64_t disp = static_cast<std::int64_t>(iat) -
                              static_cast<std::int64_t>(0x1000 + 5 + 6);
    std::vector<std::uint8_t> code{0xB9, 0x2A, 0x00, 0x00, 0x00,  // mov ecx,42
                                    0xFF, 0x15};                   // call [rip+disp]
    for (int b = 0; b < 4; ++b)
        code.push_back(static_cast<std::uint8_t>((disp >> (8 * b)) & 0xFF));
    code.push_back(0xC3);
    s.text_payloads.clear();
    s.text_payloads.push_back({0x1000, code});
    return PeBuilder(s).build();
}

// throwcatch: entry calls RaiseException(0,0,0,0) through the import;
// .pdata covers 0x1000-0x1010 with UNWIND_INFO EHANDLER -> the handler
// at 0x1020 (mov eax,42; ret) is the catch.
std::vector<std::uint8_t> MakeThrowCatchImage() {
    PeBuildSpec s;
    s.imports = {{"kernel32", {{"RaiseException", 0}}}};
    s.reloc_blocks = {{0x2000, {{10, 0x2000, 0}}}};
    // Full-layout probe: all payloads at final sizes.
    std::vector<std::uint8_t> probe(16, 0xC3);
    s.text_payloads.push_back({0x1000, probe});
    std::vector<std::uint8_t> probe_handler(6, 0xC3);
    s.text_payloads.push_back({0x1020, probe_handler});
    std::vector<std::uint8_t> probe_unwind(8, 0x00);
    s.text_payloads.push_back({0x1200, probe_unwind});
    s.exception_directory_payload = {0x00, 0x10, 0x00, 0x00, 0x10, 0x10,
                                     0x00, 0x00, 0x00, 0x12, 0x00, 0x00};
    const std::uint32_t iat = FirstIatRva(PeBuilder(s).build());
    const std::int64_t disp = static_cast<std::int64_t>(iat) -
                              static_cast<std::int64_t>(0x1000 + 10 + 6);
    std::vector<std::uint8_t> code{0x31, 0xC9,              // xor ecx,ecx
                                    0x31, 0xD2,              // xor edx,edx
                                    0x45, 0x31, 0xC0,        // xor r8d,r8d
                                    0x45, 0x31, 0xC9,        // xor r9d,r9d
                                    0xFF, 0x15};             // call [rip+disp]
    for (int b = 0; b < 4; ++b)
        code.push_back(static_cast<std::uint8_t>((disp >> (8 * b)) & 0xFF));
    while (code.size() < 0x10) code.push_back(0xC3);
    std::vector<std::uint8_t> handler{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
    // v1 + EHANDLER, count 0, handler RVA 0x1020.
    std::vector<std::uint8_t> unwind{0x09, 0x00, 0x00, 0x00,
                                     0x20, 0x10, 0x00, 0x00};
    s.text_payloads.clear();
    s.text_payloads.push_back({0x1000, code});
    s.text_payloads.push_back({0x1020, handler});
    s.text_payloads.push_back({0x1200, unwind});
    return PeBuilder(s).build();
}

struct NativeRunResult {
    int rc = 0;
    std::string json;
};

NativeRunResult RunNative(const std::vector<std::uint8_t>& image,
                          const std::filesystem::path& dir,
                          const char* name) {
    const auto fixture = dir / name;
    std::ofstream out(fixture, std::ios::binary);
    out.write(reinterpret_cast<const char*>(image.data()),
              static_cast<std::streamsize>(image.size()));
    out.close();
    const auto json = dir / (std::string(name) + ".json");
    const int rc = xbox2pc::cli::run_file(fixture.string(), json.string(),
                                          "native");
    return {rc, ReadAll(json)};
}

}  // namespace

TEST(M11NativeRun, Exit42SampleRunsThroughNativeBackend) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("xbox2pc-m11-native-" + std::to_string(nonce));
    std::filesystem::create_directories(root);
    const auto result = RunNative(MakeExit42Image(), root, "exit42.exe");
    EXPECT_EQ(result.rc, 0) << result.json;
    EXPECT_NE(result.json.find("\"backend\": \"native-run\""), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"outcome\": \"returned\""), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"return_value\": 42"), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"exit_code\": 42"), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"api_calls\": 1"), std::string::npos)
        << result.json;
    std::filesystem::remove_all(root);
}

TEST(M11NativeRun, ThrowCatchSampleRunsThroughNativeBackend) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("xbox2pc-m11-native-tc-" + std::to_string(nonce));
    std::filesystem::create_directories(root);
    const auto result = RunNative(MakeThrowCatchImage(), root, "throwcatch.exe");
    EXPECT_EQ(result.rc, 0) << result.json;
    EXPECT_NE(result.json.find("\"outcome\": \"returned\""), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"return_value\": 42"), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"exit_code\": 42"), std::string::npos)
        << result.json;
    EXPECT_NE(result.json.find("\"api_calls\": 1"), std::string::npos)
        << result.json;
    std::filesystem::remove_all(root);
}

TEST(M11NativeRun, HundredConsecutiveNativeRunsAreDeterministic) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("xbox2pc-m11-native-det-" + std::to_string(nonce));
    std::filesystem::create_directories(root);
    const auto image = MakeExit42Image();
    std::string first;
    for (int i = 0; i < 100; ++i) {
        const auto result = RunNative(image, root,
                                      ("det-" + std::to_string(i) + ".exe").c_str());
        ASSERT_EQ(result.rc, 0) << "run " << i << " failed: " << result.json;
        const auto file_pos = result.json.find("\"file\":");
        ASSERT_NE(file_pos, std::string::npos);
        const auto behavior = result.json.substr(0, file_pos) +
            result.json.substr(result.json.find(',', file_pos) + 1);
        if (i == 0) {
            first = behavior;
        } else {
            ASSERT_EQ(behavior, first)
                << "native run " << i << " diverged from run 0:\n"
                << first << "\nvs\n" << behavior;
        }
        std::filesystem::remove(root / ("det-" + std::to_string(i) + ".exe"));
        std::filesystem::remove(root / ("det-" + std::to_string(i) + ".exe.json"));
    }
    std::filesystem::remove_all(root);
}

#endif  // XBOX2PC_NATIVE_EXECUTION_ENABLED
