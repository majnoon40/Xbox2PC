// tests/m12_run_test.cpp — M12 P0 `xbox2pc run`: the report and --unimplemented.
//
// The run path writes a JSON report on every outcome (a failed load used to
// print one line and exit 1) and names every import with its status. Under
// --unimplemented=trap|zero an import without an implementation is bound so
// the image loads; what a call to it does is decided by the engines.
//
// Fixtures are built in memory with the project's PeBuilder. The
// deterministic backend cannot follow a `call [iat]` from code: the
// interpreter validates call targets as executable guest memory and the
// synthetic binding range lies below the managed address space
// (docs/m12-what-broke.md, entry 8). So the end-to-end trap/zero cases run
// on the native backend, where the thunk page makes the call land; the
// deterministic engine's handling is covered at the engine level in
// execution_test.cpp.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/run_cli.hpp"

namespace {

using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;
using Policy = xbox2pc::rt::api::UnimplementedPolicy;
using xbox2pc::cli::run_file;

// An import nothing in this repository documents or implements.
constexpr const char* kMissingDll = "kernel32";
constexpr const char* kMissingName = "Xbox2pcP0NoSuchImport";

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

// The 13 kernel32 imports of samples/m11/freestanding.c, the set the run
// path must be able to load (before M12 P0 two of them had no implementation
// in its service world). The entry only returns 42.
std::vector<std::uint8_t> MakeM11ImportSetImage() {
    PeBuildSpec s;
    s.imports = {{"kernel32.dll",
                  {{"GetCurrentProcessId", 0}, {"GetCurrentThreadId", 0},
                   {"VirtualAlloc", 0}, {"VirtualQuery", 0}, {"VirtualProtect", 0},
                   {"VirtualFree", 0}, {"CreateEventW", 0}, {"SetEvent", 0},
                   {"WaitForSingleObject", 0}, {"CloseHandle", 0},
                   {"SetLastError", 0}, {"GetLastError", 0}, {"ExitProcess", 0}}}};
    s.reloc_blocks = {{0x2000, {{10, 0x2000, 0}}}};
    s.text_payloads.push_back(
        {0x1000, {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}});   // mov eax,42; ret
    return PeBuilder(s).build();
}

// entry: mov eax,42; call [rip+disp] -> the missing import; add eax,7; ret.
// A zero-returning stub leaves RAX at 0, so the program returns 7 (an
// untouched RAX would give 49); a trapping stub never reaches the add.
std::vector<std::uint8_t> MakeStubCallImage() {
    PeBuildSpec s;
    s.imports = {{kMissingDll, {{kMissingName, 0}}}};
    s.reloc_blocks = {{0x2000, {{10, 0x2000, 0}}}};
    // Full-layout probe at the FINAL code size.
    std::vector<std::uint8_t> probe(15, 0xC3);
    s.text_payloads.push_back({0x1000, probe});
    const std::uint32_t iat = FirstIatRva(PeBuilder(s).build());
    const std::int64_t disp = static_cast<std::int64_t>(iat) -
                              static_cast<std::int64_t>(0x1000 + 5 + 6);
    std::vector<std::uint8_t> code{0xB8, 0x2A, 0x00, 0x00, 0x00,   // mov eax,42
                                   0xFF, 0x15};                     // call [rip+disp32]
    for (int b = 0; b < 4; ++b)
        code.push_back(static_cast<std::uint8_t>((disp >> (8 * b)) & 0xFF));
    code.insert(code.end(), {0x83, 0xC0, 0x07,                     // add eax,7
                             0xC3});                               // ret
    s.text_payloads.clear();
    s.text_payloads.push_back({0x1000, code});
    return PeBuilder(s).build();
}

// entry: mov ecx,<code>; call [rip+disp] -> ExitProcess; ret (never reached).
// `dll` is spelled the way a real import table spells it.
std::vector<std::uint8_t> MakeExitProcessImage(const char* dll, std::uint8_t exit_code) {
    PeBuildSpec s;
    s.imports = {{dll, {{"ExitProcess", 0}}}};
    s.reloc_blocks = {{0x2000, {{10, 0x2000, 0}}}};
    std::vector<std::uint8_t> probe(12, 0xC3);   // full-layout probe
    s.text_payloads.push_back({0x1000, probe});
    const std::uint32_t iat = FirstIatRva(PeBuilder(s).build());
    const std::int64_t disp = static_cast<std::int64_t>(iat) -
                              static_cast<std::int64_t>(0x1000 + 5 + 6);
    std::vector<std::uint8_t> code{0xB9, exit_code, 0x00, 0x00, 0x00,   // mov ecx,<code>
                                   0xFF, 0x15};                          // call [rip+disp32]
    for (int b = 0; b < 4; ++b)
        code.push_back(static_cast<std::uint8_t>((disp >> (8 * b)) & 0xFF));
    code.push_back(0xC3);
    s.text_payloads.clear();
    s.text_payloads.push_back({0x1000, code});
    return PeBuilder(s).build();
}

std::filesystem::path Scratch(const char* tag) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto dir = std::filesystem::temp_directory_path() /
        ("xbox2pc-m12-" + std::string(tag) + "-" + std::to_string(nonce));
    std::filesystem::create_directories(dir);
    return dir;
}

std::filesystem::path WriteBytes(const std::filesystem::path& dir, const char* name,
                                 const std::vector<std::uint8_t>& bytes) {
    const auto path = dir / name;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    out.close();
    return path;
}

struct RunResult {
    int rc = -1;
    std::string json;
    bool has(std::string_view fragment) const {
        return json.find(fragment) != std::string::npos;
    }
};

RunResult RunFixture(const std::filesystem::path& exe, const std::filesystem::path& dir,
              const char* tag, const char* backend, Policy policy) {
    RunResult r;
    const auto json = dir / (std::string(tag) + ".json");
    r.rc = run_file(exe.string(), json.string(), backend, policy);
    std::ifstream in(json, std::ios::binary);
    r.json.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return r;
}

}  // namespace

TEST(M12Run, StrictPolicyRefusesToLoadAndReportsEveryMissingImport) {
    const auto dir = Scratch("strict");
    const auto exe = WriteBytes(dir, "stub.exe", MakeStubCallImage());
    const auto r = RunFixture(exe, dir, "strict", "deterministic", Policy::Strict);
    EXPECT_EQ(r.rc, 1);
    EXPECT_TRUE(r.has("\"outcome\": \"load_failed\"")) << r.json;
    EXPECT_TRUE(r.has("\"stage\": \"load\"")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented\": \"strict\"")) << r.json;
    EXPECT_TRUE(r.has("\"ran\": false")) << r.json;
    EXPECT_TRUE(r.has("\"total\": 1")) << r.json;
    EXPECT_TRUE(r.has("\"resolved\": 0")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented\": 0")) << r.json;
    EXPECT_TRUE(r.has("\"name\": \"Xbox2pcP0NoSuchImport\"")) << r.json;
    EXPECT_TRUE(r.has("\"status\": \"unresolved\"")) << r.json;
    EXPECT_TRUE(r.has("\"error\": \"imports not fully resolved")) << r.json;
    std::filesystem::remove_all(dir);
}

TEST(M12Run, TheImportSetOfTheM11SampleLoads) {
    const auto dir = Scratch("m11-imports");
    const auto exe = WriteBytes(dir, "m11-imports.exe", MakeM11ImportSetImage());
    const auto r = RunFixture(exe, dir, "m11", "deterministic", Policy::Strict);
    EXPECT_EQ(r.rc, 0) << r.json;
    EXPECT_TRUE(r.has("\"outcome\": \"returned\"")) << r.json;
    EXPECT_TRUE(r.has("\"return_value\": 42")) << r.json;
    EXPECT_TRUE(r.has("\"exit_code\": 42")) << r.json;
    EXPECT_TRUE(r.has("\"total\": 13")) << r.json;
    EXPECT_TRUE(r.has("\"resolved\": 13")) << r.json;
    EXPECT_TRUE(r.has("\"unresolved\": 0")) << r.json;
    EXPECT_TRUE(r.has("\"missing\": []")) << r.json;
    std::filesystem::remove_all(dir);
}

TEST(M12Run, ReportIsWrittenWhenTheFileIsNotAPE) {
    const auto dir = Scratch("not-pe");
    const std::vector<std::uint8_t> text{'n', 'o', 't', ' ', 'a', ' ', 'P', 'E'};
    const auto exe = WriteBytes(dir, "text.exe", text);
    const auto r = RunFixture(exe, dir, "not-pe", "deterministic", Policy::Strict);
    EXPECT_EQ(r.rc, 2);
    EXPECT_TRUE(r.has("\"outcome\": \"not_pe\"")) << r.json;
    EXPECT_TRUE(r.has("\"stage\": \"parse\"")) << r.json;
    EXPECT_TRUE(r.has("\"ran\": false")) << r.json;
    std::filesystem::remove_all(dir);
}

TEST(M12Run, ReportIsWrittenWhenTheFileCannotBeOpened) {
    const auto dir = Scratch("missing");
    const auto r = RunFixture(dir / "does-not-exist.exe", dir, "missing", "deterministic",
                       Policy::Strict);
    EXPECT_EQ(r.rc, 2);
    EXPECT_TRUE(r.has("\"outcome\": \"cannot_open\"")) << r.json;
    EXPECT_TRUE(r.has("\"stage\": \"read\"")) << r.json;
    std::filesystem::remove_all(dir);
}

TEST(M12Run, UnknownBackendIsAUsageErrorWithoutAReport) {
    const auto dir = Scratch("backend");
    const auto exe = WriteBytes(dir, "stub.exe", MakeStubCallImage());
    const auto json = dir / "never.json";
    EXPECT_EQ(run_file(exe.string(), json.string(), "quantum", Policy::Strict), 2);
    EXPECT_FALSE(std::filesystem::exists(json));
    std::filesystem::remove_all(dir);
}

TEST(M12Run, PolicyNamesRoundTrip) {
    using xbox2pc::rt::api::UnimplementedPolicy;
    Policy parsed = UnimplementedPolicy::Strict;
    EXPECT_TRUE(xbox2pc::rt::api::unimplemented_policy_from_name("trap", parsed));
    EXPECT_EQ(parsed, UnimplementedPolicy::Trap);
    EXPECT_TRUE(xbox2pc::rt::api::unimplemented_policy_from_name("zero", parsed));
    EXPECT_EQ(parsed, UnimplementedPolicy::Zero);
    EXPECT_TRUE(xbox2pc::rt::api::unimplemented_policy_from_name("strict", parsed));
    EXPECT_EQ(parsed, UnimplementedPolicy::Strict);
    EXPECT_FALSE(xbox2pc::rt::api::unimplemented_policy_from_name("ignore", parsed));
    EXPECT_STREQ(xbox2pc::rt::api::unimplemented_policy_to_name(UnimplementedPolicy::Trap),
                 "trap");
}

// ── native backend: a real `call [iat]` reaches the stub ──────────────────

#if XBOX2PC_NATIVE_EXECUTION_ENABLED

TEST(M12NativeRun, TrapStopsAtTheUnimplementedImportAndNamesIt) {
    const auto dir = Scratch("native-trap");
    const auto exe = WriteBytes(dir, "stub.exe", MakeStubCallImage());
    const auto r = RunFixture(exe, dir, "trap", "native", Policy::Trap);
    EXPECT_EQ(r.rc, 1);
    EXPECT_TRUE(r.has("\"backend\": \"native-run\"")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented\": \"trap\"")) << r.json;
    EXPECT_TRUE(r.has("\"outcome\": \"faulted\"")) << r.json;
    EXPECT_TRUE(r.has("\"ran\": true")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented\": 1")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented_calls\": 1")) << r.json;
    EXPECT_TRUE(r.has("\"first_unimplemented\": \"kernel32!Xbox2pcP0NoSuchImport\""))
        << r.json;
    EXPECT_TRUE(r.has("\"fault\": \"unimplemented-api\"") || r.has("unimplemented-api"))
        << r.json;
    EXPECT_TRUE(r.has("unimplemented import called: kernel32!Xbox2pcP0NoSuchImport"))
        << r.json;
    std::filesystem::remove_all(dir);
}

TEST(M12NativeRun, ZeroReturnsZeroAndTheGuestContinues) {
    const auto dir = Scratch("native-zero");
    const auto exe = WriteBytes(dir, "stub.exe", MakeStubCallImage());
    const auto r = RunFixture(exe, dir, "zero", "native", Policy::Zero);
    EXPECT_EQ(r.rc, 0) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented\": \"zero\"")) << r.json;
    EXPECT_TRUE(r.has("\"outcome\": \"returned\"")) << r.json;
    EXPECT_TRUE(r.has("\"return_value\": 7")) << r.json;   // 0 from the stub, then add 7
    EXPECT_TRUE(r.has("\"exit_code\": 7")) << r.json;
    EXPECT_TRUE(r.has("\"api_calls\": 1")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented_calls\": 1")) << r.json;
    std::filesystem::remove_all(dir);
}

// A real import table spells the module "kernel32.dll" (any case); the
// hand-built images above spell it "kernel32". Until M12 P0 the native
// parent compared the bytes, missed ExitProcess, answered it as an ordinary
// call, and the child resumed into the guest's `for (;;) {}` until the
// watchdog fired (docs/m12-what-broke.md, entry 10).
TEST(M12NativeRun, ExitProcessIsRecognizedFromARealDllName) {
    for (const char* dll : {"kernel32.dll", "KERNEL32.DLL"}) {
        const auto dir = Scratch("native-exit-dll");
        const auto exe = WriteBytes(dir, "exit-dll.exe", MakeExitProcessImage(dll, 43));
        const auto r = RunFixture(exe, dir, "exit-dll", "native", Policy::Strict);
        EXPECT_EQ(r.rc, 0) << dll << ": " << r.json;
        EXPECT_TRUE(r.has("\"outcome\": \"returned\"")) << dll << ": " << r.json;
        EXPECT_TRUE(r.has("\"exit_code\": 43")) << dll << ": " << r.json;
        EXPECT_TRUE(r.has("\"return_value\": 43")) << dll << ": " << r.json;
        EXPECT_TRUE(r.has("\"api_calls\": 1")) << dll << ": " << r.json;
        std::filesystem::remove_all(dir);
    }
}

TEST(M12NativeRun, StrictStillRefusesToLoadOnTheNativeBackend) {
    const auto dir = Scratch("native-strict");
    const auto exe = WriteBytes(dir, "stub.exe", MakeStubCallImage());
    const auto r = RunFixture(exe, dir, "strict", "native", Policy::Strict);
    EXPECT_EQ(r.rc, 1);
    EXPECT_TRUE(r.has("\"outcome\": \"load_failed\"")) << r.json;
    EXPECT_TRUE(r.has("\"unimplemented\": \"strict\"")) << r.json;
    std::filesystem::remove_all(dir);
}

// Byte-identical reports over 100 consecutive runs (the plan's determinism
// test, applied to the run report). Only the per-run file path is removed.
TEST(M12NativeRun, HundredConsecutiveRunsProduceByteIdenticalReports) {
    const auto dir = Scratch("native-det");
    const auto exe = WriteBytes(dir, "stub.exe", MakeStubCallImage());
    std::string first;
    for (int i = 0; i < 100; ++i) {
        const auto r = RunFixture(exe, dir, "det", "native", Policy::Trap);
        ASSERT_EQ(r.rc, 1) << "run " << i << " failed: " << r.json;
        const auto file_pos = r.json.find("\"file\":");
        ASSERT_NE(file_pos, std::string::npos) << r.json;
        const auto behavior = r.json.substr(0, file_pos) +
            r.json.substr(r.json.find(',', file_pos) + 1);
        if (i == 0) {
            first = behavior;
        } else {
            ASSERT_EQ(behavior, first) << "run " << i << " diverged from run 0";
        }
    }
    std::filesystem::remove_all(dir);
}

#endif  // XBOX2PC_NATIVE_EXECUTION_ENABLED

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
