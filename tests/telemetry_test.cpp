// tests/telemetry_test.cpp — M12 P0.4: crash records, XBOX2PC_WATCH parsing,
// `xbox2pc report`, and the API trace.
//
// A run that executed and did not return normally appends one JSON line to
// <XBOX2PC_CRASH_SAVE>/crashes.log; XBOX2PC_STACKS adds the guest stack; the
// report aggregates such logs. The native backend is the one that can reach
// an import through a real `call [iat]` (what-broke entry 8), so the
// faulting-run cases run there under the flag.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "xbox2pc/json_reader.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/report_cli.hpp"
#include "xbox2pc/run_cli.hpp"
#include "xbox2pc/telemetry.hpp"

namespace {

using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;
using Policy = xbox2pc::rt::api::UnimplementedPolicy;

constexpr const char* kMissingName = "Xbox2pcP0NoSuchImport";

// Sets environment variables for the test and restores them afterwards.
class EnvGuard {
public:
    explicit EnvGuard(std::vector<std::pair<std::string, std::string>> variables) {
        for (auto& [name, value] : variables) {
            const char* old = std::getenv(name.c_str());
            saved_.emplace_back(name, old != nullptr ? std::optional<std::string>(old) : std::nullopt);
            setenv(name.c_str(), value.c_str(), 1);
        }
    }
    ~EnvGuard() {
        for (const auto& [name, old] : saved_) {
            if (old.has_value()) setenv(name.c_str(), old->c_str(), 1);
            else unsetenv(name.c_str());
        }
    }
    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;

private:
    std::vector<std::pair<std::string, std::optional<std::string>>> saved_;
};

std::filesystem::path MakeDir(const char* tag) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto dir = std::filesystem::temp_directory_path() /
        ("xbox2pc-telemetry-" + std::string(tag) + "-" + std::to_string(nonce));
    std::filesystem::create_directories(dir);
    return dir;
}

std::uint32_t FirstIatRva(const std::vector<std::uint8_t>& image) {
    std::uint32_t pe = 0;
    std::memcpy(&pe, image.data() + 0x3C, 4);
    std::uint32_t import_rva = 0;
    std::memcpy(&import_rva, image.data() + pe + 24 + 120, 4);
    const std::uint32_t off = import_rva >= 0x1000 ? import_rva - 0x1000 + 0x400 : import_rva;
    std::uint32_t iat_rva = 0;
    std::memcpy(&iat_rva, image.data() + off + 16, 4);
    return iat_rva;
}

// entry: mov eax,42; call [rip+disp] -> the missing import; ret.
std::vector<std::uint8_t> MakeStubCallImage() {
    PeBuildSpec s;
    s.imports = {{"kernel32", {{kMissingName, 0}}}};
    s.reloc_blocks = {{0x2000, {{10, 0x2000, 0}}}};
    std::vector<std::uint8_t> probe(12, 0xC3);
    s.text_payloads.push_back({0x1000, probe});
    const std::uint32_t iat = FirstIatRva(PeBuilder(s).build());
    const std::int64_t disp = static_cast<std::int64_t>(iat) -
                              static_cast<std::int64_t>(0x1000 + 5 + 6);
    std::vector<std::uint8_t> code{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xFF, 0x15};
    for (int b = 0; b < 4; ++b)
        code.push_back(static_cast<std::uint8_t>((disp >> (8 * b)) & 0xFF));
    code.push_back(0xC3);
    s.text_payloads.clear();
    s.text_payloads.push_back({0x1000, code});
    return PeBuilder(s).build();
}

std::filesystem::path WriteExe(const std::filesystem::path& dir, const char* name,
                               const std::vector<std::uint8_t>& bytes) {
    const auto path = dir / name;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return path;
}

std::string ReadAll(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::vector<std::string> Lines(const std::filesystem::path& path) {
    std::vector<std::string> out;
    std::ifstream in(path, std::ios::binary);
    std::string line;
    while (std::getline(in, line)) if (!line.empty()) out.push_back(line);
    return out;
}

}  // namespace

TEST(TelemetryTest, WatchListParsing) {
    using xbox2pc::rt::exec::telemetry::parse_watch_rvas;
    EXPECT_EQ(parse_watch_rvas(nullptr), std::vector<std::uint32_t>{});
    EXPECT_EQ(parse_watch_rvas(""), std::vector<std::uint32_t>{});
    EXPECT_EQ(parse_watch_rvas("0x10, 32,abc, 0x100000000, 7"),
              (std::vector<std::uint32_t>{0x10u, 32u, 7u}));
}

TEST(TelemetryTest, ApiTraceKeepsTheLast64) {
    xbox2pc::rt::exec::ExecutionResult result;
    for (int i = 0; i < 70; ++i)
        xbox2pc::rt::exec::telemetry::record_api_call(result, "kernel32!Call" + std::to_string(i));
    ASSERT_EQ(result.api_trace.size(), 64u);
    EXPECT_EQ(result.api_trace.front(), "kernel32!Call6");
    EXPECT_EQ(result.api_trace.back(), "kernel32!Call69");
}

TEST(TelemetryTest, ReportAggregatesAFaultLog) {
    const auto dir = MakeDir("report");
    const auto log = dir / "crashes.log";
    {
        std::ofstream out(log);
        out << "{\"outcome\":\"faulted\",\"fault\":\"unimplemented-api\",\"rip\":5370018,\"rva\":4096,"
               "\"first_unimplemented\":\"kernel32!Nope\",\"unimplemented_calls\":1,"
               "\"api_trace\":[\"kernel32!ExitProcess\",\"kernel32!Nope\"]}\n";
        out << "{\"outcome\":\"faulted\",\"fault\":\"unimplemented-api\",\"rip\":5370018,\"rva\":4096,"
               "\"first_unimplemented\":\"kernel32!Nope\",\"unimplemented_calls\":1,"
               "\"api_trace\":[\"kernel32!Nope\"]}\n";
        out << "{\"outcome\":\"returned\",\"api_trace\":[\"kernel32!ExitProcess\"]}\n";
        out << "\n";
        out << "{not json\n";
    }
    xbox2pc::report::Aggregates aggregates;
    std::string error;
    ASSERT_TRUE(xbox2pc::report::aggregate_file(log.string(), aggregates, error)) << error;
    EXPECT_EQ(aggregates.runs, 3u);
    EXPECT_EQ(aggregates.faulted, 2u);
    EXPECT_EQ(aggregates.returned, 1u);
    EXPECT_EQ(aggregates.malformed, 1u);
    ASSERT_EQ(aggregates.faults_by_site.size(), 1u);
    EXPECT_EQ(aggregates.faults_by_site.begin()->first, "unimplemented-api @ module+0x1000");
    EXPECT_EQ(aggregates.faults_by_site.begin()->second, 2u);
    EXPECT_EQ(aggregates.unimplemented_imports.at("kernel32!Nope"), 2u);
    EXPECT_EQ(aggregates.api_histogram.at("kernel32!ExitProcess"), 2u);
    EXPECT_EQ(aggregates.api_histogram.at("kernel32!Nope"), 2u);
    const std::string text = xbox2pc::report::to_text(aggregates);
    EXPECT_NE(text.find("3 run(s): 1 returned, 2 faulted, 0 other"), std::string::npos) << text;
    EXPECT_NE(text.find("Faults by site"), std::string::npos) << text;
    EXPECT_NE(text.find("unimplemented-api @ module+0x1000"), std::string::npos) << text;
    EXPECT_NE(text.find("API trace histogram (top 20)"), std::string::npos) << text;
    const std::string json = xbox2pc::report::to_json(aggregates).serialize();
    EXPECT_NE(json.find("\"faults_by_site\""), std::string::npos) << json;
    // The CLI: read and write JSON; a missing file is exit 1; no path is usage.
    const auto out = dir / "report.json";
    const std::string log_string = log.string();
    const std::string out_string = out.string();
    char arg0[] = "xbox2pc";
    char arg1[] = "report";
    char arg_json[] = "--json";
    std::vector<char*> argv{arg0, arg1, const_cast<char*>(log_string.c_str()),
                            arg_json, const_cast<char*>(out_string.c_str()), nullptr};
    EXPECT_EQ(xbox2pc::report::cli(static_cast<int>(argv.size()) - 1, argv.data()), 0);
    EXPECT_NE(ReadAll(out).find("\"faulted\": 2"), std::string::npos);
    const std::string nowhere = (dir / "nowhere.log").string();
    std::vector<char*> argv_missing{arg0, arg1, const_cast<char*>(nowhere.c_str()), nullptr};
    EXPECT_EQ(xbox2pc::report::cli(static_cast<int>(argv_missing.size()) - 1, argv_missing.data()), 1);
    std::vector<char*> argv_usage{arg0, arg1, nullptr};
    EXPECT_EQ(xbox2pc::report::cli(static_cast<int>(argv_usage.size()) - 1, argv_usage.data()), 2);
    EXPECT_FALSE(xbox2pc::report::aggregate_file(nowhere, aggregates, error));
    std::filesystem::remove_all(dir);
}

TEST(TelemetryTest, NoCrashRecordWithoutTheVariable) {
    const auto dir = MakeDir("no-record");
    const auto exe = WriteExe(dir, "stub.exe", MakeStubCallImage());
    // Without XBOX2PC_CRASH_SAVE nothing is written anywhere.
    EnvGuard none({{"XBOX2PC_CRASH_SAVE", ""}});
    const auto json = dir / "run.json";
#if XBOX2PC_NATIVE_EXECUTION_ENABLED
    // A trap faults after guest code ran, yet no record is written.
    EXPECT_EQ(xbox2pc::cli::run_file(exe.string(), json.string(), "native", Policy::Trap), 1);
#else
    // Without the native flag the backend itself is a usage error.
    EXPECT_EQ(xbox2pc::cli::run_file(exe.string(), json.string(), "native", Policy::Trap), 2);
#endif
    EXPECT_FALSE(std::filesystem::exists(dir / "crashes.log"));
    std::filesystem::remove_all(dir);
}

#if XBOX2PC_NATIVE_EXECUTION_ENABLED

TEST(TelemetryTest, FaultingRunAppendsACrashRecordWithStackAndTrace) {
    const auto dir = MakeDir("crash");
    const auto exe = WriteExe(dir, "stub.exe", MakeStubCallImage());
    const auto crash_dir = dir / "crashes";
    EnvGuard guard({{"XBOX2PC_CRASH_SAVE", crash_dir.string()},
                    {"XBOX2PC_STACKS", "1"}});
    const auto json = dir / "run.json";
    // A load failure under strict never executed guest code: no record.
    EXPECT_EQ(xbox2pc::cli::run_file(exe.string(), json.string(), "native", Policy::Strict), 1);
    EXPECT_FALSE(std::filesystem::exists(crash_dir / "crashes.log"));
    // A trap is a fault after guest code ran: one record, with the stack.
    EXPECT_EQ(xbox2pc::cli::run_file(exe.string(), json.string(), "native", Policy::Trap), 1);
    const auto lines = Lines(crash_dir / "crashes.log");
    ASSERT_EQ(lines.size(), 1u);
    const auto record = xbox2pc::json::parse(lines.front());
    EXPECT_EQ(record.get("fault").as_string(), "unimplemented-api");
    EXPECT_EQ(record.get("outcome").as_string(), "faulted");
    EXPECT_EQ(record.get("first_unimplemented").as_string(), std::string("kernel32!") + kMissingName);
    EXPECT_EQ(record.get("unimplemented_calls").as_int(), 1);
    EXPECT_TRUE(record.get("rva").is_number());
    EXPECT_TRUE(record.get("image_base").is_number());
    ASSERT_TRUE(record.get("registers").is_object());
    EXPECT_TRUE(record.get("registers").get("rip").is_number());
    EXPECT_TRUE(record.get("registers").get("rsp").is_number());
    ASSERT_EQ(record.get("api_trace").size(), 1u);
    EXPECT_EQ(record.get("api_trace").at(0).as_string(), std::string("kernel32!") + kMissingName);
    EXPECT_FALSE(record.get("stack").size() == 0);
    // The run report names the log and carries the same trace.
    const auto report_text = ReadAll(json);
    EXPECT_NE(report_text.find("\"crash_log\": \""), std::string::npos) << report_text;
    EXPECT_NE(report_text.find(kMissingName), std::string::npos) << report_text;
    // xbox2pc report reads it back.
    xbox2pc::report::Aggregates aggregates;
    std::string error;
    ASSERT_TRUE(xbox2pc::report::aggregate_file((crash_dir / "crashes.log").string(), aggregates, error));
    EXPECT_EQ(aggregates.faulted, 1u);
    EXPECT_EQ(aggregates.unimplemented_imports.at(std::string("kernel32!") + kMissingName), 1u);
    std::filesystem::remove_all(dir);
}

#endif  // XBOX2PC_NATIVE_EXECUTION_ENABLED

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
