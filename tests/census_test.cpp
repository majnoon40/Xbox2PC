// tests/census_test.cpp — M12 P0.3: `xbox2pc census` and the JSON reader.
//
// The census inspects import tables of PEs built here with the project's
// PeBuilder, classifies every dll!name against the registry and ranks the
// rows by first reach when run reports are given. Nothing is executed.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "xbox2pc/census.hpp"
#include "xbox2pc/json_reader.hpp"
#include "xbox2pc/pe_builder.hpp"

namespace {

using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;
namespace census = xbox2pc::census;

std::filesystem::path MakeDir(const char* tag) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto dir = std::filesystem::temp_directory_path() /
        ("xbox2pc-census-" + std::string(tag) + "-" + std::to_string(nonce));
    std::filesystem::create_directories(dir);
    return dir;
}

void WriteBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

std::filesystem::path WritePe(const std::filesystem::path& dir, const char* name,
                              const PeBuildSpec& spec) {
    const auto path = dir / name;
    WriteBytes(path, PeBuilder(spec).build());
    return path;
}

const census::Import* Find(const census::Report& report, const std::string& dll,
                           const std::string& name) {
    for (const auto& row : report.imports) {
        if (row.dll == dll && row.name == name) return &row;
    }
    return nullptr;
}

// NoSuchCensusImport is imported by both files; ExitProcess by one.
std::filesystem::path TwoFileDir(const char* tag) {
    const auto dir = MakeDir(tag);
    PeBuildSpec a;
    a.imports = {{"kernel32", {{"ExitProcess", 0}, {"NoSuchCensusImport", 0}}},
                 {"xgameruntime", {{"XGameRuntimeInitialize", 0}}}};
    WritePe(dir, "a.exe", a);
    PeBuildSpec b;
    b.imports = {{"KERNEL32.dll", {{"NoSuchCensusImport", 0}}}};
    WritePe(dir, "b.exe", b);
    return dir;
}

}  // namespace

TEST(JsonReaderTest, ParsesTheRuntimeSubsetAndRoundTrips) {
    const std::string text =
        "{\"a\": [1, -2, 3.5, true, false, null], "
        "\"s\": \"x\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud834\\udd1e\", "
        "\"o\": {\"k\": \"v\"}, \"big\": 9223372036854775807}";
    const auto j = xbox2pc::json::parse(text);
    ASSERT_TRUE(j.is_object());
    EXPECT_EQ(j.get("a").size(), 6u);
    EXPECT_EQ(j.get("a").at(0).as_int(), 1);
    EXPECT_EQ(j.get("a").at(1).as_int(), -2);
    EXPECT_EQ(j.get("a").at(3).type(), xbox2pc::json::Json::Type::Bool);
    EXPECT_EQ(j.get("a").at(4).type(), xbox2pc::json::Json::Type::Bool);
    EXPECT_EQ(j.get("a").at(5).type(), xbox2pc::json::Json::Type::Null);
    EXPECT_EQ(j.get("a").at(2).type(), xbox2pc::json::Json::Type::Double);
    EXPECT_EQ(j.get("s").as_string(), "x\"\\/\b\f\n\r\t\xc3\xa9\xf0\x9d\x84\x9e");
    EXPECT_EQ(j.get("o").get("k").as_string(), "v");
    EXPECT_EQ(j.get("big").as_int(), 9223372036854775807LL);
    ASSERT_NE(j.find("o"), nullptr);
    EXPECT_EQ(j.find("zz"), nullptr);
    // What the writer emits, the reader takes back, and emits again unchanged.
    const std::string once = j.serialize();
    EXPECT_EQ(xbox2pc::json::parse(once).serialize(), once);
}

TEST(JsonReaderTest, RejectsMalformedAndUnboundedInput) {
    for (const char* bad : {"", "[1,]", "{\"a\":}", "{\"a\" 1}", "tru", "[1] x",
                            "\"\\ud800\"", "\"\\udc00\"", "\"unterminated", "[1 2]",
                            "{a: 1}", "1e", "-", "01a"}) {
        SCOPED_TRACE(bad);
        EXPECT_THROW(xbox2pc::json::parse(bad), xbox2pc::json::JsonParseError);
    }
    const std::string deep(xbox2pc::json::kMaxParseDepth + 2, '[');
    EXPECT_THROW(xbox2pc::json::parse(deep), xbox2pc::json::JsonParseError);
    std::string nested;
    for (int i = 0; i < xbox2pc::json::kMaxParseDepth; ++i) nested += "[";
    nested += "7";
    for (int i = 0; i < xbox2pc::json::kMaxParseDepth; ++i) nested += "]";
    EXPECT_NO_THROW(xbox2pc::json::parse(nested));
}

TEST(CensusTest, ClassifiesAggregatesAndRanksByImporters) {
    const auto dir = TwoFileDir("classify");
    const census::Report report = census::run({dir.string()}, census::Options{});
    ASSERT_EQ(report.files.size(), 2u);
    EXPECT_EQ(report.parsed_files, 2u);
    EXPECT_TRUE(report.trace_error.empty());
    const auto* missing = Find(report, "kernel32", "NoSuchCensusImport");
    ASSERT_NE(missing, nullptr);
    EXPECT_EQ(missing->status, census::Status::Missing);
    EXPECT_EQ(missing->descriptor_status, "none");
    EXPECT_EQ(missing->files, 2u);   // both spellings of the module count
    ASSERT_EQ(missing->importers.size(), 2u);
    const auto* exit_process = Find(report, "kernel32", "ExitProcess");
    ASSERT_NE(exit_process, nullptr);
    EXPECT_EQ(exit_process->status, census::Status::Implemented);
    EXPECT_EQ(exit_process->files, 1u);
    const auto* runtime_init = Find(report, "xgameruntime", "XGameRuntimeInitialize");
    ASSERT_NE(runtime_init, nullptr);
    EXPECT_NE(runtime_init->descriptor_status, "none");
    // Unreached rows: more importing files first, then dll!name.
    ASSERT_FALSE(report.imports.empty());
    EXPECT_EQ(report.imports.front().name, "NoSuchCensusImport");
    std::filesystem::remove_all(dir);
}

TEST(CensusTest, TraceRanksFirstReachAndMalformedTracesAreReported) {
    const auto dir = TwoFileDir("trace");
    const auto trace = dir / "run.json";
    {
        std::ofstream out(trace);
        out << "{\"outcome\": \"faulted\", \"first_unimplemented\": \"kernel32.dll!ExitProcess\"}\n";
    }
    const auto bad = dir / "bad.json";
    { std::ofstream out(bad); out << "{not json"; }
    census::Options options;
    options.traces = {trace.string(), (dir / "missing.json").string(), bad.string()};
    const census::Report report = census::run({dir.string()}, options);
    EXPECT_EQ(report.reached, 1u);
    ASSERT_FALSE(report.imports.empty());
    EXPECT_EQ(report.imports.front().name, "ExitProcess");
    EXPECT_EQ(report.imports.front().reach_rank, 1);
    EXPECT_EQ(report.imports.front().files, 1u);
    EXPECT_FALSE(report.trace_error.empty()) << report.trace_error;
    std::filesystem::remove_all(dir);
}

TEST(CensusTest, MissingOnlyKeepsOnlyUnimplementedRows) {
    const auto dir = TwoFileDir("missing");
    census::Options options;
    options.missing_only = true;
    const census::Report report = census::run({dir.string()}, options);
    EXPECT_EQ(Find(report, "kernel32", "ExitProcess"), nullptr);
    EXPECT_NE(Find(report, "kernel32", "NoSuchCensusImport"), nullptr);
    for (const auto& row : report.imports) EXPECT_NE(row.status, census::Status::Implemented);
    std::filesystem::remove_all(dir);
}

TEST(CensusTest, TextHasTheTableAndTheTriageBlockAndJsonHasStatus) {
    const auto dir = TwoFileDir("text");
    census::Options options;
    options.triage = 1;
    const census::Report report = census::run({dir.string()}, options);
    const std::string text = census::to_text(report, options);
    EXPECT_NE(text.find("2 of 2 file(s) parsed"), std::string::npos) << text;
    EXPECT_NE(text.find("STATUS        FILES  REACH  IMPORT"), std::string::npos) << text;
    EXPECT_NE(text.find("missing"), std::string::npos) << text;
    EXPECT_NE(text.find("Weekly triage (top 1"), std::string::npos) << text;
    EXPECT_NE(text.find("| 1 | kernel32!NoSuchCensusImport | missing | 2 | - |"), std::string::npos)
        << text;
    const std::string json = census::to_json(report, options).serialize();
    EXPECT_NE(json.find("\"status\": \"missing\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"parsed_files\": 2"), std::string::npos) << json;
    EXPECT_NE(json.find("\"reach_rank\": 0"), std::string::npos) << json;
    std::filesystem::remove_all(dir);
}

TEST(CensusTest, CliWritesJsonAndReturnsTheDocumentedStatus) {
    const auto dir = TwoFileDir("cli");
    const auto out = dir / "census.json";
    const std::string out_string = out.string();
    const std::string dir_string = dir.string();
    char arg0[] = "xbox2pc";
    char arg1[] = "census";
    char arg_json[] = "--json";
    char arg_triage[] = "--triage";
    char arg_three[] = "3";
    std::vector<char*> argv{arg0, arg1, const_cast<char*>(dir_string.c_str()),
                            arg_json, const_cast<char*>(out_string.c_str()),
                            arg_triage, arg_three, nullptr};
    EXPECT_EQ(census::cli(static_cast<int>(argv.size()) - 1, argv.data()), 0);
    std::ifstream in(out, std::ios::binary);
    const std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_NE(body.find("\"parsed_files\": 2"), std::string::npos) << body;
    // No path: usage. A trace that does not exist: reported, exit 1.
    char arg_trace[] = "--trace";
    const std::string nowhere = (dir / "nowhere.json").string();
    std::vector<char*> argv_bad{arg0, arg1, const_cast<char*>(dir_string.c_str()),
                                arg_trace, const_cast<char*>(nowhere.c_str()), nullptr};
    EXPECT_EQ(census::cli(static_cast<int>(argv_bad.size()) - 1, argv_bad.data()), 1);
    std::vector<char*> argv_usage{arg0, arg1, nullptr};
    EXPECT_EQ(census::cli(static_cast<int>(argv_usage.size()) - 1, argv_usage.data()), 2);
    std::filesystem::remove_all(dir);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
