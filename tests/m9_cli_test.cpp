#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/m9_cli.hpp"
#include "xbox2pc/pe_builder.hpp"

namespace {

int run_command(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    return xbox2pc::cli::run_m9_binary_cli(
        static_cast<int>(argv.size()), argv.data());
}

}  // namespace

TEST(M9CliTest, AllNineBinaryCommandsProduceJsonForSyntheticPe) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("xbox2pc-m9-cli-" + std::to_string(nonce));
    std::filesystem::create_directories(root);
    const auto input = root / "fixture.exe";

    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, {0x90, 0xC3}});
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();
    {
        std::ofstream file(input, std::ios::binary);
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(file.good());
    }

    const std::vector<std::string> commands = {
        "binary-analyze", "binary-info", "binary-sections", "binary-imports",
        "binary-relocations", "binary-tls", "binary-instructions",
        "binary-compat", "binary-report"
    };
    for (const auto& command : commands) {
        const auto output = root / (command + ".json");
        EXPECT_EQ(run_command({"xbox2pc", command, input.string(),
                               "--json", output.string()}), 0) << command;
        ASSERT_TRUE(std::filesystem::exists(output)) << command;
        std::ifstream file(output, std::ios::binary);
        const std::string json((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
        EXPECT_FALSE(json.empty()) << command;
        if (command == "binary-compat") {
            EXPECT_NE(json.find("xbox2pc.binary-compatibility"), std::string::npos);
            EXPECT_NE(json.find("\"overall\""), std::string::npos);
            EXPECT_NE(json.find("\"UNKNOWN\""), std::string::npos);
        }
    }
    std::filesystem::remove_all(root);
}

TEST(M9CliTest, UnknownCommandIsLeftForLegacyCli) {
    char program[] = "xbox2pc";
    char command[] = "inspect";
    char* argv[] = {program, command};
    EXPECT_EQ(xbox2pc::cli::run_m9_binary_cli(2, argv), -1);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
