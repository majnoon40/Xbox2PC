#include <cstdint>

#include <gtest/gtest.h>

#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/static_analysis.hpp"

TEST(StaticAnalysisTest, FindsDecoderConfirmedSyntheticInstructions) {
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, {0x90, 0xC3}});
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    const auto report =
        xbox2pc::analysis::analyze_pe(bytes.data(), bytes.size(), "synthetic.exe");

    ASSERT_TRUE(report.parsed);
    ASSERT_TRUE(report.is_pe32_plus_amd64);
    ASSERT_GE(report.confirmed_instructions.size(), 2u);
    EXPECT_EQ(report.confirmed_instructions[0].text, "nop");
    EXPECT_EQ(report.confirmed_instructions[1].text, "ret");
    ASSERT_GE(report.notes.size(), 2u);
}

TEST(StaticAnalysisTest, RejectsWrongArchitectureWithoutScanning) {
    xbox2pc::test::PeBuildSpec spec;
    spec.machine = 0x14C;
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    const auto report =
        xbox2pc::analysis::analyze_pe(bytes.data(), bytes.size(), "i386.exe");

    EXPECT_TRUE(report.parsed);
    EXPECT_FALSE(report.is_pe32_plus_amd64);
    EXPECT_TRUE(report.confirmed_instructions.empty());
    EXPECT_FALSE(report.notes.empty());
}

TEST(StaticAnalysisTest, ReportsFsSegmentUse) {
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back(
        {0x1000, {0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}});
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    const auto report =
        xbox2pc::analysis::analyze_pe(bytes.data(), bytes.size(), "fs-access.exe");

    ASSERT_TRUE(report.parsed);
    ASSERT_FALSE(report.fs_gs_uses.empty());
    EXPECT_EQ(report.fs_gs_uses.front().segment, "FS");
}

TEST(StaticAnalysisTest, HandlesNullAndEmptyInput) {
    const auto report = xbox2pc::analysis::analyze_pe(nullptr, 0, "empty");
    EXPECT_FALSE(report.parsed);
    EXPECT_FALSE(report.notes.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
