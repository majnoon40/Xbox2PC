#include <cstdint>

#include <gtest/gtest.h>

#include "xbox2pc/binary_validation.hpp"
#include "xbox2pc/pe_builder.hpp"

TEST(BinaryValidationTest, RejectsNullAndEmpty) {
    const auto report = xbox2pc::validation::validate_pe(nullptr, 0, "empty");
    EXPECT_FALSE(report.structurally_valid());
    ASSERT_FALSE(report.stages.empty());
    EXPECT_EQ(report.stages.front().status,
              xbox2pc::validation::StageStatus::Failed);
}

TEST(BinaryValidationTest, RejectsTruncatedInput) {
    const std::uint8_t bytes[] = {'M', 'Z', 0, 0};
    const auto report =
        xbox2pc::validation::validate_pe(bytes, sizeof(bytes), "truncated");
    EXPECT_FALSE(report.structurally_valid());
}

TEST(BinaryValidationTest, ParsesSyntheticPeAndKeepsUnperformedStagesUntested) {
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, {0x90, 0xC3}});
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    const auto report = xbox2pc::validation::validate_pe(
        bytes.data(), bytes.size(), "synthetic.exe");

    EXPECT_TRUE(report.parsed);
    EXPECT_TRUE(report.is_pe32_plus_amd64);
    ASSERT_EQ(report.stages.size(), 6u);
    EXPECT_TRUE(report.structurally_valid());
    EXPECT_EQ(report.stages[4].status,
              xbox2pc::validation::StageStatus::NotTested);
}

TEST(BinaryValidationTest, RejectsNonAmd64Machine) {
    xbox2pc::test::PeBuildSpec spec;
    spec.machine = 0x14C;  // I386
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    const auto report = xbox2pc::validation::validate_pe(
        bytes.data(), bytes.size(), "i386.exe");

    EXPECT_TRUE(report.parsed);
    EXPECT_FALSE(report.is_pe32_plus_amd64);
    EXPECT_FALSE(report.structurally_valid());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
