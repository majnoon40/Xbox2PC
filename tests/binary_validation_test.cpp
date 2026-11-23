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
    EXPECT_EQ(report.stages[5].status,
              xbox2pc::validation::StageStatus::NotTested);
}


TEST(BinaryValidationTest, DecodesRelocationsAndTlsWithoutExecutingCallbacks) {
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000, {0x90, 0xC3}});
    spec.reloc_blocks = {
        {0x1000, {{10, 0x1008, 0x140001000ull}}},
    };
    spec.tls.template_data = {1, 2, 3, 4};
    spec.tls.zero_fill = 16;
    spec.tls.callback_vas = {0x140001000ull};
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();

    const auto report = xbox2pc::validation::validate_pe(
        bytes.data(), bytes.size(), "reloc-tls.exe");

    ASSERT_EQ(report.stages.size(), 6u);
    EXPECT_NE(report.stages[3].status,
              xbox2pc::validation::StageStatus::Failed);
    EXPECT_NE(report.stages[4].status,
              xbox2pc::validation::StageStatus::Failed);
    EXPECT_NE(report.stages[4].status,
              xbox2pc::validation::StageStatus::NotTested);
    // Validation reports callback metadata only; it never executes callbacks.
}

TEST(BinaryValidationTest, RejectsDirectoriesWithOnlyAnRvaOrOnlyASize) {
    xbox2pc::test::PeBuildSpec spec;
    const auto base = xbox2pc::test::PeBuilder(spec).build();
    const auto validate_directory = [&](std::uint16_t directory_index,
                                        std::size_t expected_stage,
                                        bool set_rva) {
        auto bytes = base;
        // PE32+ data directories start at optional-header offset 112.
        constexpr std::size_t kDirectoriesOffset = 0x98 + 112;
        const std::size_t entry = kDirectoriesOffset +
            static_cast<std::size_t>(directory_index) * 8;
        const std::uint32_t value = set_rva ? 0x2000u : 0u;
        const std::uint32_t size = set_rva ? 0u : 8u;
        for (unsigned i = 0; i < 4; ++i) {
            bytes[entry + i] = static_cast<std::uint8_t>(value >> (i * 8));
            bytes[entry + 4 + i] = static_cast<std::uint8_t>(size >> (i * 8));
        }

        const auto report = xbox2pc::validation::validate_pe(
            bytes.data(), bytes.size(), "inconsistent-directory.exe");
        EXPECT_FALSE(report.structurally_valid());
        ASSERT_EQ(report.stages.size(), 6u);
        EXPECT_EQ(report.stages[expected_stage].status,
                  xbox2pc::validation::StageStatus::Failed);
    };

    validate_directory(1, 2, true);   // import
    validate_directory(5, 3, true);   // relocation
    validate_directory(9, 4, true);   // TLS
    validate_directory(13, 2, true);  // delay import
    validate_directory(5, 3, false);  // nonzero size with zero RVA
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
