#include <algorithm>
#include <cstdint>
#include <random>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/binary_validation.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/static_analysis.hpp"
#include "xbox2pc/x64_decoder.hpp"

TEST(M9FuzzTest, DecoderTwoHundredThousandDeterministicMutations) {
    std::mt19937_64 rng(0x4D394445434F4445ull);
    std::uint64_t accepted = 0;
    for (std::uint32_t iteration = 0; iteration < 200000; ++iteration) {
        const std::size_t length = static_cast<std::size_t>(rng() % 33);
        std::vector<std::uint8_t> bytes(length);
        for (auto& byte : bytes) byte = static_cast<std::uint8_t>(rng());
        const auto result = xbox2pc::rt::x64::decode(
            bytes.empty() ? nullptr : bytes.data(), bytes.size(),
            0x140000000ull + iteration);
        if (result.status == xbox2pc::rt::x64::DecodeStatus::Ok) {
            ++accepted;
            EXPECT_GT(result.ins.length, 0u);
            EXPECT_LE(result.ins.length, xbox2pc::rt::x64::kMaxInstructionBytes);
            EXPECT_LE(result.ins.length, bytes.size());
            EXPECT_EQ(result.consumed, result.ins.length);
        } else {
            EXPECT_EQ(result.ins.length, 0u);
            EXPECT_LE(result.consumed, bytes.size());
            EXPECT_LE(result.consumed, xbox2pc::rt::x64::kMaxInstructionBytes);
            EXPECT_NE(result.reason, nullptr);
        }
    }
    EXPECT_GT(accepted, 0u);
}

TEST(M9FuzzTest, MutatedSyntheticPeValidationAndStaticAnalysis) {
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back(
        {0x1000, {0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0, 0, 0, 0xC3}});
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    spec.reloc_blocks = {{0x2000, {{10, 0x2008, 0x140000000ull}}}};
    spec.tls.template_data = {1, 2, 3, 4};
    spec.tls.zero_fill = 8;
    const auto base = xbox2pc::test::PeBuilder(spec).build();

    std::mt19937_64 rng(0x4D39504546555A5Aull);
    std::uint64_t parsed = 0;
    for (std::uint32_t iteration = 0; iteration < 10000; ++iteration) {
        auto mutated = base;
        const std::uint32_t count = 1u + static_cast<std::uint32_t>(rng() % 8);
        for (std::uint32_t n = 0; n < count; ++n) {
            const std::size_t offset = static_cast<std::size_t>(rng() % mutated.size());
            mutated[offset] ^= static_cast<std::uint8_t>(1u << (rng() % 8));
        }

        xbox2pc::diag::Diagnostics diagnostics;
        try {
            const auto image = xbox2pc::pe::parse(
                mutated.data(), mutated.size(), "m9-fuzz.exe", diagnostics);
            ++parsed;
            const auto validation = xbox2pc::validation::validate_pe(
                mutated.data(), mutated.size(), "m9-fuzz.exe");
            const auto analysis = xbox2pc::analysis::analyze_pe(
                mutated.data(), mutated.size(), "m9-fuzz.exe");
            EXPECT_EQ(validation.parsed, true);
            EXPECT_EQ(analysis.parsed, true);
            EXPECT_EQ(image.sections.size(), image.sections.size());
        } catch (const xbox2pc::pe::ParseError&) {
            // A malformed mutation is an expected typed rejection.
        } catch (const std::exception& error) {
            FAIL() << "unexpected exception at mutation " << iteration
                   << ": " << error.what();
        }
    }
    EXPECT_GT(parsed, 0u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
