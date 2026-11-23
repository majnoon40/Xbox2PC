#include <cstdint>
#include <gtest/gtest.h>
#include "xbox2pc/binary_validation.hpp"
#include "xbox2pc/pe_builder.hpp"
TEST(BinaryValidationTest, RejectsNullAndEmpty) {
    auto r=xbox2pc::validation::validate_pe(nullptr,0,"empty");
    EXPECT_FALSE(r.structurally_valid()); ASSERT_FALSE(r.stages.empty());
    EXPECT_EQ(r.stages.front().status,xbox2pc::validation::StageStatus::Failed);
}
TEST(BinaryValidationTest, RejectsTruncatedInput) {
    const std::uint8_t bytes[]={'M','Z',0,0};
    auto r=xbox2pc::validation::validate_pe(bytes,sizeof(bytes),"truncated");
    EXPECT_FALSE(r.structurally_valid());
}
TEST(BinaryValidationTest, ParsesSyntheticPeAndKeepsUnperformedStagesUntested) {
    xbox2pc::test::PeBuildSpec spec;
    spec.text_payloads.push_back({0x1000,{0x90,0xC3}});
    auto bytes=xbox2pc::test::PeBuilder(spec).build();
    auto r=xbox2pc::validation::validate_pe(bytes.data(),bytes.size(),"synthetic.exe");
    EXPECT_TRUE(r.parsed); EXPECT_TRUE(r.is_pe32_plus_amd64);
    ASSERT_EQ(r.stages.size(),6u);
    EXPECT_EQ(r.stages[4].status,xbox2pc::validation::StageStatus::NotTested);
}
