#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "xbox2pc/binary_validation.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/static_analysis.hpp"
#include "xbox2pc/x64_decoder.hpp"

int main() {
    using Clock = std::chrono::steady_clock;
    const auto elapsed_ms = [](Clock::time_point start) {
        return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    };

    xbox2pc::test::PeBuildSpec spec;
    std::vector<std::uint8_t> code;
    for (int i = 0; i < 256; ++i) {
        const std::uint8_t add[] = {0x48, 0x83, 0xC0, 0x01};
        code.insert(code.end(), add, add + sizeof(add));
    }
    code.push_back(0xC3);
    spec.text_payloads.push_back({0x1000, code});
    spec.imports = {{"xgameruntime", {{"XGameRuntimeInitialize", 1}}}};
    const auto bytes = xbox2pc::test::PeBuilder(spec).build();
    xbox2pc::diag::Diagnostics diagnostics;
    const auto image = xbox2pc::pe::parse(
        bytes.data(), bytes.size(), "m9-benchmark-synthetic.exe", diagnostics);

    constexpr std::uint64_t kDecodeIterations = 2'000'000;
    const std::uint8_t sample[] = {0x48, 0x83, 0xC0, 0x01};
    auto start = Clock::now();
    std::uint64_t decoded = 0;
    for (std::uint64_t i = 0; i < kDecodeIterations; ++i) {
        const auto result = xbox2pc::rt::x64::decode(sample, sizeof(sample), 0x1000);
        decoded += result.status == xbox2pc::rt::x64::DecodeStatus::Ok ? 1u : 0u;
    }
    const double decode_ms = elapsed_ms(start);
    std::printf("M9 synthetic benchmarks (steady_clock; local build environment)\n");
    std::printf("decoder: %.3f ns/instruction (%llu/%llu decoded)\n",
                decode_ms * 1e6 / static_cast<double>(kDecodeIterations),
                static_cast<unsigned long long>(decoded),
                static_cast<unsigned long long>(kDecodeIterations));

    constexpr std::uint64_t kValidationIterations = 10000;
    start = Clock::now();
    std::uint64_t valid = 0;
    for (std::uint64_t i = 0; i < kValidationIterations; ++i) {
        const auto report = xbox2pc::validation::validate_pe(
            bytes.data(), bytes.size(), "m9-benchmark-synthetic.exe");
        valid += report.structurally_valid() ? 1u : 0u;
    }
    const double validation_ms = elapsed_ms(start);
    std::printf("PE structural validation: %.3f us/file (%llu/%llu structurally valid)\n",
                validation_ms * 1000.0 / static_cast<double>(kValidationIterations),
                static_cast<unsigned long long>(valid),
                static_cast<unsigned long long>(kValidationIterations));

    constexpr std::uint64_t kAnalysisIterations = 1000;
    start = Clock::now();
    std::uint64_t instruction_count = 0;
    for (std::uint64_t i = 0; i < kAnalysisIterations; ++i) {
        const auto report = xbox2pc::analysis::analyze_pe(
            bytes.data(), bytes.size(), "m9-benchmark-synthetic.exe");
        instruction_count += report.confirmed_instructions.size();
    }
    const double analysis_ms = elapsed_ms(start);
    std::printf("static analysis: %.3f us/file (%.1f confirmed decodes/file)\n",
                analysis_ms * 1000.0 / static_cast<double>(kAnalysisIterations),
                static_cast<double>(instruction_count) /
                    static_cast<double>(kAnalysisIterations));
    std::printf("fixture: %zu bytes; synthetic only; no Xbox title compatibility claim\n",
                bytes.size());
    return (decoded == kDecodeIterations && valid == kValidationIterations) ? 0 : 1;
}
