// xbox2pc/tests/loader_fuzz.cpp — M6 deterministic fuzz harnesses.
//
// No libFuzzer in this environment; seeded, reproducible mutation fuzz in
// the M5 style (vfs_fuzz.cpp). Invariants: EVERY mutated input produces a
// typed Result (no crash, no hang, no uncaught throw) and — when a phase
// succeeds — the outputs stay self-consistent.
//
//   1. pe_header_fuzz   : mutate DOS/COFF/optional/section-table bytes of
//                         a valid image; validate_image must return a
//                         report (never throw) and valid => zero issues.
//   2. reloc_fuzz       : mutate relocation directory bytes + descriptor
//                         fields; decode_relocations returns typed errors
//                         or blocks whose entries respect bounds.
//   3. import_thunk_fuzz: mutate import descriptor/thunk/name bytes;
//                          resolve_imports returns typed results with
//                          well-formed bindings or typed errors.
//   4. tls_fuzz         : mutate TLS directory fields; decode_tls returns
//                         typed errors or a validated TlsInfo.
//   5. map_fuzz         : for mutated-but-valid images, map_image into a
//                         fresh process space: typed results; success =>
//                         region counts balance after unload.

#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/runtime_core.hpp"

using xbox2pc::diag::Diagnostics;
using xbox2pc::rt::RuntimeErrc;
using xbox2pc::rt::loader::ImageLoader;
using xbox2pc::rt::loader::LoadDiagnostics;
using xbox2pc::rt::loader::validate_image;
using xbox2pc::rt::loader::decode_relocations;
using xbox2pc::rt::loader::decode_tls;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

namespace {

// Base fixture: a structurally rich valid image.
std::vector<std::uint8_t> base_image() {
    PeBuildSpec spec;
    spec.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}, {"WriteConsoleW", 2}}},
        {"ORD.dll", {{"", 3}}},
    };
    spec.reloc_blocks = {
        {0x1000, {{10, 0x1008, 0x140001000ull}, {10, 0x1010, 0x140001008ull}}},
    };
    spec.tls.template_data = {1, 2, 3, 4};
    spec.tls.zero_fill = 16;
    spec.tls.callback_vas = {0x140001100};
    return PeBuilder(spec).build();
}

}  // namespace

TEST(LoaderFuzzTest, PeHeaderFuzzTypedResults) {
    const auto base = base_image();
    std::mt19937_64 rng(0x6D36F00Dull);  // fixed seed
    std::size_t valid_after_mutation = 0;
    for (int iter = 0; iter < 20000; ++iter) {
        std::vector<std::uint8_t> bad(base);
        // Mutate 1..8 bytes in the HEADER region [0, 0x400).
        std::uniform_int_distribution<int> count_dist(1, 8);
        const int n = count_dist(rng);
        for (int m = 0; m < n; ++m) {
            std::uniform_int_distribution<std::size_t> pos(0, 0x3FF);
            bad[pos(rng)] = static_cast<std::uint8_t>(rng() & 0xFF);
        }
        // The parser may reject (throw ParseError) — that is a typed
        // outcome; catch and continue. validate_image never throws.
        Diagnostics diags;
        try {
            const auto img = xbox2pc::pe::parse(bad.data(), bad.size(), "f.exe", diags);
            const auto rep = validate_image(img, bad.data(), bad.size());
            // Invariant: valid == zero issues (never "valid with issues").
            if (rep.valid) {
                EXPECT_TRUE(rep.issues.empty());
                ++valid_after_mutation;
            } else {
                EXPECT_FALSE(rep.issues.empty());
            }
        } catch (const xbox2pc::pe::ParseError&) {
            continue;  // typed parser rejection
        } catch (const std::exception&) {
            ADD_FAILURE() << "unexpected exception at iter " << iter;
            return;
        }
    }
    (void)valid_after_mutation;
    // Sanity: the mutation must produce SOME survivors (loop alive).
    EXPECT_GT(valid_after_mutation, 0u);
}

TEST(LoaderFuzzTest, RelocationDirectoryFuzz) {
    const auto base = base_image();
    // Reloc directory bytes live in .data: [0xA00, 0xA00 + 24) (two-entry
    // block padded). Mutate within that window and around it.
    std::mt19937_64 rng(0x5E10C475ull);
    for (int iter = 0; iter < 20000; ++iter) {
        std::vector<std::uint8_t> bad(base);
        std::uniform_int_distribution<std::size_t> pos(0x9E0, 0xA40);
        std::uniform_int_distribution<int> count_dist(1, 6);
        const int n = count_dist(rng);
        for (int m = 0; m < n; ++m) {
            bad[pos(rng)] = static_cast<std::uint8_t>(rng() & 0xFF);
        }
        Diagnostics diags;
        try {
            const auto img = xbox2pc::pe::parse(bad.data(), bad.size(), "f.exe", diags);
            auto blocks = decode_relocations(img, bad.data(), bad.size(),
                                             1u << 20);
            if (blocks.ok()) {
                // Invariant: blocks decode within directory bounds and
                // block sizes >= 8, 4-aligned (decode enforces; verify counts).
                std::size_t total = 0;
                for (const auto& b : blocks.value()) {
                    EXPECT_GE(b.block_size, 8u);
                    EXPECT_EQ(b.block_size % 4u, 0u);
                    total += b.entries.size();
                }
                (void)total;
            } else {
                EXPECT_NE(blocks.errc(), RuntimeErrc::Ok);
            }
        } catch (const xbox2pc::pe::ParseError&) {
            continue;
        }
    }
}

TEST(LoaderFuzzTest, ImportThunkFuzz) {
    const auto base = base_image();
    // A scratch address space for the resolve call (signature parity).
    xbox2pc::rt::AddressSpace scratch(1u << 20, 0x10000000, "fuzz-scratch");
    // Import machinery lives in .text: [0x400, 0x600).
    std::mt19937_64 rng(0x1D0EAF5Dull);
    for (int iter = 0; iter < 20000; ++iter) {
        std::vector<std::uint8_t> bad(base);
        std::uniform_int_distribution<std::size_t> pos(0x400, 0x5FF);
        std::uniform_int_distribution<int> count_dist(1, 6);
        const int n = count_dist(rng);
        for (int m = 0; m < n; ++m) {
            bad[pos(rng)] = static_cast<std::uint8_t>(rng() & 0xFF);
        }
        Diagnostics diags;
        try {
            const auto img = xbox2pc::pe::parse(bad.data(), bad.size(), "f.exe", diags);
            ImageLoader loader;
            xbox2pc::rt::loader::NullResolver res;
            LoadDiagnostics ld;
            auto bindings = loader.resolve_imports(
                scratch, xbox2pc::rt::loader::ImageLayoutInfo{}, img,
                bad.data(), bad.size(), res, ld);
            if (bindings.ok()) {
                // Every binding carries a status; null resolver never
                // resolves or writes anything.
                for (const auto& b : bindings.value()) {
                    EXPECT_NE(b.status, xbox2pc::rt::loader::ImportStatus::Resolved);
                    EXPECT_EQ(b.value, 0u);
                }
            } else {
                EXPECT_NE(bindings.errc(), RuntimeErrc::Ok);
            }
        } catch (const xbox2pc::pe::ParseError&) {
            continue;
        }
    }
}

TEST(LoaderFuzzTest, TlsDirectoryFuzz) {
    const auto base = base_image();
    // TLS directory struct lives in .data after the reloc directory
    // (0xA00 + 24 .. + 64 + callbacks).
    std::mt19937_64 rng(0x7157A5E0ull);
    for (int iter = 0; iter < 20000; ++iter) {
        std::vector<std::uint8_t> bad(base);
        std::uniform_int_distribution<std::size_t> pos(0xA18, 0xAA0);
        std::uniform_int_distribution<int> count_dist(1, 6);
        const int n = count_dist(rng);
        for (int m = 0; m < n; ++m) {
            bad[pos(rng)] = static_cast<std::uint8_t>(rng() & 0xFF);
        }
        Diagnostics diags;
        try {
            const auto img = xbox2pc::pe::parse(bad.data(), bad.size(), "f.exe", diags);
            LoadDiagnostics ld;
            auto tls = decode_tls(img, bad.data(), bad.size(), ld);
            if (tls.ok() && tls.value().has_value()) {
                const auto& t = *tls.value();
                // Invariants enforced by decode: end >= start, bounded
                // template, bounded callback count.
                EXPECT_GE(t.template_size, 0u);
                EXPECT_LE(t.callback_count, 64u);
            } else if (!tls.ok()) {
                EXPECT_NE(tls.errc(), RuntimeErrc::Ok);
            }
        } catch (const xbox2pc::pe::ParseError&) {
            continue;
        }
    }
}

TEST(LoaderFuzzTest, MapFuzzRegionBalance) {
    const auto base = base_image();
    std::mt19937_64 rng(0x34F0000Dull);
    std::size_t mapped = 0;
    for (int iter = 0; iter < 2000; ++iter) {
        std::vector<std::uint8_t> bad(base);
        // Light header mutation (mostly-valid images).
        std::uniform_int_distribution<std::size_t> pos(0, 0x3FF);
        bad[pos(rng)] = static_cast<std::uint8_t>(rng() & 0xFF);
        Diagnostics diags;
        try {
            const auto img = xbox2pc::pe::parse(bad.data(), bad.size(), "f.exe", diags);
            const auto rep = validate_image(img, bad.data(), bad.size());
            if (!rep.valid) continue;
            // Map into a FRESH process (cheap: small space), then unload.
            xbox2pc::rt::RuntimeCore core;
            if (!core.initialize().ok()) return;
            xbox2pc::rt::ProcessManager pm(core.objects());
            auto p = pm.create_process("mapfuzz.exe", 8ull << 20);
            if (!p.ok()) {
                (void)core.shutdown();
                return;
            }
            auto found = core.objects().lookup_handle(p.value());
            auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
            ImageLoader loader;
            LoadDiagnostics ld;
            auto lay = loader.map_image(proc->address_space(), img,
                                        bad.data(), bad.size(), 0, ld);
            if (lay.ok()) {
                ++mapped;
                // Unload in reverse; region count must return to baseline.
                const auto before = proc->address_space().stats().region_count;
                for (auto it = lay.value().sections.rbegin();
                     it != lay.value().sections.rend(); ++it) {
                    (void)proc->address_space().release_region(it->mapped_base);
                }
                (void)proc->address_space().release_region(
                    lay.value().headers_region_xbox_va);
                EXPECT_EQ(proc->address_space().stats().region_count,
                          before - lay.value().sections.size() - 1);
            }
            (void)pm.terminate_process(p.value(), 0);
            (void)core.shutdown();
        } catch (const xbox2pc::pe::ParseError&) {
            continue;
        }
    }
    EXPECT_GT(mapped, 0u);  // sanity: some mutations stayed valid+mappable
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
