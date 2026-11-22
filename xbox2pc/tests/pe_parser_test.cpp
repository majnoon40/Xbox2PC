// PE parser GoogleTest suites — M1 acceptance tests.
//
// Every test binary is generated in-memory by pe_builder (no fixtures from
// disk, no platform toolchain dependence). Malformed inputs are derived by
// mutating fields of an otherwise-valid image so each failure mode is
// isolated and independently asserted.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"

using xbox2pc::diag::Diagnostics;
using xbox2pc::diag::Severity;
using xbox2pc::pe::ParseError;
using xbox2pc::pe::PeImage;
using xbox2pc::test::ImportDll;
using xbox2pc::test::ImportFunc;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

namespace {

PeBuildSpec default_spec() {
    PeBuildSpec s;
    s.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}, {"ReadFile", 2}, {"", 7 /*ordinal-only*/}}},
        {"XboxOneNativeApi.dll", {{"XamGetGamepadState", 3}, {"XThreadCreate", 4}}},
    };
    s.exports = {
        {"XblInitialize", 0x1080, ""},
        {"", 0, ""},                            // unnamed export
        {"XblCleanup", 0x10C0, "XboxOneNativeApi.XblInitCore"},  // forwarder
    };
    return s;
}

std::vector<std::uint8_t> default_image() {
    return PeBuilder(default_spec()).build();
}

PeImage parse_ok(const std::vector<std::uint8_t>& buf, Diagnostics& diags) {
    return xbox2pc::pe::parse(buf.data(), buf.size(), "test-image", diags);
}

}  // namespace

// ── Valid PE32+ files ────────────────────────────────────────────────────

TEST(ValidPeTest, ParsesAndClassifies) {
    Diagnostics diags;
    const PeImage img = parse_ok(default_image(), diags);
    EXPECT_TRUE(img.is_x86_64());
    EXPECT_TRUE(img.opt.is_pe32plus);
    EXPECT_EQ(img.coff.machine, 0x8664);
    EXPECT_EQ(img.e_lfanew, 0x80);
    EXPECT_EQ(img.sections.size(), 3u);
    EXPECT_EQ(img.sections[0].name, ".text");
    EXPECT_EQ(img.sections[1].name, ".rdata");
    EXPECT_EQ(img.sections[2].name, ".data");
}

TEST(ValidPeTest, OptionalHeaderFields) {
    Diagnostics diags;
    const PeImage img = parse_ok(default_image(), diags);
    EXPECT_EQ(img.opt.image_base, 0x140000000);
    EXPECT_EQ(img.opt.address_of_entry_point, 0x1000);
    EXPECT_EQ(img.opt.subsystem, 3);
    EXPECT_GT(img.opt.size_of_image, 0u);
    EXPECT_TRUE(img.entry_point_va().has_value());
    EXPECT_EQ(*img.entry_point_va(), 0x140001000ull);
}

TEST(ValidPeTest, ImportTableDecoded) {
    Diagnostics diags;
    const PeImage img = parse_ok(default_image(), diags);
    ASSERT_TRUE(img.imports.present);
    ASSERT_EQ(img.imports.entries.size(), 2u);

    const auto& k32 = img.imports.entries[0];
    EXPECT_EQ(k32.dll_name, "KERNEL32.dll");
    ASSERT_EQ(k32.functions.size(), 2u);
    EXPECT_EQ(k32.functions[0], "CreateFileW");
    EXPECT_EQ(k32.functions[1], "ReadFile");
    ASSERT_EQ(k32.ordinal_only.size(), 1u);
    EXPECT_EQ(k32.ordinal_only[0], 7u);

    const auto& xna = img.imports.entries[1];
    EXPECT_EQ(xna.dll_name, "XboxOneNativeApi.dll");
    ASSERT_EQ(xna.functions.size(), 2u);
    EXPECT_EQ(xna.functions[0], "XamGetGamepadState");
    EXPECT_EQ(xna.functions[1], "XThreadCreate");
}

TEST(ValidPeTest, ExportTableDecoded) {
    Diagnostics diags;
    const PeImage img = parse_ok(default_image(), diags);
    ASSERT_TRUE(img.exports.present);
    EXPECT_EQ(img.exports.dll_name, "Xbox2PCTest.dll");
    ASSERT_EQ(img.exports.functions.size(), 3u);

    EXPECT_EQ(img.exports.functions[0].name, "XblInitialize");
    EXPECT_EQ(img.exports.functions[0].ordinal, 1u);
    EXPECT_TRUE(img.exports.functions[1].name.empty());  // unnamed
    EXPECT_EQ(img.exports.functions[2].name, "XblCleanup");
    EXPECT_EQ(img.exports.functions[2].forwarder, "XboxOneNativeApi.XblInitCore");
}

TEST(ValidPeTest, RvaToOffsetRoundTrip) {
    Diagnostics diags;
    const PeImage img = parse_ok(default_image(), diags);
    // .text spans RVA 0x1000..; file offset 0x400..
    const auto off = xbox2pc::pe::rva_to_offset(img, 0x1000);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, 0x400u);
    // rdata
    const auto rd = xbox2pc::pe::rva_to_offset(img, img.sections[1].virtual_address);
    ASSERT_TRUE(rd.has_value());
    EXPECT_EQ(*rd, 0x400u + img.sections[0].size_of_raw_data);
    // outside image
    EXPECT_FALSE(xbox2pc::pe::rva_to_offset(img, 0x7FFFFFF0).has_value());
    // .text virtual-only tail (beyond raw size but within vsize if bigger)
    const auto& t = img.sections[0];
    const std::uint32_t beyond = t.virtual_address + t.size_of_raw_data + 0x10;
    EXPECT_FALSE(xbox2pc::pe::rva_to_offset(img, beyond).has_value());
}

TEST(ValidPeTest, CleanImageNoWarnings) {
    Diagnostics diags;
    parse_ok(default_image(), diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_FALSE(diags.has_warnings()) << "unexpected warnings:";  // message via lines below
    for (const auto& l : diags.lines()) ADD_FAILURE() << l;
}

TEST(ValidPeTest, DataDirectoriesPresent) {
    Diagnostics diags;
    const PeImage img = parse_ok(default_image(), diags);
    ASSERT_GE(img.directories.size(), 2u);
    EXPECT_NE(img.directories[0].rva, 0u);  // export
    EXPECT_NE(img.directories[1].rva, 0u);  // import
    EXPECT_EQ(img.directories[2].rva, 0u);  // resource: absent
}

TEST(ValidPeTest, EmptyImageNoImports) {
    PeBuildSpec s;  // defaults: no imports, no exports
    Diagnostics diags;
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    EXPECT_FALSE(img.imports.present);
    EXPECT_FALSE(img.exports.present);
    EXPECT_EQ(img.sections.size(), 3u);
    EXPECT_FALSE(diags.has_errors());
}

// ── Invalid signatures ──────────────────────────────────────────────────

TEST(InvalidSignatureTest, MissingMz) {
    auto buf = default_image();
    buf[0] = 'X';  // break MZ
    Diagnostics diags;
    EXPECT_THROW(parse_ok(buf, diags), ParseError);
}

TEST(InvalidSignatureTest, MissingPeSignature) {
    auto buf = default_image();
    const std::uint64_t pe = 0x80;
    buf[pe] = 'P'; buf[pe + 1] = 'E'; buf[pe + 2] = 'X'; buf[pe + 3] = 'X';
    Diagnostics diags;
    EXPECT_THROW(parse_ok(buf, diags), ParseError);
}

TEST(InvalidSignatureTest, EmptyFile) {
    Diagnostics diags;
    EXPECT_THROW(xbox2pc::pe::parse(nullptr, 0, "empty", diags), ParseError);
}

TEST(InvalidSignatureTest, GarbageHeader) {
    std::vector<std::uint8_t> buf(64, 0xAB);
    Diagnostics diags;
    EXPECT_THROW(parse_ok(buf, diags), ParseError);
}

TEST(InvalidSignatureTest, ELfanewOutOfRange) {
    // Build a valid image, then point e_lfanew far beyond the file.
    // (Patching bytes directly avoids making the builder allocate a 4 GiB
    // buffer at the bogus offset — the builder writes headers at e_lfanew.)
    auto buf = default_image();
    buf[0x3C] = 0xF0; buf[0x3D] = 0xFF; buf[0x3E] = 0xFF; buf[0x3F] = 0xFF;
    Diagnostics diags;
    EXPECT_THROW(parse_ok(buf, diags), ParseError);
}

TEST(InvalidSignatureTest, ELfanewTooSmall) {
    // e_lfanew pointing inside the DOS header is rejected
    auto buf = default_image();
    buf[0x3C] = 0x08; buf[0x3D] = 0x00; buf[0x3E] = 0x00; buf[0x3F] = 0x00;
    Diagnostics diags;
    EXPECT_THROW(parse_ok(buf, diags), ParseError);
}

// ── Truncated headers ────────────────────────────────────────────────────

TEST(TruncatedTest, CutEverywhere) {
    const auto full = default_image();
    // Layout: PE sig 0x80 + COFF 20 + optional 240 -> section table at 0x188.
    const std::size_t sect_table = 0x80 + 4 + 20 + 240;
    // Cuts before the section table or removing any header field must fail
    // (ParseError only). Note: cuts *inside* the section table region do NOT
    // hard-fail — the parser clamps to whole entries and warns (recovery
    // path asserted below), which is intended inspection behavior.
    const std::vector<std::size_t> must_fail = {
        1, 63, 64,             // DOS header
        0x3C, 0x40,            // e_lfanew field
        0x80, 0x83,            // PE signature
        0x84, 0x97,            // COFF header
        0x98, 0x9D,            // optional header start
        0x100, 0x180,          // inside optional header (spans 0x98..0x188)
        0x184,                 // inside data directories
        sect_table - 1,        // last header byte missing (0x187)
    };
    for (std::size_t n : must_fail) {
        if (n >= full.size()) continue;
        std::vector<std::uint8_t> cut(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(n));
        Diagnostics diags;
        try {
            parse_ok(cut, diags);
            ADD_FAILURE() << "truncated file at " << n << " parsed without error";
        } catch (const ParseError&) {
            SUCCEED();
        } catch (...) {
            ADD_FAILURE() << "truncated file at " << n << " threw a non-ParseError exception";
        }
    }
    // Cuts inside the section table: parser clamps to whole entries, warns,
    // and still returns a usable image (recovery path, not failure).
    const std::vector<std::size_t> recovers = {
        sect_table + 39,       // 0 complete entries? (39/40 -> 0)
        sect_table + 80,       // exactly 2 entries
        sect_table + 119,      // 2 entries + partial third
    };
    for (std::size_t n : recovers) {
        std::vector<std::uint8_t> cut(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(n));
        Diagnostics diags;
        const PeImage img = parse_ok(cut, diags);
        EXPECT_TRUE(diags.has_warnings());
        EXPECT_LE(img.sections.size(), 3u);
    }
}

TEST(TruncatedTest, CutSectionContent) {
    // Truncating file inside section content: header parse still succeeds
    // (sections marked no-raw-data), a warning is recorded.
    const auto full = default_image();
    std::vector<std::uint8_t> cut(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(full.size() - 1));
    Diagnostics diags;
    const PeImage img = parse_ok(cut, diags);
    EXPECT_FALSE(diags.has_errors());
    // last byte of .data removed -> .data warned
    EXPECT_TRUE(diags.has_warnings());
}

// ── Invalid section offsets ──────────────────────────────────────────────

TEST(SectionTest, RawOffsetBeyondEof) {
    auto buf = default_image();
    // Section table begins after optional header; .text entry 0 raw offset at +20.
    const std::uint64_t pe = 0x80;
    const std::uint32_t opt_size = 240;
    const std::uint64_t sect_table = pe + 24 + opt_size;
    // .rdata (entry 1) PointerToRawData at sect_table + 40 + 20.
    const std::uint64_t ptr_off = sect_table + 40 + 20;
    buf[ptr_off + 0] = 0xFF; buf[ptr_off + 1] = 0xFF; buf[ptr_off + 2] = 0xFF; buf[ptr_off + 3] = 0x7F;
    Diagnostics diags;
    const PeImage img = parse_ok(buf, diags);
    EXPECT_FALSE(diags.has_errors());       // recoverable: warning path
    EXPECT_TRUE(diags.has_warnings());
    EXPECT_FALSE(img.sections[1].has_raw_data);
}

TEST(SectionTest, NumberOfSectionsTooLarge) {
    // 200 claimed sections: parser first caps the sanity bound at 96 (warns),
    // then clamps to the whole entries the file actually holds — the 2560-byte
    // test image leaves (2560 - 392)/40 = 54 whole entry slots after the headers.
    // Sections past the 3 real ones decode as zero-filled garbage entries,
    // which the inspection use-case reports rather than rejects.
    PeBuildSpec s = default_spec();
    s.number_of_sections_override = 200;
    Diagnostics diags;
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_TRUE(diags.has_warnings());
    EXPECT_EQ(img.sections.size(), 54u);
}

TEST(SectionTest, ZeroVirtualAddressWithSize) {
    auto buf = default_image();
    // .data section (entry 2): VirtualAddress -> 0 while VirtualSize nonzero.
    const std::uint64_t pe = 0x80;
    const std::uint64_t sect_table = pe + 24 + 240;
    const std::uint64_t va_off = sect_table + 40 * 2 + 12;
    buf[va_off] = 0; buf[va_off + 1] = 0; buf[va_off + 2] = 0; buf[va_off + 3] = 0;
    Diagnostics diags;
    const PeImage img = parse_ok(buf, diags);
    EXPECT_TRUE(diags.has_warnings());
}

// ── Malformed import tables ──────────────────────────────────────────────

TEST(MalformedImportTest, DirectoryRvaUnmappable) {
    auto buf = default_image();
    // Point import directory at an RVA not in any section (e.g. 0x90000000).
    const std::uint64_t pe = 0x80;
    const std::uint64_t dirs = pe + 24 + 112;
    const std::uint64_t imp_dir = dirs + 8;  // directory[1]
    // rva = 0x90000000
    buf[imp_dir + 0] = 0x00; buf[imp_dir + 1] = 0x00; buf[imp_dir + 2] = 0x00; buf[imp_dir + 3] = 0x90;
    Diagnostics diags;
    const PeImage img = parse_ok(buf, diags);
    EXPECT_TRUE(img.imports.present);
    EXPECT_TRUE(img.imports.entries.empty());  // gracefully absent
    EXPECT_TRUE(diags.has_warnings());
}

TEST(MalformedImportTest, TruncatedThunkArray) {
    auto buf = default_image();
    // Overwrite the thunk terminator for the second DLL with 0xFFs so the
    // array runs past the file end -> warning + partial parse.
    // Locate INT thunk RVA from descriptor 1 in the parsed image first.
    Diagnostics diags0;
    const PeImage img = parse_ok(buf, diags0);
    ASSERT_EQ(img.imports.entries.size(), 2u);
    // second DLL: 2 by-name functions -> thunks occupy 3 slots (2 + terminator)
    // We don't know file offsets here; instead truncate the whole file right
    // after the first DLL's data to starve the second. Simplest reliable
    // mutation: kill the directory size/rva of the import table so the INT
    // lookup fails deep inside. Alternative: set dll name RVA unmappable.
    // Chosen: name RVA -> 0x90000000 on descriptor 1.
    const std::uint64_t pe = 0x80;
    const std::uint64_t dirs = pe + 24 + 112;
    const std::uint64_t imp_dir = dirs + 8;
    std::uint32_t imp_rva = 0;
    for (unsigned i = 0; i < 4; ++i) imp_rva |= static_cast<std::uint32_t>(buf[imp_dir + i]) << (8 * i);
    const auto imp_off = xbox2pc::pe::rva_to_offset(img, imp_rva);
    ASSERT_TRUE(imp_off.has_value());
    // descriptor 1 name RVA at +12
    const std::uint64_t name_off = *imp_off + 20 + 12;
    buf[static_cast<std::size_t>(name_off)] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 1] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 2] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 3] = 0x90;
    Diagnostics diags;
    const PeImage img2 = parse_ok(buf, diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_TRUE(diags.has_warnings());
    EXPECT_NE(img2.imports.entries[1].dll_name, "XboxOneNativeApi.dll");
}

TEST(MalformedImportTest, RunawayDescriptorCount) {
    // Zero the terminating descriptor so the array runs to the cap; parse
    // must stop with a warning, not hang or crash.
    auto buf = default_image();
    Diagnostics diags0;
    const PeImage img = parse_ok(buf, diags0);
    const std::uint64_t pe = 0x80;
    const std::uint64_t dirs = pe + 24 + 112;
    const std::uint64_t imp_dir = dirs + 8;
    std::uint32_t imp_rva = 0;
    for (unsigned i = 0; i < 4; ++i) imp_rva |= static_cast<std::uint32_t>(buf[imp_dir + i]) << (8 * i);
    const auto imp_off = xbox2pc::pe::rva_to_offset(img, imp_rva);
    ASSERT_TRUE(imp_off.has_value());
    // terminator descriptor sits after the 2 real ones: +40
    const std::uint64_t term = *imp_off + 40;
    // Overwrite name/thunk fields with non-zero so it is not treated as terminator.
    for (std::size_t i = 0; i < 20; ++i) {
        buf[static_cast<std::size_t>(term) + i] = 0xEE;
    }
    Diagnostics diags;
    const PeImage img2 = parse_ok(buf, diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_TRUE(diags.has_warnings());
}

// ── Integer overflow cases ───────────────────────────────────────────────

TEST(OverflowTest, SectionRawSizeOverflow) {
    auto buf = default_image();
    // .rdata SizeOfRawData -> 0xFFFFFFFF with small raw offset: off+size wraps
    // in 32-bit world; our checked 64-bit math must reject it.
    const std::uint64_t pe = 0x80;
    const std::uint64_t sect_table = pe + 24 + 240;
    const std::uint64_t sz_off = sect_table + 40 + 16;  // .rdata SizeOfRawData
    buf[sz_off] = 0xFF; buf[sz_off + 1] = 0xFF; buf[sz_off + 2] = 0xFF; buf[sz_off + 3] = 0xFF;
    Diagnostics diags;
    const PeImage img = parse_ok(buf, diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_TRUE(diags.has_warnings());
    EXPECT_FALSE(img.sections[1].has_raw_data);
}

TEST(OverflowTest, DirectorySizeMax) {
    auto buf = default_image();
    const std::uint64_t pe = 0x80;
    const std::uint64_t dirs = pe + 24 + 112;
    // export dir size -> 0xFFFFFFFF (must not wrap in checks)
    const std::uint64_t d = dirs + 0;
    buf[d + 4] = 0xFF; buf[d + 5] = 0xFF; buf[d + 6] = 0xFF; buf[d + 7] = 0xFF;
    Diagnostics diags;
    const PeImage img = parse_ok(buf, diags);
    EXPECT_FALSE(diags.has_errors());
}

TEST(OverflowTest, EntryVaWrap) {
    PeBuildSpec s = default_spec();
    s.image_base = 0xFFFFFFFFFFFF0000ull;  // near 64-bit top
    Diagnostics diags;
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    // base + small rva still fits — verify value, no wrap
    ASSERT_TRUE(img.entry_point_va().has_value());
    EXPECT_EQ(*img.entry_point_va(), 0xFFFFFFFFFFFF0000ull + 0x1000ull);
}

TEST(OverflowTest, EntryVaExactWrap) {
    PeBuildSpec s = default_spec();
    s.image_base = 0xFFFFFFFFFFFFF000ull;  // +0x1000 wraps to 0
    Diagnostics diags;
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    EXPECT_FALSE(img.entry_point_va().has_value());  // detected wrap
}

TEST(OverflowTest, ManyDirectoriesClamped) {
    PeBuildSpec s = default_spec();
    s.number_of_rva_override = 0xFFFFFFFF;  // absurd count
    Diagnostics diags;
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    EXPECT_LE(img.directories.size(), 16u);
    EXPECT_TRUE(diags.has_warnings());
}

// ── Missing optional headers ─────────────────────────────────────────────

TEST(MissingOptionalTest, SizeZero) {
    PeBuildSpec s = default_spec();
    s.size_of_optional_override = 1;  // nonzero but absurdly small
    Diagnostics diags;
    // Optional header claims 1 byte: parse must fail (too small for magic+fields).
    EXPECT_THROW(parse_ok(PeBuilder(s).build(), diags), ParseError);
}

TEST(MissingOptionalTest, ObjectFileNoOptional) {
    // COFF object: SizeOfOptionalHeader = 0 -> distinct error message.
    auto buf = default_image();
    // SizeOfOptionalHeader lives at PE sig + 4 (COFF) + 16 = 0x80 + 20.
    const std::uint64_t soh = 0x80 + 20;
    buf[soh] = 0; buf[soh + 1] = 0;
    Diagnostics diags;
    bool saw_message = false;
    try {
        parse_ok(buf, diags);
        ADD_FAILURE() << "object file parsed as image";
    } catch (const ParseError& e) {
        saw_message = std::string(e.what()).find("optional header") != std::string::npos;
    }
    EXPECT_TRUE(saw_message);
}

TEST(MissingOptionalTest, BadOptionalMagic) {
    auto buf = default_image();
    const std::uint64_t o = 0x80 + 24;
    // magic PE32 (0x10B) instead of PE32+ — parses with a warning, not error.
    buf[o] = 0x0B; buf[o + 1] = 0x01;
    Diagnostics diags;
    const PeImage img = parse_ok(buf, diags);
    EXPECT_TRUE(img.opt.is_pe32);
    EXPECT_FALSE(img.opt.is_pe32plus);
    EXPECT_TRUE(diags.has_warnings());
}

TEST(MissingOptionalTest, UnknownMagic) {
    auto buf = default_image();
    const std::uint64_t o = 0x80 + 24;
    buf[o] = 0x99; buf[o + 1] = 0x99;
    Diagnostics diags;
    EXPECT_THROW(parse_ok(buf, diags), ParseError);
}

// ── Diagnostics component ────────────────────────────────────────────────

TEST(DiagnosticsTest, RecordAndCount) {
    Diagnostics d;
    d.info("i1");
    d.warning("w1");
    d.warning("w2", 0x40);
    d.error("e1");
    EXPECT_EQ(d.count(Severity::Info), 1u);
    EXPECT_EQ(d.count(Severity::Warning), 2u);
    EXPECT_EQ(d.count(Severity::Error), 1u);
    EXPECT_TRUE(d.has_errors());
    EXPECT_TRUE(d.has_warnings());
    const auto ls = d.lines();
    ASSERT_EQ(ls.size(), 4u);
    EXPECT_EQ(ls[0], "[info] i1");
    EXPECT_EQ(ls[1], "[warning] w1");
    EXPECT_EQ(ls[2], "[warning] w2 (offset 0x40)");
    EXPECT_EQ(ls[3], "[error] e1");
    d.clear();
    EXPECT_TRUE(d.entries().empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
