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

// ── M11 Phase 6: exception directory (.pdata) parsing + RIP lookup ───────

namespace {

std::vector<std::uint8_t> pdata_entry(std::uint32_t begin, std::uint32_t end,
                                      std::uint32_t unwind) {
    std::vector<std::uint8_t> e(12);
    for (int i = 0; i < 4; ++i) {
        e[i] = static_cast<std::uint8_t>(begin >> (8 * i));
        e[4 + i] = static_cast<std::uint8_t>(end >> (8 * i));
        e[8 + i] = static_cast<std::uint8_t>(unwind >> (8 * i));
    }
    return e;
}

std::vector<std::uint8_t> concat(const std::vector<std::vector<std::uint8_t>>& parts) {
    std::vector<std::uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

}  // namespace

TEST(PdataRuntimeFunctionLookup, ParsesSortsAndLooksUp) {
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    // Three deliberately unsorted fragments covering .text code ranges.
    s.exception_directory_payload = concat({
        pdata_entry(0x1100, 0x1140, 0x2000),
        pdata_entry(0x1080, 0x10A0, 0x2010),
        pdata_entry(0x1200, 0x1280, 0x2020),
    });
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);

    ASSERT_TRUE(img.exceptions.present);
    ASSERT_EQ(img.exceptions.functions.size(), 3u);
    // Sorted by begin_rva.
    EXPECT_EQ(img.exceptions.functions[0].begin_rva, 0x1080u);
    EXPECT_EQ(img.exceptions.functions[1].begin_rva, 0x1100u);
    EXPECT_EQ(img.exceptions.functions[2].begin_rva, 0x1200u);

    // In-range lookups resolve (begin inclusive, end exclusive).
    const auto* f1 = img.exceptions.find_function(0x1080u);
    ASSERT_NE(f1, nullptr);
    EXPECT_EQ(f1->end_rva, 0x10A0u);
    EXPECT_EQ(f1->unwind_info_rva, 0x2010u);
    const auto* f2 = img.exceptions.find_function(0x113Fu);
    ASSERT_NE(f2, nullptr);
    EXPECT_EQ(f2->begin_rva, 0x1100u);
    const auto* f3 = img.exceptions.find_function(0x127Fu);
    ASSERT_NE(f3, nullptr);
    EXPECT_EQ(f3->unwind_info_rva, 0x2020u);

    // End is exclusive; before-first and gap addresses do not resolve.
    EXPECT_EQ(img.exceptions.find_function(0x107Fu), nullptr);
    EXPECT_EQ(img.exceptions.find_function(0x10A0u), nullptr);  // gap 0x10A0..0x1100
    EXPECT_EQ(img.exceptions.find_function(0x1140u), nullptr);  // gap 0x1140..0x1200
    EXPECT_EQ(img.exceptions.find_function(0x1280u), nullptr);  // past last end
}

TEST(PdataRuntimeFunctionLookup, EqualBeginFragmentsResolveLargestEnd) {
    // Function fragments sharing a begin_rva (chained unwind) sort by end;
    // the lookup must resolve to the LAST such entry (largest end).
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    s.exception_directory_payload = concat({
        pdata_entry(0x1100, 0x1140, 0x2000),
        pdata_entry(0x1100, 0x1200, 0x2008),  // fragment with larger end
    });
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    ASSERT_EQ(img.exceptions.functions.size(), 2u);
    const auto* f = img.exceptions.find_function(0x1150u);
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->end_rva, 0x1200u);
    EXPECT_EQ(f->unwind_info_rva, 0x2008u);
    const auto* first = img.exceptions.find_function(0x1100u);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->end_rva, 0x1200u);
}

TEST(PdataRuntimeFunctionLookup, MalformedEntriesSkippedWithWarnings) {
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, 0x2000),   // valid
        pdata_entry(0x10B0, 0x10A0, 0x2004),   // end < begin: skipped
        pdata_entry(0, 0, 0),                  // empty: skipped
        pdata_entry(0x1100, 0x1140, 0x2008),   // valid
    });
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    ASSERT_TRUE(img.exceptions.present);
    ASSERT_EQ(img.exceptions.functions.size(), 2u);
    EXPECT_EQ(img.exceptions.functions[0].begin_rva, 0x1080u);
    EXPECT_EQ(img.exceptions.functions[1].begin_rva, 0x1100u);
    // Both malformed entries produced diagnostics warnings.
    EXPECT_GE(diags.count(xbox2pc::diag::Severity::Warning), 2u);
}

TEST(PdataRuntimeFunctionLookup, TrailingBytesWarned) {
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    auto payload = concat({pdata_entry(0x1080, 0x10A0, 0x2000)});
    payload.push_back(0xAB);  // 13 bytes: not a multiple of 12
    payload.push_back(0xCD);
    s.exception_directory_payload = payload;
    const PeImage img = parse_ok(PeBuilder(s).build(), diags);
    ASSERT_TRUE(img.exceptions.present);
    EXPECT_EQ(img.exceptions.functions.size(), 1u);
    EXPECT_GE(diags.count(xbox2pc::diag::Severity::Warning), 1u);
}

TEST(PdataRuntimeFunctionLookup, AbsentDirectoryYieldsEmptyTable) {
    Diagnostics diags;
    const PeImage img = parse_ok(PeBuilder(default_spec()).build(), diags);
    EXPECT_FALSE(img.exceptions.present);
    EXPECT_TRUE(img.exceptions.functions.empty());
    EXPECT_EQ(img.exceptions.find_function(0x1000u), nullptr);
}

// ── M11 Phase 6 slice 2: .xdata UNWIND_INFO decoding ─────────────────────

namespace {

// Pack a 16-bit unwind-code slot: offset byte, then opcode|opinfo<<4.
std::vector<std::uint8_t> code_slot(std::uint8_t off, unsigned opcode,
                                    unsigned opinfo) {
    return {off, static_cast<std::uint8_t>(opcode | (opinfo << 4))};
}

std::vector<std::uint8_t> u16_bytes(std::uint16_t v) {
    return {static_cast<std::uint8_t>(v),
            static_cast<std::uint8_t>(v >> 8)};
}

// Append a raw 16-bit slot to a byte vector (trailer padding).
void append_slot(std::vector<std::uint8_t>& out, std::uint16_t v) {
    const auto b = u16_bytes(v);
    out.insert(out.end(), b.begin(), b.end());
}

}  // namespace

TEST(XdataUnwindInfoDecode, DecodesPrologCodesAndFrameRegister) {
    // A representative prolog: push rbp; mov rbp,rsp; push rsi;
    // sub rsp,0x28; save rbx to [rbp-0x10].
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind;
    unwind.push_back(0x01 | (0x08 << 3));  // version 1, flags: UNW_FLAG_EHANDLER? no — 0x8 reserved; use chain flag test below. Use 0 flags here.
    unwind.clear();
    unwind.push_back(static_cast<std::uint8_t>(0x01));       // version 1, flags 0
    unwind.push_back(0x0E);                                   // size_of_prolog
    unwind.push_back(6);                                      // 6 slots (full byte)
    unwind.push_back(static_cast<std::uint8_t>((1 << 4) | 5)); // fp offset 1, frame reg rbp(5)
    auto append = [&](const std::vector<std::uint8_t>& v) {
        unwind.insert(unwind.end(), v.begin(), v.end());
    };
    append(code_slot(0x01, 0, 5));    // UWOP_PUSH_NONVOL rbp
    append(code_slot(0x03, 3, 0));    // UWOP_SET_FPREG
    append(code_slot(0x04, 0, 6));    // UWOP_PUSH_NONVOL rsi
    append(code_slot(0x06, 2, 3));    // UWOP_ALLOC_SMALL -> 3*8+8 = 32
    append(code_slot(0x09, 4, 3));    // UWOP_SAVE_NONVOL rbx
    append(u16_bytes(0x0002));        //   offset slot: 2*8 = 16
    // Place the UNWIND_INFO at a .text RVA far from the entry marker.
    const std::uint32_t unwind_rva = 0x1800;
    s.text_payloads.emplace_back(unwind_rva, unwind);
    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, unwind_rva),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);

    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);
    auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                image.size(), diags);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->version, 1u);
    EXPECT_EQ(info->flags, 0u);
    EXPECT_EQ(info->size_of_prolog, 0x0Eu);
    EXPECT_EQ(info->frame_register, 5u);
    EXPECT_EQ(info->frame_offset, 1u);
    ASSERT_EQ(info->codes.size(), 5u);
    // Stored order preserved.
    EXPECT_EQ(info->codes[0].opcode, 0u);
    EXPECT_EQ(info->codes[0].opinfo, 5u);
    EXPECT_EQ(info->codes[1].opcode, 3u);
    EXPECT_EQ(info->codes[2].opcode, 0u);
    EXPECT_EQ(info->codes[2].opinfo, 6u);
    EXPECT_EQ(info->codes[3].opcode, 2u);
    EXPECT_EQ(info->codes[3].operand, 32u);  // ALLOC_SMALL 3*8+8
    EXPECT_EQ(info->codes[4].opcode, 4u);
    EXPECT_EQ(info->codes[4].operand, 2u);   // SAVE_NONVOL offset slot
}

TEST(XdataUnwindInfoDecode, DecodesLargeAllocFarSaveAndChaining) {
    // ALLOC_LARGE 0x123*8, SAVE_XMM128_FAR with a 32-bit offset, and a
    // chained-unwind link.
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind;
    auto append = [&](const std::vector<std::uint8_t>& v) {
        unwind.insert(unwind.end(), v.begin(), v.end());
    };
    unwind.push_back(static_cast<std::uint8_t>(0x01 | (0x4 << 3)));  // v1, CHAININFO
    unwind.push_back(0x20);
    unwind.push_back(6);             // 2+3+1 slots, no frame reg (full byte)
    unwind.push_back(0x00);
    append(code_slot(0x02, 1, 0));    // ALLOC_LARGE
    append(u16_bytes(0x0123));        //   0x123*8 = 0x918
    append(code_slot(0x05, 9, 7));    // SAVE_XMM128_FAR xmm7
    append(u16_bytes(0x0040));        //   low 16 of offset
    append(u16_bytes(0x0001));        //   high 16 -> 0x10040
    append(code_slot(0x0A, 0, 5));    // PUSH_NONVOL rbp (3rd slot)
    // 6 slots is already even: no padding before the trailer.
    // Chained RUNTIME_FUNCTION (12 bytes): begin=0x1000, end=0x1010,
    // unwind=0 (only BeginAddress is consulted).
    append(u16_bytes(0x1000)); append(u16_bytes(0x0000));
    append(u16_bytes(0x1010)); append(u16_bytes(0x0000));
    append(u16_bytes(0x0000)); append(u16_bytes(0x0000));
    const std::uint32_t unwind_rva = 0x1900;
    s.text_payloads.emplace_back(unwind_rva, unwind);
    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, unwind_rva),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);

    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);
    auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                image.size(), diags);
    ASSERT_TRUE(info.has_value());
    EXPECT_TRUE(info->is_chained());
    EXPECT_EQ(info->chained_unwind_rva, 0x1000u);
    ASSERT_EQ(info->codes.size(), 3u);
    EXPECT_EQ(info->codes[0].opcode, 1u);
    EXPECT_EQ(info->codes[0].operand, 0x918u);      // 0x123 * 8
    EXPECT_EQ(info->codes[1].opcode, 9u);
    EXPECT_EQ(info->codes[1].operand, 0x10040u);    // far 32-bit offset
    EXPECT_EQ(info->codes[2].opcode, 0u);
}

TEST(XdataUnwindInfoDecode, MalformedInputsRejected) {
    Diagnostics diags;
    PeBuildSpec s = default_spec();

    // Version 2 header -> rejected.
    {
        std::vector<std::uint8_t> bad{0x02, 0x10, 0x00, 0x00};
        const std::uint32_t rva = 0x1A00;
        PeBuildSpec s2 = s;
        s2.text_payloads.emplace_back(rva, bad);
        s2.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, rva)});
        const auto image = PeBuilder(s2).build();
        const PeImage img = parse_ok(image, diags);
        const auto* fn = img.exceptions.find_function(0x1080u);
        ASSERT_NE(fn, nullptr);
        auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                    image.size(), diags);
        EXPECT_FALSE(info.has_value());
    }
    // Unknown opcode 11 -> rejected.
    {
        std::vector<std::uint8_t> bad{0x01, 0x10, 0x01, 0x00};
        bad.push_back(0x01);
        bad.push_back(static_cast<std::uint8_t>(11));  // opcode 11: invalid
        const std::uint32_t rva = 0x1B00;
        PeBuildSpec s2 = s;
        s2.text_payloads.emplace_back(rva, bad);
        s2.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, rva)});
        const auto image = PeBuilder(s2).build();
        const PeImage img = parse_ok(image, diags);
        const auto* fn = img.exceptions.find_function(0x1080u);
        ASSERT_NE(fn, nullptr);
        auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                    image.size(), diags);
        EXPECT_FALSE(info.has_value());
    }
    // Truncated operand: ALLOC_LARGE whose size slot lies past the buffer
    // end. UNWIND_INFO has no length of its own — the file continues past
    // it in a built image — so truncation is exercised by cutting the size
    // argument mid-blob (the API's per-fetch bounds checks guard exactly
    // this for hostile buffers).
    {
        std::vector<std::uint8_t> bad{0x01, 0x10, 0x02, 0x00};
        bad.push_back(0x01);
        bad.push_back(0x01);  // ALLOC_LARGE: opcode nibble 1, opinfo 0
        const std::uint32_t rva = 0x1C00;
        PeBuildSpec s2 = s;
        s2.text_payloads.emplace_back(rva, bad);
        s2.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, rva)});
        const auto image = PeBuilder(s2).build();
        const PeImage img = parse_ok(image, diags);
        const auto* fn = img.exceptions.find_function(0x1080u);
        ASSERT_NE(fn, nullptr);
        const auto off = xbox2pc::pe::rva_to_offset(img, rva);
        ASSERT_TRUE(off.has_value());
        // Full buffer: decodes (the operand is whatever follows in .text).
        EXPECT_TRUE(xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                    image.size(), diags).has_value());
        // Cut inside the operand slot: the fetch must fail the bounds check.
        auto cut = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                   off.value() + 5, diags);
        EXPECT_FALSE(cut.has_value());
    }
    // Null unwind RVA -> rejected before any buffer access.
    {
        PeBuildSpec s2 = s;
        s2.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, 0)});
        const auto image = PeBuilder(s2).build();
        const PeImage img = parse_ok(image, diags);
        const auto* fn = img.exceptions.find_function(0x1080u);
        ASSERT_NE(fn, nullptr);
        auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                    image.size(), diags);
        EXPECT_FALSE(info.has_value());
    }
    EXPECT_GE(diags.count(xbox2pc::diag::Severity::Warning), 4u);
}

// ── M11 Phase 6 slice 3: virtual unwinding ───────────────────────────────

namespace {

// A tiny simulated guest stack: u64 slots keyed by VA.
struct FakeStack {
    std::map<std::uint64_t, std::uint64_t> slots;
    std::optional<std::uint64_t> read(std::uint64_t va) const {
        const auto it = slots.find(va);
        if (it == slots.end()) return std::nullopt;
        return it->second;
    }
};

}  // namespace

TEST(VirtualUnwindOneFrame, UndoesPushesAndAlloc) {
    // Prolog: push rbp (1); sub rsp,0x28 (6); push rbx (9).
    // Fault at offset 0x20 (all three executed).
    // Entry RSP 0x7FFF0000; return address at entry+0x38 (after undoing
    // 8 + 0x28 + 8 = 0x38 of effects).
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind;
    auto append = [&](const std::vector<std::uint8_t>& v) {
        unwind.insert(unwind.end(), v.begin(), v.end());
    };
    unwind.push_back(0x01);                                  // version 1, flags 0
    unwind.push_back(0x0A);                                  // prolog size
    unwind.push_back(static_cast<std::uint8_t>(3));          // 1+1+1 slots, no FP
    unwind.push_back(0x00);
    append(code_slot(0x09, 0, 3));    // PUSH_NONVOL rbx       (executed last)
    append(code_slot(0x06, 2, 4));    // ALLOC_SMALL 4*8+8=40  (0x28)
    append(code_slot(0x01, 0, 5));    // PUSH_NONVOL rbp       (executed first)
    const std::uint32_t unwind_rva = 0x1D00;
    s.text_payloads.emplace_back(unwind_rva, unwind);
    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, unwind_rva),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);

    FakeStack stack;
    stack.slots[0x7FFF0038] = 0x140001000;   // return address at entry RSP
    const std::uint64_t current_rsp = 0x7FFF0000;  // fault point: entry - 0x38
    auto frame = xbox2pc::pe::unwind_one_frame(
        img, *fn, image.data(), image.size(), 0x20, current_rsp,
        [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->return_rip, 0x140001000u);
    EXPECT_EQ(frame->rsp_after, 0x7FFF0040u);  // entry + 8 after the ret
}

TEST(VirtualUnwindOneFrame, TargetOffsetSkipsUnexecutedCodes) {
    // Same prolog but the fault is at offset 0x04: only the first push
    // executed, so only 8 bytes are undone.
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind;
    auto append = [&](const std::vector<std::uint8_t>& v) {
        unwind.insert(unwind.end(), v.begin(), v.end());
    };
    unwind.push_back(0x01);
    unwind.push_back(0x0A);
    unwind.push_back(static_cast<std::uint8_t>(3));
    unwind.push_back(0x00);
    append(code_slot(0x09, 0, 3));
    append(code_slot(0x06, 2, 4));
    append(code_slot(0x01, 0, 5));
    const std::uint32_t unwind_rva = 0x1D00;
    s.text_payloads.emplace_back(unwind_rva, unwind);
    s.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, unwind_rva)});
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);

    FakeStack stack;
    stack.slots[0x7FFF0008] = 0x140001234;
    const std::uint64_t current_rsp = 0x7FFF0000;
    auto frame = xbox2pc::pe::unwind_one_frame(
        img, *fn, image.data(), image.size(), 0x04, current_rsp,
        [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->return_rip, 0x140001234u);
    EXPECT_EQ(frame->rsp_after, 0x7FFF0010u);
}

TEST(VirtualUnwindOneFrame, ChainedInfoContributesAllCodes) {
    // Outer function (0x1080-0x10A0) chains into inner (0x1050-0x1060)
    // whose codes ALL apply. Inner prolog: push r12; sub rsp,0x10.
    // Combined undo: 8 (outer push) + 8 + 0x10 (inner) = 0x28.
    Diagnostics diags;
    PeBuildSpec s = default_spec();

    // Inner UNWIND_INFO: plain, 2 slots.
    std::vector<std::uint8_t> inner;
    inner.push_back(0x01);
    inner.push_back(0x08);
    inner.push_back(static_cast<std::uint8_t>(2));
    inner.push_back(0x00);
    const auto push_r12 = code_slot(0x06, 0, 12);   // PUSH_NONVOL r12
    inner.insert(inner.end(), push_r12.begin(), push_r12.end());
    const auto alloc16 = code_slot(0x02, 2, 1);     // ALLOC_SMALL 1*8+8 = 16
    inner.insert(inner.end(), alloc16.begin(), alloc16.end());
    const std::uint32_t inner_rva = 0x1E00;
    s.text_payloads.emplace_back(inner_rva, inner);

    // Outer UNWIND_INFO: 1 slot (push rbp) + CHAININFO link to inner.
    // Odd code counts are padded to an even slot count before the trailer,
    // so one unused 16-bit slot precedes the 12-byte RUNTIME_FUNCTION.
    std::vector<std::uint8_t> outer;
    outer.push_back(static_cast<std::uint8_t>(0x01 | (0x4 << 3)));  // v1 + chain
    outer.push_back(0x04);
    outer.push_back(1);
    outer.push_back(0x00);
    const auto push_rbp = code_slot(0x01, 0, 5);     // PUSH_NONVOL rbp
    outer.insert(outer.end(), push_rbp.begin(), push_rbp.end());
    append_slot(outer, 0x0000);                      // unused padding slot
    // Chained RUNTIME_FUNCTION (12 bytes): begin=inner, end=inner+0x10,
    // unwind=inner's .xdata (only BeginAddress is consulted).
    outer.push_back(0x50); outer.push_back(0x10); outer.push_back(0x00); outer.push_back(0x00);
    outer.push_back(0x60); outer.push_back(0x10); outer.push_back(0x00); outer.push_back(0x00);
    outer.push_back(0x00); outer.push_back(0x1E); outer.push_back(0x00); outer.push_back(0x00);
    const std::uint32_t outer_rva = 0x1F00;
    s.text_payloads.emplace_back(outer_rva, outer);

    s.exception_directory_payload = concat({
        pdata_entry(0x1050, 0x1060, inner_rva),
        pdata_entry(0x1080, 0x10A0, outer_rva),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);

    FakeStack stack;
    // Undo: outer push rbp (8) + inner push r12 (8) + inner ALLOC_SMALL
    // (16) = 32 bytes; the return address sits at current_rsp + 0x20.
    stack.slots[0x7FFF0020] = 0x140009999;
    const std::uint64_t current_rsp = 0x7FFF0000;
    auto frame = xbox2pc::pe::unwind_one_frame(
        img, *fn, image.data(), image.size(), 0x08, current_rsp,
        [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->return_rip, 0x140009999u);
    EXPECT_EQ(frame->rsp_after, 0x7FFF0028u);
}

TEST(VirtualUnwindOneFrame, StackReadFailureAndMachframeRejection) {
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    // PUSH_MACHFRAME code -> rejected.
    std::vector<std::uint8_t> bad{0x01, 0x04, 0x01, 0x00};
    bad.push_back(0x02);
    bad.push_back(0x0A);  // opcode 10 (PUSH_MACHFRAME), opinfo 0
    const std::uint32_t rva = 0x1A00;
    s.text_payloads.emplace_back(rva, bad);
    s.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, rva)});
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);
    FakeStack stack;
    auto frame = xbox2pc::pe::unwind_one_frame(
        img, *fn, image.data(), image.size(), 0x20, 0x7FFF0000,
        [&](std::uint64_t va) { return stack.read(va); }, diags);
    EXPECT_FALSE(frame.has_value());

    // Unmapped return-address slot -> stack-read failure surfaces as
    // nullopt with a diagnostic (reuses the valid unwind from the first
    // test's shape via a fresh build).
    Diagnostics diags2;
    PeBuildSpec s2 = default_spec();
    std::vector<std::uint8_t> unwind{0x01, 0x02, 0x01, 0x00, 0x01, 0x05};
    s2.text_payloads.emplace_back(0x1D00, unwind);
    s2.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, 0x1D00)});
    const auto image2 = PeBuilder(s2).build();
    const PeImage img2 = parse_ok(image2, diags2);
    const auto* fn2 = img2.exceptions.find_function(0x1080u);
    ASSERT_NE(fn2, nullptr);
    FakeStack empty;
    auto frame2 = xbox2pc::pe::unwind_one_frame(
        img2, *fn2, image2.data(), image2.size(), 0x20, 0x7FFF0000,
        [&](std::uint64_t va) { return empty.read(va); }, diags2);
    EXPECT_FALSE(frame2.has_value());
}

// ── M11 Phase 6 slice 4: non-volatile restore locations ──────────────────

TEST(UnwindSavedRegisters, PushAndNearSaveLocations) {
    // Prolog: push rbp; sub rsp,0x28; mov [rbp-0x10], rbx; push rsi.
    // Executed in that order. Walk (reverse) encounters: push rsi (value
    // at current_rsp), ALLOC 0x28, SAVE rbx (near, offset slot 2 ->
    // 2*8 below the fragment's end-of-prolog RSP), push rbp (value at
    // current_rsp + 0x38).
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind;
    auto append = [&](const std::vector<std::uint8_t>& v) {
        unwind.insert(unwind.end(), v.begin(), v.end());
    };
    unwind.push_back(0x01);                                  // v1, flags 0
    unwind.push_back(0x0C);                                  // prolog size
    unwind.push_back(static_cast<std::uint8_t>(5));          // 5 slots, no FP
    unwind.push_back(0x00);
    append(code_slot(0x0A, 0, 6));    // PUSH_NONVOL rsi   (last executed)
    append(code_slot(0x08, 4, 3));    // SAVE_NONVOL rbx, offset slot 2
    append(u16_bytes(0x0002));        //   near offset: 2*8 = 16
    append(code_slot(0x03, 2, 4));    // ALLOC_SMALL 4*8+8 = 40 (0x28)
    append(code_slot(0x01, 0, 5));    // PUSH_NONVOL rbp  (first executed)
    const std::uint32_t unwind_rva = 0x1D00;
    s.text_payloads.emplace_back(unwind_rva, unwind);
    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, unwind_rva),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);

    FakeStack stack;
    stack.slots[0x7FFF0038] = 0x140001000;   // return address
    stack.slots[0x7FFF0030] = 0xAAAA1111;    // pushed rbp value
    stack.slots[0x7FFF0000] = 0xBBBB2222;    // pushed rsi value
    stack.slots[0x7FFF0018] = 0xCCCC3333;    // saved rbx value
    const std::uint64_t current_rsp = 0x7FFF0000;
    auto frame = xbox2pc::pe::unwind_one_frame(
        img, *fn, image.data(), image.size(), 0x20, current_rsp,
        [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->saved.size(), 3u);
    // Walk order: rsi push first (most recent), then rbx save, then rbp.
    EXPECT_EQ(frame->saved[0].reg, 6u);         // rsi
    EXPECT_FALSE(frame->saved[0].is_xmm);
    EXPECT_EQ(frame->saved[0].location, 0x7FFF0000u);
    EXPECT_EQ(frame->saved[1].reg, 3u);         // rbx
    // SAVE offsets are relative to the fragment's end-of-prolog RSP
    // (0x7FFF0000 here: the fault is past the full prolog): 2*8 = 16.
    EXPECT_EQ(frame->saved[1].location, 0x7FFF0010u);
    EXPECT_EQ(frame->saved[2].reg, 5u);         // rbp
    EXPECT_EQ(frame->saved[2].location, 0x7FFF0030u);
    // Sanity: the frame control fields still work.
    EXPECT_EQ(frame->return_rip, 0x140001000u);
    EXPECT_EQ(frame->rsp_after, 0x7FFF0040u);
}

TEST(UnwindSavedRegisters, FarSaveAndXmmLocations) {
    // Prolog: SAVE_XMM128_FAR xmm6 at 32-bit offset 0x100; SAVE rbx far
    // at 0x200; push r12. SAVE bases are the fragment end-of-prolog RSP,
    // which (no allocs) equals the walked RSP at fragment entry:
    // current_rsp + 0x8 (after the push is undone).
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind;
    auto append = [&](const std::vector<std::uint8_t>& v) {
        unwind.insert(unwind.end(), v.begin(), v.end());
    };
    unwind.push_back(0x01);
    unwind.push_back(0x10);
    unwind.push_back(static_cast<std::uint8_t>(7));  // 1 + 3 + 3 slots
    unwind.push_back(0x00);
    append(code_slot(0x04, 9, 6));    // SAVE_XMM128_FAR xmm6 (executed last)
    append(u16_bytes(0x0100));        //   low 16
    append(u16_bytes(0x0000));        //   high 16 -> 0x100
    append(code_slot(0x02, 5, 3));    // SAVE_NONVOL_FAR rbx
    append(u16_bytes(0x0200));        //   low 16
    append(u16_bytes(0x0000));        //   high 16 -> 0x200
    append(code_slot(0x01, 0, 12));   // PUSH_NONVOL r12 (executed first)
    const std::uint32_t unwind_rva = 0x1D00;
    s.text_payloads.emplace_back(unwind_rva, unwind);
    s.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, unwind_rva)});
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);

    FakeStack stack;
    stack.slots[0x7FFF0008] = 0x140001000;   // return address (entry_rsp)
    const std::uint64_t current_rsp = 0x7FFF0000;
    auto frame = xbox2pc::pe::unwind_one_frame(
        img, *fn, image.data(), image.size(), 0x20, current_rsp,
        [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->saved.size(), 3u);
    // Walk order: xmm6 far save first, then rbx far save, then r12 push.
    // SAVE offsets are relative to the end-of-prolog RSP (0x7FFF0000 —
    // the fault is past the full prolog, so that equals current_rsp).
    EXPECT_TRUE(frame->saved[0].is_xmm);
    EXPECT_EQ(frame->saved[0].reg, 6u);
    EXPECT_EQ(frame->saved[0].location, 0x7FFF0000u + 0x100u);
    EXPECT_FALSE(frame->saved[1].is_xmm);
    EXPECT_EQ(frame->saved[1].reg, 3u);
    EXPECT_EQ(frame->saved[1].location, 0x7FFF0000u + 0x200u);
    EXPECT_FALSE(frame->saved[2].is_xmm);
    EXPECT_EQ(frame->saved[2].reg, 12u);
    EXPECT_EQ(frame->saved[2].location, 0x7FFF0000u);
}

// ── M11 Phase 6 slice B: exception handler search ─────────────────────────

namespace {

// v1 UNWIND_INFO header helper for handler-search fixtures.
std::vector<std::uint8_t> unwind_header(unsigned flags, unsigned slots,
                                        unsigned size_of_prolog) {
    return {static_cast<std::uint8_t>(0x01 | (flags << 3)),
            static_cast<std::uint8_t>(size_of_prolog),
            static_cast<std::uint8_t>(slots), 0x00};
}

}  // namespace

TEST(FindExceptionHandler, FindsOuterEhandler) {
    // Inner (0x1080-0x10A0): no handler, push rbx only.
    // Outer (0x1000-0x1050): EHANDLER, push rbp.
    // Fault in inner: walk inner, then outer's handler is found.
    Diagnostics diags;
    PeBuildSpec s = default_spec();

    std::vector<std::uint8_t> inner = unwind_header(0, 1, 4);
    {
        const auto c = code_slot(0x01, 0, 3);  // PUSH_NONVOL rbx
        inner.insert(inner.end(), c.begin(), c.end());
        append_slot(inner, 0x0000);  // odd -> pad before trailer (none)
    }
    s.text_payloads.emplace_back(0x1E00, inner);

    // Outer: EHANDLER (0x1) + handler RVA after padded array.
    std::vector<std::uint8_t> outer = unwind_header(0x1, 1, 2);
    {
        const auto c = code_slot(0x01, 0, 5);  // PUSH_NONVOL rbp
        outer.insert(outer.end(), c.begin(), c.end());
        append_slot(outer, 0x0000);  // padding slot (odd count)
        outer.push_back(0x88); outer.push_back(0x12); outer.push_back(0x00); outer.push_back(0x00);
    }
    s.text_payloads.emplace_back(0x1F00, outer);

    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, 0x1E00),
        pdata_entry(0x1000, 0x1050, 0x1F00),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);

    FakeStack stack;
    // Step 1 (inner, push rbx): entry rsp 0x7FFF0008 holds the return
    // address into outer.
    stack.slots[0x7FFF0008] = 0x140001002;   // outer+2 (inside outer range)
    // Step 2 (outer, push rbp): the found frame's own return address sits
    // at its entry rsp 0x7FFF0018 (unwind_one_frame reads it while
    // reconstructing the establisher frame).
    stack.slots[0x7FFF0018] = 0x140009999;   // outer's caller
    const auto found = xbox2pc::pe::find_exception_handler(
        img, image.data(), image.size(), 0x140000000ull, 0x140001085ull,
        0x7FFF0000ull, [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(found.has_value());
    EXPECT_TRUE(found->found);
    EXPECT_EQ(found->handler_rva, 0x1288u);
    EXPECT_EQ(found->establisher_frame, 0x7FFF0018u);
    ASSERT_EQ(found->frames.size(), 2u);
    EXPECT_EQ(found->frames[0].rip, 0x140001085ull);  // inner
    EXPECT_EQ(found->frames[1].rip, 0x140001002ull);  // outer
}

TEST(FindExceptionHandler, LeafPopsReturnAddress) {
    // No .pdata entry covers the fault RIP: leaf rule pops [rsp].
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> outer = unwind_header(0x1, 1, 2);
    {
        const auto c = code_slot(0x01, 0, 5);  // PUSH_NONVOL rbp
        outer.insert(outer.end(), c.begin(), c.end());
        append_slot(outer, 0x0000);
        outer.push_back(0x34); outer.push_back(0x12); outer.push_back(0x00); outer.push_back(0x00);
    }
    s.text_payloads.emplace_back(0x1F00, outer);
    s.exception_directory_payload = concat({
        pdata_entry(0x1000, 0x1050, 0x1F00),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);

    FakeStack stack;
    stack.slots[0x7FFF0000] = 0x140001002;  // leaf's return into outer
    stack.slots[0x7FFF0010] = 0x140009999;  // outer's caller (entry rsp after pop)
    const auto found = xbox2pc::pe::find_exception_handler(
        img, image.data(), image.size(), 0x140000000ull, 0x140001200ull,
        0x7FFF0000ull, [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(found.has_value());
    EXPECT_TRUE(found->found);
    EXPECT_EQ(found->handler_rva, 0x1234u);
    ASSERT_EQ(found->frames.size(), 2u);
    EXPECT_EQ(found->frames[0].rip, 0x140001200ull);  // leaf
    EXPECT_EQ(found->frames[1].rip, 0x140001002ull);  // outer
}

TEST(FindExceptionHandler, NoHandlerWalksChain) {
    // Single function, no handler flag: walk completes, found=false.
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> fn = unwind_header(0, 1, 4);
    {
        const auto c = code_slot(0x01, 0, 3);
        fn.insert(fn.end(), c.begin(), c.end());
        append_slot(fn, 0x0000);
    }
    s.text_payloads.emplace_back(0x1E00, fn);
    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, 0x1E00),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);

    FakeStack stack;
    // Frame step (push rbx undone): return address at 0x7FFF0008.
    stack.slots[0x7FFF0008] = 0x140003000;  // somewhere outside .pdata
    // Leaf step at 0x140003000: pops [0x7FFF0010]; provide it so the walk
    // terminates by leaving the image extent (0x140008000) instead of a
    // stack-read failure.
    stack.slots[0x7FFF0010] = 0x140008000;  // one past size_of_image (0x4000)
    const auto found = xbox2pc::pe::find_exception_handler(
        img, image.data(), image.size(), 0x140000000ull, 0x140001085ull,
        0x7FFF0000ull, [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(found.has_value());
    EXPECT_FALSE(found->found);
    ASSERT_EQ(found->frames.size(), 2u);  // function step + leaf step
    EXPECT_EQ(found->frames[0].rip, 0x140001085ull);
    EXPECT_EQ(found->frames[1].rip, 0x140003000ull);
}

TEST(FindExceptionHandler, ChainedHandlerFlagsIgnored) {
    // A CHAININFO-linked outer entry carries the EHANDLER flag; the inner
    // (primary) entry does not. The unwind procedure must IGNORE the
    // chained entry's handler flag: no handler found, walk continues.
    Diagnostics diags;
    PeBuildSpec s = default_spec();

    // Inner (primary, walked first): plain, 1 slot (push rbx).
    std::vector<std::uint8_t> inner = unwind_header(0x4, 1, 4);
    {
        const auto c = code_slot(0x01, 0, 3);  // push rbx
        inner.insert(inner.end(), c.begin(), c.end());
        // No handler RVA: EHANDLER not set. Odd count -> pad slot.
        append_slot(inner, 0x0000);
        // Chained RUNTIME_FUNCTION (12 bytes) pointing at outer.
        append_slot(inner, 0x1000);
        append_slot(inner, 0x0000);
        append_slot(inner, 0x1050);
        append_slot(inner, 0x0000);
        append_slot(inner, 0x1F00);
        append_slot(inner, 0x0000);
    }
    s.text_payloads.emplace_back(0x1E00, inner);

    // Outer (chained): EHANDLER set — must be ignored per the docs.
    std::vector<std::uint8_t> outer = unwind_header(0x1, 1, 2);
    {
        const auto c = code_slot(0x01, 0, 5);  // push rbp
        outer.insert(outer.end(), c.begin(), c.end());
        append_slot(outer, 0x0000);
        outer.push_back(0x88); outer.push_back(0x12); outer.push_back(0x00); outer.push_back(0x00);
    }
    s.text_payloads.emplace_back(0x1F00, outer);

    s.exception_directory_payload = concat({
        pdata_entry(0x1080, 0x10A0, 0x1E00),
        pdata_entry(0x1000, 0x1050, 0x1F00),
    });
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);

    FakeStack stack;
    // Inner (with its chained outer codes) unwinds: push rbx (8) + chained
    // push rbp (8) = 16 -> return address at 0x7FFF0010.
    stack.slots[0x7FFF0010] = 0x140003000;  // outside .pdata: leaf pop next
    // Leaf pop at 0x140003000 reads [0x7FFF0018]; provide it so the walk
    // ends by leaving the image, not by a stack-read failure.
    stack.slots[0x7FFF0018] = 0x140008000;  // one past the image extent
    const auto found = xbox2pc::pe::find_exception_handler(
        img, image.data(), image.size(), 0x140000000ull, 0x140001085ull,
        0x7FFF0000ull, [&](std::uint64_t va) { return stack.read(va); }, diags);
    ASSERT_TRUE(found.has_value());
    // The chained outer's EHANDLER must NOT satisfy the search.
    EXPECT_FALSE(found->found);
    EXPECT_EQ(found->handler_rva, 0u);
}

TEST(XdataUnwindInfoDecode, CountOfCodesAbove15Decodes) {
    // Conformance proof for the full-byte count: 16+ slots must decode.
    // 20 pushes (20 slots, even) + handler RVA trailer.
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind = unwind_header(0x1, 20, 40);
    for (unsigned i = 0; i < 20; ++i) {
        const auto c = code_slot(static_cast<std::uint8_t>(i + 1), 0,
                                 static_cast<unsigned>((i % 12) + 1));
        unwind.insert(unwind.end(), c.begin(), c.end());
    }
    unwind.push_back(0x00); unwind.push_back(0x11); unwind.push_back(0x00); unwind.push_back(0x00);
    s.text_payloads.emplace_back(0x1A80, unwind);
    s.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, 0x1A80)});
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);
    auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                image.size(), diags);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->count_of_codes, 20u);
    ASSERT_EQ(info->codes.size(), 20u);
    EXPECT_EQ(info->language_handler_rva, 0x1100u);
}

TEST(XdataUnwindInfoDecode, AllocLargeOpinfo1Decodes) {
    // ALLOC_LARGE opinfo==1: raw 32-bit byte size (0x10000) in two slots.
    Diagnostics diags;
    PeBuildSpec s = default_spec();
    std::vector<std::uint8_t> unwind = unwind_header(0, 3, 6);
    {
        const auto c = code_slot(0x02, 1, 1);  // ALLOC_LARGE, opinfo 1
        unwind.insert(unwind.end(), c.begin(), c.end());
        append_slot(unwind, 0x0000);          // low 16: 0
        append_slot(unwind, 0x0001);          // high 16: 1 -> 0x10000
    }
    s.text_payloads.emplace_back(0x1A90, unwind);
    s.exception_directory_payload = concat({pdata_entry(0x1080, 0x10A0, 0x1A90)});
    const auto image = PeBuilder(s).build();
    const PeImage img = parse_ok(image, diags);
    const auto* fn = img.exceptions.find_function(0x1080u);
    ASSERT_NE(fn, nullptr);
    auto info = xbox2pc::pe::decode_unwind_info(img, *fn, image.data(),
                                                image.size(), diags);
    ASSERT_TRUE(info.has_value());
    ASSERT_EQ(info->codes.size(), 1u);
    EXPECT_EQ(info->codes[0].opcode, 1u);
    EXPECT_EQ(info->codes[0].operand, 0x10000u);  // NOT scaled by 8
}
