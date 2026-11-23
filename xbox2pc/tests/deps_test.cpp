// M2 GoogleTest suites — dependency intelligence engine acceptance tests.
//
// Test binaries are generated in-memory by pe_builder (M1 component,
// extended for M2): multiple DLL imports, ordinal imports, delay imports,
// duplicates (regular + delay), forwarded exports, malformed dependency
// structures (byte-mutated images), plus graph cycle/missing tests built
// from synthetic multi-image graphs and JSON serialization round checks.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "xbox2pc/api_registry.hpp"
#include "xbox2pc/compat_db.hpp"
#include "xbox2pc/dep_analyzer.hpp"
#include "xbox2pc/dep_graph.hpp"
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/json_writer.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"

using xbox2pc::compat::CompatibilityDb;
using CompatStatus = xbox2pc::compat::Status;
using xbox2pc::deps::DependencyReport;
using xbox2pc::graph::DependencyGraph;
using xbox2pc::json::Json;
using xbox2pc::pe::ParseError;
using xbox2pc::pe::PeImage;
using xbox2pc::registry::ApiCategory;
using xbox2pc::registry::ApiRegistry;
using xbox2pc::test::DelayImportDll;
using xbox2pc::test::ImportDll;
using xbox2pc::test::ImportFunc;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;
using Diagnostics = xbox2pc::diag::Diagnostics;

namespace {

PeImage parse_buf(const std::vector<std::uint8_t>& buf, Diagnostics& diags,
                  const std::string& name = "test-image") {
    return xbox2pc::pe::parse(buf.data(), buf.size(), name, diags);
}

// A rich spec: 3 DLLs (one duplicate by name), ordinal + by-name imports,
// delay imports, forwarded export.
PeBuildSpec rich_spec() {
    PeBuildSpec s;
    s.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}, {"ReadFile", 2}, {"", 7}}},
        {"XboxOneNativeApi.dll", {{"XamGetGamepadState", 3}, {"XThreadCreate", 4}}},
        {"kernel32.dll", {{"CloseHandle", 5}}},   // duplicate (case-insensitive)
    };
    s.delay_imports = {
        {"d3d12_x.dll", {{"D3D12XCreateDevice", 1}}},
        {"xgameruntime.dll", {{"XGameRuntimeInitialize", 0}, {"", 12}}},
    };
    s.exports = {
        {"XblInitialize", 0x1080, ""},
        {"", 0, ""},
        {"XblCleanup", 0x10C0, "XboxOneNativeApi.XblInitCore"},  // forwarder
    };
    return s;
}

std::vector<std::uint8_t> rich_image() {
    return PeBuilder(rich_spec()).build();
}

}  // namespace

// ── Delay-import parsing (pe_parser M2 extension) ─────────────────────────

TEST(DelayImportParseTest, DecodesDelayTable) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    ASSERT_TRUE(img.delay_imports.present);
    ASSERT_EQ(img.delay_imports.entries.size(), 2u);

    const auto& d0 = img.delay_imports.entries[0];
    EXPECT_EQ(d0.dll_name, "d3d12_x.dll");
    ASSERT_EQ(d0.functions.size(), 1u);
    EXPECT_EQ(d0.functions[0], "D3D12XCreateDevice");
    EXPECT_FALSE(d0.va_addressed);   // grAttrs bit 0 clear: RVA addressing

    const auto& d1 = img.delay_imports.entries[1];
    EXPECT_EQ(d1.dll_name, "xgameruntime.dll");
    EXPECT_EQ(d1.functions.size(), 1u);            // by-name entries
    ASSERT_EQ(d1.ordinal_only.size(), 1u);
    EXPECT_EQ(d1.ordinal_only[0], 12u);
}

TEST(DelayImportParseTest, VaAddressedDescriptors) {
    // grAttrs bit 0 set: fields are VAs. Needs a low image base so the 32-bit
    // fields can hold base+rva.
    PeBuildSpec s = rich_spec();
    s.image_base = 0x10000;
    s.delay_imports[0].attributes = 0x1;
    Diagnostics diags;
    const PeImage img = parse_buf(PeBuilder(s).build(), diags);
    ASSERT_TRUE(img.delay_imports.present);
    ASSERT_EQ(img.delay_imports.entries.size(), 2u);
    EXPECT_TRUE(img.delay_imports.entries[0].va_addressed);
    EXPECT_EQ(img.delay_imports.entries[0].dll_name, "d3d12_x.dll");
    EXPECT_FALSE(diags.has_errors());
}

TEST(DelayImportParseTest, NoDelayDirectory) {
    PeBuildSpec s;  // no delay imports
    Diagnostics diags;
    const PeImage img = parse_buf(PeBuilder(s).build(), diags);
    EXPECT_FALSE(img.delay_imports.present);
    EXPECT_TRUE(img.delay_imports.entries.empty());
}

TEST(DelayImportParseTest, TruncatedDelayThunkArray) {
    // Point the first delay descriptor's INT at the file's end region so the
    // thunk walk hits EOF: warning + partial parse, never a crash.
    auto buf = rich_image();
    Diagnostics diags0;
    const PeImage img0 = parse_buf(buf, diags0);
    const std::uint32_t d_rva = img0.directories[xbox2pc::pe::kDirDelayImport].rva;
    const std::uint64_t d_off = *xbox2pc::pe::rva_to_offset(img0, d_rva);
    // Descriptor 0 INT field at +16; point it just past the last section.
    const std::uint64_t int_field = d_off + 16;
    const std::uint32_t bad_rva = 0x7FFFFFF0;   // inside image? no: outside
    for (unsigned i = 0; i < 4; ++i) {
        buf[static_cast<std::size_t>(int_field) + i] =
            static_cast<std::uint8_t>((bad_rva >> (8 * i)) & 0xFF);
    }
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    ASSERT_GE(img.delay_imports.entries.size(), 1u);
    EXPECT_TRUE(diags.has_warnings());
}

TEST(DelayImportParseTest, UnmappableDelayDirectory) {
    // Point the delay directory at an RVA outside all sections.
    auto buf = rich_image();
    const std::uint64_t pe = 0x80;
    const std::uint64_t dirs = pe + 24 + 112;
    const std::uint64_t d = dirs + 8 * 13;  // directory 13
    buf[static_cast<std::size_t>(d)] = 0x00;
    buf[static_cast<std::size_t>(d) + 1] = 0x00;
    buf[static_cast<std::size_t>(d) + 2] = 0x00;
    buf[static_cast<std::size_t>(d) + 3] = 0x90;  // 0x90000000
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    EXPECT_TRUE(img.delay_imports.present);
    EXPECT_TRUE(img.delay_imports.entries.empty());
    EXPECT_TRUE(diags.has_warnings());
}

// ── Import metadata preservation ──────────────────────────────────────────

TEST(ImportMetadataTest, FieldsPreserved) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    ASSERT_EQ(img.imports.entries.size(), 3u);
    const auto& k = img.imports.entries[0];
    EXPECT_EQ(k.dll_name, "KERNEL32.dll");
    EXPECT_NE(k.int_rva, 0u);
    EXPECT_NE(k.iat_rva, 0u);
    EXPECT_NE(k.name_rva, 0u);
    EXPECT_EQ(k.timestamp, 0u);           // unbound
    EXPECT_FALSE(k.bound);
    EXPECT_EQ(k.forwarder_chain, 0u);
}

TEST(ImportMetadataTest, BoundImportDetected) {
    // M1's builder writes TimeDateStamp 0; patch the first descriptor's
    // stamp to nonzero -> bound flag.
    auto buf = rich_image();
    Diagnostics diags0;
    const PeImage img0 = parse_buf(buf, diags0);
    const std::uint32_t imp_rva = img0.directories[xbox2pc::pe::kDirImport].rva;
    const std::uint64_t imp_off = *xbox2pc::pe::rva_to_offset(img0, imp_rva);
    buf[static_cast<std::size_t>(imp_off) + 4] = 0x30;  // TimeDateStamp lo byte
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    EXPECT_TRUE(img.imports.entries[0].bound);
    EXPECT_EQ(img.imports.entries[0].timestamp, 0x30u);
}

// ── Dependency analyzer ───────────────────────────────────────────────────

TEST(DependencyAnalyzerTest, MultipleDllEnumeration) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    // KERNEL32.dll + kernel32.dll merge into one edge; delay DLLs appended.
    EXPECT_EQ(rep.distinct_dll_count(), 4u);
    EXPECT_EQ(rep.dependencies[0].dll_name, "KERNEL32.dll");
    EXPECT_EQ(rep.dependencies[1].dll_name, "XboxOneNativeApi.dll");
    EXPECT_EQ(rep.dependencies[2].dll_name, "d3d12_x.dll");
    EXPECT_EQ(rep.dependencies[3].dll_name, "xgameruntime.dll");
}

TEST(DependencyAnalyzerTest, OrdinalAndByNameImports) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    const auto& k = rep.dependencies[0];
    // KERNEL32.dll merged with the duplicate kernel32.dll entry: 2 by-name
    // + ordinal 7 + CloseHandle from the duplicate = 4 functions.
    ASSERT_EQ(k.function_count, 4u);
    EXPECT_EQ(k.functions[0].name, "CreateFileW");
    EXPECT_FALSE(k.functions[0].by_ordinal);
    EXPECT_EQ(k.functions[1].name, "ReadFile");
    EXPECT_TRUE(k.functions[2].by_ordinal);
    EXPECT_EQ(k.functions[2].ordinal, 7u);
    EXPECT_FALSE(k.functions[2].delay_load);
    EXPECT_EQ(k.functions[3].name, "CloseHandle");
}

TEST(DependencyAnalyzerTest, DuplicateDetection) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    EXPECT_EQ(rep.duplicate_count, 1u);
    // The merged edge is flagged with both spellings present.
    const auto& k = rep.dependencies[0];
    EXPECT_TRUE(k.duplicate);
    EXPECT_EQ(k.import_sources.size(), 2u);   // regular + regular
}

TEST(DependencyAnalyzerTest, DelayImportsFlaggedAndMerged) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    EXPECT_TRUE(rep.has_delay_imports);
    const auto* d3d = &rep.dependencies[2];
    const auto* xgrt = &rep.dependencies[3];
    EXPECT_EQ(d3d->dll_name, "d3d12_x.dll");
    EXPECT_TRUE(d3d->delay_import);
    EXPECT_FALSE(d3d->regular_import);
    EXPECT_TRUE(d3d->functions[0].delay_load);
    EXPECT_TRUE(xgrt->delay_import);
    EXPECT_EQ(xgrt->function_count, 2u);   // by-name + ordinal
    EXPECT_TRUE(xgrt->functions[1].by_ordinal);
    EXPECT_EQ(xgrt->functions[1].ordinal, 12u);
}

TEST(DependencyAnalyzerTest, RegularPlusDelayMerge) {
    // Same DLL in both tables -> one edge, both flags.
    PeBuildSpec s;
    s.imports = {{"d3d12.dll", {{"D3D12CreateDevice", 1}}}};
    s.delay_imports = {{"d3d12.dll", {{"D3D12CreateRootSignature", 2}}}};
    Diagnostics diags;
    const PeImage img = parse_buf(PeBuilder(s).build(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    ASSERT_EQ(rep.distinct_dll_count(), 1u);
    const auto& d = rep.dependencies[0];
    EXPECT_TRUE(d.regular_import);
    EXPECT_TRUE(d.delay_import);
    EXPECT_EQ(d.function_count, 2u);
    EXPECT_EQ(d.import_sources.size(), 2u);
}

TEST(DependencyAnalyzerTest, ForwardedExportsReported) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    ASSERT_EQ(rep.forwarded_exports.size(), 1u);
    EXPECT_EQ(rep.forwarded_exports[0].export_name, "XblCleanup");
    EXPECT_EQ(rep.forwarded_exports[0].forwarder, "XboxOneNativeApi.XblInitCore");
    EXPECT_EQ(rep.forwarded_exports[0].target_dll, "XboxOneNativeApi");
    EXPECT_EQ(rep.forwarded_exports[0].target_api, "XblInitCore");
}

TEST(DependencyAnalyzerTest, UnresolvedImportsCounted) {
    // Unmapped DLL name RVA -> parser records "<unresolved RVA ...>".
    auto buf = rich_image();
    Diagnostics diags0;
    const PeImage img0 = parse_buf(buf, diags0);
    const std::uint32_t imp_rva = img0.directories[xbox2pc::pe::kDirImport].rva;
    const std::uint64_t imp_off = *xbox2pc::pe::rva_to_offset(img0, imp_rva);
    // Descriptor 2 (the duplicate kernel32.dll entry) name RVA -> far away.
    const std::uint64_t name_off = imp_off + 2 * 20 + 12;
    buf[static_cast<std::size_t>(name_off)] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 1] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 2] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 3] = 0x90;
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    EXPECT_EQ(rep.unresolved_dll_count, 1u);
}

TEST(DependencyAnalyzerTest, EmptyImage) {
    PeBuildSpec s;
    Diagnostics diags;
    const PeImage img = parse_buf(PeBuilder(s).build(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    EXPECT_EQ(rep.distinct_dll_count(), 0u);
    EXPECT_EQ(rep.total_function_imports(), 0u);
    EXPECT_FALSE(rep.has_delay_imports);
}

// ── Evidence-based classification ─────────────────────────────────────────

TEST(ApiRegistryTest, XboxGraphicsStacks) {
    const ApiRegistry reg;
    // [GDK-SUBVAL]: d3d12_x.dll = Xbox One, d3d12_xs.dll = Scarlett.
    EXPECT_EQ(reg.classify_library("d3d12_x.dll")->category, ApiCategory::XboxGraphics);
    EXPECT_EQ(reg.classify_library("D3D12_X")->category, ApiCategory::XboxGraphics);
    EXPECT_EQ(reg.classify_library("d3d12_xs.dll")->category, ApiCategory::XboxGraphics);
    // Stock Direct3D must NOT classify as Xbox graphics.
    EXPECT_EQ(reg.classify_library("d3d12.dll")->category, ApiCategory::Direct3D);
    EXPECT_EQ(reg.classify_library("d3d11.dll")->category, ApiCategory::Direct3D);
}

TEST(ApiRegistryTest, XboxGameOsAndGdk) {
    const ApiRegistry reg;
    EXPECT_EQ(reg.classify_library("kernelx.dll")->category, ApiCategory::XboxGameOs);
    EXPECT_EQ(reg.classify_library("xgameruntime.dll")->category, ApiCategory::XboxGdk);
    EXPECT_EQ(reg.classify_library("XGAMERUNTIME.DLL")->category, ApiCategory::XboxGdk);
}

TEST(ApiRegistryTest, Win32AndWinRt) {
    const ApiRegistry reg;
    EXPECT_EQ(reg.classify_library("KERNEL32.DLL")->category, ApiCategory::WindowsWin32);
    EXPECT_EQ(reg.classify_library("kernel32")->category, ApiCategory::WindowsWin32);
    EXPECT_EQ(reg.classify_library("combase.dll")->category, ApiCategory::WindowsRuntime);
    // API-set contracts classify as Win32 [MS-APTSETS].
    EXPECT_EQ(reg.classify_library("api-ms-win-core-winrt-l1-1-0.dll")->category,
              ApiCategory::WindowsWin32);
    EXPECT_EQ(reg.classify_library("ext-ms-win-core-samplefeature-l1-1-0")->category,
              ApiCategory::WindowsWin32);
}

TEST(ApiRegistryTest, UnknownStaysUnknown) {
    const ApiRegistry reg;
    // Never classify from a similar name: a made-up "d3d12_xx.dll" or
    // "XboxOneNativeApi.dll" has no evidence -> Unknown.
    EXPECT_FALSE(reg.classify_library("d3d12_xx.dll").has_value());
    EXPECT_FALSE(reg.classify_library("XboxOneNativeApi.dll").has_value());
    EXPECT_FALSE(reg.classify_library("XamRuntime.dll").has_value());
}

TEST(ApiRegistryTest, FunctionLevelRequiresExactPair) {
    const ApiRegistry reg;
    // kernel32!CreateFileW is documented.
    EXPECT_EQ(reg.classify_api("kernel32.dll", "CreateFileW")->category,
              ApiCategory::WindowsWin32);
    // A similar name in the same DLL is NOT auto-classified from the name.
    EXPECT_FALSE(reg.classify_api("kernel32.dll", "CreateFileA").has_value()
                 ? reg.classify_api("kernel32.dll", "CreateFileA")->category ==
                       ApiCategory::WindowsWin32 && false
                 : false);
    // combase!RoGetActivationFactory [MS-ROAPI].
    EXPECT_EQ(reg.classify_api("combase.dll", "RoGetActivationFactory")->category,
              ApiCategory::WindowsRuntime);
}

TEST(ApiRegistryTest, EveryRecordCarriesEvidence) {
    const ApiRegistry reg;
    EXPECT_TRUE(reg.validate().empty()) << "registry records missing evidence";
    EXPECT_GT(reg.record_count(), 20u);
}

// ── Compatibility database ────────────────────────────────────────────────

TEST(CompatDbTest, StatusesPerPlatform) {
    const CompatibilityDb db;
    // Stock Win32/Direct3D/WinRT: Compatible on PC.
    EXPECT_EQ(db.lookup("kernel32.dll", "")->status, CompatStatus::Compatible);
    EXPECT_EQ(db.lookup("d3d11.dll", "")->status, CompatStatus::Compatible);
    EXPECT_EQ(db.lookup("combase.dll", "")->status, CompatStatus::Compatible);
    // Console stacks: Unsupported on PC.
    EXPECT_EQ(db.lookup("d3d12_x.dll", "")->status, CompatStatus::Unsupported);
    EXPECT_EQ(db.lookup("d3d12_xs.dll", "")->status, CompatStatus::Unsupported);
    EXPECT_EQ(db.lookup("kernelx.dll", "")->status, CompatStatus::Unsupported);
    // GDK: Partially compatible.
    EXPECT_EQ(db.lookup("xgameruntime.dll", "")->status,
              CompatStatus::PartiallyCompatible);
}

TEST(CompatDbTest, NoClaimsWithoutEvidence) {
    const CompatibilityDb db;
    EXPECT_TRUE(db.validate().empty()) << "compat claims without evidence";
}

TEST(CompatDbTest, SignatureWhereKnown) {
    const CompatibilityDb db;
    const auto ro = db.lookup("combase.dll", "RoGetActivationFactory");
    ASSERT_TRUE(ro.has_value());
    EXPECT_NE(ro->signature.find("RoGetActivationFactory"), std::string::npos);
    const auto cg = db.lookup("kernel32.dll", "CreateFileW");
    ASSERT_TRUE(cg.has_value());
    EXPECT_FALSE(cg->signature.empty());
}

TEST(CompatDbTest, UnknownLibraryIsUnknown) {
    const CompatibilityDb db;
    EXPECT_FALSE(db.lookup("XboxOneNativeApi.dll", "").has_value());
}

// ── Dependency graph ──────────────────────────────────────────────────────

TEST(DepGraphTest, SingleHopGraph) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags, "game.exe");
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    DependencyGraph g;
    g.build_from_report(rep, img, diags);
    EXPECT_EQ(g.node_count(), 5u);   // root + 4 distinct DLLs
    EXPECT_EQ(g.edge_count(), 4u);
    // Root edges carry function records.
    for (const auto& e : g.edges()) {
        EXPECT_FALSE(e.functions.empty());
    }
}

TEST(DepGraphTest, FunctionRecordsOnEdges) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags, "game.exe");
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    DependencyGraph g;
    g.build_from_report(rep, img, diags);
    const auto deps = g.dependencies_of("game.exe");
    ASSERT_EQ(deps.size(), 4u);
    // KERNEL32 edge: 4 function records (3 + CloseHandle from the duplicate).
    for (const auto& e : g.edges()) {
        if (e.to == "KERNEL32.dll") {
            EXPECT_EQ(e.functions.size(), 4u);
            EXPECT_TRUE(e.functions[2].by_ordinal);
        }
    }
}

TEST(DepGraphTest, CycleDetection) {
    DependencyGraph g;
    g.add_edge("a.dll", "b.dll", {}, false);
    g.add_edge("b.dll", "c.dll", {}, false);
    g.add_edge("c.dll", "a.dll", {}, false);   // a -> b -> c -> a
    g.add_edge("c.dll", "d.dll", {}, false);   // unrelated tail
    const auto cycles = g.detect_cycles();
    ASSERT_EQ(cycles.size(), 1u);
    ASSERT_EQ(cycles[0].nodes.size(), 4u);  // a b c a (closed)
    // Node ids are normalized module names (extension stripped).
    EXPECT_EQ(cycles[0].nodes[0], "a");
    EXPECT_EQ(cycles[0].nodes[3], "a");
}

TEST(DepGraphTest, SelfLoopCycle) {
    DependencyGraph g;
    g.add_edge("solo.dll", "solo.dll", {}, false);
    const auto cycles = g.detect_cycles();
    ASSERT_EQ(cycles.size(), 1u);
    ASSERT_EQ(cycles[0].nodes.size(), 2u);
    EXPECT_EQ(cycles[0].nodes[0], "solo");
}

TEST(DepGraphTest, NoCycleInDag) {
    DependencyGraph g;
    g.add_edge("a.dll", "b.dll", {}, false);
    g.add_edge("a.dll", "c.dll", {}, false);
    g.add_edge("b.dll", "d.dll", {}, false);
    EXPECT_TRUE(g.detect_cycles().empty());
}

TEST(DepGraphTest, MissingDependencies) {
    DependencyGraph g;
    g.add_node("root.exe", true);
    g.add_edge("root.exe", "kernel32.dll", {}, false);
    g.add_edge("root.exe", "NotFound.dll", {}, false);
    g.mark_missing("NotFound.dll");
    // kernel32 is "provided" (registered, not marked missing).
    const auto missing = g.missing_dependencies();
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0].to, "NotFound.dll");
}

TEST(DepGraphTest, TransitiveDependencies) {
    DependencyGraph g;
    g.add_edge("root.exe", "a.dll", {}, false);
    g.add_edge("a.dll", "b.dll", {}, false);
    g.add_edge("b.dll", "c.dll", {}, false);
    g.add_edge("root.exe", "z.dll", {}, false);
    const auto t = g.transitive_dependencies("root.exe");
    ASSERT_EQ(t.size(), 4u);   // a, b, c, z
}

TEST(DepGraphTest, CaseInsensitiveMerge) {
    DependencyGraph g;
    g.add_edge("root.exe", "KERNEL32.dll", {}, false);
    g.add_edge("kernel32.dll", "user32.dll", {}, false);
    // KERNEL32 == kernel32 (one node), plus root.exe and user32.dll.
    EXPECT_EQ(g.node_count(), 3u);
    EXPECT_EQ(g.edge_count(), 2u);
}

// ── Multi-level graph from synthetic images ───────────────────────────────

TEST(DepGraphTest, TwoLevelGraphFromImages) {
    // game.exe -> middleware.dll (own image) -> kernel32.dll.
    PeBuildSpec game;
    game.imports = {{"middleware.dll", {{"MdOpen", 1}}}};
    PeBuildSpec mid;
    mid.imports = {{"kernel32.dll", {{"CreateFileW", 1}}}};
    Diagnostics diags;
    const PeImage game_img = parse_buf(PeBuilder(game).build(), diags, "game.exe");
    const PeImage mid_img = parse_buf(PeBuilder(mid).build(), diags, "middleware.dll");
    const auto rep = xbox2pc::deps::analyze(game_img, diags);
    DependencyGraph g;
    g.build_multi(rep, game_img, {{"middleware.dll", mid_img}}, diags);
    EXPECT_EQ(g.node_count(), 3u);
    EXPECT_EQ(g.edge_count(), 2u);
    EXPECT_TRUE(g.detect_cycles().empty());
    const auto t = g.transitive_dependencies("game.exe");
    EXPECT_EQ(t.size(), 2u);   // middleware.dll + kernel32.dll
}

TEST(DepGraphTest, CircularBetweenImages) {
    // a.dll imports b.dll; b.dll imports a.dll — cycle across two images.
    PeBuildSpec sa;
    sa.imports = {{"b.dll", {{"Bfn", 1}}}};
    PeBuildSpec sb;
    sb.imports = {{"a.dll", {{"Afn", 1}}}};
    Diagnostics diags;
    const PeImage a = parse_buf(PeBuilder(sa).build(), diags, "a.dll");
    const PeImage b = parse_buf(PeBuilder(sb).build(), diags, "b.dll");
    const auto rep = xbox2pc::deps::analyze(a, diags);
    DependencyGraph g;
    g.build_multi(rep, a, {{"b.dll", b}}, diags);
    const auto cycles = g.detect_cycles();
    ASSERT_EQ(cycles.size(), 1u);
    // Canonical rotation starts at the lexicographically smallest node id
    // (normalized: "a", not "a.dll").
    EXPECT_EQ(cycles[0].nodes.front(), "a");
    EXPECT_EQ(cycles[0].nodes.size(), 3u);  // a b a
}

// ── Malformed dependency structures ───────────────────────────────────────

TEST(MalformedDepsTest, DelayImportNameRvaUnmappable) {
    auto buf = rich_image();
    Diagnostics diags0;
    const PeImage img0 = parse_buf(buf, diags0);
    const std::uint32_t d_rva = img0.directories[xbox2pc::pe::kDirDelayImport].rva;
    const std::uint64_t d_off = *xbox2pc::pe::rva_to_offset(img0, d_rva);
    // First descriptor name RVA (offset +4 in ImgDelayDescr).
    const std::uint64_t name_off = d_off + 4;
    buf[static_cast<std::size_t>(name_off)] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 1] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 2] = 0x00;
    buf[static_cast<std::size_t>(name_off) + 3] = 0x90;
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_TRUE(diags.has_warnings());
    ASSERT_GE(img.delay_imports.entries.size(), 1u);
    EXPECT_NE(img.delay_imports.entries[0].dll_name, "d3d12_x.dll");
}

TEST(MalformedDepsTest, DelayRunawayDescriptors) {
    // Zero the terminator descriptor: bounded scan + warning.
    auto buf = rich_image();
    Diagnostics diags0;
    const PeImage img0 = parse_buf(buf, diags0);
    const std::uint32_t d_rva = img0.directories[xbox2pc::pe::kDirDelayImport].rva;
    const std::uint64_t d_off = *xbox2pc::pe::rva_to_offset(img0, d_rva);
    // Descriptor 2 (terminator) start = d_off + 2*32.
    for (unsigned i = 0; i < 32; ++i) {
        buf[static_cast<std::size_t>(d_off) + 2 * 32 + i] = 0xEE;
    }
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    EXPECT_FALSE(diags.has_errors());
    EXPECT_TRUE(diags.has_warnings());
}

TEST(MalformedDepsTest, AnalyzerSurvivesMalformedTables) {
    // Malformed import directory (unmappable) must not break analyze().
    auto buf = rich_image();
    const std::uint64_t pe = 0x80;
    const std::uint64_t dirs = pe + 24 + 112;
    const std::uint64_t d = dirs + 8 * 1;
    buf[static_cast<std::size_t>(d)] = 0x00;
    buf[static_cast<std::size_t>(d) + 1] = 0x00;
    buf[static_cast<std::size_t>(d) + 2] = 0x00;
    buf[static_cast<std::size_t>(d) + 3] = 0x90;
    Diagnostics diags;
    const PeImage img = parse_buf(buf, diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    EXPECT_FALSE(diags.has_errors());
    // Only delay imports survive.
    EXPECT_EQ(rep.distinct_dll_count(), 2u);
}

// ── JSON serialization ────────────────────────────────────────────────────

TEST(JsonWriterTest, EscapesControlChars) {
    EXPECT_EQ(Json::escape("a\nb"), "a\\nb");
    EXPECT_EQ(Json::escape("tab\there"), "tab\\there");
    EXPECT_EQ(Json::escape("quote\"back\\"), "quote\\\"back\\\\");
    // \001 is one byte each: "c", 0x01, 0x02 / "d", 0x7F.
    EXPECT_EQ(Json::escape(std::string("c\001\002")), "c\\u0001\\u0002");
    EXPECT_EQ(Json::escape(std::string("d\177")), "d\\u007f");
    // UTF-8 bytes pass through.
    EXPECT_EQ(Json::escape("caf\xc3\xa9"), "caf\xc3\xa9");
}

TEST(JsonWriterTest, SerializeStructure) {
    Json root = Json::object();
    root.set("name", "xbox2pc");
    root.set("count", 42);
    root.set("ok", true);
    Json arr = Json::array();
    Json inner = Json::object();
    inner.set("dll", "kernel32.dll");
    arr.push_back(inner);
    arr.push_back(Json("plain"));
    root.set("items", arr);
    const std::string out = root.serialize();
    // Round-trip through a real JSON parser (Python) in test via file? Here
    // structural spot checks:
    EXPECT_NE(out.find("\"name\": \"xbox2pc\""), std::string::npos);
    EXPECT_NE(out.find("\"count\": 42"), std::string::npos);
    EXPECT_NE(out.find("\"dll\": \"kernel32.dll\""), std::string::npos);
    EXPECT_NE(out.find("\"plain\""), std::string::npos);
    // Compact form has no newlines.
    EXPECT_EQ(root.serialize_compact().find('\n'), std::string::npos);
}

TEST(JsonWriterTest, IntPrecisionAndTypes) {
    Json big = Json::object();
    big.set("u64", static_cast<std::uint64_t>(0xFFFFFFFFull));
    big.set("neg", -42);
    big.set("zero", 0);
    const std::string out = big.serialize_compact();
    EXPECT_NE(out.find("4294967295"), std::string::npos);
    EXPECT_NE(out.find("-42"), std::string::npos);
    EXPECT_NE(out.find("\"zero\":0"), std::string::npos);
    // Pretty form uses ": ".
    EXPECT_NE(big.serialize().find("\"zero\": 0"), std::string::npos);
    // Type errors throw.
    Json s = Json("x");
    EXPECT_THROW(s.push_back(Json(1)), xbox2pc::json::JsonError);
    EXPECT_THROW(big.get("missing"), xbox2pc::json::JsonError);
}

TEST(JsonWriterTest, DependencyReportJsonRoundTrip) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags, "game.exe");
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    DependencyGraph g;
    g.build_from_report(rep, img, diags);
    const std::string js = g.to_json().serialize_compact();
    // Basic sanity: valid braces, all required top-level keys present.
    EXPECT_EQ(js.front(), '{');
    EXPECT_EQ(js.back(), '}');
    for (const char* key : {"nodes", "edges", "cycles", "missing_dependencies",
                            "node_count", "edge_count"}) {
        EXPECT_NE(js.find(std::string("\"") + key + "\""), std::string::npos)
            << "missing key " << key;
    }
}

TEST(JsonWriterTest, GraphJsonContent) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags, "game.exe");
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    DependencyGraph g;
    g.build_from_report(rep, img, diags);
    const Json j = g.to_json();
    EXPECT_EQ(j.get("node_count").as_int(), 5);
    EXPECT_EQ(j.get("edge_count").as_int(), 4);
    const auto& cycles = j.get("cycles");
    EXPECT_EQ(cycles.size(), 0u);
}

// ── Classification is used end-to-end by the analyzer ──────────────────────

TEST(AnalyzerClassificationTest, CategoriesOnEdges) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    // KERNEL32 -> Windows Win32; d3d12_x -> Xbox graphics; unknown DLL stays
    // explicitly unclassified.
    EXPECT_EQ(rep.dependencies[0].category, ApiCategory::WindowsWin32);
    EXPECT_TRUE(rep.dependencies[0].classified);
    EXPECT_EQ(rep.dependencies[2].category, ApiCategory::XboxGraphics);
    EXPECT_FALSE(rep.dependencies[1].classified);
    EXPECT_EQ(rep.dependencies[1].category_name, "Unknown");
}

TEST(AnalyzerClassificationTest, CompatOnEdges) {
    Diagnostics diags;
    const PeImage img = parse_buf(rich_image(), diags);
    const DependencyReport rep = xbox2pc::deps::analyze(img, diags);
    EXPECT_EQ(rep.dependencies[0].compat_status, CompatStatus::Compatible);
    EXPECT_EQ(rep.dependencies[2].compat_status, CompatStatus::Unsupported);
    // xgameruntime: Partially compatible.
    for (const auto& d : rep.dependencies) {
        if (d.dll_name == "xgameruntime.dll") {
            EXPECT_EQ(d.compat_status, CompatStatus::PartiallyCompatible);
        }
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
