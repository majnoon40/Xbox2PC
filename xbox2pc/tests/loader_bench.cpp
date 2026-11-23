// xbox2pc/tests/loader_bench.cpp — M6 loader benchmarks (spec §15).
//
// Measures the loader phases on synthetic fixtures (clearly labeled):
//   - PE validation        (validate_image over valid + issue-laden images)
//   - section mapping      (map_image into a fresh space)
//   - relocation processing(decode + apply, 256 DIR64 entries)
//   - import resolution    (2 DLLs x 8 symbols)
//   - full image loading   (load_image lifecycle incl. rollback-free path)
//   - image unloading      (unload_image)
//   - repeated loading     (N cycles: load -> unload)
//   - multi-process        (8 processes, one image each)
// Fixture characteristics are printed with the results (image size,
// sections, entries). Timings use std::chrono::steady_clock. Correctness
// beats throughput: no benchmark here weakens a safety check.

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "xbox2pc/image_loader.hpp"
#include "xbox2pc/pe_builder.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/runtime_core.hpp"

using xbox2pc::diag::Diagnostics;
using xbox2pc::rt::RuntimeCore;
using xbox2pc::rt::loader::ImageLoader;
using xbox2pc::rt::loader::LoadDiagnostics;
using xbox2pc::rt::loader::LoadResult;
using xbox2pc::rt::loader::StaticResolver;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0)
        .count();
}

}  // namespace

int main() {
    // ── fixture ──
    PeBuildSpec spec;
    spec.imports = {
        {"KERNEL32.dll",
         {{"CreateFileW", 1}, {"WriteConsoleW", 2}, {"CloseHandle", 3},
          {"ReadFile", 4}, {"WriteFile", 5}, {"SetFilePointer", 6},
          {"GetLastError", 7}, {"VirtualAlloc", 8}}},
        {"d3d12_x.dll",
         {{"D3D12XCreateDevice", 1}, {"D3D12XCreateQueue", 2},
          {"D3D12XCreateSwapChain", 3}, {"D3D12XSubmit", 4},
          {"D3D12XWait", 5}, {"D3D12XMap", 6}, {"D3D12XFlush", 7},
          {"D3D12XRelease", 8}}},
    };
    // 96 DIR64 entries across 2 pages (0x2000/.rdata, 0x3000/.data —
    // inside the 0x4000 image; targets 8..0xF8 in-page). The .text page is
    // NOT used: the import thunk machinery lives there and reloc planting
    // would corrupt it.
    for (std::uint32_t page = 0x2000; page < 0x4000; page += 0x1000) {
        xbox2pc::test::RelocBlockSpec blk;
        blk.page_rva = page;
        for (int e = 0; e < 32; ++e) {
            blk.entries.push_back({10, page + 8u + static_cast<std::uint32_t>(e) * 8,
                                   0x140000000ull + page});
        }
        spec.reloc_blocks.push_back(std::move(blk));
    }
    spec.tls.template_data = std::vector<std::uint8_t>(64, 0xAB);
    spec.tls.zero_fill = 128;
    spec.tls.callback_vas = {0x140001100, 0x140001108};
    const auto image = PeBuilder(spec).build();

    Diagnostics diags;
    const auto img = xbox2pc::pe::parse(image.data(), image.size(), "bench.exe", diags);
    std::printf("fixture: %zu bytes, %zu sections, %zu imports, "
                "%zu reloc blocks, TLS template 64 B\n",
                image.size(), img.sections.size(), img.imports.entries.size(),
                spec.reloc_blocks.size());

    RuntimeCore core;
    if (!core.initialize().ok()) {
        std::fprintf(stderr, "error: runtime init failed\n");
        return 1;
    }
    xbox2pc::rt::ProcessManager pm(core.objects());
    ImageLoader loader;
    StaticResolver res;
    for (const auto& e : img.imports.entries) res.add_module(e.dll_name, e.functions);

    // ── validation ──
    {
        const int N = 2000;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            (void)xbox2pc::rt::loader::validate_image(img, image.data(), image.size());
        }
        std::printf("validate_image:   %8.3f ms/op (%d ops)\n",
                    ms_since(t0) / N, N);
    }

    // ── mapping ──
    std::uint64_t mapped_ops = 0;
    {
        auto p = pm.create_process("bench-map.exe", 64ull << 20);
        auto found = core.objects().lookup_handle(p.value());
        auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
        const int N = 500;
        const auto t0 = Clock::now();
        for (int i = 0; i < N; ++i) {
            LoadDiagnostics ld;
            auto lay = loader.map_image(proc->address_space(), img,
                                        image.data(), image.size(), 0, ld);
            if (!lay.ok()) break;
            ++mapped_ops;
            for (auto it = lay.value().sections.rbegin();
                 it != lay.value().sections.rend(); ++it)
                (void)proc->address_space().release_region(it->mapped_base);
            (void)proc->address_space().release_region(
                lay.value().headers_region_xbox_va);
        }
        std::printf("map+unmap_image:  %8.3f ms/op (%llu ops, map+release)\n",
                    ms_since(t0) / static_cast<double>(mapped_ops ? mapped_ops : 1),
                    static_cast<unsigned long long>(mapped_ops));
        (void)pm.terminate_process(p.value(), 0);
    }

    // ── relocation processing (decode + apply) ──
    {
        auto p = pm.create_process("bench-rel.exe", 64ull << 20);
        auto found = core.objects().lookup_handle(p.value());
        auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
        LoadDiagnostics ld;
        auto lay = loader.map_image(proc->address_space(), img, image.data(),
                                    image.size(), 0, ld);
        if (lay.ok()) {
            const int N = 500;
            const auto t0 = Clock::now();
            std::uint64_t applied = 0;
            for (int i = 0; i < N; ++i) {
                LoadDiagnostics d2;
                applied = loader
                             .apply_relocations(proc->address_space(),
                                                 lay.value(), img,
                                                 image.data(), image.size(), d2)
                             .value();
            }
            std::printf("relocations:      %8.3f ms/op (%llu DIR64 applied/op)\n",
                        ms_since(t0) / static_cast<double>(N),
                        static_cast<unsigned long long>(applied));
        }
        (void)pm.terminate_process(p.value(), 0);
    }

    // ── import resolution ──
    {
        auto p = pm.create_process("bench-imp.exe", 64ull << 20);
        auto found = core.objects().lookup_handle(p.value());
        auto* proc = found.value().get()->as<xbox2pc::rt::ManagedProcess>();
        LoadDiagnostics ld;
        auto lay = loader.map_image(proc->address_space(), img, image.data(),
                                    image.size(), 0, ld);
        if (lay.ok()) {
            const int N = 500;
            const auto t0 = Clock::now();
            for (int i = 0; i < N; ++i) {
                LoadDiagnostics d2;
                (void)loader.resolve_imports(proc->address_space(), lay.value(),
                                             img, image.data(), image.size(),
                                             res, d2);
            }
            std::printf("import resolve:   %8.3f ms/op (16 symbols)\n",
                        ms_since(t0) / N);
        }
        (void)pm.terminate_process(p.value(), 0);
    }

    // ── full load + unload cycles ──
    {
        auto p = pm.create_process("bench-load.exe", 64ull << 20);
        const int N = 300;
        const auto t0 = Clock::now();
        int ok = 0;
        for (int i = 0; i < N; ++i) {
            LoadDiagnostics ld;
            LoadResult out;
            auto h = loader.load_image(pm, core.objects(), p.value(), img,
                                       image.data(), image.size(), &res, ld, out);
            if (h.ok()) {
                ++ok;
                (void)loader.unload_image(pm, core.objects(), p.value(), h.value());
            }
        }
        std::printf("load_image:       %8.3f ms/op (full lifecycle, %d ok)\n",
                    ms_since(t0) / (ok ? ok : 1), ok);
        (void)pm.terminate_process(p.value(), 0);
    }

    // ── multi-process: 8 processes, one load each ──
    {
        const int P = 8;
        const auto t0 = Clock::now();
        for (int i = 0; i < P; ++i) {
            auto p = pm.create_process("bench-multi.exe", 64ull << 20);
            if (!p.ok()) continue;
            LoadDiagnostics ld;
            LoadResult out;
            auto h = loader.load_image(pm, core.objects(), p.value(), img,
                                       image.data(), image.size(), &res, ld, out);
            if (h.ok())
                (void)loader.unload_image(pm, core.objects(), p.value(), h.value());
            (void)pm.terminate_process(p.value(), 0);
        }
        std::printf("multi-process:    %8.3f ms for %d process load+unload\n",
                    ms_since(t0), P);
    }

    (void)core.shutdown();
    std::printf("done.\n");
    return 0;
}
