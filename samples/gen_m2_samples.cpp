// gen_m2_samples.cpp — builds a rich M2 demo binary (delay imports,
// duplicate DLL, forwarded exports, Xbox graphics + GDK imports) and writes
// it next to the M1 samples.
//
// Build: g++ -I include -std=c++20 -o gen_samples gen_m2_samples.cpp
//        src/pe_builder.cpp  (run from the xbox2pc repo root)

#include <cstdio>
#include <fstream>
#include <vector>

#include "xbox2pc/pe_builder.hpp"

using xbox2pc::test::DelayImportDll;
using xbox2pc::test::ImportDll;
using xbox2pc::test::ImportFunc;
using xbox2pc::test::PeBuildSpec;
using xbox2pc::test::PeBuilder;

int main(int argc, char** argv) {
    const char* out_dir = argc > 1 ? argv[1] : "samples";
    const char* out_name = argc > 2 ? argv[2] : "demo_xbox_m2.exe";

    PeBuildSpec s;
    // A Durango-style import set: Xbox One graphics stack + Game OS kernel
    // (both [GDK-SUBVAL]/[XVALKYRIE] evidenced) plus stock Win32.
    s.imports = {
        {"KERNEL32.dll", {{"CreateFileW", 1}, {"ReadFile", 2}, {"", 7}}},
        {"kernel32.dll", {{"CloseHandle", 5}}},                // duplicate
        {"d3d12_x.dll", {{"D3D12XCreateDevice", 3}}},          // Xbox One gfx
    };
    s.delay_imports = {
        {"xgameruntime.dll", {{"XGameRuntimeInitialize", 0}}},  // GDK GRTS
        {"XboxOneNativeApi.dll", {{"XamGetGamepadState", 4}}},  // unknown -> Unknown
    };
    s.exports = {
        {"XblInitialize", 0x1080, ""},
        {"XblCleanup", 0x10C0, "XboxOneNativeApi.XblInitCore"},  // forwarder
    };

    const std::vector<std::uint8_t> img = PeBuilder(s).build();
    std::string path = std::string(out_dir) + "/" + out_name;
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        std::fprintf(stderr, "cannot write %s\n", path.c_str());
        return 1;
    }
    f.write(reinterpret_cast<const char*>(img.data()),
            static_cast<std::streamsize>(img.size()));
    std::printf("wrote %s (%zu bytes)\n", path.c_str(), img.size());
    return 0;
}
