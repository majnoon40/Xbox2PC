// gen_samples: writes demo PE binaries for CLI end-to-end verification.
// Not part of the shipped library — a samples generator.
#include <cstdio>
#include <fstream>
#include <vector>

#include "xbox2pc/pe_builder.hpp"

int main() {
    using xbox2pc::test::ImportDll;
    using xbox2pc::test::ImportFunc;
    using xbox2pc::test::PeBuildSpec;
    using xbox2pc::test::PeBuilder;

    const std::string dir = "/home/z/my-project/xbox2pc/samples/";

    // 1. Valid PE32+ with imports and exports.
    {
        PeBuildSpec s;
        s.imports = {
            {"KERNEL32.dll", {{"CreateFileW", 1}, {"ReadFile", 2}, {"CloseHandle", 3}, {"", 7}}},
            {"XboxOneNativeApi.dll", {{"XamGetGamepadState", 3}, {"XThreadCreate", 4}}},
        };
        s.exports = {
            {"XblInitialize", 0x1080, ""},
            {"", 0, ""},
            {"XblCleanup", 0, "XboxOneNativeApi.XblInitCore"},
        };
        const auto buf = PeBuilder(s).build();
        std::ofstream f(dir + "demo_valid.exe", std::ios::binary);
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        std::printf("demo_valid.exe: %zu bytes\n", buf.size());
    }

    // 2. No imports/exports minimal image.
    {
        const auto buf = PeBuilder(PeBuildSpec()).build();
        std::ofstream f(dir + "demo_minimal.exe", std::ios::binary);
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        std::printf("demo_minimal.exe: %zu bytes\n", buf.size());
    }

    // 3. Truncated: header cut mid section table.
    {
        auto buf = PeBuilder(PeBuildSpec()).build();
        buf.resize(0x1A0);
        std::ofstream f(dir + "demo_truncated.exe", std::ios::binary);
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        std::printf("demo_truncated.exe: %zu bytes\n", buf.size());
    }

    // 4. Bad DOS magic.
    {
        auto buf = PeBuilder(PeBuildSpec()).build();
        buf[0] = 'Z'; buf[1] = 'X';
        std::ofstream f(dir + "demo_badmagic.exe", std::ios::binary);
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        std::printf("demo_badmagic.exe: %zu bytes\n", buf.size());
    }

    // 5. Not a PE at all (garbage).
    {
        std::vector<std::uint8_t> buf(256, 0x37);
        std::ofstream f(dir + "demo_garbage.bin", std::ios::binary);
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        std::printf("demo_garbage.bin: %zu bytes\n", buf.size());
    }

    return 0;
}
