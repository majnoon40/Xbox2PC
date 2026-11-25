// Generates the sample PEs using the repo's PeBuilder.
#include "xbox2pc/pe_builder.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
using namespace xbox2pc;

static void dump(const char* out, const std::vector<std::uint8_t>& bytes) {
    std::ofstream f(out, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

// Parse the first descriptor's IAT RVA out of a built image.
static std::uint32_t first_iat_rva(const std::vector<std::uint8_t>& image) {
    std::uint32_t pe = 0;
    std::memcpy(&pe, image.data() + 0x3C, 4);
    std::uint32_t import_rva = 0;
    std::memcpy(&import_rva, image.data() + pe + 24 + 120, 4);
    std::uint32_t off = import_rva >= 0x1000 ? import_rva - 0x1000 + 0x400 : import_rva;
    std::uint32_t iat_rva = 0;
    std::memcpy(&iat_rva, image.data() + off + 16, 4);
    return iat_rva;
}

int main(int argc, char** argv) {
    if (argc != 5) { std::fprintf(stderr, "usage: gen <ignored1> <ignored2> <out42> <outtc>\n"); return 2; }
    {
        // exit42: mov ecx,42; call [rip+disp]; ret  (12 bytes)
        test::PeBuildSpec s;
        s.image_base = 0x140000000;
        s.entry_point_rva = 0x1000;
        s.imports = {{"kernel32", {{"ExitProcess", 0}}}};
        s.reloc_blocks = {test::RelocBlockSpec{0x2000, {test::RelocSpec{10, 0x2000, 0}}}};
        std::vector<std::uint8_t> probe(12, 0xC3);
        s.text_payloads.emplace_back(0x1000, probe);
        const std::uint32_t iat_rva = first_iat_rva(test::PeBuilder(s).build());
        const std::int64_t disp = static_cast<std::int64_t>(iat_rva) -
                                  static_cast<std::int64_t>(0x1000 + 5 + 6);
        std::vector<std::uint8_t> code;
        code.push_back(0xB9); code.push_back(0x2A); code.push_back(0x00);
        code.push_back(0x00); code.push_back(0x00);
        code.push_back(0xFF); code.push_back(0x15);
        code.push_back(static_cast<std::uint8_t>(disp & 0xFF));
        code.push_back(static_cast<std::uint8_t>((disp >> 8) & 0xFF));
        code.push_back(static_cast<std::uint8_t>((disp >> 16) & 0xFF));
        code.push_back(static_cast<std::uint8_t>((disp >> 24) & 0xFF));
        code.push_back(0xC3);
        s.text_payloads.clear();
        s.text_payloads.emplace_back(0x1000, code);
        dump(argv[3], test::PeBuilder(s).build());
        std::printf("exit42: iat rva 0x%x, disp %lld\n", iat_rva, (long long)disp);
    }
    {
        // throwcatch (SEH): entry calls RaiseException(0xE0000001,0,0,0);
        // the language handler at 0x1020 is the "catch": mov eax,0x2A; ret.
        // .pdata: function 0x1000-0x1010, UNWIND_INFO at 0x1200 with
        // EHANDLER=0x1020. count=0 -> the trailer handler RVA follows
        // immediately (0 slots, even -> no pad).
        test::PeBuildSpec s;
        s.image_base = 0x140000000;
        s.entry_point_rva = 0x1000;
        s.imports = {{"kernel32", {{"RaiseException", 0}}}};
        s.reloc_blocks = {test::RelocBlockSpec{0x2000, {test::RelocSpec{10, 0x2000, 0}}}};
        // Probe with the FULL final payload set (same sizes) so the
        // builder's import placement matches the final image exactly.
        std::vector<std::uint8_t> probe(16, 0xC3);
        s.text_payloads.emplace_back(0x1000, probe);
        std::vector<std::uint8_t> probe_handler(6, 0xC3);
        s.text_payloads.emplace_back(0x1020, probe_handler);
        std::vector<std::uint8_t> probe_unwind(8, 0x00);
        s.text_payloads.emplace_back(0x1200, probe_unwind);
        s.exception_directory_payload = {
            0x00, 0x10, 0x00, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00};
        const std::uint32_t iat_rva2 = first_iat_rva(test::PeBuilder(s).build());
        const std::int64_t disp = static_cast<std::int64_t>(iat_rva2) -
                                  static_cast<std::int64_t>(0x1000 + 10 + 6);
        std::vector<std::uint8_t> code;
        code.push_back(0x31); code.push_back(0xC9);            // xor ecx,ecx
        code.push_back(0x31); code.push_back(0xD2);            // xor edx,edx
        code.push_back(0x45); code.push_back(0x31); code.push_back(0xC0); // xor r8d,r8d
        code.push_back(0x45); code.push_back(0x31); code.push_back(0xC9); // xor r9d,r9d
        code.push_back(0xFF); code.push_back(0x15);            // call [rip+disp]
        code.push_back(static_cast<std::uint8_t>(disp & 0xFF));
        code.push_back(static_cast<std::uint8_t>((disp >> 8) & 0xFF));
        code.push_back(static_cast<std::uint8_t>((disp >> 16) & 0xFF));
        code.push_back(static_cast<std::uint8_t>((disp >> 24) & 0xFF));
        // (the SEH transfer never returns here; pad to 0x1010)
        while (code.size() < 0x10) code.push_back(0xC3);
        // handler at 0x1020: mov eax,0x2A; ret
        std::vector<std::uint8_t> handler{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
        s.text_payloads.clear();
        s.text_payloads.emplace_back(0x1000, code);
        s.text_payloads.emplace_back(0x1020, handler);
        // UNWIND_INFO at 0x1200: v1 + EHANDLER, prolog 0, count 0;
        // handler RVA 0x1020 at +4.
        std::vector<std::uint8_t> unwind{0x09, 0x00, 0x00, 0x00,
                                         0x20, 0x10, 0x00, 0x00};
        s.text_payloads.emplace_back(0x1200, unwind);
        // .pdata: 0x1000-0x1010 -> unwind 0x1200
        s.exception_directory_payload = {
            0x00, 0x10, 0x00, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00};
        dump(argv[4], test::PeBuilder(s).build());
        std::printf("throwcatch: iat rva 0x%x, disp %lld\n", iat_rva2, (long long)disp);
    }
    return 0;
}
