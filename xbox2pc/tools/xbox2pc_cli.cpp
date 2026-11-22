// xbox2pc CLI — M1: `xbox2pc inspect <file>`
//
// Prints a structured inspection report of a PE32+ binary:
//   architecture, PE format, entry point, image base, sections,
//   imports (DLLs + functions), exports, warnings and errors.
//
// Exit codes: 0 = parsed (warnings allowed), 1 = hard parse error,
// 2 = usage error. Output goes to stdout; diagnostics to stderr.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_parser.hpp"

namespace {

std::string hex(std::uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(v));
    return b;
}

std::string human_size(std::uint64_t bytes) {
    char b[48];
    if (bytes >= 1024 * 1024) {
        std::snprintf(b, sizeof(b), "%.2f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        std::snprintf(b, sizeof(b), "%.2f KiB", static_cast<double>(bytes) / 1024.0);
    } else {
        std::snprintf(b, sizeof(b), "%llu B", static_cast<unsigned long long>(bytes));
    }
    return b;
}

void print_report(const xbox2pc::pe::PeImage& img, const xbox2pc::diag::Diagnostics& diags) {
    using namespace xbox2pc::pe;

    // header block
    std::printf("%s\n", std::string(64, '=').c_str());
    std::printf("xbox2pc PE inspection report\n");
    std::printf("source: %s\n", img.source_name.c_str());
    std::printf("%s\n", std::string(64, '=').c_str());

    std::printf("architecture:  %s\n", img.machine_name().c_str());
    std::printf("pe_format:     %s\n",
                img.opt.is_pe32plus ? "PE32+ (x86-64, 64-bit addresses)"
                                    : (img.opt.is_pe32 ? "PE32 (32-bit)" : "unknown"));
    std::printf("entry_point:   RVA %s", hex(img.opt.address_of_entry_point).c_str());
    if (const auto va = img.entry_point_va()) {
        std::printf(" (VA %s)", hex(*va).c_str());
    }
    std::printf("\n");
    std::printf("image_base:    %s\n", hex(img.opt.image_base).c_str());
    std::printf("subsystem:     %u (%s)\n", img.opt.subsystem, img.subsystem_name().c_str());
    std::printf("size_of_image: %s\n", hex(img.opt.size_of_image).c_str());
    std::printf("timestamp:     %u (0x%X)\n", img.coff.time_date_stamp, img.coff.time_date_stamp);
    std::printf("linker:        %u.%u\n", img.opt.major_linker_version,
                img.opt.minor_linker_version);
    std::printf("dll_characteristics: 0x%04X\n", img.opt.dll_characteristics);
    if (img.coff.characteristics & 0x0002) std::printf("image_type:    DLL\n");
    else if (img.coff.characteristics & 0x0001) std::printf("image_type:    object\n");
    else std::printf("image_type:    executable\n");

    // sections
    std::printf("\nsections (%u):\n", static_cast<unsigned>(img.sections.size()));
    std::printf("  %-8s %-10s %-10s %-10s %-10s\n", "name", "vsize", "vaddr", "rawsz", "raw@");
    for (const auto& s : img.sections) {
        const bool readable = (s.characteristics & sect_flags::kReadable) != 0;
        std::printf("  %-8s %-10s %-10s %-10s %-10s %s%s%s%s%s\n",
                    s.name.c_str(),
                    hex(s.virtual_size).c_str(),
                    hex(s.virtual_address).c_str(),
                    hex(s.size_of_raw_data).c_str(),
                    hex(s.raw_data_offset).c_str(),
                    human_size(s.size_of_raw_data).c_str(),
                    readable ? " r" : "",
                    (s.characteristics & sect_flags::kCode) != 0 ? " code" : "",
                    (s.characteristics & sect_flags::kWritable) != 0 ? " w" : "",
                    s.has_raw_data ? "" : " [no raw data]");
    }

    // directories (non-empty only)
    std::printf("\ndata_directories:\n");
    bool any_dir = false;
    for (std::uint16_t i = 0; i < img.directories.size(); ++i) {
        const auto& d = img.directories[i];
        if (d.rva == 0 && d.size == 0) continue;
        any_dir = true;
        std::printf("  %-14s rva %s  size %s\n", d.name.c_str(), hex(d.rva).c_str(),
                    hex(d.size).c_str());
    }
    if (!any_dir) std::printf("  (none)\n");

    // imports
    std::printf("\nimports:\n");
    if (!img.imports.present || img.imports.entries.empty()) {
        std::printf("  (none)\n");
    } else {
        std::size_t total_fn = 0;
        for (const auto& e : img.imports.entries) {
            total_fn += e.functions.size() + e.ordinal_only.size();
        }
        std::printf("  %zu DLL(s), %zu function(s)\n", img.imports.entries.size(), total_fn);
        for (const auto& e : img.imports.entries) {
            std::printf("  %s\n", e.dll_name.c_str());
            for (const auto& fn : e.functions) std::printf("      %s\n", fn.c_str());
            for (std::uint32_t ord : e.ordinal_only) {
                std::printf("      #%u (ordinal only)\n", ord);
            }
        }
    }

    // exports
    std::printf("\nexports:\n");
    if (!img.exports.present || img.exports.functions.empty()) {
        std::printf("  (none)\n");
    } else {
        std::printf("  name: %s  (ordinal base %u, %zu functions, %zu named)\n",
                    img.exports.dll_name.empty() ? "(unnamed)" : img.exports.dll_name.c_str(),
                    img.exports.ordinal_base, img.exports.functions.size(),
                    img.exports.name_rvas.size());
        for (const auto& f : img.exports.functions) {
            const std::string fwd = f.forwarder.empty() ? ""
                : " -> forwarded to " + f.forwarder;
            std::printf("  #%-6u %-12s %s%s\n", f.ordinal, hex(f.rva).c_str(),
                        f.name.empty() ? "(unnamed)" : f.name.c_str(), fwd.c_str());
        }
    }

    // warnings / errors
    std::printf("\ndiagnostics:\n");
    const auto& es = diags.entries();
    if (es.empty()) {
        std::printf("  (no warnings or errors)\n");
    } else {
        for (const auto& l : diags.lines()) std::printf("  %s\n", l.c_str());
    }
    std::printf("%s\n", std::string(64, '=').c_str());
}

int cmd_inspect(const std::string& path, bool quiet) {
    xbox2pc::diag::Diagnostics diags;
    try {
        const xbox2pc::pe::PeImage img = xbox2pc::pe::parse_file(path, diags);
        print_report(img, diags);
        if (!quiet && diags.has_warnings()) {
            std::fprintf(stderr, "note: %zu warning(s) during parse\n",
                         static_cast<std::size_t>(diags.count(xbox2pc::diag::Severity::Warning)));
        }
        return 0;
    } catch (const xbox2pc::pe::ParseError& e) {
        std::fprintf(stderr, "error: %s", e.what());
        if (e.has_offset()) std::fprintf(stderr, " at offset %s", hex(e.offset()).c_str());
        std::fprintf(stderr, "\n");
        for (const auto& l : diags.lines()) std::fprintf(stderr, "  %s\n", l.c_str());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && (std::strcmp(argv[1], "--version") == 0 || std::strcmp(argv[1], "-v") == 0)) {
        std::printf("xbox2pc 0.1.0 (M1: PE32+ inspection)\n");
        return 0;
    }
    if (argc < 3 || std::strcmp(argv[1], "inspect") != 0) {
        std::fprintf(stderr,
                      "usage: xbox2pc inspect <pe-file> [--quiet]\n"
                      "       xbox2pc --version\n");
        return 2;
    }
    bool quiet = false;
    for (int i = 3; i < argc; ++i) {
        if (std::strcmp(argv[i], "--quiet") == 0) quiet = true;
        else {
            std::fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 2;
        }
    }
    return cmd_inspect(argv[2], quiet);
}
