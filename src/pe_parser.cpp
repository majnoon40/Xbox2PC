#include "xbox2pc/pe_parser.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <utility>

#include "pe_internal.hpp"

namespace xbox2pc::pe {
namespace {

// ── overflow-safe arithmetic ─────────────────────────────────────────────

// Returns a+b or nullopt on overflow. Every size computation in the parser
// flows through this, so a hostile 0xFFFFFFFF size field can never wrap
// into a small passable value.
template <typename T>
std::optional<T> checked_add(T a, T b) {
    static_assert(std::is_unsigned_v<T>);
    const T sum = a + b;
    if (sum < a) return std::nullopt;  // wrapped
    return sum;
}

bool in_range(std::uint64_t off, std::uint64_t len, std::uint64_t total) {
    // off + len must fit and stay within total; len == 0 is fine at off == total.
    const auto end = checked_add<std::uint64_t>(off, len);
    if (!end.has_value()) return false;
    return *end <= total;
}

// ── little-endian readers (bounds-checked against the buffer end) ───────

struct Reader {
    const std::uint8_t* base;
    std::uint64_t size;  // logical end for all reads (whole file)

    // All reads funnel through read_u8 so every single-byte fetch is checked;
    // wider readers assemble bytes individually — no memcpy past the end can
    // occur even transiently.
    std::uint8_t read_u8(std::uint64_t off) const {
        if (off >= size) throw ParseError("unexpected end of file while reading", off);
        return base[off];
    }

    std::uint16_t read_u16(std::uint64_t off) const {
        std::uint16_t v = 0;
        for (unsigned i = 0; i < 2; ++i) {
            v = static_cast<std::uint16_t>(v | (static_cast<std::uint16_t>(read_u8(off + i)) << (8 * i)));
        }
        return v;
    }

    std::uint32_t read_u32(std::uint64_t off) const {
        std::uint32_t v = 0;
        for (unsigned i = 0; i < 4; ++i) {
            v |= static_cast<std::uint32_t>(read_u8(off + i)) << (8 * i);
        }
        return v;
    }

    std::uint64_t read_u64(std::uint64_t off) const {
        std::uint64_t v = 0;
        for (unsigned i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(read_u8(off + i)) << (8 * i);
        }
        return v;
    }

    // Read a NUL-terminated ASCII-ish string starting at off, at most
    // max_len bytes. Stops at NUL or the read bound; never reads past `size`.
    std::string read_cstr(std::uint64_t off, std::uint64_t max_len) const {
        std::string out;
        out.reserve(16);
        if (off >= size) return out;
        const std::uint64_t available = size - off;
        const std::uint64_t limit = max_len < available ? max_len : available;
        for (std::uint64_t i = 0; i < limit; ++i) {
            const std::uint8_t c = base[off + i];
            if (c == 0) break;
            out.push_back(static_cast<char>(c));
        }
        return out;
    }
};

const char* kDirNames[kMaxDataDirectories] = {
    "Export", "Import", "Resource", "Exception", "Security", "BaseRelocation",
    "Debug", "Architecture", "GlobalPtr", "Tls", "LoadConfig", "BoundImport",
    "Iat", "DelayImport", "ClrRuntime", "Reserved",
};

}  // namespace

// ── public string helpers ──────────────────────────────────────────────

const char* directory_to_name(std::uint16_t dir) {
    if (dir >= kMaxDataDirectories) return "Reserved";
    const char* n = kDirNames[dir];
    return n ? n : "Reserved";
}

const char* machine_to_name(std::uint16_t machine) {
    switch (machine) {
        case kMachineAmd64: return "x86-64 (AMD64)";
        case kMachineI386: return "x86 (i386)";
        case kMachineArm64: return "ARM64";
        case 0x1C0: return "ARM (Thumb-2)";
        case 0x01C4: return "ARMNT";
        case 0x0200: return "IA-64";
        case kMachineUnknown: return "Unknown";
        default: return "Other/Unknown";
    }
}

const char* subsystem_to_name(std::uint16_t subsystem) {
    switch (subsystem) {
        case 0: return "Unknown";
        case 1: return "Native";
        case 2: return "Windows GUI";
        case 3: return "Windows Console (CUI)";
        case 5: return "OS/2 CLI";
        case 7: return "POSIX CUI";
        case 8: return "Native Windows";
        case 9: return "Windows CE GUI";
        case 10: return "EFI Application";
        case 11: return "EFI Boot Service Driver";
        case 12: return "EFI Runtime Driver";
        case 13: return "EFI ROM";
        case 14: return "Xbox";
        case 16: return "Windows Boot Application";
        default: return "Other";
    }
}

bool Section::contains_rva(std::uint32_t rva) const {
    // Section virtual span uses max(VirtualSize, SizeOfRawData): VirtualSize
    // can be smaller than the raw size and can also be 0 (invalid) in some
    // shipped binaries, in which case raw size governs.
    std::uint32_t span = virtual_size;
    if (span < size_of_raw_data) span = size_of_raw_data;
    if (span == 0) return false;
    const std::uint64_t start = virtual_address;
    const std::uint64_t end = start + static_cast<std::uint64_t>(span);  // no overflow in 64-bit
    return rva >= start && rva < end;
}

std::optional<std::uint64_t> rva_to_offset(const PeImage& img, std::uint32_t rva) {
    for (const auto& s : img.sections) {
        if (!s.contains_rva(rva)) continue;
        if (!s.has_raw_data) return std::nullopt;  // BSS-like: no file backing
        const std::uint64_t delta = static_cast<std::uint64_t>(rva) - s.virtual_address;
        if (delta >= s.size_of_raw_data) return std::nullopt;  // in virtual-only tail
        return s.raw_data_offset + delta;
    }
    return std::nullopt;
}

std::string PeImage::machine_name() const { return machine_to_name(coff.machine); }
std::string PeImage::subsystem_name() const { return subsystem_to_name(opt.subsystem); }

// ── main parse ──────────────────────────────────────────────────────────

PeImage parse(const std::uint8_t* data, std::size_t size, std::string source_name,
              diag::Diagnostics& diags) {
    if (data == nullptr) {
        throw ParseError("null input buffer", 0);
    }
    if (size < kDosHeaderSize) {
        throw ParseError("file too small for a DOS header (" + std::to_string(size) + " bytes)", 0);
    }
    const Reader rd{data, size};
    PeImage img;
    img.source_name = std::move(source_name);

    // ── DOS header ──
    if (rd.read_u16(0) != kDosMagic) {
        throw ParseError("missing MZ (DOS) signature", 0);
    }
    img.e_lfanew = rd.read_u32(0x3C);

    // e_lfanew must point at the PE signature with room for COFF+opt headers.
    const std::uint64_t pe_off = img.e_lfanew;
    constexpr std::uint64_t kMinPePrefix = 4 + kCoffHeaderSize + 2;  // sig + COFF + magic
    if (pe_off < kDosHeaderSize || pe_off > size) {
        throw ParseError("e_lfanew out of range", 0x3C);
    }
    if (!in_range(pe_off, kMinPePrefix, size)) {
        throw ParseError("truncated PE header", pe_off);
    }
    if (rd.read_u32(pe_off) != kPeSignature) {
        throw ParseError("missing PE\\0\\0 signature", pe_off);
    }

    // ── COFF header ──
    const std::uint64_t coff_off = pe_off + 4;
    img.coff.machine = rd.read_u16(coff_off + 0);
    img.coff.number_of_sections = rd.read_u16(coff_off + 2);
    img.coff.time_date_stamp = rd.read_u32(coff_off + 4);
    img.coff.pointer_to_symbol_table = rd.read_u32(coff_off + 8);
    img.coff.number_of_symbols = rd.read_u32(coff_off + 12);
    img.coff.size_of_optional_header = rd.read_u16(coff_off + 16);
    img.coff.characteristics = rd.read_u16(coff_off + 18);

    if (img.coff.number_of_sections > kMaxSections) {
        diags.warning("NumberOfSections (" + std::to_string(img.coff.number_of_sections) +
                      ") exceeds sane bound; clamping parse to 96",
                      coff_off + 2);
        // Still parse the first 96; more than that is essentially never legit.
        img.coff.number_of_sections = kMaxSections;
    }

    if (img.coff.pointer_to_symbol_table != 0 || img.coff.number_of_symbols != 0) {
        // COFF symbol table present — common in older binaries, note it.
        if (img.coff.pointer_to_symbol_table >= size && img.coff.number_of_symbols != 0) {
            diags.warning("COFF symbol table pointer beyond end of file", coff_off + 8);
        }
    }

    // ── Optional header ──
    const std::uint64_t opt_off = coff_off + kCoffHeaderSize;
    const std::uint16_t opt_size = img.coff.size_of_optional_header;
    if (opt_size == 0) {
        // Object file / headerless image — not an executable image.
        throw ParseError("no optional header present (object file or stripped image)", opt_off);
    }
    if (!in_range(opt_off, opt_size, size)) {
        throw ParseError("truncated optional header", opt_off);
    }
    const std::uint16_t magic = rd.read_u16(opt_off);
    img.opt.magic = magic;
    switch (magic) {
        case kOptMagicPe32Plus:
            img.opt.is_pe32plus = true;
            break;
        case kOptMagicPe32:
            img.opt.is_pe32 = true;
            diags.warning("PE32 (32-bit) optional header; this tool fully models PE32+ only");
            break;
        case kOptMagicRom:
            throw ParseError("ROM optional header is not supported", opt_off);
        default:
            throw ParseError("unknown optional header magic 0x" + [&] {
                char b[8];
                std::snprintf(b, sizeof(b), "%X", magic);
                return std::string(b);
            }(), opt_off);
    }

    // Minimum fixed sizes: PE32+ fixed part is 112 bytes; PE32 is 96 bytes.
    const std::uint64_t fixed = (magic == kOptMagicPe32Plus) ? 112u : 96u;
    if (opt_size < fixed) {
        throw ParseError("optional header too small for its magic (" + std::to_string(opt_size) +
                         " bytes)", opt_off);
    }
    if (!in_range(opt_off, fixed, size)) {
        throw ParseError("truncated optional header (fixed part)", opt_off);
    }

    auto& o = img.opt;
    o.major_linker_version = rd.read_u8(opt_off + 2);
    o.minor_linker_version = rd.read_u8(opt_off + 3);
    o.size_of_code = rd.read_u32(opt_off + 4);
    o.size_of_initialized_data = rd.read_u32(opt_off + 8);
    o.size_of_uninitialized_data = rd.read_u32(opt_off + 12);
    o.address_of_entry_point = rd.read_u32(opt_off + 16);
    o.base_of_code = rd.read_u32(opt_off + 20);
    if (magic == kOptMagicPe32Plus) {
        o.image_base = rd.read_u64(opt_off + 24);
    } else {
        o.image_base = rd.read_u32(opt_off + 28);  // PE32: ImageBase is u32
    }
    o.section_alignment = rd.read_u32(opt_off + 32);
    o.file_alignment = rd.read_u32(opt_off + 36);
    o.major_os_version = rd.read_u16(opt_off + 40);
    o.minor_os_version = rd.read_u16(opt_off + 42);
    o.major_image_version = rd.read_u16(opt_off + 44);
    o.minor_image_version = rd.read_u16(opt_off + 46);
    o.major_subsystem_version = rd.read_u16(opt_off + 48);
    o.minor_subsystem_version = rd.read_u16(opt_off + 50);
    o.win32_version_value = rd.read_u32(opt_off + 52);
    o.size_of_image = rd.read_u32(opt_off + 56);
    o.size_of_headers = rd.read_u32(opt_off + 60);
    o.checksum = rd.read_u32(opt_off + 64);
    o.subsystem = rd.read_u16(opt_off + 68);
    o.dll_characteristics = rd.read_u16(opt_off + 70);
    if (magic == kOptMagicPe32Plus) {
        o.size_of_stack_reserve = rd.read_u64(opt_off + 72);
        o.size_of_stack_commit = rd.read_u64(opt_off + 80);
        o.size_of_heap_reserve = rd.read_u64(opt_off + 88);
        o.size_of_heap_commit = rd.read_u64(opt_off + 96);
        o.loader_flags = rd.read_u32(opt_off + 104);
        o.number_of_rva_and_sizes = rd.read_u32(opt_off + 108);
    } else {
        o.size_of_stack_reserve = rd.read_u32(opt_off + 72);
        o.size_of_stack_commit = rd.read_u32(opt_off + 76);
        o.size_of_heap_reserve = rd.read_u32(opt_off + 80);
        o.size_of_heap_commit = rd.read_u32(opt_off + 84);
        o.loader_flags = rd.read_u32(opt_off + 88);
        o.number_of_rva_and_sizes = rd.read_u32(opt_off + 92);
    }

    // Sanity checks that are warnings, not fatal.
    if (o.file_alignment != 0 && o.file_alignment < 512) {
        diags.warning("FileAlignment below the spec minimum of 512", opt_off + 36);
    } else if (o.file_alignment != 0 && (o.file_alignment & (o.file_alignment - 1)) != 0) {
        diags.warning("FileAlignment is not a power of two", opt_off + 36);
    }
    if (o.section_alignment != 0 && (o.section_alignment & (o.section_alignment - 1)) != 0) {
        diags.warning("SectionAlignment is not a power of two", opt_off + 32);
    }
    if (o.image_base != 0 && (o.image_base & 0xFFFF) != 0) {
        diags.warning("ImageBase is not 64KiB aligned", opt_off + 24);
    }

    // ── Data directories ──
    // number_of_rva_and_sizes counts entries of 8 bytes each; anything above
    // 16 is either future-extension or garbage — cap with a warning.
    std::uint32_t ndirs = o.number_of_rva_and_sizes;
    if (ndirs > kMaxDataDirectories) {
        diags.warning("NumberOfRvaAndSizes (" + std::to_string(ndirs) +
                      ") exceeds 16; clamping", opt_off + 108);
        ndirs = kMaxDataDirectories;
    }
    const std::uint64_t dirs_off = opt_off + fixed;
    const auto dirs_end = checked_add<std::uint64_t>(dirs_off, static_cast<std::uint64_t>(ndirs) * 8);
    const auto opt_end = checked_add<std::uint64_t>(opt_off, opt_size);
    if (!dirs_end.has_value() || !opt_end.has_value() ||
        *dirs_end > *opt_end || *opt_end > size) {
        // Directory array extends beyond the optional header: clamped count.
        if (opt_size >= fixed) {
            const std::uint64_t avail = (opt_size - fixed) / 8;  // bytes available in header
            const std::uint32_t fit = static_cast<std::uint32_t>(avail < ndirs ? avail : ndirs);
            if (fit < ndirs) {
                diags.warning("data directory array truncated by optional header size; reading " +
                              std::to_string(fit) + " of " + std::to_string(ndirs) + " entries",
                              dirs_off);
                ndirs = fit;
            }
        }
    }
    img.directories.resize(ndirs);
    for (std::uint32_t i = 0; i < ndirs; ++i) {
        DataDirectory& d = img.directories[i];
        d.rva = rd.read_u32(dirs_off + 8ull * i);
        d.size = rd.read_u32(dirs_off + 8ull * i + 4);
        d.name = directory_to_name(static_cast<std::uint16_t>(i));
    }

    // ── Section table ──
    const std::uint64_t sect_off = opt_off + opt_size;
    const auto table_end = checked_add<std::uint64_t>(
        sect_off, static_cast<std::uint64_t>(img.coff.number_of_sections) * 40ull);
    if (!table_end.has_value()) {
        throw ParseError("section table size overflows", sect_off);
    }
    if (*table_end > size) {
        // Header claims more sections than the file can hold: clamp to what
        // fits and warn rather than rejecting — an inspection tool should
        // still report the readable part.
        const std::uint64_t avail64 = (size - sect_off) / 40ull;
        const std::uint16_t fit = static_cast<std::uint16_t>(
            avail64 < img.coff.number_of_sections ? avail64 : img.coff.number_of_sections);
        diags.warning("section table extends beyond end of file; parsing " +
                      std::to_string(fit) + " of " + std::to_string(img.coff.number_of_sections) +
                      " entries", sect_off);
        img.coff.number_of_sections = fit;
    }
    img.sections.reserve(img.coff.number_of_sections);
    for (std::uint16_t i = 0; i < img.coff.number_of_sections; ++i) {
        const std::uint64_t s = sect_off + 40ull * i;
        Section sec;
        // 8-byte name, may run to the field boundary without NUL.
        std::string nm = rd.read_cstr(s, kSectionNameLen);
        // Preserve visible control chars as-is; the PE spec allows arbitrary bytes.
        sec.name = nm.empty() ? std::string(".") : nm;
        sec.virtual_size = rd.read_u32(s + 8);
        sec.virtual_address = rd.read_u32(s + 12);
        sec.size_of_raw_data = rd.read_u32(s + 16);
        sec.raw_data_offset = rd.read_u32(s + 20);
        sec.characteristics = rd.read_u32(s + 36);
        sec.has_raw_data = sec.raw_data_offset != 0 && sec.size_of_raw_data != 0;
        if (sec.has_raw_data && !in_range(sec.raw_data_offset, sec.size_of_raw_data, size)) {
            diags.warning("section '" + sec.name + "' raw data (offset " +
                          std::to_string(sec.raw_data_offset) + ", size " +
                          std::to_string(sec.size_of_raw_data) + ") beyond end of file",
                          s + 20);
            sec.has_raw_data = false;
        }
        if (sec.virtual_address == 0 && sec.virtual_size != 0) {
            diags.warning("section '" + sec.name + "' has VirtualAddress 0 with nonzero VirtualSize");
        }
        img.sections.push_back(std::move(sec));
    }
    if (img.coff.number_of_sections == 0) {
        diags.warning("image has no sections");
    }

    // ── Import / export tables (implemented in pe_tables.cpp) ──
    parse_imports(img, data, size, diags);
    parse_exports(img, data, size, diags);
    parse_delay_imports(img, data, size, diags);

    return img;
}

PeImage parse_file(const std::string& path, diag::Diagnostics& diags) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw ParseError("cannot open file: " + path);
    const std::streamoff end = f.tellg();
    if (end < 0) throw ParseError("cannot determine file size: " + path);
    const auto size = static_cast<std::size_t>(end);
    if (size > (1ull << 34)) {  // 16 GiB sanity cap for in-memory parse
        throw ParseError("file too large to inspect in memory: " + path);
    }
    std::vector<std::uint8_t> buf(size);
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size))) {
        throw ParseError("failed to read file contents: " + path);
    }
    return parse(buf.data(), size, path, diags);
}

}  // namespace xbox2pc::pe
