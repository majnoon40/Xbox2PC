#include "xbox2pc/pe_builder.hpp"

#include <cstring>
#include <utility>

namespace xbox2pc::test {

// ── ByteBuf ──────────────────────────────────────────────────────────────

void ByteBuf::u8(std::uint64_t off, std::uint8_t v) {
    if (off >= buf_.size()) buf_.resize(static_cast<std::size_t>(off) + 1, 0);
    buf_[static_cast<std::size_t>(off)] = v;
}

void ByteBuf::u16(std::uint64_t off, std::uint16_t v) {
    for (unsigned i = 0; i < 2; ++i) {
        u8(off + i, static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

void ByteBuf::u32(std::uint64_t off, std::uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) {
        u8(off + i, static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

void ByteBuf::u64(std::uint64_t off, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) {
        u8(off + i, static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

std::uint64_t ByteBuf::cstr(const std::string& s) {
    const std::uint64_t off = buf_.size();
    buf_.insert(buf_.end(), s.begin(), s.end());
    buf_.push_back(0);
    return off;
}

std::uint64_t ByteBuf::bytes(const std::vector<std::uint8_t>& v) {
    const std::uint64_t off = buf_.size();
    buf_.insert(buf_.end(), v.begin(), v.end());
    return off;
}

// ── PeBuilder ───────────────────────────────────────────────────────────

namespace {

constexpr std::uint32_t kSectionAlignment = 0x1000;
constexpr std::uint32_t kFileAlignment = 0x200;

std::uint32_t align_up(std::uint32_t v, std::uint32_t a) {
    if (a == 0) return v;
    const std::uint64_t r = (static_cast<std::uint64_t>(v) + a - 1) / a * a;
    return static_cast<std::uint32_t>(r);
}

}  // namespace

PeBuilder::PeBuilder(PeBuildSpec s) : spec(std::move(s)) {}

PeBuilder::Layout PeBuilder::plan() const {
    Layout l;
    // headers: DOS(64) + optional stub -> PE at 0x80, COFF(20),
    // optional(240 incl. dirs), section table (3*40) -> pad to 0x400.
    l.headers_size = 0x400;

    // .text at 0x1000: descriptors + thunks + names for imports +
    // export directory machinery; all computed during build, sized here
    // coarsely then finalized after materialization (we do two passes:
    // first compute sizes by simulating writes into throwaway buffers).
    std::uint32_t text_used = 0x10;  // entry point marker

    // Import descriptors: 20 bytes each + terminator.
    const std::size_t n_dlls = spec.imports.size();
    text_used += static_cast<std::uint32_t>((n_dlls + 1) * 20);

    // Per DLL: name + thunk arrays (8 bytes/entry + terminator) + name strings.
    for (const auto& dll : spec.imports) {
        text_used += static_cast<std::uint32_t>(dll.name.size() + 1);
        const std::size_t n_thunks = dll.funcs.size() + 1;
        text_used += static_cast<std::uint32_t>(n_thunks * 8);  // INT
        text_used += static_cast<std::uint32_t>(n_thunks * 8);  // IAT (separate)
        for (const auto& f : dll.funcs) {
            if (!f.name.empty()) text_used += static_cast<std::uint32_t>(2 + f.name.size() + 1);
        }
    }

    // Export directory (40) + address table + name ptrs + ordinals + strings.
    if (!spec.exports.empty()) {
        text_used += 40;
        text_used += static_cast<std::uint32_t>(spec.exports.size() * 4);
        std::size_t named = 0;
        for (const auto& f : spec.exports) {
            if (!f.name.empty()) ++named;
        }
        text_used += static_cast<std::uint32_t>(named * 4);
        text_used += static_cast<std::uint32_t>(named * 2);
        for (const auto& f : spec.exports) {
            text_used += static_cast<std::uint32_t>(f.name.size() + 1);
            if (!f.forwarder.empty()) {
                text_used += static_cast<std::uint32_t>(f.forwarder.size() + 1);
            }
        }
    }

    l.text_size = align_up(text_used, kFileAlignment);
    l.rdata_rva = align_up(l.text_rva + l.text_size, kSectionAlignment);
    l.rdata_size = 0x200;  // fixed small data section
    l.data_rva = align_up(l.rdata_rva + l.rdata_size, kSectionAlignment);
    l.data_size = 0x200;

    // Import/export directories live in .text (single writable location
    // keeps RVAs contiguous and simple to verify in tests).
    l.import_dir_rva = l.text_rva + 0x10;
    l.export_dir_rva = 0;  // computed during build when exports exist
    return l;
}

std::vector<std::uint8_t> PeBuilder::build() const {
    // Pass 1: materialize .text content in a virtual address space to learn
    // the exact size and the offset of the export directory.
    // We write everything at "text_rva + cursor" in a scratch ByteBuf whose
    // offsets are relative to .text start.
    ByteBuf text;  // offset 0 == RVA text_rva
    const std::uint32_t text_rva = 0x1000;

    // entry point marker at RVA text_rva (0x10 bytes of 0xCC).
    {
        std::vector<std::uint8_t> marker(0x10, 0xCC);
        text.bytes(marker);
    }

    // Import thunk machinery, then descriptors.
    //
    // Materialization order (single pass, every blob appended at the current
    // end so earlier offsets stay final):
    //   1. per-DLL: name string, INT slots, IAT slots, hint/name strings
    //   2. descriptor array written LAST at the end
    // Writing descriptors first (before thunk data) once produced descriptors
    // landing inside later-appended thunk bytes — exactly the corruption the
    // parser flagged. Descriptors go last, and their RVA is the import
    // directory RVA.
    std::uint32_t import_dir_rva = 0;

    struct DllLayout {
        std::uint32_t name_rva = 0;
        std::uint32_t int_rva = 0;
        std::uint32_t iat_rva = 0;
        std::vector<std::uint32_t> hint_name_rvas;  // by-name entries only
    };
    std::vector<DllLayout> dll_layouts(spec.imports.size());
    for (std::size_t d = 0; d < spec.imports.size(); ++d) {
        const auto& dll = spec.imports[d];
        auto& lay = dll_layouts[d];
        // DLL name string.
        lay.name_rva = text_rva + static_cast<std::uint32_t>(text.cstr(dll.name));
        // INT slots (values filled in a second sub-pass below).
        lay.int_rva = text_rva + static_cast<std::uint32_t>(text.size());
        for (std::size_t i = 0; i < dll.funcs.size() + 1; ++i) {
            text.resize(text.size() + 8);  // zero-filled slot
        }
        // IAT slots (same count, separate array).
        lay.iat_rva = text_rva + static_cast<std::uint32_t>(text.size());
        for (std::size_t i = 0; i < dll.funcs.size() + 1; ++i) {
            text.resize(text.size() + 8);
        }
        // Hint/name entries (2-byte hint + name + NUL).
        for (const auto& f : dll.funcs) {
            if (f.name.empty()) continue;
            const std::uint64_t hn_rel = text.size();
            text.u16(hn_rel, f.ordinal);  // hint
            for (std::size_t i = 0; i < f.name.size(); ++i) {
                text.u8(hn_rel + 2 + i, static_cast<std::uint8_t>(f.name[i]));
            }
            text.resize(hn_rel + 2 + f.name.size() + 1);  // NUL terminator
            lay.hint_name_rvas.push_back(text_rva + static_cast<std::uint32_t>(hn_rel));
        }
    }
    // Fill INT entries (hint/name RVAs or ordinal-flagged thunks).
    for (std::size_t d = 0; d < spec.imports.size(); ++d) {
        const auto& dll = spec.imports[d];
        const auto& lay = dll_layouts[d];
        std::uint64_t t = lay.int_rva - text_rva;
        std::size_t by_name = 0;
        for (const auto& f : dll.funcs) {
            if (f.name.empty()) {
                text.u64(t, (1ull << 63) | f.ordinal);
            } else {
                text.u64(t, lay.hint_name_rvas[by_name]);
                ++by_name;
            }
            t += 8;
        }
    }
    // Descriptors written last: their start is the import directory RVA.
    if (!spec.imports.empty()) {
        import_dir_rva = text_rva + static_cast<std::uint32_t>(text.size());
        const std::uint64_t desc_start = text.size();
        const std::uint64_t desc_count = spec.imports.size() + 1;  // + terminator
        text.resize(desc_start + desc_count * 20);
        for (std::size_t d = 0; d < spec.imports.size(); ++d) {
            const auto& lay = dll_layouts[d];
            const std::uint64_t desc = desc_start + d * 20;
            text.u32(desc + 0, lay.int_rva);        // OriginalFirstThunk (INT)
            text.u32(desc + 4, 0);                   // TimeDateStamp
            text.u32(desc + 8, 0);                   // ForwarderChain
            text.u32(desc + 12, lay.name_rva);       // Name
            text.u32(desc + 16, lay.iat_rva);       // FirstThunk (IAT)
        }
        // terminator descriptor remains zero-filled.
    }

    // Export directory.
    std::uint32_t export_dir_rva = 0;
    std::uint32_t export_dir_size = 0;
    if (!spec.exports.empty()) {
        export_dir_rva = text_rva + static_cast<std::uint32_t>(text.size());
        const std::uint64_t ed = text.size();
        text.resize(ed + 40);

        // DLL name string.
        const std::uint32_t name_rva = text_rva + static_cast<std::uint32_t>(text.cstr("Xbox2PCTest.dll"));

        // Function address table: each export gets an RVA. Forwarded exports
        // point at a forwarder string inside the export data.
        std::uint32_t ordinal_base = 1;
        std::vector<std::uint32_t> fn_rvas(spec.exports.size());
        std::vector<std::uint32_t> fwd_rvas(spec.exports.size());
        // assign code addresses spread in .text
        for (std::size_t i = 0; i < spec.exports.size(); ++i) {
            if (!spec.exports[i].forwarder.empty()) {
                fwd_rvas[i] = text_rva + static_cast<std::uint32_t>(text.cstr(spec.exports[i].forwarder));
            } else {
                fn_rvas[i] = text_rva + 0x1000 + static_cast<std::uint32_t>(0x20 * (i + 1));
            }
        }
        const std::uint64_t addr_table_rel = text.size();
        for (std::size_t i = 0; i < spec.exports.size(); ++i) {
            text.u32(addr_table_rel + 4 * i,
                     spec.exports[i].forwarder.empty() ? fn_rvas[i] : fwd_rvas[i]);
        }
        // Name pointer table + names.
        std::vector<std::uint32_t> name_rvas;
        std::vector<std::uint16_t> name_ords;
        for (std::size_t i = 0; i < spec.exports.size(); ++i) {
            if (spec.exports[i].name.empty()) continue;
            name_rvas.push_back(text_rva + static_cast<std::uint32_t>(text.cstr(spec.exports[i].name)));
            name_ords.push_back(static_cast<std::uint16_t>(i));
        }
        const std::uint64_t namep_rel = text.size();
        for (std::size_t i = 0; i < name_rvas.size(); ++i) {
            text.u32(namep_rel + 4 * i, name_rvas[i]);
        }
        const std::uint64_t ordtbl_rel = text.size();
        for (std::size_t i = 0; i < name_ords.size(); ++i) {
            text.u16(ordtbl_rel + 2 * i, name_ords[i]);
        }

        // Header.
        text.u32(ed + 0, 0);              // Characteristics
        text.u32(ed + 4, 0);              // TimeDateStamp
        text.u32(ed + 8, 0);              // Major/MinorVersion
        text.u32(ed + 12, name_rva);      // Name RVA
        text.u32(ed + 16, ordinal_base);
        text.u32(ed + 20, static_cast<std::uint32_t>(spec.exports.size()));
        text.u32(ed + 24, static_cast<std::uint32_t>(name_rvas.size()));
        text.u32(ed + 28, text_rva + static_cast<std::uint32_t>(addr_table_rel));
        text.u32(ed + 32, text_rva + static_cast<std::uint32_t>(namep_rel));
        text.u32(ed + 36, text_rva + static_cast<std::uint32_t>(ordtbl_rel));
        // Export directory size: the whole region (header + address table +
        // name pointers + ordinals + strings) so forwarder detection sees
        // forwarder strings as "inside the export data".
        export_dir_size = static_cast<std::uint32_t>(text.size() - ed);
    }

    // ── Pass 2: assemble the whole file ──
    const std::uint32_t text_file_size = align_up(static_cast<std::uint32_t>(text.size()), kFileAlignment);
    const std::uint32_t rdata_rva = align_up(text_rva + text_file_size, kSectionAlignment);
    const std::uint32_t rdata_file_size = 0x200;
    const std::uint32_t data_rva = align_up(rdata_rva + rdata_file_size, kSectionAlignment);
    const std::uint32_t data_file_size = 0x200;
    const std::uint32_t headers = 0x400;
    const std::uint32_t size_of_image = align_up(data_rva + data_file_size, kSectionAlignment);

    ByteBuf out;
    // DOS header: magic + reserved + e_lfanew.
    out.u16(0, 0x5A4D);  // "MZ"
    const std::uint32_t e_lfanew = spec.e_lfanew_override != 0 ? spec.e_lfanew_override : 0x80;
    out.u32(0x3C, e_lfanew);
    // (DOS stub omitted; zeros are fine.)

    // PE signature + COFF + optional header.
    const std::uint64_t pe = e_lfanew;
    out.u32(pe, 0x00004550);  // "PE\0\0"
    // COFF header (20 bytes): Machine@+0, NumberOfSections@+2, TimeDateStamp@+4,
    // PointerToSymbolTable@+8, NumberOfSymbols@+12, SizeOfOptionalHeader@+16,
    // Characteristics@+18 — all relative to pe+4.
    const std::uint64_t coff = pe + 4;
    out.u16(coff + 0, spec.machine);
    const std::uint16_t n_sections = spec.number_of_sections_override != 0
        ? spec.number_of_sections_override
        : static_cast<std::uint16_t>(spec.section_names.size());
    out.u16(coff + 2, n_sections);
    out.u32(coff + 4, 0x68743230);  // TimeDateStamp (arbitrary fixed)
    out.u32(coff + 8, 0);           // PointerToSymbolTable
    out.u32(coff + 12, 0);          // NumberOfSymbols
    const std::uint32_t opt_size = spec.size_of_optional_override != 0
        ? spec.size_of_optional_override
        : 240;  // 112 fixed + 16*8 directories
    out.u16(coff + 16, static_cast<std::uint16_t>(opt_size));
    out.u16(coff + 18, static_cast<std::uint16_t>(0x0022));  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional header (PE32+, 112-byte fixed part) begins at pe+24.
    const std::uint64_t o = pe + 24;
    out.u16(o + 0, 0x20B);  // PE32+ magic
    out.u8(o + 2, 14); out.u8(o + 3, 0);  // linker 14.0
    out.u32(o + 4, text_file_size);       // SizeOfCode
    out.u32(o + 8, rdata_file_size);
    out.u32(o + 12, 0);
    out.u32(o + 16, spec.entry_point_rva);
    out.u32(o + 20, text_rva);            // BaseOfCode
    out.u64(o + 24, spec.image_base);
    out.u32(o + 32, kSectionAlignment);
    out.u32(o + 36, kFileAlignment);
    out.u16(o + 40, 6); out.u16(o + 42, 0);   // OS 6.0
    out.u16(o + 44, 0); out.u16(o + 46, 0);
    out.u16(o + 48, 6); out.u16(o + 50, 0);   // Subsystem version
    out.u32(o + 52, 0);
    out.u32(o + 56, size_of_image);
    out.u32(o + 60, headers);
    out.u32(o + 64, 0);                    // CheckSum
    out.u16(o + 68, spec.subsystem);
    out.u16(o + 70, static_cast<std::uint16_t>(0x8160));  // DllCharacteristics (high-entropy VA etc.)
    out.u64(o + 72, 0x100000);              // StackReserve
    out.u64(o + 80, 0x1000);               // StackCommit
    out.u64(o + 88, 0x100000);             // HeapReserve
    out.u64(o + 96, 0x1000);               // HeapCommit
    out.u32(o + 104, 0);
    out.u32(o + 108, spec.number_of_rva_override != 0 ? spec.number_of_rva_override : 16);

    // Data directories (16 entries at o+112).
    const std::uint64_t dirs = o + 112;
    if (!spec.imports.empty()) {
        out.u32(dirs + 8 * 1, import_dir_rva);
        out.u32(dirs + 8 * 1 + 4, static_cast<std::uint32_t>((spec.imports.size() + 1) * 20));
    }
    if (!spec.exports.empty()) {
        out.u32(dirs + 8 * 0, export_dir_rva);
        out.u32(dirs + 8 * 0 + 4, export_dir_size);
    }

    // Section table at pe + 24 + opt_size.
    const std::uint64_t sect_table = pe + 24 + opt_size;
    struct SecInfo { const char* name; std::uint32_t vsize, rva, rawsz, rawoff, chars; };
    const std::uint32_t text_off = headers;
    const std::uint32_t rdata_off = text_off + text_file_size;
    const std::uint32_t data_off = rdata_off + rdata_file_size;
    const std::vector<SecInfo> secs = {
        {".text",  static_cast<std::uint32_t>(text.size()), text_rva, text_file_size, text_off,
         0x60000020},   // code|execute|read
        {".rdata", rdata_file_size, rdata_rva, rdata_file_size, rdata_off, 0x40000040},
        {".data",  data_file_size, data_rva, data_file_size, data_off, 0xC0000040},
    };
    for (std::size_t i = 0; i < secs.size(); ++i) {
        const std::uint64_t s = sect_table + 40 * i;
        // name (8 bytes max, NUL padded)
        for (std::size_t j = 0; j < 8; ++j) {
            out.u8(s + j, j < std::strlen(secs[i].name) ? static_cast<std::uint8_t>(secs[i].name[j]) : 0);
        }
        out.u32(s + 8, secs[i].vsize);
        out.u32(s + 12, secs[i].rva);
        out.u32(s + 16, secs[i].rawsz);
        out.u32(s + 20, secs[i].rawoff);
        out.u32(s + 36, secs[i].chars);
    }

    // Section contents.
    const std::uint32_t file_end = data_off + data_file_size;
    out.resize(file_end);  // ensure the file covers every section's raw range
    for (std::size_t i = 0; i < text.size(); ++i) {
        out.u8(text_off + i, text.data()[i]);
    }
    // .rdata / .data left as zero padding (file already grown).

    return out.data();
}

}  // namespace xbox2pc::test
