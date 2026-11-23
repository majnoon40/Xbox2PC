#pragma once
// xbox2pc/pe_builder.hpp — synthetic PE32+ image builder for tests.
//
// Builds minimal but structurally faithful PE32+ images entirely in memory
// on Linux: DOS header, PE signature, COFF header, optional header (PE32+),
// data directories, section table, and section contents including real
// import/export table structures that the parser must decode.
//
// Malformed variants are produced by mutating fields of a valid image
// (bad magic, truncated buffers, out-of-range offsets, wrapped sizes),
// so every test binary is independently generated, never fetched.

#include <cstdint>
#include <string>
#include <vector>

namespace xbox2pc::test {

// A function import to embed in the image.
struct ImportFunc {
    std::string name;    // empty -> ordinal import
    std::uint16_t ordinal = 0;  // used when name is empty (hint value otherwise)
};

struct ImportDll {
    std::string name;
    std::vector<ImportFunc> funcs;
};

// M2: delay-load import descriptor to embed in the image (directory 13).
struct DelayImportDll {
    std::string name;
    std::vector<ImportFunc> funcs;
    std::uint32_t attributes = 0;   // grAttributes; bit 0 set -> VA addressing
};

struct ExportFunc {
    std::string name;    // may be empty -> unnamed export
    std::uint32_t rva = 0;
    std::string forwarder;  // non-empty -> forwarder string
};

// One base-relocation entry to embed (M6 loader tests). Types follow the
// PE/COFF spec: 0=ABSOLUTE (padding), 3=HIGHLOW, 10=DIR64.
struct RelocSpec {
    std::uint16_t type = 10;         // IMAGE_REL_BASED_DIR64 default
    std::uint32_t target_rva = 0;    // where the fixup applies
    std::uint64_t addend = 0;       // value planted at target (pre-reloc)
};

// One relocation BLOCK (page-rva + entries). The builder packs entries
// into blocks per the spec (page-relative 12-bit offsets).
struct RelocBlockSpec {
    std::uint32_t page_rva = 0;
    std::vector<RelocSpec> entries;
};

// TLS directory content to embed (M6): template bytes (planted in .rdata),
// zero-fill size, and callback VAs (planted as an array; NEVER executed).
struct TlsSpec {
    std::vector<std::uint8_t> template_data;   // copied to .rdata
    std::uint32_t zero_fill = 0;               // SizeOfZeroFill
    std::vector<std::uint64_t> callback_vas;   // synthetic (never run)
};

struct PeBuildSpec {
    std::uint16_t machine = 0x8664;         // AMD64 default
    std::uint16_t subsystem = 3;             // console
    std::uint64_t image_base = 0x140000000;
    std::uint32_t entry_point_rva = 0x1000;
    std::vector<std::string> section_names = {".text", ".rdata", ".data"};
    std::vector<ImportDll> imports;
    std::vector<ExportFunc> exports;
    std::vector<DelayImportDll> delay_imports;  // M2: directory 13 content
    bool export_with_forwarder_chain = false;   // M2: ForwarderChain != 0 metadata
    std::vector<RelocBlockSpec> reloc_blocks;    // M6: directory 5 content
    TlsSpec tls;                                 // M6: directory 9 (when template non-empty)
    // M8: raw code bytes planted at an explicit .text RVA (synthetic guest
    // programs for the execution tests). Empty rva/bytes = no payload (the
    // existing marker-only behavior is unchanged).
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> text_payloads;
    std::uint16_t number_of_sections_override = 0;   // 0 = actual count
    std::uint32_t size_of_optional_override = 0;     // 0 = real size
    std::uint32_t number_of_rva_override = 0;        // 0 = 16
    std::uint32_t e_lfanew_override = 0;              // 0 = 0x80
    bool include_dos_stub = true;                     // pad between DOS hdr and PE
};

class PeBuilder {
public:
    explicit PeBuilder(PeBuildSpec spec);

    // Assemble the full image according to the spec (no mutation).
    std::vector<std::uint8_t> build() const;

    // The spec (mutable for tests that tweak single fields).
    PeBuildSpec spec;

private:
    // Layout plan computed once: where each table lives (RVAs and file offsets).
    struct Layout {
        std::uint32_t text_rva = 0x1000;
        std::uint32_t text_size = 0;
        std::uint32_t rdata_rva = 0;
        std::uint32_t rdata_size = 0;
        std::uint32_t data_rva = 0;
        std::uint32_t data_size = 0;
        std::uint32_t import_dir_rva = 0;   // import descriptors
        std::uint32_t export_dir_rva = 0;   // export directory
        std::uint32_t headers_size = 0;
        // computed per-DLL thunk locations etc. are materialized during build
    };
    Layout plan() const;
};

// A memory buffer with little-endian write helpers — bounded, self-growing.
class ByteBuf {
public:
    // Write at absolute offset (grows with zero fill as needed).
    void u8(std::uint64_t off, std::uint8_t v);
    void u16(std::uint64_t off, std::uint16_t v);
    void u32(std::uint64_t off, std::uint32_t v);
    void u64(std::uint64_t off, std::uint64_t v);
    // Append a NUL-terminated string at the end; returns its offset.
    std::uint64_t cstr(const std::string& s);
    // Append raw bytes; returns start offset.
    std::uint64_t bytes(const std::vector<std::uint8_t>& v);
    // M8: write raw bytes at an absolute offset (zero-fill growth) for
    // explicit-RVA code payloads.
    void put_bytes(std::uint64_t off, const std::vector<std::uint8_t>& v);
    std::uint64_t size() const { return buf_.size(); }
    const std::vector<std::uint8_t>& data() const { return buf_; }
    void resize(std::uint64_t n) { buf_.resize(static_cast<std::size_t>(n), 0); }
    // Clear.
    void reset() { buf_.clear(); }

private:
    std::vector<std::uint8_t> buf_;
};

}  // namespace xbox2pc::test
