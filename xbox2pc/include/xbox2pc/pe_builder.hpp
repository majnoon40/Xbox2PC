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

struct ExportFunc {
    std::string name;    // may be empty -> unnamed export
    std::uint32_t rva = 0;
    std::string forwarder;  // non-empty -> forwarder string
};

struct PeBuildSpec {
    std::uint16_t machine = 0x8664;         // AMD64 default
    std::uint16_t subsystem = 3;             // console
    std::uint64_t image_base = 0x140000000;
    std::uint32_t entry_point_rva = 0x1000;
    std::vector<std::string> section_names = {".text", ".rdata", ".data"};
    std::vector<ImportDll> imports;
    std::vector<ExportFunc> exports;
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
    std::uint64_t size() const { return buf_.size(); }
    const std::vector<std::uint8_t>& data() const { return buf_; }
    void resize(std::uint64_t n) { buf_.resize(static_cast<std::size_t>(n), 0); }
    // Clear.
    void reset() { buf_.clear(); }

private:
    std::vector<std::uint8_t> buf_;
};

}  // namespace xbox2pc::test
