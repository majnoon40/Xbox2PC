#pragma once
// xbox2pc/pe_parser.hpp — safe PE32+ (x86-64) parser for Linux.
//
// Design rules for this component:
//   1. The file is fully loaded into memory once; every access goes through
//      bounds-checked helpers. No pointer arithmetic on raw buffers anywhere.
//   2. Every field is read at a checked offset with overflow-safe arithmetic
//      (checked_add) — malformed size fields cannot wrap into small values.
//   3. Errors: hard failures throw pe::ParseError (derived from an
//      std::system_error-style category); recoverable anomalies are recorded
//      as warnings in the provided Diagnostics.
//   4. The parser never executes or maps anything — pure data inspection.
//
// Layout constants follow the PE/COFF specification (MS-PELYB / pecoff v11):
//   DOS header (64 bytes) -> e_lfanew -> PE signature "PE\0\0" ->
//   COFF header (20 bytes) -> Optional header PE32+ (112 bytes) ->
//   section table -> sections; directories live inside sections.

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "xbox2pc/diagnostics.hpp"

namespace xbox2pc::pe {

// ── Error type ──────────────────────────────────────────────────────────

class ParseError : public std::runtime_error {
public:
    ParseError(std::string msg, std::uint64_t offset)
        : std::runtime_error(msg), offset_(offset), has_offset_(true) {}
    explicit ParseError(std::string msg)
        : std::runtime_error(std::move(msg)), offset_(0), has_offset_(false) {}

    std::uint64_t offset() const { return offset_; }
    bool has_offset() const { return has_offset_; }

private:
    std::uint64_t offset_;
    bool has_offset_;
};

// ── PE constants ────────────────────────────────────────────────────────

inline constexpr std::uint16_t kDosMagic = 0x5A4D;     // "MZ"
inline constexpr std::uint32_t kPeSignature = 0x00004550;  // "PE\0\0"
inline constexpr std::uint16_t kOptMagicPe32Plus = 0x20B;  // PE32+ optional header
inline constexpr std::uint16_t kOptMagicPe32 = 0x10B;      // PE32 (32-bit)
inline constexpr std::uint16_t kOptMagicRom = 0x107;       // ROM image
inline constexpr std::uint16_t kMachineAmd64 = 0x8664;    // x86-64
inline constexpr std::uint16_t kMachineI386 = 0x14C;
inline constexpr std::uint16_t kMachineArm64 = 0xAA64;
inline constexpr std::uint16_t kMachineUnknown = 0x0;

inline constexpr std::uint16_t kDirExport = 0;
inline constexpr std::uint16_t kDirImport = 1;
inline constexpr std::uint16_t kDirResource = 2;
inline constexpr std::uint16_t kDirException = 3;
inline constexpr std::uint16_t kDirSecurity = 4;
inline constexpr std::uint16_t kDirReloc = 5;
inline constexpr std::uint16_t kDirDebug = 6;
inline constexpr std::uint16_t kDirArchitecture = 7;
inline constexpr std::uint16_t kDirGlobalPtr = 8;
inline constexpr std::uint16_t kDirTls = 9;
inline constexpr std::uint16_t kDirLoadConfig = 10;
inline constexpr std::uint16_t kDirBoundImport = 11;
inline constexpr std::uint16_t kDirIat = 12;
inline constexpr std::uint16_t kDirDelayImport = 13;
inline constexpr std::uint16_t kDirClr = 14;

inline constexpr std::uint16_t kMaxDataDirectories = 16;
inline constexpr std::uint32_t kMaxSections = 96;   // sane upper bound (spec tools use 96)
inline constexpr std::size_t kDosHeaderSize = 64;
inline constexpr std::size_t kCoffHeaderSize = 20;
inline constexpr std::size_t kOptHeader32Size = 224;  // without data directories
inline constexpr std::size_t kOptHeaderPlusSize = 240;  // PE32+ fixed part 112 + 16*8
inline constexpr std::size_t kSectionNameLen = 8;     // 8-byte non-NUL-terminated names

// Section characteristics flags the inspector reports.
namespace sect_flags {
inline constexpr std::uint32_t kCode = 0x00000020;
inline constexpr std::uint32_t kInitializedData = 0x00000040;
inline constexpr std::uint32_t kUninitializedData = 0x00000080;
inline constexpr std::uint32_t kExecutable = 0x20000000;
inline constexpr std::uint32_t kReadable = 0x40000000;
inline constexpr std::uint32_t kWritable = 0x80000000;
}  // namespace sect_flags

// ── Parsed structures ───────────────────────────────────────────────────

struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    std::string name;  // friendly name, filled by parser
};

struct Section {
    std::string name;              // up to 8 bytes, may contain trailing NULs
    std::uint32_t virtual_size = 0; // VirtualSize (uninitialized region size)
    std::uint32_t virtual_address = 0; // RVA of the section
    std::uint32_t size_of_raw_data = 0; // SizeOfRawData (file-backed size)
    std::uint32_t raw_data_offset = 0;  // PointerToRawData
    std::uint32_t characteristics = 0;
    bool has_raw_data = false;      // PointerToRawData != 0 and SizeOfRawData != 0

    // True when `rva` (a virtual address) falls inside this section's virtual
    // range [VirtualAddress, VirtualAddress + max(VirtualSize, SizeOfRawData)).
    bool contains_rva(std::uint32_t rva) const;
};

struct ImportEntry {
    std::string dll_name;
    std::vector<std::string> functions;      // by-name imports in order
    std::vector<std::uint32_t> ordinal_only; // ordinal imports (in order)
    std::vector<std::uint32_t> by_name_ordinals; // hint/ord for by-name entries
};

struct ExportedFunction {
    std::uint32_t rva = 0;
    std::uint32_t ordinal = 0;   // ordinal_base + table index
    std::string name;            // may be empty -> forwarded or unnamed
    std::string forwarder;       // non-empty when RVA points into the export table itself
};

struct ExportTable {
    bool present = false;
    std::string dll_name;
    std::uint32_t ordinal_base = 0;
    std::vector<std::uint32_t> function_rvas;   // ExportAddressTable
    std::vector<std::uint32_t> name_rvas;       // ExportNamePointerTable
    std::vector<std::uint16_t> name_ordinal_table; // ExportOrdinalTable
    std::vector<ExportedFunction> functions;    // resolved view
};

struct ImportTable {
    bool present = false;
    std::vector<ImportEntry> entries;
};

// Optional header — both magic flavours are accepted for structure parsing,
// but PE32+ fields are the ones fully modelled (this is an x86-64 tool).
struct OptionalHeader {
    std::uint16_t magic = 0;
    std::uint16_t major_linker_version = 0;
    std::uint16_t minor_linker_version = 0;
    std::uint64_t size_of_code = 0;
    std::uint64_t size_of_initialized_data = 0;
    std::uint64_t size_of_uninitialized_data = 0;
    std::uint64_t address_of_entry_point = 0;      // RVA
    std::uint64_t base_of_code = 0;                // RVA
    std::uint64_t image_base = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint16_t major_os_version = 0;
    std::uint16_t minor_os_version = 0;
    std::uint16_t major_image_version = 0;
    std::uint16_t minor_image_version = 0;
    std::uint16_t major_subsystem_version = 0;
    std::uint16_t minor_subsystem_version = 0;
    std::uint32_t win32_version_value = 0;
    std::uint64_t size_of_image = 0;
    std::uint64_t size_of_headers = 0;
    std::uint32_t checksum = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint64_t size_of_stack_reserve = 0;
    std::uint64_t size_of_stack_commit = 0;
    std::uint64_t size_of_heap_reserve = 0;
    std::uint64_t size_of_heap_commit = 0;
    std::uint32_t loader_flags = 0;
    std::uint32_t number_of_rva_and_sizes = 0;
    bool is_pe32plus = false;
    bool is_pe32 = false;
};

struct CoffHeader {
    std::uint16_t machine = 0;
    std::uint16_t number_of_sections = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint32_t pointer_to_symbol_table = 0;
    std::uint32_t number_of_symbols = 0;
    std::uint16_t size_of_optional_header = 0;
    std::uint16_t characteristics = 0;
};

// Complete parse result. All strings decoded as UTF-8-ish (PE names are
// byte strings; non-ASCII is preserved as-is).
struct PeImage {
    // provenance
    std::string source_name;

    // headers
    std::uint32_t e_lfanew = 0;
    CoffHeader coff;
    OptionalHeader opt;
    std::vector<DataDirectory> directories;
    std::vector<Section> sections;

    // tables
    ImportTable imports;
    ExportTable exports;

    // classification helpers
    bool is_x86_64() const { return coff.machine == kMachineAmd64; }
    std::string machine_name() const;
    std::string subsystem_name() const;
    // Entry point VA (image base + RVA); nullopt when the sum would wrap.
    std::optional<std::uint64_t> entry_point_va() const {
        const std::uint64_t va = opt.image_base + opt.address_of_entry_point;
        if (va < opt.image_base) return std::nullopt;  // wrapped
        return va;
    }
};

// ── Parser ──────────────────────────────────────────────────────────────

// Parse PE from an in-memory buffer. Throws ParseError on hard failure;
// records warnings in `diags` for recoverable anomalies (odd alignments,
// overlapping sections, directory pointing outside image, ...).
PeImage parse(const std::uint8_t* data, std::size_t size, std::string source_name,
              diag::Diagnostics& diags);

// Convenience overload for tests/tools: loads a file and parses it.
PeImage parse_file(const std::string& path, diag::Diagnostics& diags);

// RVA -> file offset conversion using the section table. Returns nullopt
// when the RVA does not map into any file-backed region.
std::optional<std::uint64_t> rva_to_offset(const PeImage& img, std::uint32_t rva);

// Friendly names for machine / subsystem / directory constants.
const char* machine_to_name(std::uint16_t machine);
const char* subsystem_to_name(std::uint16_t subsystem);
const char* directory_to_name(std::uint16_t dir);

}  // namespace xbox2pc::pe
