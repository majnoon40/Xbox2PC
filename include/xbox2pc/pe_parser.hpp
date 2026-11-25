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
#include <functional>
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

    // ── M2: preserved import metadata ────────────────────────────────────
    std::uint32_t int_rva = 0;           // OriginalFirstThunk RVA (0 when absent)
    std::uint32_t iat_rva = 0;           // FirstThunk (IAT) RVA
    std::uint32_t name_rva = 0;          // DLL name string RVA
    std::uint32_t timestamp = 0;         // TimeDateStamp (bound import info)
    std::uint32_t forwarder_chain = 0;  // ForwarderChain field
    bool bound = false;                  // TimeDateStamp != 0 (bound import)
};

// One delay-imported DLL (directory 13, ImgDelayDescr in delayimp fashion).
// All RVAs are stored as 32-bit in the on-disk structure regardless of
// architecture when grAttrs bit 0 is 0; with bit 0 set they are VAs. The
// parser records which addressing was used.
struct DelayImportEntry {
    std::string dll_name;
    std::vector<std::string> functions;
    std::vector<std::uint32_t> ordinal_only;
    std::uint32_t int_rva = 0;         // pointer to thunk array (names)
    std::uint32_t iat_rva = 0;         // address of thunk array (bound IAT)
    std::uint32_t name_rva = 0;
    std::uint32_t bind_rva = 0;        // RVA of bound IAT copy
    std::uint32_t unload_rva = 0;      // RVA of unload thunk table
    std::uint32_t timestamp = 0;
    bool va_addressed = false;          // grAttrs bit 0: entries are VAs not RVAs
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

// x64 .pdata entry (RUNTIME_FUNCTION): 12 bytes, RVAs relative to the
// image base. begin is inclusive, end exclusive; unwind points at the
// .xdata UNWIND_INFO blob.
struct RuntimeFunction {
    std::uint32_t begin_rva = 0;
    std::uint32_t end_rva = 0;
    std::uint32_t unwind_info_rva = 0;
};

// One decoded x64 unwind code (UNWIND_CODE). slot_offset is the prolog
// offset the code applies to (bytes from function start); opcode and
// opinfo are the raw 4-bit code fields; operand carries the decoded
// operand (register number, allocation size, or frame/slot offset —
// 32-bit because far saves use 32-bit offsets).
struct UnwindCode {
    std::uint8_t slot_offset = 0;   // code offset within the prolog
    std::uint8_t opcode = 0;        // UWOP_*
    std::uint8_t opinfo = 0;        // opcode-specific info bits
    std::uint32_t operand = 0;      // decoded operand
};

// Decoded UNWIND_INFO (.xdata) for one function. codes keep their stored
// order (reverse application order); count_of_codes is the header's slot
// count (a full byte — arrays over 15 slots are legal). language_handler_rva
// is the language-handler RVA from the trailer: non-chained entries store
// it after the (slot-padded) code array; CHAININFO entries store a
// per-function handler RVA followed by the 12-byte chained RUNTIME_FUNCTION
// trailer (whose BeginAddress is the chained function). handler_present()
// reports only the EHANDLER flag — the unwind procedure never invokes
// handlers of chained entries.
struct UnwindInfo {
    std::uint8_t version = 0;
    std::uint8_t flags = 0;
    std::uint8_t size_of_prolog = 0;
    std::uint8_t count_of_codes = 0;   // full byte-2 slot count
    std::uint8_t frame_register = 0;   // 0 when no frame pointer
    std::uint8_t frame_offset = 0;     // scaled: (byte3 >> 4) * 16
    std::vector<UnwindCode> codes;
    std::uint32_t language_handler_rva = 0;  // 0 when no handler
    std::uint32_t chained_unwind_rva = 0;    // begin RVA of chained function

    bool is_chained() const { return (flags & 0x4) != 0; }
    bool handler_present() const { return (flags & 0x1) != 0; }
};

// Directory 3 (.pdata) contents, sorted by begin_rva for lookup.
struct ExceptionTable {
    bool present = false;
    std::vector<RuntimeFunction> functions;  // sorted by begin_rva

    // Find the function covering rva (begin inclusive, end exclusive).
    // Returns nullptr when no entry covers the address. Binary search:
    // .pdata is sorted by begin_rva in valid images; entries with equal
    // begin_rva (from malformed inputs) resolve to the LAST entry, which
    // is the largest-end entry after the parser's (begin, end) sort.
    const RuntimeFunction* find_function(std::uint32_t rva) const {
        std::size_t lo = 0;
        std::size_t hi = functions.size();
        while (lo < hi) {
            const std::size_t mid = lo + (hi - lo) / 2;
            if (functions[mid].begin_rva <= rva) lo = mid + 1;
            else hi = mid;
        }
        if (lo == 0) return nullptr;
        const RuntimeFunction* candidate = &functions[lo - 1];
        if (rva < candidate->begin_rva || rva >= candidate->end_rva)
            return nullptr;
        return candidate;
    }
};

struct ImportTable {
    bool present = false;
    std::vector<ImportEntry> entries;
};

// M2: delay-load import table (data directory 13).
struct DelayImportTable {
    bool present = false;
    std::vector<DelayImportEntry> entries;
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
    DelayImportTable delay_imports;  // M2: directory 13 (delayimp)
    ExceptionTable exceptions;       // M11 Phase 6: directory 3 (.pdata)

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

// Decode the .xdata UNWIND_INFO blob for one RUNTIME_FUNCTION. base/size
// are the raw file bytes (the parser keeps no copy). Returns nullopt and
// reports through diags for unmappable RVAs, truncated arrays, unknown
// opcodes, or unsupported versions.
std::optional<UnwindInfo> decode_unwind_info(const PeImage& img,
                                             const RuntimeFunction& fn,
                                             const std::uint8_t* base,
                                             std::uint64_t size,
                                             diag::Diagnostics& diags);

// Where a saved non-volatile register lives once the frame is undone.
// reg uses the x64 unwind-code register encoding (0=RAX..9=R9,
// 10=R10..15=R15); is_xmm marks 128-bit XMM saves (16 bytes at
// location, value not read by this API — only the location is
// reported; the caller reads it with its own memory access).
struct SavedRegister {
    std::uint8_t reg = 0;
    bool is_xmm = false;
    std::uint64_t location = 0;     // guest VA of the saved value
};

// Result of virtually unwinding one frame.
struct UnwindFrame {
    std::uint64_t return_rip = 0;   // guest VA of the return address
    std::uint64_t rsp_after = 0;    // guest RSP after the RET pops it
    // Saved non-volatile locations in walk (reverse-execution) order:
    // the FIRST entry per register is the most recently executed save,
    // i.e. the live value. Duplicates appear only in malformed data.
    std::vector<SavedRegister> saved;
};

// Virtually unwind one frame. current_rsp is the guest RSP at the
// query point; target_offset is the faulting instruction's offset
// within fn (codes with slot_offset > target_offset have not executed
// and are skipped, per the documented unwind algorithm). read_stack
// reads one guest-stack u64 (the caller plugs GuestMemory in; the pe
// layer stays free of runtime types). Chained UNWIND_INFO entries
// continue the walk with their full code arrays. PUSH_MACHFRAME and
// stack-read failures return nullopt with diagnostics. Restoring saved
// non-volatile registers is out of scope for this slice: only the
// control-flow frame (return address + RSP) is reconstructed.
std::optional<UnwindFrame> unwind_one_frame(
    const PeImage& img, const RuntimeFunction& fn, const std::uint8_t* base,
    std::uint64_t size, std::uint32_t target_offset, std::uint64_t current_rsp,
    const std::function<std::optional<std::uint64_t>(std::uint64_t va)>& read_stack,
    diag::Diagnostics& diags);

// ── exception handler search (M11 Phase 6 slice B) ────────────────────────

// One step of the documented unwind procedure.
struct UnwindStep {
    std::uint64_t rip = 0;           // guest RIP at this step
    std::uint64_t rsp = 0;           // guest RSP at this step
    std::vector<SavedRegister> saved; // registers this step restores
};

// Result of searching for an exception handler.
struct ExceptionHandlerSearchResult {
    bool found = false;              // a handler accepted the exception
    std::uint32_t handler_rva = 0;   // image-relative language handler
    std::uint64_t establisher_frame = 0; // guest RSP of the handler frame
    std::vector<UnwindStep> frames;  // walk steps, innermost first
};

// Walk the documented x64 unwind procedure from fault_rip/current_rsp
// looking for a function whose (primary, non-chained) UNWIND_INFO has
// UNW_FLAG_EHANDLER set. Leaf functions (no .pdata entry) advance by
// popping the return address. Returns nullopt only on decode/walk
// failure; a completed walk with no handler returns found=false with
// the walked chain.
std::optional<ExceptionHandlerSearchResult> find_exception_handler(
    const PeImage& img, const std::uint8_t* base, std::uint64_t size,
    std::uint64_t image_base, std::uint64_t fault_rip, std::uint64_t current_rsp,
    const std::function<std::optional<std::uint64_t>(std::uint64_t va)>& read_stack,
    diag::Diagnostics& diags);

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
