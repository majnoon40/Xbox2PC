#include "xbox2pc/pe_parser.hpp"

#include <algorithm>
#include <cstdio>
#include <utility>

#include "pe_internal.hpp"

namespace xbox2pc::pe {
namespace {

// Bounds-checked readers reused for table parsing (same contract as in
// pe_parser.cpp — every byte fetch validated against the logical end).
struct TableReader {
    const std::uint8_t* base;
    std::uint64_t size;

    std::uint8_t u8(std::uint64_t off) const {
        if (off >= size) throw ParseError("unexpected end of file while reading table", off);
        return base[off];
    }
    std::uint16_t u16(std::uint64_t off) const {
        std::uint16_t v = 0;
        for (unsigned i = 0; i < 2; ++i) {
            v = static_cast<std::uint16_t>(v | (static_cast<std::uint16_t>(u8(off + i)) << (8 * i)));
        }
        return v;
    }
    std::uint32_t u32(std::uint64_t off) const {
        std::uint32_t v = 0;
        for (unsigned i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(u8(off + i)) << (8 * i);
        return v;
    }
    std::uint64_t u64(std::uint64_t off) const {
        std::uint64_t v = 0;
        for (unsigned i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(u8(off + i)) << (8 * i);
        return v;
    }
    std::string cstr(std::uint64_t off, std::uint64_t cap) const {
        std::string out;
        for (std::uint64_t i = 0; i < cap; ++i) {
            if (off + i >= size) break;
            const std::uint8_t c = base[off + i];
            if (c == 0) break;
            out.push_back(static_cast<char>(c));
        }
        return out;
    }
};

template <typename T>
std::optional<T> tadd(T a, T b) {
    static_assert(std::is_unsigned_v<T>);
    const T s = a + b;
    if (s < a) return std::nullopt;
    return s;
}

bool in_range(std::uint64_t off, std::uint64_t len, std::uint64_t total) {
    const auto e = tadd<std::uint64_t>(off, len);
    if (!e.has_value()) return false;
    return *e <= total;
}

}  // namespace

// ── Import table ─────────────────────────────────────────────────────────
//
// Structure (all RVAs, converted via the section table):
//   IMAGE_IMPORT_DESCRIPTOR[] { OriginalFirstThunk(INT), TimeDateStamp,
//                              ForwarderChain, Name(RVA), FirstThunk(IAT) }
//   terminated by an all-zero descriptor. Each thunk array is terminated by
//   a zero entry; PE32+ thunks are 8 bytes; ordinal flag is bit 63.
void parse_imports(PeImage& img, const std::uint8_t* base, std::uint64_t size,
                   diag::Diagnostics& diags) {
    if (img.directories.size() <= kDirImport) return;
    const auto& dir = img.directories[kDirImport];
    if (dir.rva == 0 && dir.size == 0) {
        img.imports.present = false;
        return;
    }
    img.imports.present = true;
    TableReader rd{base, size};

    if (dir.rva == 0 || dir.size == 0) {
        diags.warning("import directory has a zero RVA or size; imports unavailable");
        return;
    }

    const auto desc_off = rva_to_offset(img, dir.rva);
    if (!desc_off.has_value()) {
        diags.warning("import directory RVA " + std::to_string(dir.rva) +
                      " does not map to any section; imports unavailable", 0);
        return;
    }
    if (!in_range(*desc_off, dir.size, size)) {
        diags.warning("import directory raw range exceeds file bounds", *desc_off);
        return;
    }
    const std::uint64_t desc_end = *desc_off + dir.size;

    // The descriptor array is null-terminated. DataDirectory.Size is a byte
    // bound for the import data, not a descriptor count; linkers may include
    // padding or other .idata data after the descriptor terminator.
    constexpr std::uint32_t kMaxDescriptors = 4096;
    std::uint32_t n_desc = 0;
    std::uint64_t off = *desc_off;
    for (; n_desc < kMaxDescriptors; ++n_desc) {
        if (!in_range(off, 20, desc_end)) {
            diags.warning("import descriptor array truncated by declared directory size; read " +
                          std::to_string(n_desc) + " entries", off);
            break;
        }
        const std::uint32_t name_rva = rd.u32(off + 12);
        const std::uint32_t first_thunk = rd.u32(off + 16);
        const std::uint32_t int_rva = rd.u32(off + 0);
        if (name_rva == 0 && first_thunk == 0 && int_rva == 0) break;  // terminator
        ImportEntry entry;
        // ── preserved import metadata (M2) ──
        entry.int_rva = int_rva;
        entry.iat_rva = first_thunk;
        entry.name_rva = name_rva;
        entry.timestamp = rd.u32(off + 4);
        entry.forwarder_chain = rd.u32(off + 8);
        entry.bound = entry.timestamp != 0;

        const auto name_off = rva_to_offset(img, name_rva);
        if (!name_off.has_value()) {
            diags.warning("import DLL name RVA " + std::to_string(name_rva) +
                          " unmappable; entry recorded without a name");
            entry.dll_name = "<unresolved RVA " + std::to_string(name_rva) + ">";
        } else {
            entry.dll_name = rd.cstr(*name_off, 256);  // DLL names < 256 bytes in practice
            if (entry.dll_name.empty()) {
                entry.dll_name = "<empty name>";
                diags.warning("import descriptor has empty DLL name", *name_off);
            }
        }

        // Prefer the INT (names intact) — the IAT can be bound/patched.
        std::uint32_t thunk_rva = int_rva != 0 ? int_rva : first_thunk;
        if (thunk_rva != 0) {
            const auto thunk_off = rva_to_offset(img, thunk_rva);
            if (!thunk_off.has_value()) {
                diags.warning("thunk array for '" + entry.dll_name + "' unmappable");
            } else {
                std::uint64_t t = *thunk_off;
                constexpr std::uint32_t kMaxThunks = 1u << 16;
                for (std::uint32_t n = 0; n < kMaxThunks; ++n) {
                    if (!in_range(t, 8, size)) {
                        diags.warning("thunk array for '" + entry.dll_name +
                                      "' truncated; read " + std::to_string(n) + " entries", t);
                        break;
                    }
                    const std::uint64_t th = rd.u64(t);
                    if (th == 0) break;  // terminator
                    if ((th >> 63) & 1) {
                        // Ordinal import: low 16 bits.
                        entry.ordinal_only.push_back(static_cast<std::uint32_t>(th & 0xFFFF));
                    } else {
                        const std::uint32_t hint_rva = static_cast<std::uint32_t>(th & 0xFFFFFFFF);
                        const auto fn_off = rva_to_offset(img, hint_rva);
                        if (!fn_off.has_value()) {
                            diags.warning("import name RVA " + std::to_string(hint_rva) +
                                          " unmappable; recorded as ordinal-less entry");
                            entry.functions.push_back("<unresolved RVA " +
                                                      std::to_string(hint_rva) + ">");
                        } else {
                            entry.functions.push_back(rd.cstr(*fn_off + 2, 512));  // +2 skips hint
                            entry.by_name_ordinals.push_back(rd.u16(*fn_off));
                        }
                    }
                    t += 8;
                }
            }
        } else {
            diags.warning("import descriptor for '" + entry.dll_name + "' has no thunk arrays");
        }

        img.imports.entries.push_back(std::move(entry));
        off += 20;
        if (n_desc + 1 == kMaxDescriptors) {
            diags.warning("import descriptor count exceeded " + std::to_string(kMaxDescriptors) +
                          "; truncating");
        }
    }
}

// ── Export table ─────────────────────────────────────────────────────────
//
// IMAGE_EXPORT_DIRECTORY (40 bytes, file offset via directory RVA):
//   [0] Characteristics, [4] TimeDateStamp, [8] Major/MinorVersion,
//   [12] Name RVA, [16] OrdinalBase, [20] AddressTableEntries,
//   [22 -> u32 @20] NumberOfNames, [24] NamePointerRVA (AddressOfNames),
//   [28] OrdinalTableRVA (AddressOfNameOrdinals), [32] FunctionRVA.
// Careful: NumberOfFunctions lives at offset 20, NumberOfNames at 24,
// AddressOfFunctions at 28, AddressOfNames at 32, AddressOfNameOrdinals at 36.
void parse_exports(PeImage& img, const std::uint8_t* base, std::uint64_t size,
                   diag::Diagnostics& diags) {
    if (img.directories.size() <= kDirExport) return;
    const auto& dir = img.directories[kDirExport];
    if (dir.rva == 0 && dir.size == 0) {
        img.exports.present = false;
        return;
    }
    img.exports.present = true;
    TableReader rd{base, size};

    const auto dir_off = rva_to_offset(img, dir.rva);
    if (!dir_off.has_value()) {
        diags.warning("export directory RVA " + std::to_string(dir.rva) +
                      " does not map to any section; exports unavailable");
        return;
    }
    if (!in_range(*dir_off, 40, size)) {
        diags.warning("export directory header truncated; exports unavailable", *dir_off);
        return;
    }
    const std::uint64_t d = *dir_off;
    ExportTable& et = img.exports;

    const std::uint32_t name_rva = rd.u32(d + 12);
    et.ordinal_base = rd.u32(d + 16);
    const std::uint32_t n_funcs = rd.u32(d + 20);
    const std::uint32_t n_names = rd.u32(d + 24);
    const std::uint32_t addr_rva = rd.u32(d + 28);
    const std::uint32_t names_rva = rd.u32(d + 32);
    const std::uint32_t ords_rva = rd.u32(d + 36);

    if (name_rva != 0) {
        const auto no = rva_to_offset(img, name_rva);
        if (no.has_value()) et.dll_name = rd.cstr(*no, 256);
        if (et.dll_name.empty()) diags.warning("export directory name is empty or unmappable");
    }

    // Hostile-count guards: each entry has a fixed width, so cap by what the
    // file could actually hold, then warn when counts exceed that.
    constexpr std::uint32_t kCap = 1u << 20;  // 1M entries sanity cap
    std::uint32_t n_f = n_funcs > kCap ? kCap : n_funcs;
    std::uint32_t n_n = n_names > n_funcs ? n_funcs : n_names;  // names ⊆ functions
    n_n = n_n > kCap ? kCap : n_n;
    if (n_funcs != n_f || n_names != n_n) {
        diags.warning("export counts clamped (functions " + std::to_string(n_funcs) +
                      ", names " + std::to_string(n_names) + ")");
    }

    // Function RVAs.
    if (addr_rva != 0 && n_f != 0) {
        const auto ao = rva_to_offset(img, addr_rva);
        if (!ao.has_value() || !in_range(*ao, 4ull * n_f, size)) {
            diags.warning("export address table unmappable or truncated; export RVAs unavailable");
            n_f = 0;  // keep parsing names, but no resolved functions
            if (n_n != 0) diags.warning("name/ordinal tables still parsed");
        } else {
            et.function_rvas.reserve(n_f);
            for (std::uint32_t i = 0; i < n_f; ++i) {
                et.function_rvas.push_back(rd.u32(*ao + 4ull * i));
            }
        }
    }

    // Name pointer + ordinal tables.
    if (names_rva != 0 && n_n != 0) {
        const auto no = rva_to_offset(img, names_rva);
        const auto oo = rva_to_offset(img, ords_rva);
        if (!no.has_value() || !in_range(*no, 4ull * n_n, size)) {
            diags.warning("export name table unmappable or truncated; names unavailable");
            n_n = 0;
        } else if (ords_rva == 0 || !oo.has_value() || !in_range(*oo, 2ull * n_n, size)) {
            diags.warning("export ordinal table unmappable or truncated; names unavailable");
            n_n = 0;
        } else {
            et.name_rvas.reserve(n_n);
            et.name_ordinal_table.reserve(n_n);
            for (std::uint32_t i = 0; i < n_n; ++i) {
                et.name_rvas.push_back(rd.u32(*no + 4ull * i));
                et.name_ordinal_table.push_back(rd.u16(*oo + 2ull * i));
            }
        }
    }

    // Resolve the unified view in O(N + M) time. Pre-index the first valid
    // name-table entry for each function index to avoid an O(N * M) scan on
    // crafted PE files with large export tables. The ordinal table may be
    // EMPTY while n_n > 0 (e.g. a mutated PE with NumberOfNames > 0 but a
    // null AddressOfNames/AddressOfNameOrdinals): bound the scan by the
    // parsed table size, not by the directory count, so hostile headers
    // cannot index an empty vector.
    constexpr std::uint32_t kNoName = ~0u;
    std::vector<std::uint32_t> name_for_func(et.function_rvas.size(), kNoName);
    const std::uint32_t n_ord = std::min<std::uint32_t>(
        n_n, static_cast<std::uint32_t>(et.name_ordinal_table.size()));
    for (std::uint32_t j = 0; j < n_ord; ++j) {
        const std::uint16_t func_idx = et.name_ordinal_table[j];
        if (func_idx < name_for_func.size() && name_for_func[func_idx] == kNoName) {
            name_for_func[func_idx] = j;
        }
    }
    et.functions.reserve(et.function_rvas.size());
    for (std::uint32_t i = 0; i < et.function_rvas.size(); ++i) {
        ExportedFunction f;
        f.rva = et.function_rvas[i];
        f.ordinal = et.ordinal_base + i;  // may overflow-wrap on hostile input; harmless label
        if (name_for_func[i] != kNoName) {
            const auto s_off = rva_to_offset(img, et.name_rvas[name_for_func[i]]);
            if (s_off.has_value()) {
                f.name = rd.cstr(*s_off, 512);
            }
        }
        // Forwarder detection: function RVA points inside the export dir itself.
        const auto& ed = img.directories[kDirExport];
        if (f.rva >= ed.rva && f.rva < ed.rva + std::min<std::uint64_t>(ed.size, 0x10000000ull)) {
            const auto fwd_off = rva_to_offset(img, f.rva);
            if (fwd_off.has_value()) f.forwarder = rd.cstr(*fwd_off, 256);
        }
        et.functions.push_back(std::move(f));
    }
}

// ── Delay-load import table (M2) ─────────────────────────────────────────
//
// Data directory 13 points at an array of ImgDelayDescr (32 bytes each,
// zero-terminated like import descriptors):
//   [0]  grAttributes — bit 0 set: the other address fields are VAs
//        (base-relocated at bind time); bit 0 clear: they are RVAs.
//   [4]  szName (RVA/VA of the DLL name string),
//   [8]  phmod (RVA/VA of the HMODULE slot),
//   [12] pIAT (RVA/VA of the delay IAT),
//   [16] pINT (RVA/VA of the delay INT),
//   [20] pBoundIAT (RVA/VA of the bound IAT copy),
//   [24] pUnloadIAT (RVA/VA of the unload thunk table),
//   [28] dwTimeStamp (bound timestamp).
// Thunk arrays use the exact same encoding as the regular import INT
// (8-byte PE32+ thunks, ordinal flag bit 63), so resolution is shared.
// ── directory 3: exception directory (.pdata RUNTIME_FUNCTION array) ──────
// Layout: array of 12-byte entries {u32 begin, u32 end, u32 unwind}. The
// loader sorts by begin (pairs of begin+end for function fragments) so the
// RIP lookup is a binary search. Malformed entries are warned and skipped;
// the table stays sorted by (begin, end).
// ── .xdata UNWIND_INFO decoding (M11 Phase 6 slice 2) ─────────────────────
// Header layout: byte 0 = version | flags<<3; byte 1 = size_of_prolog;
// byte 2 = count_of_codes | frame_register<<4; byte 3 = frame_offset<<4.
// The unwind code array follows as count_of_codes 16-bit slots; some
// opcodes consume extra slots for operands. The header's count is never
// trusted beyond per-fetch bounds checks against the file size.
std::optional<UnwindInfo> decode_unwind_info(const PeImage& img,
                                             const RuntimeFunction& fn,
                                             const std::uint8_t* base,
                                             std::uint64_t size,
                                             diag::Diagnostics& diags) {
    if (base == nullptr || fn.unwind_info_rva == 0) {
        diags.warning("decode_unwind_info: null buffer or unwind RVA");
        return std::nullopt;
    }
    const auto off = rva_to_offset(img, fn.unwind_info_rva);
    if (!off.has_value()) {
        diags.warning("unwind info RVA " + std::to_string(fn.unwind_info_rva) +
                      " does not map to any section", fn.unwind_info_rva);
        return std::nullopt;
    }
    if (!in_range(*off, 4, size)) {
        diags.warning("unwind info header truncated", *off);
        return std::nullopt;
    }
    TableReader rd{base, size};
    UnwindInfo info;
    const std::uint8_t b0 = rd.u8(*off);
    info.version = static_cast<std::uint8_t>(b0 & 0x7);
    info.flags = static_cast<std::uint8_t>(b0 >> 3);
    info.size_of_prolog = rd.u8(*off + 1);
    const std::uint8_t b2 = rd.u8(*off + 2);
    const unsigned slot_count = b2 & 0xF;
    info.frame_register = static_cast<std::uint8_t>(b2 >> 4);
    info.frame_offset = static_cast<std::uint8_t>(rd.u8(*off + 3) >> 4);
    if (info.version != 1) {
        diags.warning("unsupported UNWIND_INFO version " +
                      std::to_string(info.version), *off);
        return std::nullopt;
    }
    std::uint64_t cursor = *off + 4;
    for (unsigned i = 0; i < slot_count; ++i) {
        if (!in_range(cursor, 2, size)) {
            diags.warning("unwind code array truncated at slot " +
                          std::to_string(i), cursor);
            return std::nullopt;
        }
        const std::uint8_t lo = rd.u8(cursor);
        const std::uint8_t hi = rd.u8(cursor + 1);
        UnwindCode code;
        code.slot_offset = lo;
        code.opcode = static_cast<std::uint8_t>(hi & 0xF);
        code.opinfo = static_cast<std::uint8_t>(hi >> 4);
        unsigned extra_slots = 0;
        switch (code.opcode) {
        case 0:  // UWOP_PUSH_NONVOL — reg in opinfo
        case 3:  // UWOP_SET_FPREG
        case 10: // UWOP_PUSH_MACHFRAME
            extra_slots = 0;
            code.operand = code.opinfo;
            break;
        case 2:  // UWOP_ALLOC_SMALL — size = opinfo*8+8
            extra_slots = 0;
            code.operand = static_cast<std::uint32_t>(code.opinfo) * 8 + 8;
            break;
        case 1:  // UWOP_ALLOC_LARGE — size in next slot *8 (opinfo==0 form)
            extra_slots = 1;
            break;
        case 4:  // UWOP_SAVE_NONVOL — offset in next slot*8
        case 6:  // UWOP_EPILOG
        case 7:  // UWOP_SPARE_CODE
        case 8:  // UWOP_SAVE_XMM128 — offset in next slot*16
            extra_slots = 1;
            break;
        case 5:  // UWOP_SAVE_NONVOL_FAR — 32-bit offset
        case 9:  // UWOP_SAVE_XMM128_FAR — 32-bit offset
            extra_slots = 2;
            break;
        default:
            diags.warning("unknown unwind opcode " + std::to_string(code.opcode) +
                          " at slot " + std::to_string(i), cursor);
            return std::nullopt;
        }
        if (extra_slots != 0) {
            if (!in_range(cursor + 2, static_cast<std::uint64_t>(extra_slots) * 2, size)) {
                diags.warning("unwind code operand truncated at slot " +
                              std::to_string(i), cursor + 2);
                return std::nullopt;
            }
            if (code.opcode == 1) {  // ALLOC_LARGE
                if (code.opinfo != 0) {
                    diags.warning("ALLOC_LARGE reserved opinfo form", cursor);
                    return std::nullopt;
                }
                code.operand = static_cast<std::uint32_t>(rd.u16(cursor + 2)) * 8;
            } else if (extra_slots == 1) {
                code.operand = rd.u16(cursor + 2);
            } else {
                code.operand = rd.u16(cursor + 2) |
                               (static_cast<std::uint32_t>(rd.u16(cursor + 4)) << 16);
            }
        }
        info.codes.push_back(code);
        cursor += 2 + static_cast<std::uint64_t>(extra_slots) * 2;
    }
    if (info.is_chained()) {
        if (!in_range(cursor, 4, size)) {
            diags.warning("chained unwind RVA truncated", cursor);
            return std::nullopt;
        }
        info.chained_unwind_rva = rd.u32(cursor);
    }
    return info;
}

// ── virtual unwinding (M11 Phase 6 slice 3) ────────────────────────────────
// The documented x64 unwind walk: codes are stored in reverse execution
// order. Walking them in stored order and adding each effect undoes the
// prolog step by step, so the accumulated delta is the distance from
// current_rsp back to the entry RSP. SET_FPREG is a no-op for the walk:
// once every post-establishment effect is undone, the walked RSP equals
// the frame pointer by construction. Chained entries contribute their
// full code array (the chained prolog has fully executed when control
// is inside the outer range).
std::optional<UnwindFrame> unwind_one_frame(
    const PeImage& img, const RuntimeFunction& fn, const std::uint8_t* base,
    std::uint64_t size, std::uint32_t target_offset, std::uint64_t current_rsp,
    const std::function<std::optional<std::uint64_t>(std::uint64_t va)>& read_stack,
    diag::Diagnostics& diags) {
    std::uint64_t delta = 0;  // current_rsp + delta == entry_rsp
    const RuntimeFunction* current = &fn;
    const std::optional<UnwindFrame> none;
    for (int depth = 0; depth < 8; ++depth) {  // chain-loop guard
        auto info = decode_unwind_info(img, *current, base, size, diags);
        if (!info.has_value()) return none;
        const bool outer = (current == &fn);
        for (const auto& code : info->codes) {
            // Outer codes are target-filtered: a prolog op at offset X has
            // executed when the control point is at or past X, so codes with
            // slot_offset > target_offset are skipped. Chained codes all
            // executed (control inside the outer range implies the chained
            // prolog completed).
            if (outer && code.slot_offset > target_offset) continue;
            switch (code.opcode) {
            case 0:  // PUSH_NONVOL: 8 bytes to undo
                delta += 8;
                break;
            case 1:  // ALLOC_LARGE (operand pre-scaled by 8)
            case 2:  // ALLOC_SMALL (operand = opinfo*8+8)
                delta += code.operand;
                break;
            case 3:  // SET_FPREG: walked RSP already equals FP here
                break;
            case 4:  // SAVE_NONVOL: below the frame, no RSP effect
            case 5:  // SAVE_NONVOL_FAR
            case 8:  // SAVE_XMM128
            case 9:  // SAVE_XMM128_FAR
            case 6:  // EPILOG
            case 7:  // SPARE_CODE (padding)
                break;
            case 10: // PUSH_MACHFRAME: interrupt frames — not modeled
                diags.warning("unwind: PUSH_MACHFRAME is not supported");
                return none;
            default:
                diags.warning("unwind: unknown opcode " +
                              std::to_string(code.opcode));
                return none;
            }
        }
        if (info->is_chained() && info->chained_unwind_rva != 0) {
            const RuntimeFunction* chained =
                img.exceptions.find_function(info->chained_unwind_rva);
            if (chained == nullptr) {
                diags.warning("unwind: chained RVA " +
                              std::to_string(info->chained_unwind_rva) +
                              " has no covering RUNTIME_FUNCTION");
                return none;
            }
            current = chained;
            continue;
        }
        break;
    }
    const std::uint64_t entry_rsp = current_rsp + delta;
    auto return_rip = read_stack(entry_rsp);
    if (!return_rip.has_value()) {
        diags.warning("unwind: return-address read failed at guest " +
                      std::to_string(entry_rsp));
        return none;
    }
    UnwindFrame frame;
    frame.return_rip = return_rip.value();
    frame.rsp_after = entry_rsp + 8;
    return frame;
}

void parse_exception_table(PeImage& img, const std::uint8_t* base, std::uint64_t size,
                           diag::Diagnostics& diags) {
    if (img.directories.size() <= kDirException) return;
    const auto& dir = img.directories[kDirException];
    if (dir.rva == 0 && dir.size == 0) return;
    img.exceptions.present = true;
    if (dir.size == 0) {
        diags.warning("exception directory has zero size; no unwind data");
        return;
    }
    if (dir.size % 12 != 0) {
        diags.warning("exception directory size " + std::to_string(dir.size) +
                      " is not a multiple of 12; trailing bytes ignored");
    }
    const auto off = rva_to_offset(img, dir.rva);
    if (!off.has_value()) {
        diags.warning("exception directory RVA " + std::to_string(dir.rva) +
                      " does not map to any section; unwind data unavailable");
        return;
    }
    if (!in_range(*off, dir.size, size)) {
        diags.warning("exception directory truncated; unwind data unavailable", *off);
        return;
    }
    const std::uint64_t count = dir.size / 12;
    // Hostile-count guard: cap at 1M entries (12 MB of .pdata — far beyond
    // any legitimate image) and warn when clamped.
    constexpr std::uint64_t kCap = 1ull << 20;
    const std::uint64_t n = count > kCap ? kCap : count;
    if (n != count)
        diags.warning("exception entry count clamped from " + std::to_string(count) +
                      " to " + std::to_string(n));
    TableReader rd{base, size};
    auto& table = img.exceptions.functions;
    table.reserve(n);
    for (std::uint64_t i = 0; i < n; ++i) {
        RuntimeFunction fn;
        fn.begin_rva = rd.u32(*off + i * 12);
        fn.end_rva = rd.u32(*off + i * 12 + 4);
        fn.unwind_info_rva = rd.u32(*off + i * 12 + 8);
        if (fn.end_rva < fn.begin_rva) {
            diags.warning("RUNTIME_FUNCTION entry " + std::to_string(i) +
                          " has end < begin; entry skipped");
            continue;
        }
        if (fn.begin_rva == 0 && fn.end_rva == 0) {
            diags.warning("RUNTIME_FUNCTION entry " + std::to_string(i) +
                          " is empty; entry skipped");
            continue;
        }
        table.push_back(fn);
    }
    // (begin, end) sort keeps equal-begin fragments ordered by end, so the
    // lookup's "last entry with begin <= rva" resolves to the largest
    // fragment — matching the PE loader's documented merge behavior.
    std::sort(table.begin(), table.end(), [](const RuntimeFunction& a,
                                             const RuntimeFunction& b) {
        return a.begin_rva != b.begin_rva ? a.begin_rva < b.begin_rva
                                          : a.end_rva < b.end_rva;
    });
}

void parse_delay_imports(PeImage& img, const std::uint8_t* base, std::uint64_t size,
                          diag::Diagnostics& diags) {
    if (img.directories.size() <= kDirDelayImport) return;
    const auto& dir = img.directories[kDirDelayImport];
    if (dir.rva == 0 && dir.size == 0) {
        img.delay_imports.present = false;
        return;
    }
    img.delay_imports.present = true;
    TableReader rd{base, size};

    const auto desc_off = rva_to_offset(img, dir.rva);
    if (!desc_off.has_value()) {
        diags.warning("delay-import directory RVA " + std::to_string(dir.rva) +
                      " does not map to any section; delay imports unavailable");
        return;
    }

    constexpr std::uint32_t kMaxDelayDesc = 4096;
    std::uint32_t n_desc = 0;
    std::uint64_t off = *desc_off;
    for (; n_desc < kMaxDelayDesc; ++n_desc) {
        if (!in_range(off, 32, size)) {
            diags.warning("delay-import descriptor array truncated; read " +
                          std::to_string(n_desc) + " entries", off);
            break;
        }
        const std::uint32_t gr_attrs = rd.u32(off + 0);
        const std::uint32_t name_field = rd.u32(off + 4);
        const std::uint32_t iat_field = rd.u32(off + 12);
        const std::uint32_t int_field = rd.u32(off + 16);
        const std::uint32_t bind_field = rd.u32(off + 20);
        const std::uint32_t unload_field = rd.u32(off + 24);
        const std::uint32_t stamp = rd.u32(off + 28);
        if (name_field == 0 && iat_field == 0 && int_field == 0) break;  // terminator

        // With grAttrs bit 0 set the fields are VAs: subtract ImageBase to
        // get RVAs. A malformed base produces unmappable RVAs -> warnings.
        const bool va_mode = (gr_attrs & 0x1) != 0;
        const std::uint64_t image_base = img.opt.image_base;
        auto to_rva = [va_mode, image_base](std::uint32_t field) -> std::uint32_t {
            if (!va_mode || field == 0) return field;
            if (field < image_base) return field;  // already RVA-ish
            return static_cast<std::uint32_t>(field - image_base);
        };

        DelayImportEntry entry;
        entry.va_addressed = va_mode;
        entry.timestamp = stamp;
        entry.name_rva = to_rva(name_field);
        entry.iat_rva = to_rva(iat_field);
        entry.int_rva = to_rva(int_field);
        entry.bind_rva = to_rva(bind_field);
        entry.unload_rva = to_rva(unload_field);

        // DLL name.
        const auto name_off = rva_to_offset(img, entry.name_rva);
        if (!name_off.has_value()) {
            diags.warning("delay-import DLL name RVA " + std::to_string(entry.name_rva) +
                          " unmappable; entry recorded without a name");
            entry.dll_name = "<unresolved RVA " + std::to_string(entry.name_rva) + ">";
        } else {
            entry.dll_name = rd.cstr(*name_off, 256);
            if (entry.dll_name.empty()) {
                entry.dll_name = "<empty name>";
                diags.warning("delay-import descriptor has empty DLL name", *name_off);
            }
        }

        // Resolve function names from the INT (names intact; IAT is bound).
        std::uint32_t thunk_rva = entry.int_rva != 0 ? entry.int_rva : entry.iat_rva;
        if (thunk_rva != 0) {
            const auto thunk_off = rva_to_offset(img, thunk_rva);
            if (!thunk_off.has_value()) {
                diags.warning("delay-import thunk array for '" + entry.dll_name + "' unmappable");
            } else {
                std::uint64_t t = *thunk_off;
                constexpr std::uint32_t kMaxThunks = 1u << 16;
                for (std::uint32_t n = 0; n < kMaxThunks; ++n) {
                    if (!in_range(t, 8, size)) {
                        diags.warning("delay-import thunk array for '" + entry.dll_name +
                                      "' truncated; read " + std::to_string(n) + " entries", t);
                        break;
                    }
                    const std::uint64_t th = rd.u64(t);
                    if (th == 0) break;  // terminator
                    if ((th >> 63) & 1) {
                        entry.ordinal_only.push_back(static_cast<std::uint32_t>(th & 0xFFFF));
                    } else {
                        const std::uint32_t hint_rva = static_cast<std::uint32_t>(th & 0xFFFFFFFF);
                        const auto fn_off = rva_to_offset(img, hint_rva);
                        if (!fn_off.has_value()) {
                            diags.warning("delay-import name RVA " + std::to_string(hint_rva) +
                                          " unmappable; recorded as ordinal-less entry");
                            entry.functions.push_back("<unresolved RVA " +
                                                      std::to_string(hint_rva) + ">");
                        } else {
                            entry.functions.push_back(rd.cstr(*fn_off + 2, 512));
                        }
                    }
                    t += 8;
                }
            }
        } else {
            diags.warning("delay-import descriptor for '" + entry.dll_name +
                          "' has no thunk arrays");
        }

        img.delay_imports.entries.push_back(std::move(entry));
        off += 32;
        if (n_desc + 1 == kMaxDelayDesc) {
            diags.warning("delay-import descriptor count exceeded " +
                          std::to_string(kMaxDelayDesc) + "; truncating");
        }
    }
}

}  // namespace xbox2pc::pe
