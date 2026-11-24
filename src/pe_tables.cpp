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
