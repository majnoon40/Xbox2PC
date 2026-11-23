// xbox2pc/src/image_loader.cpp — M6 executable loader implementation.
//
// Component breakdown (single library, cohesive implementation):
//   validate_image()       — pre-allocation safety validation
//   pe_section_protection() — characteristics → MemProtect (W^X)
//   map_image()            — reserve/commit/stage/write/protect via M4
//   decode/apply_relocations() — X64 base relocation processing
//   Static/Null resolvers, resolve_imports(), write_iat_slots()
//   decode_tls()           — TLS directory validation/reporting
//   ImageLoader::load_image/unload_image — lifecycle + rollback
//   prepare_exec()         — entry-point validation (never execution)
//
// Address model (documented in docs/pe-loader.md):
//   file offset → RVA (section table) → Xbox VA (actual_base + rva)
//   Host backing memory is ONE mmap per AddressSpace; the loader obtains
//   staging host pointers via AddressSpace::translate() and never stores
//   them beyond the local scope of a write.

#include "xbox2pc/image_loader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace xbox2pc::rt::loader {

namespace {

// ── checked arithmetic ──────────────────────────────────────────────────

bool add_ok(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

// ── little-endian bounded readers (M1 parser discipline) ─────────────────

bool rd_u16(const std::uint8_t* f, std::size_t n, std::uint64_t off,
            std::uint16_t& out) {
    if (off + 2 > n) return false;
    out = static_cast<std::uint16_t>(f[off]) |
          (static_cast<std::uint16_t>(f[off + 1]) << 8);
    return true;
}
bool rd_u32(const std::uint8_t* f, std::size_t n, std::uint64_t off,
            std::uint32_t& out) {
    if (off + 4 > n) return false;
    out = static_cast<std::uint32_t>(f[off]) |
          (static_cast<std::uint32_t>(f[off + 1]) << 8) |
          (static_cast<std::uint32_t>(f[off + 2]) << 16) |
          (static_cast<std::uint32_t>(f[off + 3]) << 24);
    return true;
}
bool rd_u64(const std::uint8_t* f, std::size_t n, std::uint64_t off,
            std::uint64_t& out) {
    if (off + 8 > n) return false;
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i)
        v = (v << 8) | f[off + static_cast<unsigned>(i)];
    out = v;
    return true;
}

const pe::Section* rva_section(const pe::PeImage& img, std::uint32_t rva) {
    for (const auto& s : img.sections) {
        if (s.contains_rva(rva)) return &s;
    }
    return nullptr;
}

bool rva_in_headers(std::uint64_t rva, std::uint64_t size_of_headers) {
    return rva < size_of_headers;
}

// RVA → file offset (headers map 1:1; sections via raw ranges). `ok` is
// false when the RVA resolves to nothing file-backed (zero-fill or
// unmapped); callers treat that per their validation rules.
std::uint64_t checked_rva_to_offset(const pe::PeImage& img, std::uint32_t rva,
                                    bool& ok) {
    ok = false;
    if (rva_in_headers(rva, img.opt.size_of_headers)) {
        ok = true;
        return rva;  // headers map 1:1 (mapped at base + 0)
    }
    const pe::Section* s = rva_section(img, rva);
    if (s == nullptr || !s->has_raw_data) return 0;
    const std::uint64_t in = rva - s->virtual_address;
    if (in >= s->size_of_raw_data) return 0;  // zero-fill territory
    std::uint64_t off = 0;
    if (!add_ok(s->raw_data_offset, in, off)) return 0;
    ok = true;
    return off;
}

struct FileReader {
    const std::uint8_t* f;
    std::size_t n;
    bool u16(std::uint64_t off, std::uint16_t& out) const {
        return rd_u16(f, n, off, out);
    }
    bool u32(std::uint64_t off, std::uint32_t& out) const {
        return rd_u32(f, n, off, out);
    }
    bool u64(std::uint64_t off, std::uint64_t& out) const {
        return rd_u64(f, n, off, out);
    }
};

// Section region list for rollback (headers first, then sections in order).
std::vector<std::uint64_t> region_list(const ImageLayoutInfo& layout) {
    std::vector<std::uint64_t> out;
    if (layout.headers_region_xbox_va != 0) out.push_back(layout.headers_region_xbox_va);
    for (const auto& s : layout.sections) out.push_back(s.mapped_base);
    return out;
}

// Read a NUL-terminated ASCII/byte string from the file at `off` (bounded
// by file end and max_len). Returns false when the string is unterminated
// within bounds or empty.
bool read_cstr(const std::uint8_t* f, std::size_t n, std::uint64_t off,
               std::size_t max_len, std::string& out) {
    out.clear();
    if (off >= n) return false;
    for (std::uint64_t p = off; p < n; ++p) {
        const char c = static_cast<char>(f[p]);
        if (c == '\0') {
            // Count the terminator: an empty string is invalid for names.
            return !out.empty() && out.size() <= max_len;
        }
        if (out.size() == max_len) return false;  // over-long
        out.push_back(c);
    }
    return false;  // ran off the file without a NUL
}

}  // namespace

// ── validation ───────────────────────────────────────────────────────────

ValidationReport validate_image(const pe::PeImage& img, const std::uint8_t* file,
                                std::size_t file_size) {
    ValidationReport rep;
    auto issue = [&](const char* code, std::string msg) {
        rep.issues.push_back(ValidationIssue{code, std::move(msg)});
    };

    // Truncation / signature (standalone: validation must not depend on
    // the M1 parser having accepted the same bytes).
    if (file == nullptr || file_size < pe::kDosHeaderSize) {
        issue(vcode::kTruncated, "file smaller than the DOS header");
        return rep;
    }
    std::uint16_t dos_magic = 0;
    if (!rd_u16(file, file_size, 0, dos_magic) || dos_magic != pe::kDosMagic) {
        issue(vcode::kNotMapped, "DOS magic missing (not a PE)");
        return rep;
    }
    std::uint32_t lfanew = 0;
    if (!rd_u32(file, file_size, 0x3C, lfanew)) {
        issue(vcode::kTruncated, "e_lfanew out of file");
        return rep;
    }
    if (lfanew + 4 + pe::kCoffHeaderSize > file_size) {
        issue(vcode::kTruncated, "PE header beyond file end");
        return rep;
    }
    std::uint32_t sig = 0;
    if (!rd_u32(file, file_size, lfanew, sig) || sig != pe::kPeSignature) {
        issue(vcode::kBadSignature, "PE signature mismatch");
        return rep;
    }

    // Machine: this runtime loads AMD64 images only (documented scope).
    if (img.coff.machine != pe::kMachineAmd64) {
        issue(vcode::kBadMachine,
              "machine " + img.machine_name() + " not loadable (AMD64 only)");
    }

    // Optional header: PE32+ magic + alignments.
    if (img.opt.magic != pe::kOptMagicPe32Plus) {
        issue(vcode::kBadOptionalHeader,
              "optional header is not PE32+ (magic 0x" +
                  std::to_string(img.opt.magic) + ")");
    }
    const auto pow2 = [](std::uint32_t v) { return v != 0 && (v & (v - 1)) == 0; };
    if (img.opt.section_alignment < kMinSectionAlignment ||
        img.opt.section_alignment > kMaxSectionAlignment ||
        !pow2(img.opt.section_alignment)) {
        issue(vcode::kBadAlignment,
              "SectionAlignment " + std::to_string(img.opt.section_alignment) +
                  " not a power of two in [512, 2^28]");
    }
    if (img.opt.file_alignment != 0 &&
        (img.opt.file_alignment < kMinFileAlignment ||
         img.opt.file_alignment > kMaxFileAlignment ||
         !pow2(img.opt.file_alignment))) {
        issue(vcode::kBadAlignment,
              "FileAlignment " + std::to_string(img.opt.file_alignment) +
                  " not a power of two in [512, 2^16]");
    }
    if (img.opt.size_of_headers > file_size) {
        issue(vcode::kHeadersSize,
              "SizeOfHeaders " + std::to_string(img.opt.size_of_headers) +
                  " exceeds file size " + std::to_string(file_size));
    }

    // Image size consistency: SizeOfImage must cover headers + every
    // section's virtual extent (spec: SizeOfImage is section-aligned).
    const std::uint32_t raw_salign = img.opt.section_alignment;
    // Continue collecting validation issues without dividing by zero when
    // the hostile header supplies SectionAlignment == 0.
    const std::uint32_t salign = raw_salign == 0 ? 1u : raw_salign;
    std::uint64_t need = img.opt.size_of_headers;
    for (const auto& s : img.sections) {
        const std::uint64_t vs =
            std::max<std::uint64_t>(s.virtual_size, s.size_of_raw_data);
        std::uint64_t extent = 0;
        if (!add_ok(s.virtual_address, vs, extent)) {
            issue(vcode::kSectionOutsideImage,
                  "section " + s.name + " virtual extent wraps");
            continue;
        }
        const std::uint64_t aligned = (extent + salign - 1) / salign * salign;
        if (aligned > need) need = aligned;
    }
    const std::uint64_t hdr_aligned =
        (img.opt.size_of_headers + salign - 1) / salign * salign;
    if (img.opt.size_of_image != 0) {
        if (img.opt.size_of_image < hdr_aligned || img.opt.size_of_image < need) {
            issue(vcode::kImageSizeInconsistent,
                  "SizeOfImage " + std::to_string(img.opt.size_of_image) +
                      " smaller than headers (" + std::to_string(hdr_aligned) +
                      ") or section extent (" + std::to_string(need) + ")");
        }
        if (img.opt.size_of_image > kMaxImageSize) {
            issue(vcode::kImageTooLarge,
                  "SizeOfImage " + std::to_string(img.opt.size_of_image) +
                      " exceeds loader limit " + std::to_string(kMaxImageSize));
        }
    } else if (!img.sections.empty()) {
        issue(vcode::kImageSizeInconsistent, "SizeOfImage is zero with sections present");
    }

    // Entry point: inside the image; in an executable section when it
    // lands in one (headers-resident entries are a degenerate case that
    // prepare_exec rejects for execution anyway).
    if (img.opt.address_of_entry_point >= img.opt.size_of_image) {
        issue(vcode::kEntryOutsideImage,
              "entry RVA " + std::to_string(img.opt.address_of_entry_point) +
                  " >= SizeOfImage " + std::to_string(img.opt.size_of_image));
    } else if (img.opt.address_of_entry_point != 0 &&
               !rva_in_headers(img.opt.address_of_entry_point,
                               img.opt.size_of_headers)) {
        const pe::Section* s = rva_section(
            img, static_cast<std::uint32_t>(img.opt.address_of_entry_point));
        if (s != nullptr && (s->characteristics & pe::sect_flags::kExecutable) == 0) {
            issue(vcode::kEntryBadSection,
                  "entry RVA inside non-executable section " + s->name);
        }
        if (s == nullptr) {
            issue(vcode::kEntryOutsideImage,
                  "entry RVA not inside any section and not in headers");
        }
    }

    // Sections: raw ranges in-file, virtual start above headers, pairwise
    // overlap for file-backed sections.
    for (const auto& s : img.sections) {
        if (s.has_raw_data) {
            std::uint64_t raw_end = 0;
            if (!add_ok(s.raw_data_offset, s.size_of_raw_data, raw_end) ||
                raw_end > file_size) {
                issue(vcode::kSectionRawRange,
                      "section " + s.name + " raw data exceeds file size");
            }
        }
        const std::uint64_t section_extent =
            std::max<std::uint64_t>(s.virtual_size, s.size_of_raw_data);
        if (section_extent != 0 && s.virtual_address < hdr_aligned) {
            issue(vcode::kSectionOutsideImage,
                  "section " + s.name + " overlaps the mapped headers region");
        }
        if (std::max<std::uint64_t>(s.virtual_size, s.size_of_raw_data) >
            kMaxImageSize) {
            issue(vcode::kImageTooLarge,
                  "section " + s.name + " virtual extent exceeds loader limit");
        }
    }
    for (std::size_t i = 0; i < img.sections.size(); ++i) {
        for (std::size_t j = i + 1; j < img.sections.size(); ++j) {
            const auto& a = img.sections[i];
            const auto& b = img.sections[j];
            const auto extent = [](const pe::Section& s) {
                return std::max<std::uint64_t>(s.virtual_size, s.size_of_raw_data);
            };
            const std::uint64_t a_end = a.virtual_address + extent(a);
            const std::uint64_t b_end = b.virtual_address + extent(b);
            if (extent(a) != 0 && extent(b) != 0 &&
                a.virtual_address < b_end && b.virtual_address < a_end) {
                issue(vcode::kSectionOverlap,
                      "sections " + a.name + " and " + b.name +
                          " overlap in virtual space with raw data");
            }
        }
    }

    // Data directories: RVA+size must fit the image.
    for (std::size_t d = 0; d < img.directories.size(); ++d) {
        const auto& dir = img.directories[d];
        if (dir.size == 0) continue;
        std::uint64_t end = 0;
        if (d == pe::kDirSecurity) {
            // IMAGE_DIRECTORY_ENTRY_SECURITY is the exception: VirtualAddress
            // is a FILE OFFSET to the certificate table, not an image RVA.
            if (!add_ok(dir.rva, dir.size, end) || end > file_size) {
                issue(vcode::kDirectoryRange,
                      "security certificate table exceeds file bounds");
            }
            continue;
        }
        if (!add_ok(dir.rva, dir.size, end)) {
            issue(vcode::kDirectoryRange,
                  std::string(pe::directory_to_name(static_cast<std::uint16_t>(d))) +
                      " directory RVA+size wraps");
            continue;
        }
        if (end > img.opt.size_of_image) {
            issue(vcode::kDirectoryRange,
                  std::string(pe::directory_to_name(static_cast<std::uint16_t>(d))) +
                      " directory exceeds SizeOfImage");
        }
    }

    // Relocation directory specifics.
    if (img.directories.size() > pe::kDirReloc) {
        const auto& rd = img.directories[pe::kDirReloc];
        if (rd.size != 0) {
            if (rd.size < 8) {
                issue(vcode::kRelocDirectory,
                      "relocation directory smaller than one block header");
            } else if ((rd.size % 4) != 0) {
                issue(vcode::kRelocDirectory,
                      "relocation directory size not 4-byte aligned");
            }
            if (rd.size > kMaxRelocEntries * 2) {
                issue(vcode::kRelocDirectory,
                      "relocation directory size " + std::to_string(rd.size) +
                          " exceeds limit");
            }
        }
    }

    // Import directory specifics (descriptor-size multiple).
    if (img.directories.size() > pe::kDirImport) {
        const auto& id = img.directories[pe::kDirImport];
        if (id.size != 0 && (id.size % 20) != 0) {
            issue(vcode::kImportDirectory,
                  "import directory size not a multiple of 20 (descriptor size)");
        }
    }

    // TLS directory presence (details validated in decode_tls).
    if (img.directories.size() > pe::kDirTls &&
        img.directories[pe::kDirTls].size != 0) {
        rep.has_tls_directory = true;
    }

    // Fill the report.
    rep.size_of_image = img.opt.size_of_image;
    rep.size_of_headers = img.opt.size_of_headers;
    rep.preferred_base = img.opt.image_base;
    rep.entry_rva = static_cast<std::uint32_t>(img.opt.address_of_entry_point);
    rep.needs_relocation = img.directories.size() > pe::kDirReloc &&
                           img.directories[pe::kDirReloc].size != 0;
    rep.valid = rep.issues.empty();
    return rep;
}

// ── names / protection ──────────────────────────────────────────────────

const char* import_status_to_name(ImportStatus s) {
    switch (s) {
        case ImportStatus::Resolved: return "resolved";
        case ImportStatus::Unresolved: return "unresolved";
        case ImportStatus::Unsupported: return "unsupported";
        case ImportStatus::Invalid: return "invalid";
    }
    return "?";
}

const char* load_state_to_name(LoadState s) {
    switch (s) {
        case LoadState::Created: return "Created";
        case LoadState::Validating: return "Validating";
        case LoadState::Allocating: return "Allocating";
        case LoadState::Mapping: return "Mapping";
        case LoadState::Relocating: return "Relocating";
        case LoadState::ResolvingImports: return "ResolvingImports";
        case LoadState::Preparing: return "Preparing";
        case LoadState::Prepared: return "Prepared";
        case LoadState::Failed: return "Failed";
        case LoadState::Unloaded: return "Unloaded";
    }
    return "?";
}

MemProtect pe_section_protection(std::uint32_t ch) {
    const bool exec = (ch & pe::sect_flags::kExecutable) != 0;
    const bool write = (ch & pe::sect_flags::kWritable) != 0;
    // W^X: write and execute never both honored. A W+X request degrades
    // to RW (write honored, execute refused) — the degradation is
    // documented and tested, never silent success of RWX.
    if (write) return MemProtect::ReadWrite;
    if (exec) return MemProtect::ReadExecute;
    return MemProtect::ReadOnly;
}

// ── relocation decoding ──────────────────────────────────────────────────

const char* reloc_type_to_name(RelocType t) {
    switch (t) {
        case RelocType::Absolute: return "ABSOLUTE";
        case RelocType::High: return "HIGH";
        case RelocType::Low: return "LOW";
        case RelocType::HighLow: return "HIGHLOW";
        case RelocType::HighAdj: return "HIGHADJ";
        case RelocType::Dir64: return "DIR64";
    }
    return "UNSUPPORTED";
}

Result<std::vector<RelocBlock>> decode_relocations(const pe::PeImage& img,
                                                   const std::uint8_t* file,
                                                   std::size_t file_size,
                                                   std::size_t max_entries) {
    using Ret = Result<std::vector<RelocBlock>>;
    if (img.directories.size() <= pe::kDirReloc) return Ret(std::vector<RelocBlock>{});
    const auto& dir = img.directories[pe::kDirReloc];
    if (dir.size == 0) return Ret(std::vector<RelocBlock>{});

    bool ok = false;
    const std::uint64_t start_off = checked_rva_to_offset(img, dir.rva, ok);
    if (!ok) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "relocation directory RVA not file-backed");
    }
    std::uint64_t end_off = 0;
    if (!add_ok(start_off, dir.size, end_off) || end_off > file_size) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "relocation directory exceeds file bounds");
    }

    const FileReader rd{file, file_size};
    std::vector<RelocBlock> blocks;
    std::size_t total_entries = 0;
    std::uint64_t off = start_off;
    while (off < end_off) {
        if (off + 8 > end_off) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "truncated relocation block header");
        }
        std::uint32_t page_rva = 0, block_size = 0;
        if (!rd.u32(off, page_rva) || !rd.u32(off + 4, block_size)) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "relocation block header read failure");
        }
        if (block_size < 8) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "relocation block size smaller than its header");
        }
        if ((block_size % 4) != 0) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "relocation block size not 4-byte aligned");
        }
        if (off + block_size > end_off) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "relocation block exceeds directory bounds");
        }
        const std::size_t count = (block_size - 8) / 2;
        RelocBlock blk;
        blk.page_rva = page_rva;
        blk.block_size = block_size;
        for (std::size_t e = 0; e < count; ++e) {
            std::uint16_t ent = 0;
            if (!rd.u16(off + 8 + e * 2, ent)) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "relocation entry read failure");
            }
            const std::uint16_t type = ent >> 12;
            const std::uint16_t woff = ent & 0x0FFF;
            RelocEntry re;
            re.type = static_cast<RelocType>(type);
            re.page_rva = page_rva;
            if (!add_ok(page_rva, woff, re.target_rva)) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "relocation target RVA wraps");
            }
            blk.entries.push_back(re);
            ++total_entries;
            if (total_entries > max_entries) {
                return Ret(RuntimeErrc::OutOfResources,
                           "relocation entry count exceeds limit");
            }
        }
        blocks.push_back(std::move(blk));
        off += block_size;
    }
    return Ret(std::move(blocks));
}

namespace {

// Apply one DIR64 relocation: read64, add/subtract delta, write64.
bool apply_dir64(AddressSpace& space, std::uint64_t xbox_va,
                 std::uint64_t delta, bool delta_negative, std::string& err) {
    auto dst = space.translate(xbox_va);
    if (!dst.ok()) {
        err = "relocation target VA does not resolve";
        return false;
    }
    std::uint64_t v = 0;
    std::memcpy(&v, dst.value(), sizeof(v));
    // Null pointers must remain null when the image is rebased.
    if (v == 0) return true;
    if (delta_negative) {
        if (delta > v) {
            err = "relocation value underflows when applying the base delta";
            return false;
        }
        v -= delta;
    } else {
        std::uint64_t nv = 0;
        if (!add_ok(v, delta, nv)) {
            err = "relocated value wraps";
            return false;
        }
        v = nv;
    }
    std::memcpy(dst.value(), &v, sizeof(v));
    return true;
}

}  // namespace

// ── resolvers ────────────────────────────────────────────────────────────

void StaticResolver::add_module(std::string dll,
                                std::vector<std::string> symbols) {
    modules_[std::move(dll)] = Module{false, std::move(symbols)};
}

void StaticResolver::add_ordinal_module(std::string dll) {
    modules_[std::move(dll)] = Module{true, {}};
}

ImportBinding StaticResolver::resolve(const ImportLookup& lookup) {
    // Deterministic synthetic value: FNV-style hash of dll+symbol —
    // NEVER a host address (documented in the header + docs).
    const auto h = [](const std::string& s) {
        std::uint64_t v = 1469598103934665603ull;
        for (char ci : s) {
            const auto c = static_cast<unsigned char>(ci);
            v ^= c;
            v *= 1099511628211ull;
        }
        return v;
    };
    ImportBinding b;
    b.lookup = lookup;
    const auto it = modules_.find(lookup.dll);
    if (it == modules_.end()) {
        b.status = ImportStatus::Unresolved;
        b.note = "no synthetic module registered for DLL";
        return b;
    }
    if (it->second.ordinal_only) {
        if (!lookup.by_ordinal) {
            b.status = ImportStatus::Unresolved;
            b.note = "ordinal-only module got a by-name import";
            return b;
        }
        b.status = ImportStatus::Resolved;
        b.value = h(lookup.dll + ":#" + std::to_string(lookup.ordinal));
        b.note = "synthetic ordinal binding";
        return b;
    }
    if (lookup.by_ordinal) {
        b.status = ImportStatus::Unresolved;
        b.note = "named-symbol module got an ordinal import";
        return b;
    }
    const auto& syms = it->second.symbols;
    if (std::find(syms.begin(), syms.end(), lookup.symbol) == syms.end()) {
        b.status = ImportStatus::Unresolved;
        b.note = "symbol not registered in the synthetic module";
        return b;
    }
    b.status = ImportStatus::Resolved;
    b.value = h(lookup.dll + ":" + lookup.symbol);
    b.note = "synthetic named binding";
    return b;
}

bool StaticResolver::resolve_module(const std::string& dll) {
    return modules_.find(dll) != modules_.end();
}

ImportBinding NullResolver::resolve(const ImportLookup& lookup) {
    ImportBinding b;
    b.lookup = lookup;
    b.status = ImportStatus::Unresolved;
    b.note = "null resolver: nothing resolves";
    return b;
}
bool NullResolver::resolve_module(const std::string&) { return false; }

// ── mapping ──────────────────────────────────────────────────────────────

Result<ImageLayoutInfo> ImageLoader::map_image(AddressSpace& space,
                                               const pe::PeImage& img,
                                               const std::uint8_t* file,
                                               std::size_t file_size,
                                               std::uint64_t want_base,
                                               LoadDiagnostics& diag) {
    using Ret = Result<ImageLayoutInfo>;
    (void)diag;

    const std::uint64_t image_pages =
        (img.opt.size_of_image + space.page_size() - 1) / space.page_size() *
        space.page_size();
    const bool has_relocs = img.directories.size() > pe::kDirReloc &&
                            img.directories[pe::kDirReloc].size != 0;

    // ── placement ──
    std::uint64_t base = 0;
    const std::uint64_t preferred = want_base != 0 ? want_base : img.opt.image_base;
    if (!space.is_page_aligned(preferred)) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "preferred/requested base not page-aligned");
    }
    const std::uint64_t preferred_off =
        preferred >= space.base() ? preferred - space.base() : ~0ull;
    const bool in_bounds = preferred_off <= space.capacity() &&
                           image_pages <= space.capacity() - preferred_off;
    if (in_bounds && space.find_overlap(preferred, image_pages) == 0) {
        base = preferred;
    } else if (want_base != 0) {
        // A FORCED base that is unavailable is a hard failure (no silent
        // move of a caller-specified address).
        return Ret(RuntimeErrc::InvalidState,
                   "requested base unavailable (out of bounds or occupied)");
    } else if (has_relocs) {
        // First-fit gap scan (mirrors reserve_region_auto's policy; the
        // image range cannot be claimed as one region because headers and
        // sections are SEPARATE regions for per-section protections —
        // claiming the whole range first would overlap them). Race note:
        // a concurrent reservation landing in the same gap makes the
        // first reserve below fail with typed AlreadyExists — a clean,
        // deterministic failure, never corruption.
        base = space.base();
        const std::uint64_t page = space.page_size();
        for (const auto& r : space.list_regions()) {
            if (r.xbox_va >= base && r.xbox_va - base >= image_pages) {
                break;  // the gap before this region is large enough
            }
            const std::uint64_t region_end = r.xbox_va + r.size;
            if (region_end > base) {
                const std::uint64_t rem = region_end % page;
                const std::uint64_t delta = rem == 0 ? 0 : page - rem;
                if (region_end > (~0ull) - delta) {
                    return Ret(RuntimeErrc::OutOfResources,
                               "image placement alignment overflow");
                }
                base = region_end + delta;
            }
        }
        if (base < space.base() ||
            base - space.base() > space.capacity() ||
            image_pages > space.capacity() - (base - space.base())) {
            return Ret(RuntimeErrc::OutOfResources,
                       "no free gap for the image in the address space");
        }
    } else {
        return Ret(RuntimeErrc::InvalidState,
                   "preferred image base unavailable and the image has no "
                   "relocations (cannot move)");
    }
    const bool relocated = base != img.opt.image_base;

    ImageLayoutInfo layout;
    layout.actual_base = base;
    layout.preferred_base = img.opt.image_base;
    layout.mapped_size = image_pages;
    layout.relocated = relocated;
    layout.delta_negative = base < img.opt.image_base;
    layout.delta = layout.delta_negative ? img.opt.image_base - base
                                         : base - img.opt.image_base;
    layout.entry_rva = static_cast<std::uint32_t>(img.opt.address_of_entry_point);
    layout.entry_va = base + layout.entry_rva;

    std::vector<std::uint64_t> reserved_vas;
    auto rollback = [&]() {
        for (auto it = reserved_vas.rbegin(); it != reserved_vas.rend(); ++it) {
            (void)space.release_region(*it);
        }
    };

    // ── headers region ──
    const std::uint64_t hdr_pages =
        (img.opt.size_of_headers + space.page_size() - 1) / space.page_size() *
        space.page_size();
    if (hdr_pages == 0 || hdr_pages > image_pages) {
        rollback();
        return Ret(RuntimeErrc::InvalidArgument,
                   "mapped headers exceed the image extent");
    }
    // Preflight every section against the page-rounded headers and against
    // every other section before reserving any guest memory.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> section_ranges;
    for (const auto& section : img.sections) {
        const std::uint64_t extent =
            std::max<std::uint64_t>(section.virtual_size,
                                    section.size_of_raw_data);
        if (extent == 0) continue;
        const std::uint64_t pages =
            (extent + space.page_size() - 1) / space.page_size() *
            space.page_size();
        if (section.virtual_address < hdr_pages ||
            section.virtual_address > image_pages ||
            pages > image_pages - section.virtual_address ||
            section.virtual_address % space.page_size() != 0) {
            rollback();
            return Ret(RuntimeErrc::InvalidArgument,
                       "section overlaps headers or exceeds the mapped image: " +
                           section.name);
        }
        const std::uint64_t end = section.virtual_address + pages;
        for (const auto& existing : section_ranges) {
            if (section.virtual_address < existing.second &&
                existing.first < end) {
                rollback();
                return Ret(RuntimeErrc::InvalidArgument,
                           "page-rounded PE sections overlap");
            }
        }
        section_ranges.emplace_back(section.virtual_address, end);
    }
    auto hdr_res = space.reserve_region(base, hdr_pages, "pe-headers");
    if (!hdr_res.ok()) return Ret(hdr_res.errc(), hdr_res.context());
    reserved_vas.push_back(base);
    auto header_type = space.set_region_type(base, VmRegionType::Image);
    if (!header_type.ok()) {
        rollback();
        return Ret(header_type.errc(), header_type.context());
    }
    auto commit_hdr = space.commit_region(base);
    if (!commit_hdr.ok()) {
        rollback();
        return Ret(commit_hdr.errc(), commit_hdr.context());
    }
    auto hdr_dst = space.translate(base);
    if (!hdr_dst.ok()) {
        rollback();
        return Ret(hdr_dst.errc(), hdr_dst.context());
    }
    if (img.opt.size_of_headers > file_size) {
        rollback();
        return Ret(RuntimeErrc::InvalidArgument,
                   "SizeOfHeaders exceeds file size (validation gap)");
    }
    std::memcpy(hdr_dst.value(), file,
                static_cast<std::size_t>(img.opt.size_of_headers));
    layout.headers_region_xbox_va = base;
    layout.headers_region_size = hdr_pages;

    // ── sections: one region each (protection granularity) ──
    for (const auto& s : img.sections) {
        if (s.virtual_address % space.page_size() != 0) {
            rollback();
            return Ret(RuntimeErrc::InvalidArgument,
                       "section RVA not page-aligned: " + s.name);
        }
        const std::uint64_t vs = std::max<std::uint64_t>(s.virtual_size,
                                                         s.size_of_raw_data);
        const std::uint64_t pages =
            (vs + space.page_size() - 1) / space.page_size() * space.page_size();
        if (pages == 0) continue;  // degenerate zero-size section entry
        const std::uint64_t sva = base + s.virtual_address;
        auto res = space.reserve_region(sva, pages, "sect-" + s.name);
        if (!res.ok()) {
            rollback();
            return Ret(res.errc(), res.context());
        }
        reserved_vas.push_back(sva);
        auto section_type = space.set_region_type(sva, VmRegionType::Image);
        if (!section_type.ok()) {
            rollback();
            return Ret(section_type.errc(), section_type.context());
        }
        auto com = space.commit_region(sva);
        if (!com.ok()) {
            rollback();
            return Ret(com.errc(), com.context());
        }
        auto dst = space.translate(sva);
        if (!dst.ok()) {
            rollback();
            return Ret(dst.errc(), dst.context());
        }
        // Zero the whole region (zero-fill guarantee), then copy raw data
        // (bounded by the file and by the region).
        std::memset(dst.value(), 0, static_cast<std::size_t>(pages));
        if (s.has_raw_data) {
            std::uint64_t copy = s.size_of_raw_data;
            if (s.raw_data_offset + copy > file_size) {
                rollback();
                return Ret(RuntimeErrc::InvalidArgument,
                           "section raw data exceeds file (validation gap)");
            }
            if (copy > pages) copy = pages;
            std::memcpy(static_cast<std::uint8_t*>(dst.value()),
                        file + s.raw_data_offset,
                        static_cast<std::size_t>(copy));
        }
        SectionLayout sl;
        sl.name = s.name;
        sl.rva = s.virtual_address;
        sl.virtual_size = s.virtual_size;
        sl.raw_size = s.size_of_raw_data;
        sl.mapped_base = sva;
        sl.mapped_size = pages;
        sl.protection = pe_section_protection(s.characteristics);
        sl.file_backed = s.has_raw_data;
        layout.sections.push_back(std::move(sl));
    }

    // ── final protections (staging RW → final mask) ──
    // Sections map as RW at commit; now protect to their final mask.
    // W+X requests degrade to RW (documented, never RWX).
    for (auto& sl : layout.sections) {
        const MemProtect final_prot =
            sl.protection == MemProtect::Full ? MemProtect::ReadWrite
                                               : sl.protection;
        if (final_prot != MemProtect::ReadWrite) {
            auto pr = space.protect_region(sl.mapped_base, final_prot);
            if (!pr.ok()) {
                rollback();
                return Ret(pr.errc(), pr.context());
            }
        }
        sl.protection = final_prot;
    }
    // Headers: ReadOnly after the copy (validation data only).
    {
        auto pr = space.protect_region(base, MemProtect::ReadOnly);
        if (!pr.ok()) {
            rollback();
            return Ret(pr.errc(), pr.context());
        }
    }
    return Ret(std::move(layout));
}

// ── relocations application ──────────────────────────────────────────────

Result<std::uint64_t> ImageLoader::apply_relocations(
    AddressSpace& space, const ImageLayoutInfo& layout, const pe::PeImage& img,
    const std::uint8_t* file, std::size_t file_size, LoadDiagnostics& diag) {
    using Ret = Result<std::uint64_t>;
    auto blocks = decode_relocations(img, file, file_size,
                                      limits_.max_relocations);
    if (!blocks.ok()) return Ret(blocks.errc(), blocks.context());

    // Validate every relocation type before touching memory. A late
    // unsupported entry must not leave earlier DIR64 entries applied.
    for (const auto& blk : blocks.value()) {
        for (const auto& e : blk.entries) {
            if (e.type != RelocType::Absolute && e.type != RelocType::Dir64) {
                return Ret(RuntimeErrc::PlatformUnsupported,
                           std::string("unsupported relocation type: ") +
                               reloc_type_to_name(e.type) +
                               " (rejected, not skipped)");
            }
        }
    }

    // Relocation writes need page RW; sections were protected final in
    // map_image. Flip each affected section to RW, apply, restore.
    std::vector<std::pair<std::uint64_t, MemProtect>> flipped;
    std::uint64_t applied = 0;
    for (const auto& blk : blocks.value()) {
        for (const auto& e : blk.entries) {
            if (e.type == RelocType::Absolute) continue;  // padding
            if (e.type != RelocType::Dir64) {
                return Ret(RuntimeErrc::PlatformUnsupported,
                           std::string("unsupported relocation type: ") +
                               reloc_type_to_name(e.type) +
                               " (rejected, not skipped)");
            }
            // The full 8-byte target must be within the image and ONE
            // mapped section. Validate the RVA before adding the image base.
            if (e.target_rva > img.opt.size_of_image ||
                img.opt.size_of_image - e.target_rva < 8 ||
                layout.actual_base > (~0ull) - e.target_rva) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "relocation target RVA outside the image");
            }
            const SectionLayout* host = nullptr;
            const std::uint64_t target_va = layout.actual_base + e.target_rva;
            if (target_va > (~0ull) - 8) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "relocation target VA overflows");
            }
            for (const auto& sl : layout.sections) {
                if (target_va >= sl.mapped_base &&
                    target_va - sl.mapped_base <= sl.mapped_size &&
                    8 <= sl.mapped_size - (target_va - sl.mapped_base)) {
                    host = &sl;
                    break;
                }
            }
            if (host == nullptr) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "relocation target not fully inside a mapped section");
            }
            const bool writable_now =
                host->protection == MemProtect::ReadWrite ||
                host->protection == MemProtect::Full;
            if (!writable_now) {
                auto pr = space.protect_region(host->mapped_base,
                                               MemProtect::ReadWrite);
                if (!pr.ok()) return Ret(pr.errc(), pr.context());
                flipped.emplace_back(host->mapped_base, host->protection);
            }
            std::string err;
            if (!apply_dir64(space, target_va, layout.delta,
                             layout.delta_negative, err)) {
                return Ret(RuntimeErrc::InvalidArgument, err);
            }
            ++applied;
        }
    }
    // Restore flipped protections (reverse order).
    for (auto it = flipped.rbegin(); it != flipped.rend(); ++it) {
        auto pr = space.protect_region(it->first, it->second);
        if (!pr.ok()) return Ret(pr.errc(), pr.context());
    }
    diag.relocations_applied = applied;
    diag.relocations_total = applied;
    return Ret(applied);
}

// ── import resolution ─────────────────────────────────────────────────────

Result<std::vector<ImportBinding>> ImageLoader::resolve_imports(
    AddressSpace& space, const ImageLayoutInfo& layout, const pe::PeImage& img,
    const std::uint8_t* file, std::size_t file_size, IImportResolver& resolver,
    LoadDiagnostics& diag) {
    using Ret = Result<std::vector<ImportBinding>>;
    (void)space;
    (void)layout;
    (void)diag;

    std::vector<ImportBinding> bindings;
    if (img.directories.size() <= pe::kDirImport) return Ret(std::move(bindings));
    const auto& dir = img.directories[pe::kDirImport];
    if (dir.size == 0) return Ret(std::move(bindings));

    bool ok = false;
    std::uint64_t desc_off = checked_rva_to_offset(img, dir.rva, ok);
    if (!ok) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "import directory RVA not file-backed");
    }
    std::uint64_t desc_end = 0;
    if (!add_ok(desc_off, dir.size, desc_end) || desc_end > file_size) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "import directory exceeds file bounds");
    }

    const FileReader rd{file, file_size};
    std::size_t total = 0;
    bool descriptor_terminated = false;
    for (std::uint64_t d = desc_off; d <= desc_end && desc_end - d >= 20;
         d += 20) {
        std::uint32_t int_rva = 0, name_rva = 0, iat_rva = 0;
        if (!rd.u32(d + 0, int_rva) || !rd.u32(d + 12, name_rva) ||
            !rd.u32(d + 16, iat_rva)) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "import descriptor read failure");
        }
        if (int_rva == 0 && name_rva == 0 && iat_rva == 0) {
            descriptor_terminated = true;
            break;
        }
        if (++total > limits_.max_imports) {
            return Ret(RuntimeErrc::OutOfResources, "import count exceeds limit");
        }

        // DLL name.
        std::uint64_t name_off = 0;
        bool nok = false;
        name_off = checked_rva_to_offset(img, name_rva, nok);
        std::string dll;
        if (!nok || !read_cstr(file, file_size, name_off, kMaxImportNameLen, dll)) {
            ImportBinding b;
            b.status = ImportStatus::Invalid;
            b.note = "DLL name missing, over-long, or not file-backed";
            bindings.push_back(std::move(b));
            continue;
        }

        // Thunk table: INT preferred; bound images (INT == 0) use the IAT.
        const std::uint32_t thunk_rva = int_rva != 0 ? int_rva : iat_rva;
        if (thunk_rva == 0) {
            ImportBinding b;
            b.lookup.dll = dll;
            b.status = ImportStatus::Invalid;
            b.note = "descriptor has no thunk table";
            bindings.push_back(std::move(b));
            continue;
        }
        std::uint64_t t_off = 0;
        bool tok = false, iok = false;
        t_off = checked_rva_to_offset(img, thunk_rva, tok);
        const std::uint64_t iat_off = checked_rva_to_offset(img, iat_rva, iok);
        if (!tok || !iok || iat_off == 0) {
            ImportBinding b;
            b.lookup.dll = dll;
            b.status = ImportStatus::Invalid;
            b.note = "thunk/IAT table not file-backed";
            bindings.push_back(std::move(b));
            continue;
        }
        const bool module_ok = resolver.resolve_module(dll);

        // Walk thunk entries (8 bytes, PE32+). IAT slot k of this DLL is
        // iat_off + k*8 in the FILE; its RVA is iat_rva + k*8 (the IAT
        // array mirrors the INT order), so its Xbox VA is
        // layout.actual_base + iat_rva + k*8.
        std::uint64_t k = 0;
        bool thunk_terminated = false;
        for (std::uint64_t t = t_off;
             t <= file_size && file_size - t >= 8; t += 8) {
            std::uint64_t tv = 0;
            if (!rd.u64(t, tv)) {
                return Ret(RuntimeErrc::InvalidArgument, "thunk read failure");
            }
            if (tv == 0) {
                thunk_terminated = true;
                break;
            }
            if (++total > limits_.max_imports) {
                return Ret(RuntimeErrc::OutOfResources,
                           "import count exceeds limit");
            }
            if (k > (~0ull) / 8) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "IAT slot index overflows");
            }
            std::uint64_t slot_rva = 0;
            if (!add_ok(iat_rva, k * 8, slot_rva) ||
                slot_rva > img.opt.size_of_image ||
                img.opt.size_of_image - slot_rva < 8 ||
                layout.actual_base > (~0ull) - slot_rva) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "IAT slot lies outside the image");
            }
            bool slot_file_ok = false;
            (void)checked_rva_to_offset(img, static_cast<std::uint32_t>(slot_rva),
                                        slot_file_ok);
            if (!slot_file_ok) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "IAT slot is not file-backed");
            }
            const std::uint64_t slot_va = layout.actual_base + slot_rva;
            ImportLookup look;
            look.dll = dll;
            if ((tv & 0x8000000000000000ull) != 0) {
                look.by_ordinal = true;
                look.ordinal = static_cast<std::uint32_t>(tv & 0xFFFF);
            } else {
                if (tv > UINT32_MAX) {
                    ImportBinding b;
                    b.lookup = look;
                    b.status = ImportStatus::Invalid;
                    b.note = "import-by-name RVA exceeds 32 bits";
                    b.iat_va = slot_va;
                    bindings.push_back(std::move(b));
                    ++k;
                    continue;
                }
                bool xok = false;
                const std::uint64_t hn_off =
                    checked_rva_to_offset(img, static_cast<std::uint32_t>(tv), xok);
                std::uint64_t symbol_off = 0;
                // Skip the 2-byte hint; read the name.
                if (!xok || !add_ok(hn_off, 2, symbol_off) ||
                    !read_cstr(file, file_size, symbol_off, kMaxImportNameLen,
                               look.symbol)) {
                    ImportBinding b;
                    b.lookup = look;
                    b.status = ImportStatus::Invalid;
                    b.note = "import name not file-backed or over-long";
                    b.iat_va = slot_va;
                    bindings.push_back(std::move(b));
                    ++k;
                    continue;
                }
            }
            ImportBinding b;
            if (module_ok) {
                b = resolver.resolve(look);
            } else {
                b.lookup = look;
                b.status = ImportStatus::Unsupported;
                b.note = "resolver rejected the module (unknown DLL)";
            }
            b.iat_va = slot_va;
            bindings.push_back(std::move(b));
            ++k;
        }
        if (!thunk_terminated) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "import thunk table lacks an in-bounds terminator");
        }
    }
    if (!descriptor_terminated) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "import descriptor table lacks an in-bounds terminator");
    }
    return Ret(std::move(bindings));
}

// Write resolved bindings into the mapped IAT slots (RW flip + restore).
Result<void> ImageLoader::write_iat_slots(
    AddressSpace& space, const ImageLayoutInfo& layout,
    const std::vector<ImportBinding>& bindings) {
    using Ret = Result<void>;
    std::vector<std::pair<std::uint64_t, MemProtect>> flipped;
    struct RestoreOnExit {
        AddressSpace& space;
        std::vector<std::pair<std::uint64_t, MemProtect>>& regions;
        ~RestoreOnExit() {
            for (auto it = regions.rbegin(); it != regions.rend(); ++it) {
                (void)space.protect_region(it->first, it->second);
            }
        }
    } restore_on_error{space, flipped};

    for (const auto& b : bindings) {
        if (b.status != ImportStatus::Resolved) continue;
        if (b.iat_va == 0) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "resolved import missing its IAT slot VA");
        }
        const SectionLayout* host = nullptr;
        for (const auto& sl : layout.sections) {
            if (b.iat_va >= sl.mapped_base) {
                const std::uint64_t offset = b.iat_va - sl.mapped_base;
                if (offset <= sl.mapped_size && 8 <= sl.mapped_size - offset) {
                    host = &sl;
                    break;
                }
            }
        }
        if (host == nullptr) {
            // Headers are read-only after mapping; temporarily make the
            // header region writable for a headers-resident IAT slot.
            if (b.iat_va >= layout.actual_base) {
                const std::uint64_t offset = b.iat_va - layout.actual_base;
                if (offset <= layout.headers_region_size &&
                    8 <= layout.headers_region_size - offset) {
                    const auto already = std::find_if(
                        flipped.begin(), flipped.end(),
                        [&](const auto& x) {
                            return x.first == layout.headers_region_xbox_va;
                        });
                    if (already == flipped.end()) {
                        auto pr = space.protect_region(
                            layout.headers_region_xbox_va, MemProtect::ReadWrite);
                        if (!pr.ok()) return Ret(pr.errc(), pr.context());
                        flipped.emplace_back(layout.headers_region_xbox_va,
                                             MemProtect::ReadOnly);
                    }
                    auto dst = space.translate(b.iat_va);
                    if (!dst.ok()) return Ret(dst.errc(), dst.context());
                    std::memcpy(dst.value(), &b.value, 8);
                    continue;
                }
            }
            return Ret(RuntimeErrc::InvalidArgument,
                       "IAT slot VA outside the mapped image");
        }
        const bool writable_now =
            host->protection == MemProtect::ReadWrite ||
            host->protection == MemProtect::Full;
        if (!writable_now) {
            const auto already = std::find_if(
                flipped.begin(), flipped.end(),
                [&](const auto& x) { return x.first == host->mapped_base; });
            if (already == flipped.end()) {
                auto pr = space.protect_region(host->mapped_base,
                                               MemProtect::ReadWrite);
                if (!pr.ok()) return Ret(pr.errc(), pr.context());
                flipped.emplace_back(host->mapped_base, host->protection);
            }
        }
        auto dst = space.translate(b.iat_va);
        if (!dst.ok()) return Ret(dst.errc(), dst.context());
        std::memcpy(dst.value(), &b.value, 8);
    }
    // Restore (reverse order). The scope guard retries restoration if a
    // failure path returns before this point.
    for (auto it = flipped.rbegin(); it != flipped.rend(); ++it) {
        auto pr = space.protect_region(it->first, it->second);
        if (!pr.ok()) return Ret(pr.errc(), pr.context());
    }
    flipped.clear();
    return Ret::ok_result();
}

// ── TLS ──────────────────────────────────────────────────────────────────

Result<std::optional<TlsInfo>> decode_tls(const pe::PeImage& img,
                                          const std::uint8_t* file,
                                          std::size_t file_size,
                                          LoadDiagnostics& diag) {
    using Ret = Result<std::optional<TlsInfo>>;
    if (img.directories.size() <= pe::kDirTls) return Ret(std::nullopt);
    const auto& dir = img.directories[pe::kDirTls];
    if (dir.size == 0) return Ret(std::nullopt);
    // IMAGE_TLS_DIRECTORY64 is 40 bytes (four 64-bit VAs and two DWORDs).
    if (dir.size < 40) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "TLS directory smaller than 40 bytes (PE32+)");
    }
    bool ok = false;
    const std::uint64_t off = checked_rva_to_offset(img, dir.rva, ok);
    if (!ok) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "TLS directory RVA not file-backed");
    }
    if (off > file_size || file_size - off < 40) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "TLS directory truncated in file");
    }
    const FileReader rd{file, file_size};
    std::uint64_t start_va = 0, end_va = 0, idx_va = 0, cb_va = 0;
    std::uint32_t zero_fill = 0;
    if (!rd.u64(off + 0, start_va) || !rd.u64(off + 8, end_va) ||
        !rd.u64(off + 16, idx_va) || !rd.u64(off + 24, cb_va) ||
        !rd.u32(off + 32, zero_fill)) {
        return Ret(RuntimeErrc::InvalidArgument, "TLS directory read failure");
    }
    const std::uint64_t image_base = img.opt.image_base;
    const std::uint64_t image_size = img.opt.size_of_image;
    std::uint64_t start_rva = 0, end_rva = 0;
    if (start_va == 0 && end_va == 0) {
        // A zero-length TLS template is valid.
    } else {
        if (start_va < image_base || end_va < image_base || end_va < start_va) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS template VAs are outside the image or reversed");
        }
        const std::uint64_t raw_template_size = end_va - start_va;
        if (raw_template_size > kMaxTlsTemplate) {
            return Ret(RuntimeErrc::OutOfResources,
                       "TLS raw template exceeds the limit");
        }
        start_rva = start_va - image_base;
        end_rva = end_va - image_base;
        if (start_rva > image_size || end_rva > image_size) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS template range exceeds the image");
        }
    }
    TlsInfo info;
    info.present = true;
    info.raw_data_start_rva = start_rva;
    info.raw_data_end_rva = end_rva;
    info.template_size = end_rva - start_rva;
    info.template_rva = start_rva;
    if (idx_va != 0) {
        if (idx_va < image_base) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS index VA is below the image base");
        }
        const std::uint64_t index_rva = idx_va - image_base;
        if (index_rva > image_size || image_size - index_rva < 4) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS index slot lies outside the image");
        }
        info.index_slot_rva = static_cast<std::uint32_t>(index_rva);
    }
    info.callbacks_va = cb_va;
    info.zero_fill_size = zero_fill;
    // The raw template is file-backed and decoded here. Zero-fill is
    // metadata only; enforce the combined allocation limit when a thread's
    // TLS block is actually created, not while decoding the image.
    if (info.template_size != 0) {
        bool start_ok = false, end_ok = false;
        (void)checked_rva_to_offset(img, static_cast<std::uint32_t>(start_rva),
                                    start_ok);
        (void)checked_rva_to_offset(img, static_cast<std::uint32_t>(end_rva - 1),
                                    end_ok);
        if (!start_ok || !end_ok) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS template is not fully file-backed");
        }
    }
    // Callback count (bounded walk; callbacks are NEVER executed).
    std::uint32_t cbs = 0;
    if (cb_va != 0) {
        if (cb_va < image_base) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS callback-array VA is below the image base");
        }
        const std::uint64_t cb_rva = cb_va - image_base;
        if (cb_rva > image_size || image_size - cb_rva < 8) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS callback-array pointer lies outside the image");
        }
        bool cok = false;
        std::uint64_t p = checked_rva_to_offset(
            img, static_cast<std::uint32_t>(cb_rva), cok);
        if (!cok) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS callback array is not file-backed");
        }
        bool terminated = false;
        while (p <= file_size && file_size - p >= 8) {
            if (cbs == 64) {
                return Ret(RuntimeErrc::OutOfResources,
                           "TLS callback count exceeds 64");
            }
            std::uint64_t cb = 0;
            if (!rd.u64(p, cb)) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "TLS callback entry is truncated");
            }
            if (cb == 0) {
                terminated = true;
                break;
            }
            if (cb < image_base || cb - image_base >= image_size) {
                return Ret(RuntimeErrc::InvalidArgument,
                           "TLS callback VA lies outside the image");
            }
            ++cbs;
            p += 8;
        }
        if (!terminated) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "TLS callback array lacks an in-bounds terminator");
        }
    }
    info.callback_count = cbs;
    diag.tls_callbacks = cbs;
    diag.has_tls = true;
    diag.tls_template_size = info.template_size;
    return Ret(info);
}

// ── loaded image object ──────────────────────────────────────────────────

TypeId LoadedImageObject::static_type_id() {
    // Built-in MemoryRegion id: fits the 9-bit handle type field (user
    // ids >= 512 truncate — see the header note). as<T> double-validates.
    return TypeId::MemoryRegion;
}

LoadedImageObject::LoadedImageObject(std::string image_name,
                                     ImageLayoutInfo layout, LoadDiagnostics diag)
    : RuntimeObject(static_type_id()),
      image_name_(std::move(image_name)),
      layout_(std::move(layout)),
      diag_(std::move(diag)) {}

Result<void> LoadedImageObject::unload(AddressSpace& space) {
    const LoadState s = state_.load(std::memory_order_acquire);
    if (s == LoadState::Unloaded) {
        return Result<void>(RuntimeErrc::InvalidState, "already unloaded");
    }
    // Exact reverse of the mapping order: sections (reverse), then headers.
    for (auto it = layout_.sections.rbegin(); it != layout_.sections.rend(); ++it) {
        (void)space.release_region(it->mapped_base);
    }
    if (layout_.headers_region_xbox_va != 0) {
        (void)space.release_region(layout_.headers_region_xbox_va);
    }
    state_.store(LoadState::Unloaded, std::memory_order_release);
    return Result<void>::ok_result();
}

// ── lifecycle ───────────────────────────────────────────────────────────

Result<Handle> ImageLoader::load_image(ProcessManager& pm, ObjectManager& mgr,
                                      Handle process, const pe::PeImage& img,
                                      const std::uint8_t* file,
                                      std::size_t file_size,
                                      IImportResolver* resolver,
                                      LoadDiagnostics& diag, LoadResult& out) {
    using Ret = Result<Handle>;
    out = LoadResult{};

    // Resolve the process (handle validation up front).
    RefGuard guard;
    ManagedProcess* proc = nullptr;
    {
        auto found = pm.find_process(process);
        if (!found.ok()) return Ret(found.errc(), found.context());
        auto* mp = found.value().get()->as<ManagedProcess>();
        if (mp == nullptr) {
            return Ret(RuntimeErrc::ObjectTypeMismatch, "not a managed process");
        }
        proc = mp;
    }
    AddressSpace& space = proc->address_space();

    // 1. Validate (nothing allocated yet).
    out.final_state = LoadState::Validating;
    const auto rep = validate_image(img, file, file_size);
    if (!rep.valid) {
        out.final_state = LoadState::Failed;
        out.error = rep.issues.empty()
                        ? "validation failed"
                        : rep.issues.front().code + ": " +
                              rep.issues.front().message;
        return Ret(RuntimeErrc::InvalidArgument, out.error);
    }
    out.exec.validated = true;

    // 2. Map.
    out.final_state = LoadState::Allocating;
    auto layout = map_image(space, img, file, file_size, /*want_base=*/0, diag);
    if (!layout.ok()) {
        out.final_state = LoadState::Failed;
        out.error = layout.error_string();
        return Ret(layout.errc(), layout.context());
    }
    out.layout = layout.value();
    out.exec.mapped = true;

    // 3. Relocate (only when moved; DIR64 with delta 0 is a no-op).
    out.final_state = LoadState::Relocating;
    if (out.layout.relocated && out.layout.delta != 0) {
        auto rel = apply_relocations(space, out.layout, img, file, file_size, diag);
        if (!rel.ok()) {
            rollback_regions(space, region_list(out.layout));
            out.final_state = LoadState::Failed;
            out.error = rel.error_string();
            return Ret(rel.errc(), rel.context());
        }
        out.exec.relocations_applied = rel.value();
    }
    out.exec.relocated = true;

    // 4. Imports.
    out.final_state = LoadState::ResolvingImports;
    std::vector<ImportBinding> bindings;
    if (resolver != nullptr) {
        auto bres = resolve_imports(space, out.layout, img, file, file_size,
                                    *resolver, diag);
        if (!bres.ok()) {
            rollback_regions(space, region_list(out.layout));
            out.final_state = LoadState::Failed;
            out.error = bres.error_string();
            return Ret(bres.errc(), bres.context());
        }
        bindings = std::move(bres.value());

        // The PE parser also retains a bounded, normalized import view.
        // Prefer the raw thunk walk above, but fall back to that parsed view
        // when the directory is present and the raw walker yields no entries.
        // This keeps a structurally parsed import table from being silently
        // treated as an image with no imports.
    } else if (img.imports.present) {
        // No resolver: enumerate via M1 metadata as Unresolved (explicit;
        // loading then fails below when imports exist — never a silent 0).
        for (const auto& e : img.imports.entries) {
            for (const auto& f : e.functions) {
                ImportBinding b;
                b.lookup.dll = e.dll_name;
                b.lookup.symbol = f;
                b.status = ImportStatus::Unresolved;
                b.note = "no resolver supplied";
                bindings.push_back(std::move(b));
            }
            for (std::uint32_t ord : e.ordinal_only) {
                ImportBinding b;
                b.lookup.dll = e.dll_name;
                b.lookup.ordinal = ord;
                b.lookup.by_ordinal = true;
                b.status = ImportStatus::Unresolved;
                b.note = "no resolver supplied";
                bindings.push_back(std::move(b));
            }
        }
    }

    std::uint64_t resolved_n = 0, unresolved_n = 0, unsupported_n = 0, invalid_n = 0;
    for (const auto& b : bindings) {
        switch (b.status) {
            case ImportStatus::Resolved: ++resolved_n; break;
            case ImportStatus::Unresolved: ++unresolved_n; break;
            case ImportStatus::Unsupported: ++unsupported_n; break;
            case ImportStatus::Invalid: ++invalid_n; break;
        }
    }
    diag.imports = bindings;
    out.exec.imports_resolved = resolved_n;
    out.exec.imports_unresolved = unresolved_n;
    out.exec.imports_unsupported = unsupported_n;
    out.exec.imports_invalid = invalid_n;
    // Empty binding list with a resolver: fine (image has no imports);
    // all four counters are 0 — imports_resolved_all stays true.

    // Write IAT values for resolved bindings.
    if (resolved_n > 0) {
        auto wr = write_iat_slots(space, out.layout, bindings);
        if (!wr.ok()) {
            rollback_regions(space, region_list(out.layout));
            out.final_state = LoadState::Failed;
            out.error = wr.error_string();
            return Ret(wr.errc(), wr.context());
        }
    }

    // Required-import rule: an image WITH imports must have them all
    // resolved to reach Prepared (unresolved imports fail loading —
    // explicit, never faked as success).
    if (!bindings.empty() && resolved_n != bindings.size()) {
        rollback_regions(space, region_list(out.layout));
        out.final_state = LoadState::Failed;
        out.error = "imports not fully resolved: " +
                    std::to_string(bindings.size() - resolved_n) + " of " +
                    std::to_string(bindings.size()) +
                    " unresolved/unsupported/invalid";
        return Ret(RuntimeErrc::MissingDependency, out.error);
    }
    out.exec.imports_resolved_all = true;

    // 5. TLS metadata (validation + reporting; never executed).
    auto tls = decode_tls(img, file, file_size, diag);
    if (!tls.ok()) {
        rollback_regions(space, region_list(out.layout));
        out.final_state = LoadState::Failed;
        out.error = tls.error_string();
        return Ret(tls.errc(), tls.context());
    }
    if (tls.value().has_value()) {
        // Synthetic TLS index (deterministic per process; documented as a
        // runtime bookkeeping id, NOT an Xbox TLS-slot reproduction).
        diag.tls_index_assigned = true;
        diag.tls_index = static_cast<std::uint32_t>(space.space_id() & 0xFFFF);
        out.exec.tls_present = true;
        diag.unsupported.push_back(
            {"per-thread TLS initialization",
             "thread model has per-thread slots but no image-template copy "
             "path; reported unsupported (callbacks counted, never run)"});
    }

    // 6. Prepare.
    out.final_state = LoadState::Preparing;
    auto prepared = prepare_exec(space, out.layout, out.exec, diag);
    if (!prepared.ok()) {
        rollback_regions(space, region_list(out.layout));
        out.final_state = LoadState::Failed;
        out.error = prepared.error_string();
        return Ret(prepared.errc(), prepared.context());
    }
    out.exec = prepared.value();
    out.final_state = LoadState::Prepared;
    out.ok = true;

    // 7. Register the loaded image as a runtime object; a process-table
    // handle owns it (termination close_all → destroy → regions stay
    // released by terminate's release_all; the object's unload is the
    // explicit path).
    auto obj = std::make_unique<LoadedImageObject>(img.source_name, out.layout,
                                                   diag);
    obj->set_exec(out.exec);
    auto reg = mgr.register_object(std::move(obj));
    if (!reg.ok()) {
        rollback_regions(space, region_list(out.layout));
        out.final_state = LoadState::Failed;
        out.error = reg.error_string();
        return Ret(reg.errc(), reg.context());
    }
    auto found = mgr.lookup_id(reg.value());
    auto* lo = found.ok() ? found.value().get()->as<LoadedImageObject>() : nullptr;
    if (lo == nullptr) {
        (void)mgr.destroy(reg.value());
        rollback_regions(space, region_list(out.layout));
        out.final_state = LoadState::Failed;
        out.error = "loaded-image registration failed";
        return Ret(RuntimeErrc::InvalidState, out.error);
    }
    lo->set_name(img.source_name);
    auto hd = proc->handle_table().create_with_rights(
        *lo, AccessRights::Read | AccessRights::Close, false);
    if (!hd.ok()) {
        (void)mgr.destroy(reg.value());
        rollback_regions(space, region_list(out.layout));
        out.final_state = LoadState::Failed;
        out.error = hd.error_string();
        return Ret(hd.errc(), hd.context());
    }
    return Ret(hd.value());
}

namespace {
// Unload-image sentinel ids (distinct failure markers; 0 is a VALID object
// id so sentinels use impossible id values instead).
constexpr std::uint64_t kNoImageId = 0xFFFFFFFFFFFFFFFFull;
constexpr std::uint64_t kErrSentinel = 0xFFFFFFFFFFFFFFFEull;
}  // namespace

Result<void> ImageLoader::unload_image(ProcessManager& pm, ObjectManager& mgr,
                                      Handle process, Handle image) {
    // Resolve the process, then the image handle in ITS table.
    auto found = pm.find_process(process);
    if (!found.ok()) return Result<void>(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr) {
        return Result<void>(RuntimeErrc::ObjectTypeMismatch,
                            "not a managed process");
    }
    auto lo = resolve_loaded_image(mgr, *proc, image);
    if (!lo.ok()) return Result<void>(lo.errc(), lo.context());
    // Read what we need WITHOUT holding the guard during close/destroy:
    // ObjectManager::destroy drains pins before erasure, so a live guard
    // self-deadlocks (found in the M6 smoke run). Snapshot id + state,
    // release the pin, then close + destroy.
    {
        RefGuard guard = std::move(lo.value());
        auto* obj = guard.get()->as<LoadedImageObject>();
        if (obj == nullptr) {
            return Result<void>(RuntimeErrc::ObjectTypeMismatch,
                                "not a loaded image");
        }
        if (obj->state() == LoadState::Unloaded) {
            // Only the handle teardown remains.
            guard.release();
            auto close = proc->handle_table().close(image);
            if (!close.ok()) return close;
            return Result<void>::ok_result();
        }
    }
    // Re-pin briefly for the unload call (releasing before destroy below).
    auto lo2 = resolve_loaded_image(mgr, *proc, image);
    if (!lo2.ok()) return Result<void>(lo2.errc(), lo2.context());
    const std::uint64_t obj_id = [&]() {
        RefGuard guard = std::move(lo2.value());
        auto* obj = guard.get()->as<LoadedImageObject>();
        if (obj == nullptr) return kNoImageId;
        const std::uint64_t id = obj->id();
            auto un = obj->unload(proc->address_space());
            return un.ok() ? id : kErrSentinel;
    }();
    if (obj_id == kNoImageId) {
        return Result<void>(RuntimeErrc::ObjectTypeMismatch, "not a loaded image");
    }
    if (obj_id == kErrSentinel) {
        return Result<void>(RuntimeErrc::InvalidState, "unload failed");
    }
    // Close the handle and destroy the object (exactly once). No guard is
    // held here — the drain cannot self-deadlock.
    auto close = proc->handle_table().close(image);
    if (!close.ok()) return close;
    auto destroy = mgr.destroy(obj_id);
    if (!destroy.ok()) return destroy;
    return Result<void>::ok_result();
}

Result<RefGuard> resolve_loaded_image(ObjectManager&,
                                      const ManagedProcess& proc, Handle image) {
    using Ret = Result<RefGuard>;
    auto lk = proc.handle_table().lookup(image);
    if (!lk.ok()) return Ret(lk.errc(), lk.context());
    RefGuard guard = std::move(lk.value());
    RuntimeObject* obj = guard.get();
    if (obj == nullptr) {
        return Ret(RuntimeErrc::ObjectDestroyed, "image object destroyed");
    }
    if (obj->type_id() != LoadedImageObject::static_type_id()) {
        return Ret(RuntimeErrc::ObjectTypeMismatch,
                   "handle does not reference a loaded image");
    }
    return Ret(std::move(guard));
}

Result<std::vector<ImageLoader::LoadedImageInfo>> ImageLoader::list_images(
    ProcessManager& pm, ObjectManager& mgr, Handle process) {
    using Ret = Result<std::vector<LoadedImageInfo>>;
    auto found = pm.find_process(process);
    if (!found.ok()) return Ret(found.errc(), found.context());
    auto* proc = found.value().get()->as<ManagedProcess>();
    if (proc == nullptr) {
        return Ret(RuntimeErrc::ObjectTypeMismatch, "not a managed process");
    }
    std::vector<LoadedImageInfo> out;
    for (const auto& hi : proc->handle_table().list_handles()) {
        // MemoryRegion-typed handles: validate the dynamic type below
        // (other MemoryRegion users pass the id check but fail as<T>).
        if (hi.type != static_cast<std::uint16_t>(LoadedImageObject::static_type_id())) {
            continue;
        }
        auto lo = mgr.lookup_id(hi.object_id);
        if (!lo.ok() || lo.value().get() == nullptr) continue;
        auto* obj = lo.value().get()->as<LoadedImageObject>();
        if (obj == nullptr) continue;
        LoadedImageInfo info;
        info.handle = hi.handle;
        info.name = obj->name();
        info.state = obj->state();
        info.layout = obj->layout();
        std::uint64_t res = 0, unres = 0;
        for (const auto& b : obj->diagnostics().imports) {
            if (b.status == ImportStatus::Resolved) ++res;
            else ++unres;
        }
        info.imports_resolved = res;
        info.imports_unresolved = unres;
        out.push_back(std::move(info));
    }
    (void)mgr;
    return Ret(std::move(out));
}

void ImageLoader::rollback_regions(AddressSpace& space,
                                   const std::vector<std::uint64_t>& vas) const {
    for (auto it = vas.rbegin(); it != vas.rend(); ++it) {
        (void)space.release_region(*it);
    }
}

// ── execution preparation ────────────────────────────────────────────────

Result<ExecDescription> prepare_exec(AddressSpace& space,
                                     const ImageLayoutInfo& layout,
                                     const ExecDescription& in_progress,
                                     LoadDiagnostics& diag) {
    using Ret = Result<ExecDescription>;
    (void)diag;
    ExecDescription e = in_progress;
    const std::uint64_t entry = layout.actual_base + layout.entry_rva;
    // Containment + section membership + executable protection.
    const SectionLayout* host = nullptr;
    for (const auto& s : layout.sections) {
        if (entry >= s.mapped_base && entry < s.mapped_base + s.mapped_size) {
            host = &s;
            break;
        }
    }
    if (host == nullptr) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "entry point not inside any mapped section");
    }
    if (host->protection != MemProtect::ReadExecute &&
        host->protection != MemProtect::Full) {
        return Ret(RuntimeErrc::InvalidArgument,
                   std::string("entry point section ") + host->name +
                       " is not executable (protection " +
                       mem_protect_to_name(host->protection) + ")");
    }
    // Alignment: x86-64 entry points carry no architectural alignment
    // requirement (variable-length instructions); page-level placement is
    // the only rule and containment covers it. Documented in the docs.
    auto acc = space.validate_access(entry, /*write=*/false, /*exec=*/true);
    if (!acc.ok()) {
        return Ret(acc.errc(), acc.context());
    }
    e.entry_va = entry;
    e.sections = layout.sections;
    e.image_base = layout.actual_base;
    e.image_size = layout.mapped_size;
    e.prepared = true;
    return Ret(std::move(e));
}

}  // namespace xbox2pc::rt::loader
