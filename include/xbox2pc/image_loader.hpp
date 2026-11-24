#pragma once
// xbox2pc/image_loader.hpp — M6 executable loader: PE32+ image validation,
// mapping into an M4 AddressSpace, base relocations, import resolution, TLS
// metadata, and execution preparation.
//
// Design (docs/pe-loader.md):
//   1. Layering: the loader sits ABOVE the M4 memory/process layer and the
//      M1 PE parser; it creates no second manager of anything. Xbox VAs
//      come from the process's AddressSpace (base 0x10000000*(pid%256+1)
//      by default); host pointers exist only as transient staging buffers
//      obtained via AddressSpace::translate() and never leave the loader.
//   2. Validation before allocation: validate_image() performs the full
//      safety check set (machine, magic, alignments, image-size/size-of-
//      -headers consistency, entry-point containment, section raw/virtual
//      range arithmetic with 64-bit checked math, directory bounds,
//      relocation-directory bounds) BEFORE any process memory is touched.
//      It returns a typed report; nothing is mapped on failure.
//   3. Map = build validation FIRST, then reserve+commit+write via the M4
//      AddressSpace (one region per PE section + one for headers).
//      Sections get protections translated from PE characteristics with
//      W^X discipline (see pe_section_protection); the image's pages are
//      first committed RW for staging, then protected to the final mask —
//      a transition AddressSpace already validates.
//   4. Relocations: X64 base-relocation types (ABSOLUTE, HIGHLOW absent in
//      PE32+, DIR64) are decoded from the file-backed image bytes and
//      applied to the staged pages; only then are pages protected final.
//      Unsupported types are REJECTED (never silently skipped).
//   5. Imports: IImportResolver is an EXPLICIT interface. The loader never
//      invents Xbox APIs or binds host functions; a controlled test
//      resolver (StaticResolver) serves synthetic modules for tests/CLI.
//      Resolved/Unresolved/Unsupported/Invalid import states stay distinct.
//   6. TLS: the PE TLS directory is validated and its template/index/
//      callbacks are REPORTED (LoadDiagnostics); callbacks are never called
//      by the loader (M6 exclusion). Per-thread TLS initialization is
//      deferred: the M4 thread model has per-thread slots but no image-
//      template copy path yet — reported as UnsupportedCapability.
//   7. Lifecycle: LoadState machine (Created/Validating/Allocating/
//      Mapping/Relocating/ResolvingImports/Preparing/Prepared/Failed/
//      Unloaded); every failure rolls back ALL reserved regions (exact
//      reverse order); unload_image releases them; process termination
//      cleans up via the M4 ordering (the loader registers itself as a
//      Loaded image object; the process's on_destroy path unloads).
//   8. Execution preparation: prepare_exec() validates entry-point
//      containment + RX (or RWX-with-allow-wx) accessibility + section
//      alignment, and returns an ExecDescription. The loader NEVER starts
//      execution (loading and execution are separate operations).
//
// Xbox framing: general-purpose loading infrastructure; no GTA VI or any
// title-specific assumptions. Confirmed PE format facts follow the
// PE/COFF spec (MS-PELYB); runtime integration is xbox2pc architecture.

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_parser.hpp"
#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/runtime_error.hpp"
#include "xbox2pc/vfs_process.hpp"

namespace xbox2pc::rt::loader {

// ── constants (PE/COFF spec) ───────────────────────────────────────────────

inline constexpr std::uint32_t kMinSectionAlignment = 512u;    // spec floor
inline constexpr std::uint32_t kMinFileAlignment = 512u;
inline constexpr std::uint32_t kMaxSectionAlignment = 0x10000000u;
inline constexpr std::uint32_t kMaxFileAlignment = 0x10000u;
inline constexpr std::size_t kMaxRelocEntries = 1u << 20;      // 1M entries
inline constexpr std::size_t kMaxImports = 4096;
inline constexpr std::size_t kMaxImportNameLen = 512;
inline constexpr std::uint32_t kMaxTlsTemplate = 1u << 20;      // 1 MiB

// Image mapping upper bound: reject images larger than 256 MiB before any
// allocation attempt (resource safety; typical Xbox images are far smaller
// — design bound, not an Xbox claim).
inline constexpr std::uint64_t kMaxImageSize = 256ull << 20;

// ── validation ─────────────────────────────────────────────────────────────

struct ValidationIssue {
    std::string code;       // machine codes below
    std::string message;
};

// Validation error codes (stable strings; CLI + tests match on them).
namespace vcode {
inline constexpr const char* kNotMapped = "not-pe";               // no MZ/PE
inline constexpr const char* kTruncated = "truncated";
inline constexpr const char* kBadSignature = "bad-signature";
inline constexpr const char* kBadMachine = "bad-machine";
inline constexpr const char* kBadOptionalHeader = "bad-optional-header";
inline constexpr const char* kBadAlignment = "bad-alignment";
inline constexpr const char* kImageSizeInconsistent = "image-size-inconsistent";
inline constexpr const char* kEntryOutsideImage = "entry-outside-image";
inline constexpr const char* kEntryBadSection = "entry-bad-section";
inline constexpr const char* kSectionOutsideImage = "section-outside-image";
inline constexpr const char* kSectionRawRange = "section-raw-range";
inline constexpr const char* kSectionOverlap = "section-overlap";
inline constexpr const char* kDirectoryRange = "directory-range";
inline constexpr const char* kRelocDirectory = "reloc-directory";
inline constexpr const char* kImportDirectory = "import-directory";
inline constexpr const char* kTlsDirectory = "tls-directory";
inline constexpr const char* kHeadersSize = "headers-size";
inline constexpr const char* kImageTooLarge = "image-too-large";
inline constexpr const char* kUnalignedImageBase = "unaligned-image-base";
inline constexpr const char* kCharUnsupported = "characteristics-unsupported";
}

struct ValidationReport {
    bool valid = false;
    std::uint64_t size_of_image = 0;      // from the optional header (64-bit)
    std::uint64_t size_of_headers = 0;
    std::uint64_t preferred_base = 0;
    std::uint32_t entry_rva = 0;
    bool needs_relocation = false;         // reloc dir present AND base moved
    bool has_tls_directory = false;
    std::vector<ValidationIssue> issues;   // empty when valid
};

// Full pre-allocation validation of a parsed image against the raw bytes it
// was parsed from (the loader needs the ORIGINAL buffer for section raw
// data + reloc/import decoding). Pure function: no process state touched.
ValidationReport validate_image(const pe::PeImage& img, const std::uint8_t* file,
                                 std::size_t file_size);

// ── import resolution ─────────────────────────────────────────────────────

enum class ImportStatus { Resolved, Unresolved, Unsupported, Invalid };

const char* import_status_to_name(ImportStatus s);

struct ImportLookup {
    std::string dll;             // byte-exact, as imported
    std::string symbol;          // name ("" for ordinal)
    std::uint32_t ordinal = 0;   // 0 when by-name
    bool by_ordinal = false;
};

// One resolved (or not) IAT slot outcome.
struct ImportBinding {
    ImportLookup lookup;
    ImportStatus status = ImportStatus::Unresolved;
    std::uint64_t value = 0;          // the value written into the IAT
    std::string note;                 // resolver-provided detail
    // IAT slot location (filled by resolve_imports when the slot is
    // file-backed; 0 when unknown — write_iat_slots rejects those).
    std::uint64_t iat_va = 0;
};

// The resolver interface. Implementations provide an address value for an
// imported symbol. NO implementation of Xbox GDK/Game OS APIs exists in M6
// (roadmap); resolvers are test/CLI-controlled. Resolvers never receive
// host function pointers as values unless the implementer decides so —
// the loader only writes what the resolver returned.
class IImportResolver {
public:
    virtual ~IImportResolver() = default;

    // Resolve one import. Never called for a DLL the resolver rejected at
    // the module level (resolve_module below).
    virtual ImportBinding resolve(const ImportLookup& lookup) = 0;

    // Module-level gate: called once per distinct DLL before its imports.
    // Returning false marks every entry of that DLL Unsupported and stops
    // per-symbol calls for it (used by the null resolver for unknown DLLs).
    virtual bool resolve_module(const std::string& dll) = 0;
};

// Controlled resolver for synthetic test modules: resolves ONLY the DLLs
// and symbols registered in its tables to deterministic synthetic
// addresses. Everything else is Unresolved (with a note). Deterministic:
// values are derived from a hash of dll+symbol, not from host state.
class StaticResolver : public IImportResolver {
public:
    // Registers a synthetic DLL with named symbols. Each symbol resolves
    // to a deterministic synthetic value (documented: NOT a host address).
    void add_module(std::string dll, std::vector<std::string> symbols);
    // Registers a DLL as ordinal-only (any ordinal resolves).
    void add_ordinal_module(std::string dll);

    ImportBinding resolve(const ImportLookup& lookup) override;
    bool resolve_module(const std::string& dll) override;

private:
    struct Module {
        bool ordinal_only = false;
        std::vector<std::string> symbols;
    };
    std::map<std::string, Module> modules_;
};

// A resolver that refuses everything (module-level gate). Used to prove
// unresolved-import failure paths without any resolver cooperation.
class NullResolver : public IImportResolver {
public:
    ImportBinding resolve(const ImportLookup& lookup) override;
    bool resolve_module(const std::string& dll) override;
};

// ── image layout / mapping result ─────────────────────────────────────────

struct SectionLayout {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t virtual_size = 0;    // header VirtualSize
    std::uint32_t raw_size = 0;        // header SizeOfRawData
    std::uint64_t mapped_base = 0;     // Xbox VA = actual base + rva
    std::uint64_t mapped_size = 0;     // rounded to page, >= virtual_size
    MemProtect protection = MemProtect::NoAccess;
    bool file_backed = false;
};

// Translate PE section characteristics to a memory protection. W^X is
// enforced: writable sections never receive execute; the mapping from the
// PE flags IMAGE_SCN_*_WRITE/READ/EXEC to MemProtect is total (default
// ReadOnly for data with no flags). Returns nullopt for combinations the
// M4 model cannot express safely (none exist today: every combination of
// R/W/X is representable; the function keeps the Option type so a future
// combination cannot silently weaken).
MemProtect pe_section_protection(std::uint32_t characteristics);

struct ImageLayoutInfo {
    std::uint64_t preferred_base = 0;
    std::uint64_t actual_base = 0;         // Xbox VA base of the mapping
    std::uint64_t mapped_size = 0;         // page-rounded total
    std::uint32_t entry_rva = 0;
    std::uint64_t entry_va = 0;            // actual_base + entry_rva
    std::uint64_t headers_region_xbox_va = 0;
    std::uint64_t headers_region_size = 0;
    std::vector<SectionLayout> sections;
    bool relocated = false;                // actual != preferred
    std::uint64_t delta = 0;               // actual - preferred (signed via
                                           // actual>=preferred flag below)
    bool delta_negative = false;
};

// ── load state machine ────────────────────────────────────────────────────

enum class LoadState : std::uint8_t {
    Created, Validating, Allocating, Mapping, Relocating, ResolvingImports,
    Preparing, Prepared, Failed, Unloaded,
};
const char* load_state_to_name(LoadState s);

// ── diagnostics ───────────────────────────────────────────────────────────

struct LoadDiagnostics {
    diag::Diagnostics diags;               // warnings/info reuse M1 model
    std::vector<ImportBinding> imports;    // one entry per IAT slot
    std::uint64_t relocations_applied = 0;
    std::uint64_t relocations_total = 0;
    std::uint32_t tls_callbacks = 0;       // count discovered (never run)
    bool tls_index_assigned = false;       // synthetic index allocation
    std::uint32_t tls_index = 0;
    std::uint64_t tls_template_size = 0;
    std::uint32_t tls_index_slot_rva = 0;
    std::uint32_t tls_zero_fill_size = 0;
    std::vector<std::uint8_t> tls_template_bytes;
    bool has_tls = false;

    // Capabilities the image requested but this runtime cannot express
    // (reported, never faked).
    struct Unsupported {
        std::string capability;
        std::string detail;
    };
    std::vector<Unsupported> unsupported;
};

// ── load result / execution description ───────────────────────────────────

struct ExecDescription {
    std::uint64_t image_base = 0;          // actual Xbox VA base
    std::uint32_t entry_rva = 0;
    std::uint64_t entry_va = 0;
    std::uint64_t image_size = 0;
    std::vector<SectionLayout> sections;
    std::uint64_t imports_resolved = 0;
    std::uint64_t imports_unresolved = 0;
    std::uint64_t imports_unsupported = 0;
    std::uint64_t imports_invalid = 0;
    bool tls_present = false;
    std::uint64_t relocations_applied = 0;
    // Initialization phases that reached completion.
    bool validated = false;
    bool mapped = false;
    bool relocated = false;
    bool imports_resolved_all = false;     // every required import bound
    bool prepared = false;
};

struct LoadResult {
    bool ok = false;
    ImageLayoutInfo layout;
    ExecDescription exec;
    std::string error;                     // non-empty on failure
    LoadState final_state = LoadState::Created;
};

// ── loaded image object (runtime-object integration) ────────────────────────

// A loaded image living in a process's address space, registered as a
// RuntimeObject so handles/generation protection apply and process
// termination can unload it through the standard object teardown.
//
// Type id note: the handle encoding carries a 9-bit type field (M4
// layout), so only built-in ids (< 512) survive round-trips through
// handle tables. Loaded images ARE mapped memory regions, so the class
// reuses TypeId::MemoryRegion (7) — as<T> still double-validates the C++
// dynamic type, and user-type ids > 511 are documented as unusable for
// handle-bearing objects (see docs/pe-loader.md, "object typing").
class LoadedImageObject : public RuntimeObject {
public:
    static TypeId static_type_id();

    LoadedImageObject(std::string image_name, ImageLayoutInfo layout,
                      LoadDiagnostics diag);
    ~LoadedImageObject() override = default;

    const ImageLayoutInfo& layout() const { return layout_; }
    const LoadDiagnostics& diagnostics() const { return diag_; }
    LoadState state() const { return state_.load(std::memory_order_acquire); }
    // Process cleanup path calls this (idempotent, typed).
    Result<void> unload(AddressSpace& space);

    // Execution description (post-prepare snapshot).
    const ExecDescription& exec() const { return exec_; }
    void set_exec(ExecDescription e) { exec_ = std::move(e); }

private:
    void on_destroy() override {}
    const std::string image_name_;
    const ImageLayoutInfo layout_;
    const LoadDiagnostics diag_;
    ExecDescription exec_;
    std::atomic<LoadState> state_{LoadState::Prepared};
};

// ── the loader ─────────────────────────────────────────────────────────────

struct LoaderLimits {
    std::uint64_t max_image_size = kMaxImageSize;
    std::size_t max_relocations = kMaxRelocEntries;
    std::size_t max_imports = kMaxImports;
    bool allow_wx_pages = false;   // mirrors the M4 ResourceLimits flag
};

class ImageLoader {
public:
    // The loader operates on OTHER processes' spaces; it owns nothing
    // global. All host interaction goes through the M4 AddressSpace.
    ImageLoader() = default;

    // ── staged API (each phase independently usable) ──

    // Phase 1: validate (no allocation). Reuses the M1 parse result.
    Result<ValidationReport> validate(const pe::PeImage& img,
                                      const std::uint8_t* file,
                                      std::size_t file_size) const;

    // Phase 2: map sections + headers into a process space. `want_base`
    // overrides the preferred base (pass 0 for preferred); falls back to
    // auto placement when the preferred base is unavailable and the image
    // carries relocations; without relocations a preferred-base conflict
    // is a typed failure.
    Result<ImageLayoutInfo> map_image(AddressSpace& space,
                                      const pe::PeImage& img,
                                      const std::uint8_t* file,
                                      std::size_t file_size,
                                      std::uint64_t want_base,
                                      LoadDiagnostics& diag);

    // Phase 3: apply base relocations to the mapped image (staging RW
    // pages then re-protecting is handled inside map_image's final
    // protect step; relocations run BEFORE final protection, so this
    // phase requires the layout's staging window).
    Result<std::uint64_t> apply_relocations(AddressSpace& space,
                                            const ImageLayoutInfo& layout,
                                            const pe::PeImage& img,
                                            const std::uint8_t* file,
                                            std::size_t file_size,
                                            LoadDiagnostics& diag);

    // Phase 4: resolve imports through an EXPLICIT resolver and write the
    // IAT (page RW during the write, restored after).
    Result<std::vector<ImportBinding>> resolve_imports(
        AddressSpace& space, const ImageLayoutInfo& layout,
        const pe::PeImage& img, const std::uint8_t* file,
        std::size_t file_size, IImportResolver& resolver,
        LoadDiagnostics& diag);

    // ── one-shot lifecycle ──

    // Full load: validate → map → relocate → resolve imports → prepare.
    // On ANY failure rolls back every allocation (exact reverse order)
    // and returns the failed state + error. Registers the loaded image as
    // a RuntimeObject in `mgr` (handle in the process's table) on
    // success. `resolver` may be null: imports then count as Unresolved
    // and loading fails IF the image has any import (required imports are
    // mandatory for a Prepared image; inspection-only use can call the
    // staged APIs instead).
    Result<Handle> load_image(ProcessManager& pm, ObjectManager& mgr,
                              Handle process, const pe::PeImage& img,
                              const std::uint8_t* file, std::size_t file_size,
                              IImportResolver* resolver, LoadDiagnostics& diag,
                              LoadResult& out);

    // Unload by handle (releases image regions from the process space).
    Result<void> unload_image(ProcessManager& pm, ObjectManager& mgr,
                              Handle process, Handle image);

    // List loaded images of a process.
    struct LoadedImageInfo {
        Handle handle;
        std::string name;
        LoadState state;
        ImageLayoutInfo layout;
        std::uint64_t imports_resolved;
        std::uint64_t imports_unresolved;
    };
    Result<std::vector<LoadedImageInfo>> list_images(ProcessManager& pm,
                                                    ObjectManager& mgr,
                                                    Handle process);

    const LoaderLimits& limits() const { return limits_; }
    void set_limits(const LoaderLimits& l) { limits_ = l; }

private:
    // Rollback helper: release regions in reverse reservation order.
    void rollback_regions(AddressSpace& space,
                          const std::vector<std::uint64_t>& vas) const;
    // Write resolved bindings into mapped IAT slots (RW flip + restore).
    Result<void> write_iat_slots(AddressSpace& space,
                                 const ImageLayoutInfo& layout,
                                 const std::vector<ImportBinding>& bindings);
    LoaderLimits limits_;
};

// Resolve an image handle in a process's OWN table to a pinned
// LoadedImageObject (typed errors on mismatch/stale).
Result<RefGuard> resolve_loaded_image(ObjectManager& mgr,
                                      const ManagedProcess& proc, Handle image);

// Execution preparation on an already-loaded image: validates the entry
// point (containment in the mapped image, membership in an executable
// section, accessibility under final protections) and fills the exec
// description. Loading and execution stay separate; nothing is executed.
Result<ExecDescription> prepare_exec(AddressSpace& space,
                                      const ImageLayoutInfo& layout,
                                      const ExecDescription& in_progress,
                                      LoadDiagnostics& diag);

// ── relocation decoding (exposed for direct tests) ────────────────────────

// X64 base-relocation types (PE/COFF spec, IMAGE_REL_BASED_*).
enum class RelocType : std::uint8_t {
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    Dir64 = 10,
    // Everything else: unsupported by this loader (rejected, never
    // skipped silently). Named constants for the common unsupported ones:
    // 5 = Arm Movex64 (x64 N/A), 6 = Reserved, 7 = Reserved,
    // 8 = Reserved, 9 = Reserved, 11.. = ARM64/-specific.
};
const char* reloc_type_to_name(RelocType t);

// One decoded relocation entry (before application).
struct RelocEntry {
    RelocType type = RelocType::Absolute;
    std::uint64_t page_rva = 0;   // owning block's page
    std::uint64_t target_rva = 0; // page_rva + offset
};

// Decoded relocation block listing (bounded by limits.max_relocations).
struct RelocBlock {
    std::uint64_t page_rva = 0;
    std::uint32_t block_size = 0;
    std::vector<RelocEntry> entries;
};

// Decode the relocation directory into blocks. Typed validation of block
// sizes/entry counts/targets happens here (reloc-directory bounds in
// validate_image). Empty when the directory is absent.
Result<std::vector<RelocBlock>> decode_relocations(const pe::PeImage& img,
                                                   const std::uint8_t* file,
                                                   std::size_t file_size,
                                                   std::size_t max_entries);

// ── TLS directory (validation + reporting; no callback execution) ────────

struct TlsInfo {
    bool present = false;
    std::uint64_t raw_data_start_rva = 0;
    std::uint64_t raw_data_end_rva = 0;
    std::uint64_t template_size = 0;   // end - start (file-backed template)
    std::uint64_t template_rva = 0;
    std::uint32_t index_slot_rva = 0;  // StartAddressOfRawData in PE32+ is
                                       // a VA; see decode notes (docs).
    std::uint64_t callbacks_va = 0;
    std::uint32_t callback_count = 0;
    std::uint32_t zero_fill_size = 0;  // SizeOfZeroFill
};

// Decode + validate the TLS directory (PE32+ layout). Reports callbacks
// (count only — never executed). nullopt result = directory absent.
Result<std::optional<TlsInfo>> decode_tls(const pe::PeImage& img,
                                          const std::uint8_t* file,
                                          std::size_t file_size,
                                          LoadDiagnostics& diag);

}  // namespace xbox2pc::rt::loader
