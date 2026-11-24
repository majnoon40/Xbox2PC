#pragma once
// xbox2pc/memory_management.hpp — M4 memory management subsystem.
//
// Design (docs/memory-management.md, docs/address-spaces.md):
//   1. AddressSpace = per-process virtual-memory bookkeeping: a sorted map
//      of non-overlapping VmRegion descriptors over ONE host PAL region
//      (a single mmap per space; subranges get mprotect granularity).
//      Xbox virtual addresses are modeled EXPLICITLY: each space picks a
//      base "Xbox-address" for the mapping model; host pointers never
//      leak through the public interface (translated via region lookup).
//   2. VmRegion = descriptor: xbox_va, size, state (Reserved/Committed),
//      protection (none/R/RW/RX/RWX), name, ownership (alloc id).
//   3. MemoryAllocator = aligned tracked allocations carved from a
//      committed region: per-allocation metadata + usage statistics +
//      limits; failures are typed (OutOfResources/InvalidArgument).
//   4. Protection model: W^X discipline — RWX is never a default; the
//      only way to get RWX is an explicit protect() call, and transitions
//      are validated (Reserved -> Committed -> protect; decommit only
//      when it was committed; Committed regions cannot transition to
//      Reserved without release).
//   5. Isolation: every lookup goes through an AddressSpace; a different
//      process's space cannot resolve another space's addresses.
//
// Confirmed-vs-inferred framing lives in the docs: the mmap/mprotect
// semantics are host (Linux) behavior; region-state modeling is an
// xbox2pc design decision (inferred), NOT Xbox page-table reproduction.

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/platform.hpp"
#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt {

// ── protection model ─────────────────────────────────────────────────────

enum class MemProtect : std::uint8_t {
    NoAccess = 0,  // reserved / PROT_NONE
    ReadOnly,      // R
    ReadWrite,     // RW (the DEFAULT for committed regions)
    ReadExecute,   // RX
    Full,          // RWX — requires explicit request; never default
};

const char* mem_protect_to_name(MemProtect p);
// Writes must never be default; helper validates the W^X discipline for
// construction paths.
bool mem_protect_is_valid_default(MemProtect p);

// ── region state ──────────────────────────────────────────────────────────

enum class RegionState : std::uint8_t {
    Reserved,   // address space held (PROT_NONE), no storage promised
    Committed,  // host storage assigned (RW unless re-protected)
};

enum class VmRegionType : std::uint8_t { Private, Mapped, Image };

const char* region_state_to_name(RegionState s);

// ── region descriptor ────────────────────────────────────────────────────
//
// One descriptor per contiguous state/protection segment. Split segments
// retain allocation_base so the original reservation remains identifiable.
struct VmRegion {
    std::uint64_t xbox_va = 0;       // virtual address within the space
    std::uint64_t size = 0;         // bytes (page-aligned on allocation)
    RegionState state = RegionState::Reserved;
    MemProtect protection = MemProtect::NoAccess;
    MemProtect allocation_protection = MemProtect::ReadWrite;
    VmRegionType region_type = VmRegionType::Private;
    std::string name;               // diagnostics
    std::uint64_t alloc_id = 0;     // MemoryAllocator token (0 = not owned)
    std::uint64_t allocation_base = 0; // original reservation base across split segments
};

// ── resource limits ───────────────────────────────────────────────────────

struct MemoryLimits {
    std::uint64_t max_committed_bytes = 0;    // 0 = unlimited
    std::uint64_t max_reserved_bytes = 0;    // 0 = unlimited
    std::uint64_t max_regions = 0;           // 0 = unlimited
};

// ── address space ─────────────────────────────────────────────────────────
//
// All public operations take/return XBOX virtual addresses; host pointers
// exist only inside the implementation (translate() returns them solely
// for runtime-internal use by tests and the loader in later milestones —
// never exposed as object identity).
class AddressSpace {
public:
    // Creates a space backed by ONE host PAL region of `host_capacity`
    // (rounded to page size), with a virtual base address of xbox_base
    // (page-aligned; multiple of host page size enforced).
    // xbox_base default 0x10000000 keeps the model distinct from typical
    // host heaps (a DESIGN decision, not an Xbox layout claim).
    AddressSpace(std::uint64_t host_capacity, std::uint64_t xbox_base,
                 std::string name);
    ~AddressSpace();

    AddressSpace(const AddressSpace&) = delete;
    AddressSpace& operator=(const AddressSpace&) = delete;

    // ── region lifecycle ──
    // Reserves [xbox_va, size) — xbox_va must be page-aligned; size is
    // rounded UP to page size; overlap -> AlreadyExists typed error.
    Result<std::uint64_t> reserve_region(std::uint64_t xbox_va, std::uint64_t size,
                                         std::string name);
    // Reserve at an auto-chosen aligned gap (first-fit above the base).
    Result<std::uint64_t> reserve_region_auto(std::uint64_t size, std::string name);
    // Commit a reserved region (host storage via mprotect RW subrange).
    Result<void> commit_region(std::uint64_t xbox_va);
    Result<void> commit_range(std::uint64_t xbox_va, std::uint64_t size,
                              MemProtect protection = MemProtect::ReadWrite);
    // Decommit one complete region while retaining its virtual reservation.
    Result<void> decommit_region(std::uint64_t xbox_va);
    Result<void> decommit_range(std::uint64_t xbox_va, std::uint64_t size);
    // Change protection of a COMMITTED region (validated transitions).
    Result<void> protect_region(std::uint64_t xbox_va, MemProtect p);
    Result<MemProtect> protect_range(std::uint64_t xbox_va, std::uint64_t size, MemProtect p);
    Result<void> set_allocation_protection(std::uint64_t xbox_va, MemProtect p);
    Result<void> set_region_type(std::uint64_t xbox_va, VmRegionType type);
    // Release a region entirely (any state) — decommit + unreserve.
    Result<void> release_region(std::uint64_t xbox_va);
    // Resize (grow in place if the next bytes are free; shrink keeps the
    // same start). Grow requires the region be in any state; new pages
    // follow the region's current state.
    Result<void> resize_region(std::uint64_t xbox_va, std::uint64_t new_size);

    // ── lookup / validation ──
    Result<VmRegion> find_region(std::uint64_t xbox_va) const;      // exact start
    Result<VmRegion> find_containing(std::uint64_t xbox_va) const;  // any offset inside
    // Overlap probe: returns the overlapping region's start (0 when free).
    std::uint64_t find_overlap(std::uint64_t xbox_va, std::uint64_t size) const;
    bool is_page_aligned(std::uint64_t va) const;
    std::uint64_t page_size() const { return page_size_; }
    std::uint64_t base() const { return xbox_base_; }
    std::uint64_t capacity() const { return capacity_; }
    const std::string& name() const { return name_; }

    // ── host translation (runtime-internal) ──
    // Returns the host pointer for a virtual address INSIDE a committed
    // region; typed errors otherwise. Used by tests + future loader.
    Result<void*> translate(std::uint64_t xbox_va) const;
    // Validate an access (read/write/execute) at a virtual address:
    // checks containment + protection; InvalidArgument when denied.
    Result<void> validate_access(std::uint64_t xbox_va, bool write,
                                 bool exec) const;

    // ── statistics / limits ──
    struct Stats {
        std::uint64_t reserved_bytes = 0;
        std::uint64_t committed_bytes = 0;
        std::uint32_t region_count = 0;
        std::uint64_t capacity = 0;
    };
    Stats stats() const;
    void set_limits(const MemoryLimits& limits);
    const MemoryLimits& limits() const { return limits_; }

    // Snapshot listing (CLI/diagnostics).
    std::vector<VmRegion> list_regions() const;

    // Release everything (space teardown helper; also used by process
    // cleanup). Idempotent.
    Result<void> release_all();

    // Space identity for isolation checks (unique, monotonically).
    std::uint64_t space_id() const { return space_id_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    const std::uint64_t xbox_base_;
    const std::uint64_t capacity_;
    const std::uint64_t page_size_;
    const std::uint64_t space_id_;
    const std::string name_;
    MemoryLimits limits_;
};

// ── aligned allocator over committed storage ──────────────────────────────
//
// Carves aligned allocations from a caller-provided host buffer (the
// AddressSpace::translate result of a committed region). Tracks every
// allocation with metadata; double-free and stale-pointer frees are
// typed errors; usage stats + limit enforcement included.
class MemoryAllocator {
public:
    struct AllocationInfo {
        std::uint64_t id = 0;
        void* ptr = nullptr;
        std::uint64_t size = 0;        // requested
        std::uint64_t aligned_size = 0; // including alignment padding
        std::uint64_t alignment = 0;
        std::string tag;
    };

    explicit MemoryAllocator(void* buffer, std::uint64_t capacity,
                             std::uint64_t max_bytes = 0);
    ~MemoryAllocator();  // out-of-line: Impl is incomplete here

    // Allocates `size` bytes with `alignment` (power of two, <= page
    // size recommended); returns the allocation id (0 = failure typed).
    Result<std::uint64_t> allocate(std::uint64_t size, std::uint64_t alignment,
                                   std::string tag);
    // Resolves id -> pointer (null typed error for stale/unknown ids).
    Result<void*> resolve(std::uint64_t alloc_id) const;
    // Frees by id (double-free -> typed error). Zero-fill on free when
    // requested (debug hygiene).
    Result<void> free(std::uint64_t alloc_id, bool scrub = false);
    Result<AllocationInfo> info(std::uint64_t alloc_id) const;

    struct Stats {
        std::uint64_t used_bytes = 0;       // aligned
        std::uint64_t capacity = 0;
        std::uint32_t allocation_count = 0;
        std::uint64_t peak_used_bytes = 0;
    };
    Stats stats() const;
    std::vector<AllocationInfo> list_allocations() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

 // ── guest virtual-address allocator / XMem seam ──────────────────────────
 //
 // Internal guest-visible allocation contract. It deliberately does not
 // claim undocumented XMem API semantics.
struct XMemAllocation {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint64_t alignment = 0;
    std::string tag;
};

class IXMemAllocator {
public:
    virtual ~IXMemAllocator() = default;
    virtual Result<std::uint64_t> allocate(std::uint64_t size,
                                           std::uint64_t alignment,
                                           std::string tag,
                                           bool zero_initialize) = 0;
    virtual Result<void> free(std::uint64_t guest_address,
                              bool scrub = false) = 0;
    virtual Result<XMemAllocation> query(std::uint64_t guest_address) const = 0;
    virtual MemoryAllocator::Stats stats() const = 0;
    virtual std::uint64_t arena_base() const = 0;
};

class GuestXMemAllocator final : public IXMemAllocator {
public:
    static Result<std::unique_ptr<GuestXMemAllocator>> create(
        AddressSpace& space, std::uint64_t arena_size, std::string arena_name,
        std::uint64_t max_bytes = 0);
    ~GuestXMemAllocator() override;
    GuestXMemAllocator(const GuestXMemAllocator&) = delete;
    GuestXMemAllocator& operator=(const GuestXMemAllocator&) = delete;

    Result<std::uint64_t> allocate(std::uint64_t size,
                                   std::uint64_t alignment,
                                   std::string tag,
                                   bool zero_initialize) override;
    Result<void> free(std::uint64_t guest_address,
                      bool scrub = false) override;
    Result<XMemAllocation> query(std::uint64_t guest_address) const override;
    MemoryAllocator::Stats stats() const override;
    std::uint64_t arena_base() const override { return arena_base_; }

private:
    GuestXMemAllocator(AddressSpace& space, std::uint64_t arena_base,
                       std::uint64_t arena_size, void* host_base,
                       std::uint64_t max_bytes);
    AddressSpace& space_;
    const std::uint64_t arena_base_;
    const std::uint64_t arena_size_;
    void* const host_base_;
    std::unique_ptr<MemoryAllocator> allocator_;
    mutable std::mutex lock_;
    std::map<std::uint64_t, std::uint64_t> guest_to_allocation_;
};

}  // namespace xbox2pc::rt
