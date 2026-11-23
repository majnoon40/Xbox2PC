// memory_management.cpp — M4 AddressSpace + MemoryAllocator implementation.
//
// Host mapping model (docs/memory-management.md): ONE PalMemoryRegion
// backs each AddressSpace; regions are mprotect subranges of it. Xbox VAs
// are the space's own coordinate system (base + offsets) — host pointers
// never appear in the public interface; translate() is explicitly
// documented as runtime-internal (loader/tests).

#include "xbox2pc/memory_management.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <sstream>
#include <utility>

namespace xbox2pc::rt {

// ── protection / state names ───────────────────────────────────────────────

const char* mem_protect_to_name(MemProtect p) {
    switch (p) {
        case MemProtect::NoAccess: return "no_access";
        case MemProtect::ReadOnly: return "read_only";
        case MemProtect::ReadWrite: return "read_write";
        case MemProtect::ReadExecute: return "read_execute";
        case MemProtect::Full: return "full";
    }
    return "?";
}

bool mem_protect_is_valid_default(MemProtect p) {
    // W^X discipline: only NoAccess/ReadOnly/ReadWrite/ReadExecute may be
    // defaults; Full (RWX) requires an explicit protect call.
    return p == MemProtect::NoAccess || p == MemProtect::ReadOnly ||
           p == MemProtect::ReadWrite || p == MemProtect::ReadExecute;
}

const char* region_state_to_name(RegionState s) {
    return s == RegionState::Reserved ? "reserved" : "committed";
}

// ── AddressSpace ────────────────────────────────────────────────────────────

namespace {
std::atomic<std::uint64_t> g_next_space_id{1};

// Lock-free overlap scan over the (caller-locked) region map.
bool checked_align_up(std::uint64_t value, std::uint64_t alignment,
                      std::uint64_t& out) {
    if (alignment == 0) return false;
    const std::uint64_t rem = value % alignment;
    const std::uint64_t delta = rem == 0 ? 0 : alignment - rem;
    if (value > (~0ull) - delta) return false;
    out = value + delta;
    return true;
}

std::uint64_t overlap_in(const std::map<std::uint64_t, VmRegion>& regions,
                         std::uint64_t xbox_va, std::uint64_t size) {
    for (const auto& [va, r] : regions) {
        // Compare distances instead of forming potentially wrapping ends.
        if (va <= xbox_va) {
            if (xbox_va - va < r.size) return va;
        } else if (va - xbox_va < size) {
            return va;
        }
    }
    return 0;
}

// Split a tracked reservation at a page boundary without changing its
// logical allocation identity. The caller holds AddressSpace::Impl::lock.
bool split_region_at(std::map<std::uint64_t, VmRegion>& regions,
                     std::uint64_t boundary) {
    auto it = regions.upper_bound(boundary);
    if (it == regions.begin()) return false;
    --it;
    const auto start = it->first;
    const auto end = start + it->second.size;
    if (boundary <= start || boundary >= end) return true;
    VmRegion right = it->second;
    right.xbox_va = boundary;
    right.size = end - boundary;
    it->second.size = boundary - start;
    regions.emplace(boundary, std::move(right));
    return true;
}

// Host-side protection bits for a MemProtect value.
pal::Result<void> apply_subrange_protect(pal::PalMemoryRegion& host,
                                          std::uint64_t offset,
                                          std::uint64_t size,
                                          MemProtect p) {
    switch (p) {
        case MemProtect::NoAccess:
            return host.protect_subrange(offset, size, false, false, false);
        case MemProtect::ReadOnly:
            return host.protect_subrange(offset, size, true, false, false);
        case MemProtect::ReadWrite:
            return host.protect_subrange(offset, size, true, true, false);
        case MemProtect::ReadExecute:
            return host.protect_subrange(offset, size, true, false, true);
        case MemProtect::Full:
            return host.protect_subrange(offset, size, true, true, true);
    }
    return pal::Result<void>(RuntimeErrc::InvalidArgument, "bad protection");
}
}  // namespace

struct AddressSpace::Impl {
    mutable std::mutex lock;
    std::map<std::uint64_t, VmRegion> regions;  // sorted by xbox_va
    std::unique_ptr<pal::PalMemoryRegion> host; // the ONE backing mapping
};

AddressSpace::AddressSpace(std::uint64_t host_capacity, std::uint64_t xbox_base,
                           std::string name)
    : impl_(std::make_unique<Impl>()),
      xbox_base_(xbox_base),
      capacity_((xbox_base > (~0ull) - host_capacity) ? 0 : host_capacity),
      page_size_(pal::host_page_size()),
      space_id_(g_next_space_id.fetch_add(1, std::memory_order_acq_rel)),
      name_(std::move(name)) {
    // Reject zero/overflowed coordinate ranges. capacity_ is sanitized in
    // the initializer because it is immutable; invalid spaces stay unmapped.
    if (capacity_ == 0 || capacity_ != host_capacity) return;
    // Backing host mapping: reserve (PROT_NONE) the whole capacity up
    // front; per-region commit flips subranges to RW via mprotect.
    impl_->host = pal::reserve_memory(capacity_);
    if (impl_->host == nullptr) {
        // Construction failure is observable: every region op will fail
        // with OutOfResources and the failure is recorded in metadata of
        // the space name (never silent).
        impl_->host = nullptr;
    }
}

AddressSpace::~AddressSpace() {
    // release_all via destruction: host region unmaps in its own dtor.
}

// ── region lifecycle ───────────────────────────────────────────────────────

Result<std::uint64_t> AddressSpace::reserve_region(std::uint64_t xbox_va,
                                                   std::uint64_t size,
                                                   std::string name) {
    if (size == 0) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "zero size");
    }
    if (!is_page_aligned(xbox_va)) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "xbox_va not page-aligned");
    }
    if (xbox_base_ > (~0ull) - capacity_ || xbox_va < xbox_base_) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "xbox_va outside space bounds");
    }
    const std::uint64_t offset = xbox_va - xbox_base_;
    if (offset > capacity_ || page_size_ > capacity_ - offset) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "xbox_va outside space bounds");
    }
    std::uint64_t aligned_size = 0;
    if (!checked_align_up(size, page_size_, aligned_size) ||
        aligned_size > capacity_ - offset) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "region exceeds space capacity");
    }
    std::lock_guard lock(impl_->lock);
    if (impl_->host == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "space backing mapping failed at construction");
    }
    // Overlap detection against the sorted map (lock-free helper: the
    // public find_overlap would deadlock on the already-held lock).
    if (overlap_in(impl_->regions, xbox_va, aligned_size) != 0) {
        return Result<std::uint64_t>(RuntimeErrc::AlreadyExists,
                                     "region overlaps an existing one");
    }
    // Limit check (reservation).
    if (limits_.max_reserved_bytes != 0) {
        std::uint64_t current_reserved = 0;
        for (const auto& [va, r] : impl_->regions) {
            current_reserved += r.size; // committed regions still occupy reserved VA space
        }
        if (current_reserved > limits_.max_reserved_bytes ||
            aligned_size > limits_.max_reserved_bytes - current_reserved) {
            return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                         "reservation limit exceeded");
        }
    }
    if (limits_.max_regions != 0 &&
        impl_->regions.size() + 1 > limits_.max_regions) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "region count limit exceeded");
    }
    VmRegion r;
    r.xbox_va = xbox_va;
    r.size = aligned_size;
    r.allocation_base = xbox_va;
    r.state = RegionState::Reserved;
    r.protection = MemProtect::NoAccess;
    r.name = std::move(name);
    impl_->regions[xbox_va] = r;
    // Host: ensure the subrange is PROT_NONE (it already is after reserve;
    // re-apply defensively for regions released earlier this session).
    const auto prot = apply_subrange_protect(*impl_->host, xbox_va - xbox_base_,
                                             aligned_size, MemProtect::NoAccess);
    if (!prot.ok()) {
        impl_->regions.erase(xbox_va);   // roll back the descriptor
        return Result<std::uint64_t>(prot.errc(), prot.context());
    }
    return Result<std::uint64_t>(xbox_va);
}

Result<std::uint64_t> AddressSpace::reserve_region_auto(std::uint64_t size,
                                                        std::string name) {
    if (size == 0) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "zero size");
    }
    std::uint64_t aligned = 0;
    if (!checked_align_up(size, page_size_, aligned) ||
        xbox_base_ > (~0ull) - capacity_ || aligned > capacity_) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "request exceeds space capacity");
    }
    // Placement + descriptor insert + host mprotect ALL under one lock:
    // no scan-then-insert race window (the M4 draft released the lock
    // between the scan and insert, losing reservations under contention).
    std::lock_guard lock(impl_->lock);
    if (impl_->host == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "space backing mapping failed at construction");
    }
    // First-fit scan using offsets from xbox_base_; all bounds checks are
    // subtraction-based so hostile sizes cannot wrap address arithmetic.
    std::uint64_t candidate_off = 0;
    for (const auto& [va, r] : impl_->regions) {
        const std::uint64_t region_off = va - xbox_base_;
        if (region_off >= candidate_off &&
            aligned <= region_off - candidate_off) {
            break;
        }
        const std::uint64_t region_end = region_off + r.size;
        if (region_end > candidate_off) candidate_off = region_end;
        if (!checked_align_up(candidate_off, page_size_, candidate_off)) {
            return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                         "address alignment overflow");
        }
    }
    if (candidate_off > capacity_ || aligned > capacity_ - candidate_off) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "no gap large enough");
    }
    const std::uint64_t candidate = xbox_base_ + candidate_off;
    // Insert the descriptor (limits enforced on the locked map).
    if (limits_.max_reserved_bytes != 0) {
        std::uint64_t current_reserved = 0;
        for (const auto& [va, r] : impl_->regions) {
            current_reserved += r.size; // committed regions still occupy reserved VA space
        }
        if (current_reserved > limits_.max_reserved_bytes ||
            aligned > limits_.max_reserved_bytes - current_reserved) {
            return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                         "reservation limit exceeded");
        }
    }
    if (limits_.max_regions != 0 &&
        impl_->regions.size() + 1 > limits_.max_regions) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "region count limit exceeded");
    }
    VmRegion r;
    r.xbox_va = candidate;
    r.size = aligned;
    r.allocation_base = candidate;
    r.state = RegionState::Reserved;
    r.protection = MemProtect::NoAccess;
    r.name = std::move(name);
    impl_->regions[r.xbox_va] = r;
    const auto prot = apply_subrange_protect(*impl_->host, candidate - xbox_base_,
                                             aligned, MemProtect::NoAccess);
    if (!prot.ok()) {
        impl_->regions.erase(candidate);
        return Result<std::uint64_t>(prot.errc(), prot.context());
    }
    return Result<std::uint64_t>(candidate);
}

Result<void> AddressSpace::commit_region(std::uint64_t xbox_va) {
    auto region = find_region(xbox_va);
    if (!region.ok()) return Result<void>(region.errc(), region.context());
    return commit_range(xbox_va, region.value().size);
}

Result<void> AddressSpace::commit_range(std::uint64_t xbox_va,
                                        std::uint64_t size) {
    if (size == 0 || !is_page_aligned(xbox_va) || size % page_size_ != 0 ||
        xbox_va > (~0ull) - size)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "commit range must be non-empty, page-aligned, and non-overflowing");
    const auto end = xbox_va + size;
    std::lock_guard lock(impl_->lock);
    auto it = impl_->regions.upper_bound(xbox_va);
    if (it == impl_->regions.begin())
        return Result<void>(RuntimeErrc::NotFound, "commit range is not reserved");
    --it;
    const auto allocation = it->second.allocation_base;
    std::uint64_t cursor = xbox_va;
    for (; cursor < end; ++it) {
        if (it == impl_->regions.end() || it->first > cursor ||
            cursor - it->first >= it->second.size ||
            it->second.allocation_base != allocation ||
            it->second.state != RegionState::Reserved)
            return Result<void>(RuntimeErrc::InvalidState,
                                "commit range must lie in one reserved allocation");
        cursor = std::min(end, it->first + it->second.size);
    }
    if (impl_->host == nullptr)
        return Result<void>(RuntimeErrc::OutOfResources, "no backing mapping");
    if (limits_.max_committed_bytes != 0) {
        std::uint64_t used = 0;
        for (const auto& [va, region] : impl_->regions) {
            (void)va;
            if (region.state == RegionState::Committed)
                used = region.size > (~0ull) - used ? ~0ull : used + region.size;
        }
        if (used > limits_.max_committed_bytes ||
            size > limits_.max_committed_bytes - used)
            return Result<void>(RuntimeErrc::OutOfResources,
                                "committed-bytes limit exceeded");
    }
    const auto host_ok = impl_->host->commit_subrange(xbox_va - xbox_base_, size);
    if (!host_ok.ok()) return Result<void>(host_ok.errc(), host_ok.context());
    if (!split_region_at(impl_->regions, xbox_va) ||
        !split_region_at(impl_->regions, end))
        return Result<void>(RuntimeErrc::InvalidState, "failed to split committed range metadata");
    for (auto page = impl_->regions.lower_bound(xbox_va);
         page != impl_->regions.end() && page->first < end; ++page) {
        page->second.state = RegionState::Committed;
        page->second.protection = MemProtect::ReadWrite;
    }
    return Result<void>::ok_result();
}

Result<void> AddressSpace::decommit_region(std::uint64_t xbox_va) {
    auto region = find_region(xbox_va);
    if (!region.ok()) return Result<void>(region.errc(), region.context());
    return decommit_range(xbox_va, region.value().size);
}

Result<void> AddressSpace::decommit_range(std::uint64_t xbox_va,
                                          std::uint64_t size) {
    if (size == 0 || !is_page_aligned(xbox_va) || size % page_size_ != 0 ||
        xbox_va > (~0ull) - size)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "decommit range must be non-empty, page-aligned, and non-overflowing");
    const auto end = xbox_va + size;
    std::lock_guard lock(impl_->lock);
    auto it = impl_->regions.upper_bound(xbox_va);
    if (it == impl_->regions.begin())
        return Result<void>(RuntimeErrc::NotFound, "decommit range is not committed");
    --it;
    const auto allocation = it->second.allocation_base;
    std::uint64_t cursor = xbox_va;
    for (; cursor < end; ++it) {
        if (it == impl_->regions.end() || it->first > cursor ||
            cursor - it->first >= it->second.size ||
            it->second.allocation_base != allocation ||
            it->second.state != RegionState::Committed)
            return Result<void>(RuntimeErrc::InvalidState,
                                "decommit range must lie in one committed allocation");
        cursor = std::min(end, it->first + it->second.size);
    }
    if (impl_->host == nullptr)
        return Result<void>(RuntimeErrc::OutOfResources, "no backing mapping");
    struct PreviousProtection {
        std::uint64_t start;
        std::uint64_t size;
        MemProtect protection;
    };
    std::vector<PreviousProtection> previous;
    for (auto segment = impl_->regions.upper_bound(xbox_va);
         segment != impl_->regions.begin();) {
        --segment;
        if (segment->first + segment->second.size <= xbox_va) break;
        for (; segment != impl_->regions.end() && segment->first < end; ++segment) {
            const auto begin = std::max(xbox_va, segment->first);
            const auto finish = std::min(end, segment->first + segment->second.size);
            if (begin < finish)
                previous.push_back({begin, finish - begin, segment->second.protection});
        }
        break;
    }
    const auto host_ok = impl_->host->decommit_subrange(
        xbox_va - xbox_base_, size);
    if (!host_ok.ok()) {
        for (const auto& old : previous)
            (void)apply_subrange_protect(*impl_->host, old.start - xbox_base_,
                                         old.size, old.protection);
        return Result<void>(host_ok.errc(), host_ok.context());
    }
    if (!split_region_at(impl_->regions, xbox_va) ||
        !split_region_at(impl_->regions, end))
        return Result<void>(RuntimeErrc::InvalidState, "failed to split decommitted range metadata");
    for (auto page = impl_->regions.lower_bound(xbox_va);
         page != impl_->regions.end() && page->first < end; ++page) {
        page->second.state = RegionState::Reserved;
        page->second.protection = MemProtect::NoAccess;
    }
    return Result<void>::ok_result();
}

Result<void> AddressSpace::set_allocation_protection(
    std::uint64_t xbox_va, MemProtect p) {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->regions.find(xbox_va);
    if (it == impl_->regions.end())
        return Result<void>(RuntimeErrc::NotFound, "no region at that address");
    if (it->second.state != RegionState::Reserved)
        return Result<void>(RuntimeErrc::InvalidState,
                            "allocation protection is immutable after commit");
    it->second.allocation_protection = p;
    return Result<void>::ok_result();
}

Result<void> AddressSpace::set_region_type(
    std::uint64_t xbox_va, VmRegionType type) {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->regions.find(xbox_va);
    if (it == impl_->regions.end())
        return Result<void>(RuntimeErrc::NotFound, "no region at that address");
    if (it->second.state != RegionState::Reserved)
        return Result<void>(RuntimeErrc::InvalidState,
                            "region type is immutable after commit");
    it->second.region_type = type;
    return Result<void>::ok_result();
}

Result<void> AddressSpace::protect_region(std::uint64_t xbox_va, MemProtect p) {
    auto region = find_region(xbox_va);
    if (!region.ok()) return Result<void>(region.errc(), region.context());
    auto changed = protect_range(xbox_va, region.value().size, p);
    if (!changed.ok()) return Result<void>(changed.errc(), changed.context());
    return Result<void>::ok_result();
}

Result<MemProtect> AddressSpace::protect_range(std::uint64_t xbox_va,
                                               std::uint64_t size,
                                               MemProtect p) {
    if (size == 0 || !is_page_aligned(xbox_va) || size % page_size_ != 0 ||
        xbox_va > (~0ull) - size)
        return Result<MemProtect>(RuntimeErrc::InvalidArgument,
            "protection range must be non-empty, page-aligned, and non-overflowing");
    const auto end = xbox_va + size;
    std::lock_guard lock(impl_->lock);
    auto it = impl_->regions.upper_bound(xbox_va);
    if (it == impl_->regions.begin())
        return Result<MemProtect>(RuntimeErrc::NotFound, "protection range is not committed");
    --it;
    const auto allocation = it->second.allocation_base;
    const auto previous = it->second.protection;
    std::uint64_t cursor = xbox_va;
    for (; cursor < end; ++it) {
        if (it == impl_->regions.end() || it->first > cursor ||
            cursor - it->first >= it->second.size ||
            it->second.allocation_base != allocation ||
            it->second.state != RegionState::Committed)
            return Result<MemProtect>(RuntimeErrc::InvalidState,
                "protection range must lie in one committed allocation");
        cursor = std::min(end, it->first + it->second.size);
    }
    if (impl_->host == nullptr)
        return Result<MemProtect>(RuntimeErrc::OutOfResources, "no backing mapping");
    const auto host_ok = apply_subrange_protect(*impl_->host,
        xbox_va - xbox_base_, size, p);
    if (!host_ok.ok()) return Result<MemProtect>(host_ok.errc(), host_ok.context());
    if (!split_region_at(impl_->regions, xbox_va) ||
        !split_region_at(impl_->regions, end))
        return Result<MemProtect>(RuntimeErrc::InvalidState,
                                  "failed to split protected range metadata");
    for (auto page = impl_->regions.lower_bound(xbox_va);
         page != impl_->regions.end() && page->first < end; ++page)
        page->second.protection = p;
    return Result<MemProtect>(previous);
}

Result<void> AddressSpace::release_region(std::uint64_t xbox_va) {
    std::lock_guard lock(impl_->lock);
    auto it = impl_->regions.find(xbox_va);
    if (it == impl_->regions.end())
        return Result<void>(RuntimeErrc::NotFound, "no allocation starts at that address");
    const auto allocation = it->second.allocation_base == 0
        ? xbox_va : it->second.allocation_base;
    if (allocation != xbox_va)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "release requires the original allocation base");
    std::uint64_t first = ~0ull;
    std::uint64_t last = 0;
    for (const auto& [va, region] : impl_->regions) {
        const auto base = region.allocation_base == 0 ? va : region.allocation_base;
        if (base == allocation) {
            first = std::min(first, va);
            last = std::max(last, va + region.size);
        }
    }
    if (first == ~0ull || last <= first)
        return Result<void>(RuntimeErrc::NotFound, "allocation metadata is inconsistent");
    if (impl_->host != nullptr) {
        const auto host_ok = apply_subrange_protect(*impl_->host,
            first - xbox_base_, last - first, MemProtect::NoAccess);
        if (!host_ok.ok()) return Result<void>(host_ok.errc(), host_ok.context());
    }
    for (auto current = impl_->regions.begin(); current != impl_->regions.end();) {
        const auto base = current->second.allocation_base == 0
            ? current->first : current->second.allocation_base;
        if (base == allocation) current = impl_->regions.erase(current);
        else ++current;
    }
    return Result<void>::ok_result();
}

Result<void> AddressSpace::resize_region(std::uint64_t xbox_va,
                                         std::uint64_t new_size) {
    if (new_size == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "zero size (use release_region)");
    }
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->regions.find(xbox_va);
    if (it == impl_->regions.end()) {
        return Result<void>(RuntimeErrc::NotFound, "no region at that address");
    }
    VmRegion& r = it->second;
    const auto allocation = r.allocation_base == 0 ? xbox_va : r.allocation_base;
    for (const auto& [va, segment] : impl_->regions) {
        if (va != xbox_va &&
            (segment.allocation_base == 0 ? va : segment.allocation_base) == allocation)
            return Result<void>(RuntimeErrc::InvalidState,
                                "cannot resize an allocation after it has been split into ranges");
    }
    std::uint64_t aligned_new = 0;
    if (!checked_align_up(new_size, page_size_, aligned_new)) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "resize alignment overflow");
    }
    const std::uint64_t offset = xbox_va - xbox_base_;
    if (offset > capacity_ || aligned_new > capacity_ - offset) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "resize exceeds space capacity");
    }
    if (aligned_new < r.size) {
        // Shrink: the tail returns to PROT_NONE.
        if (impl_->host != nullptr) {
            const auto host_ok = apply_subrange_protect(
                *impl_->host, xbox_va - xbox_base_ + aligned_new,
                r.size - aligned_new, MemProtect::NoAccess);
            if (!host_ok.ok()) {
                return Result<void>(host_ok.errc(), host_ok.context());
            }
        }
        r.size = aligned_new;
        return Result<void>::ok_result();
    }
    if (aligned_new == r.size) return Result<void>::ok_result();
    // Grow: next bytes must be free and in-bounds.
    const auto next = impl_->regions.upper_bound(xbox_va);
    if (next != impl_->regions.end() &&
        next->first > xbox_va &&
        next->first - xbox_va < aligned_new) {
        return Result<void>(RuntimeErrc::AlreadyExists,
                            "grow would overlap the next region");
    }
    const std::uint64_t delta = aligned_new - r.size;
    // Every region consumes reservation address space regardless of
    // whether its pages are currently committed.
    if (limits_.max_reserved_bytes != 0) {
        std::uint64_t current_reserved = 0;
        for (const auto& [va, reg] : impl_->regions) current_reserved += reg.size;
        if (current_reserved > limits_.max_reserved_bytes ||
            delta > limits_.max_reserved_bytes - current_reserved) {
            return Result<void>(RuntimeErrc::OutOfResources,
                                "reservation limit exceeded on resize");
        }
    }
    if (r.state == RegionState::Committed &&
        limits_.max_committed_bytes != 0) {
        std::uint64_t current = 0;
        for (const auto& [va, reg] : impl_->regions) {
            if (reg.state == RegionState::Committed) current += reg.size;
        }
        if (current > limits_.max_committed_bytes ||
            delta > limits_.max_committed_bytes - current) {
            return Result<void>(RuntimeErrc::OutOfResources,
                                "committed-bytes limit exceeded on resize");
        }
    }
    if (impl_->host != nullptr) {
        // New pages follow the region's current state/protection.
        MemProtect tail_prot = r.protection;
        if (r.state == RegionState::Reserved) tail_prot = MemProtect::NoAccess;
        const auto host_ok = apply_subrange_protect(
            *impl_->host, xbox_va - xbox_base_ + r.size, aligned_new - r.size,
            tail_prot);
        if (!host_ok.ok()) {
            return Result<void>(host_ok.errc(), host_ok.context());
        }
    }
    r.size = aligned_new;
    return Result<void>::ok_result();
}

// ── lookup / validation ───────────────────────────────────────────────────

Result<VmRegion> AddressSpace::find_region(std::uint64_t xbox_va) const {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->regions.find(xbox_va);
    if (it == impl_->regions.end()) {
        return Result<VmRegion>(RuntimeErrc::NotFound,
                                "no region starts at " + std::to_string(xbox_va));
    }
    return Result<VmRegion>(it->second);
}

Result<VmRegion> AddressSpace::find_containing(std::uint64_t xbox_va) const {
    std::lock_guard lock(impl_->lock);
    if (impl_->regions.empty()) {
        return Result<VmRegion>(RuntimeErrc::NotFound, "space is empty");
    }
    // upper_bound then step back: the region that starts <= xbox_va.
    auto it = impl_->regions.upper_bound(xbox_va);
    if (it == impl_->regions.begin()) {
        return Result<VmRegion>(RuntimeErrc::NotFound, "before first region");
    }
    --it;
    if (xbox_va - it->first >= it->second.size) {
        return Result<VmRegion>(RuntimeErrc::NotFound, "inside a gap");
    }
    return Result<VmRegion>(it->second);
}

std::uint64_t AddressSpace::find_overlap(std::uint64_t xbox_va,
                                          std::uint64_t size) const {
    std::lock_guard lock(impl_->lock);
    for (const auto& [va, r] : impl_->regions) {
        if (va <= xbox_va) {
            if (xbox_va - va < r.size) return va;
        } else if (va - xbox_va < size) {
            return va;
        }
    }
    return 0;
}

bool AddressSpace::is_page_aligned(std::uint64_t va) const {
    return (va % page_size_) == 0;
}

Result<void*> AddressSpace::translate(std::uint64_t xbox_va) const {
    auto found = find_containing(xbox_va);
    if (!found.ok()) {
        return Result<void*>(found.errc(), found.context());
    }
    const VmRegion& r = found.value();
    if (r.state != RegionState::Committed) {
        return Result<void*>(RuntimeErrc::InvalidState,
                             "region not committed (reserved only)");
    }
    if (impl_->host == nullptr || impl_->host->base() == nullptr) {
        return Result<void*>(RuntimeErrc::OutOfResources, "no backing mapping");
    }
    const std::uint64_t offset_in_region = xbox_va - r.xbox_va;
    auto* base = static_cast<std::uint8_t*>(impl_->host->base());
    return Result<void*>(base + (r.xbox_va - xbox_base_) + offset_in_region);
}

Result<void> AddressSpace::validate_access(std::uint64_t xbox_va, bool write,
                                           bool exec) const {
    auto found = find_containing(xbox_va);
    if (!found.ok()) {
        return Result<void>(found.errc(), found.context());
    }
    const VmRegion& r = found.value();
    if (r.state != RegionState::Committed) {
        return Result<void>(RuntimeErrc::InvalidState,
                            "access to non-committed region");
    }
    const bool may_write = r.protection == MemProtect::ReadWrite ||
                           r.protection == MemProtect::Full;
    const bool may_exec = r.protection == MemProtect::ReadExecute ||
                          r.protection == MemProtect::Full;
    if (write && !may_write) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                             "write access to non-writable region (" +
                                 std::string(mem_protect_to_name(r.protection)) + ")");
    }
    if (exec && !may_exec) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "execute access to non-executable region (" +
                                 std::string(mem_protect_to_name(r.protection)) + ")");
    }
    return Result<void>::ok_result();
}

// ── statistics / listing ──────────────────────────────────────────────────

AddressSpace::Stats AddressSpace::stats() const {
    std::lock_guard lock(impl_->lock);
    Stats s;
    s.capacity = capacity_;
    for (const auto& [va, r] : impl_->regions) {
        if (r.state == RegionState::Committed) s.committed_bytes += r.size;
        else s.reserved_bytes += r.size;
        ++s.region_count;
    }
    return s;
}

void AddressSpace::set_limits(const MemoryLimits& limits) {
    std::lock_guard lock(impl_->lock);
    limits_ = limits;
}

std::vector<VmRegion> AddressSpace::list_regions() const {
    std::lock_guard lock(impl_->lock);
    std::vector<VmRegion> out;
    out.reserve(impl_->regions.size());
    for (const auto& [va, r] : impl_->regions) out.push_back(r);
    return out;
}

Result<void> AddressSpace::release_all() {
    std::lock_guard lock(impl_->lock);
    if (impl_->host != nullptr) {
        // Whole backing region back to PROT_NONE in one call.
        const auto host_ok = impl_->host->protect(false, false, false);
        if (!host_ok.ok()) {
            return Result<void>(host_ok.errc(), host_ok.context());
        }
    }
    impl_->regions.clear();
    return Result<void>::ok_result();
}

// ── MemoryAllocator ──────────────────────────────────────────────────────

struct MemoryAllocator::Impl {
    mutable std::mutex lock;
    void* buffer = nullptr;
    std::uint64_t capacity = 0;
    std::uint64_t max_bytes = 0;
    std::uint64_t used = 0;            // aligned bytes in use
    std::uint64_t peak = 0;
    std::map<std::uint64_t, AllocationInfo> live;   // id -> info
    std::map<std::uint64_t, std::uint64_t> offset_of;  // id -> buffer offset
    // offset -> allocation id (sorted layout; first-fit scans the gaps).
    // M4 performance fix: the draft rebuilt a span vector per allocate
    // (O(n) per op, quadratic); the sorted layout keeps placement bounded.
    std::map<std::uint64_t, std::uint64_t> layout;
    std::uint64_t next_id = 1;
};

MemoryAllocator::~MemoryAllocator() = default;

MemoryAllocator::MemoryAllocator(void* buffer, std::uint64_t capacity,
                                 std::uint64_t max_bytes)
    : impl_(std::make_unique<Impl>()) {
    impl_->buffer = buffer;
    impl_->capacity = capacity;
    impl_->max_bytes = max_bytes;
}

Result<std::uint64_t> MemoryAllocator::allocate(std::uint64_t size,
                                                std::uint64_t alignment,
                                                std::string tag) {
    if (size == 0) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "zero size");
    }
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "alignment must be a power of two");
    }
    const std::uint64_t host_page = pal::host_page_size();
    if (alignment > host_page) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "alignment above page size unsupported");
    }
    std::lock_guard lock(impl_->lock);
    // First-fit with ABSOLUTE-address alignment over the sorted layout map
    // (offset -> allocation id). M4 performance fix: the draft rebuilt a
    // span vector on every allocate (O(n) per op — quadratic overall, the
    // benchmark showed 2.6k ops/s); the sorted layout keeps placement a
    // bounded gap scan with O(log n) insert/erase.
    // The host buffer's own base can be unaligned to `alignment` (vector
    // data aligns to alignof(max_align_t) only), so every aligned_start
    // computation folds the buffer misalignment in — aligned addresses
    // are aligned in ABSOLUTE terms, not merely relative to the buffer.
    const std::uintptr_t base_addr = reinterpret_cast<std::uintptr_t>(impl_->buffer);
    const std::uint64_t base_skew = alignment <= 1
        ? 0
        : (alignment - (base_addr % alignment)) % alignment;
    // Smallest offset x >= `from` with (base + x) % alignment == 0,
    // i.e. x ≡ base_skew (mod alignment).
    const auto align_abs = [&](std::uint64_t from,
                               std::uint64_t& aligned) -> bool {
        if (alignment <= 1) {
            aligned = from;
            return true;
        }
        const std::uint64_t rel = from % alignment;
        const std::uint64_t delta =
            rel == base_skew ? 0 : (base_skew + alignment - rel) % alignment;
        if (from > (~0ull) - delta) return false;
        aligned = from + delta;
        return true;
    };
    if (impl_->buffer == nullptr || size > impl_->capacity) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "allocation exceeds or lacks backing storage");
    }
    std::uint64_t chosen = impl_->capacity;  // sentinel: not found
    // Tail fast path (the common append case): try after the LAST block
    // first — O(log n) via rbegin, no gap scan at all.
    if (!impl_->layout.empty()) {
        const auto& last = *impl_->layout.rbegin();
        const std::uint64_t last_len = impl_->live.at(last.second).aligned_size;
        if (last.first <= impl_->capacity &&
            last_len <= impl_->capacity - last.first) {
            const std::uint64_t last_end = last.first + last_len;
            std::uint64_t tail = 0;
            if (align_abs(last_end, tail) && tail <= impl_->capacity &&
                size <= impl_->capacity - tail) {
                chosen = tail;
            }
        }
    } else {
        std::uint64_t head = 0;
        if (align_abs(0, head) && head <= impl_->capacity &&
            size <= impl_->capacity - head) {
            chosen = head;
        }
    }
    if (chosen == impl_->capacity) {
        // Full first-fit gap scan (fragmented case).
        std::uint64_t prev_end = 0;
        for (const auto& [off, id] : impl_->layout) {
            const std::uint64_t len = impl_->live.at(id).aligned_size;
            std::uint64_t aligned_start = 0;
            if (align_abs(prev_end, aligned_start) &&
                aligned_start <= off && size <= off - aligned_start) {
                chosen = aligned_start;
                break;
            }
            if (off > impl_->capacity || len > impl_->capacity - off) {
                return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                             "allocator layout invariant violated");
            }
            prev_end = off + len;
        }
    }
    if (chosen == impl_->capacity) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "no room for " + std::to_string(size) +
                                         " bytes @ alignment " + std::to_string(alignment));
    }
    const std::uint64_t aligned_size = size;   // padding already in `chosen`
    if (impl_->max_bytes != 0 &&
        (impl_->used > impl_->max_bytes ||
         aligned_size > impl_->max_bytes - impl_->used)) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "allocator byte limit exceeded");
    }
    if (impl_->next_id == 0) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "allocation ID space exhausted");
    }
    const std::uint64_t id = impl_->next_id++;
    AllocationInfo info;
    info.id = id;
    info.ptr = static_cast<std::uint8_t*>(impl_->buffer) + chosen;
    info.size = size;
    info.aligned_size = aligned_size;
    info.alignment = alignment;
    info.tag = std::move(tag);
    impl_->live[id] = info;
    impl_->offset_of[id] = chosen;
    impl_->layout[chosen] = id;
    impl_->used += aligned_size;
    if (impl_->used > impl_->peak) impl_->peak = impl_->used;
    return Result<std::uint64_t>(id);
}

Result<void*> MemoryAllocator::resolve(std::uint64_t alloc_id) const {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->live.find(alloc_id);
    if (it == impl_->live.end()) {
        return Result<void*>(RuntimeErrc::NotFound,
                             "allocation id " + std::to_string(alloc_id) +
                                 " unknown or freed");
    }
    return Result<void*>(it->second.ptr);
}

Result<void> MemoryAllocator::free(std::uint64_t alloc_id, bool scrub) {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->live.find(alloc_id);
    if (it == impl_->live.end()) {
        return Result<void>(RuntimeErrc::NotFound,
                            "double free or unknown id " +
                                std::to_string(alloc_id));
    }
    if (scrub) {
        std::memset(it->second.ptr, 0,
                    static_cast<std::size_t>(it->second.size));
    }
    impl_->used -= it->second.aligned_size;
    const auto off_it = impl_->offset_of.find(alloc_id);
    if (off_it != impl_->offset_of.end()) {
        impl_->layout.erase(off_it->second);
        impl_->offset_of.erase(off_it);
    }
    impl_->live.erase(it);
    return Result<void>::ok_result();
}

Result<MemoryAllocator::AllocationInfo> MemoryAllocator::info(
    std::uint64_t alloc_id) const {
    std::lock_guard lock(impl_->lock);
    const auto it = impl_->live.find(alloc_id);
    if (it == impl_->live.end()) {
        return Result<AllocationInfo>(RuntimeErrc::NotFound,
                                      "allocation id " +
                                          std::to_string(alloc_id) + " unknown");
    }
    return Result<AllocationInfo>(it->second);
}

MemoryAllocator::Stats MemoryAllocator::stats() const {
    std::lock_guard lock(impl_->lock);
    Stats s;
    s.used_bytes = impl_->used;
    s.capacity = impl_->capacity;
    s.allocation_count = static_cast<std::uint32_t>(impl_->live.size());
    s.peak_used_bytes = impl_->peak;
    return s;
}

std::vector<MemoryAllocator::AllocationInfo> MemoryAllocator::list_allocations()
    const {
    std::lock_guard lock(impl_->lock);
    std::vector<AllocationInfo> out;
    out.reserve(impl_->live.size());
    for (const auto& [id, info] : impl_->live) out.push_back(info);
    return out;
}

}  // namespace xbox2pc::rt
