// xmem_allocator.cpp — guest-VA allocation adapter over the M4 address space.
#include "xbox2pc/memory_management.hpp"

#include <cstring>
#include <limits>
#include <new>

namespace xbox2pc::rt {

GuestXMemAllocator::GuestXMemAllocator(
    AddressSpace& space, std::uint64_t arena_base, std::uint64_t arena_size,
    void* host_base, std::uint64_t max_bytes)
    : space_(space), arena_base_(arena_base), arena_size_(arena_size),
      host_base_(host_base),
      allocator_(std::make_unique<MemoryAllocator>(host_base, arena_size,
                                                   max_bytes)) {}

Result<std::unique_ptr<GuestXMemAllocator>> GuestXMemAllocator::create(
    AddressSpace& space, std::uint64_t arena_size, std::string arena_name,
    std::uint64_t max_bytes) {
    if (arena_size == 0)
        return Result<std::unique_ptr<GuestXMemAllocator>>(
            RuntimeErrc::InvalidArgument, "XMem arena size must be non-zero");
    if (max_bytes > arena_size)
        return Result<std::unique_ptr<GuestXMemAllocator>>(
            RuntimeErrc::InvalidArgument, "XMem byte limit exceeds arena size");
    auto reservation = space.reserve_region_auto(arena_size, std::move(arena_name));
    if (!reservation.ok())
        return Result<std::unique_ptr<GuestXMemAllocator>>(reservation.errc(), reservation.context());
    const auto base = reservation.value();
    const auto region = space.find_region(base);
    if (!region.ok()) {
        (void)space.release_region(base);
        return Result<std::unique_ptr<GuestXMemAllocator>>(region.errc(), region.context());
    }
    const auto committed = space.commit_range(base, region.value().size, MemProtect::ReadWrite);
    if (!committed.ok()) {
        (void)space.release_region(base);
        return Result<std::unique_ptr<GuestXMemAllocator>>(committed.errc(), committed.context());
    }
    const auto host = space.translate(base);
    if (!host.ok()) {
        (void)space.release_region(base);
        return Result<std::unique_ptr<GuestXMemAllocator>>(host.errc(), host.context());
    }
    try {
        auto result = std::unique_ptr<GuestXMemAllocator>(
            new GuestXMemAllocator(space, base, region.value().size, host.value(), max_bytes));
        return Result<std::unique_ptr<GuestXMemAllocator>>(std::move(result));
    } catch (const std::bad_alloc&) {
        (void)space.release_region(base);
        return Result<std::unique_ptr<GuestXMemAllocator>>(
            RuntimeErrc::OutOfResources, "unable to create XMem allocator metadata");
    }
}

GuestXMemAllocator::~GuestXMemAllocator() {
    allocator_.reset();
    (void)space_.release_region(arena_base_);
}

Result<std::uint64_t> GuestXMemAllocator::allocate(
    std::uint64_t size, std::uint64_t alignment, std::string tag, bool zero_initialize) {
    std::lock_guard lock(lock_);
    auto id = allocator_->allocate(size, alignment, std::move(tag));
    if (!id.ok()) return Result<std::uint64_t>(id.errc(), id.context());
    auto pointer = allocator_->resolve(id.value());
    if (!pointer.ok()) {
        (void)allocator_->free(id.value());
        return Result<std::uint64_t>(pointer.errc(), pointer.context());
    }
    const auto host = reinterpret_cast<std::uintptr_t>(pointer.value());
    const auto base = reinterpret_cast<std::uintptr_t>(host_base_);
    if (host < base || host - base >= arena_size_ ||
        size > arena_size_ - static_cast<std::uint64_t>(host - base) ||
        arena_base_ > std::numeric_limits<std::uint64_t>::max() -
                          static_cast<std::uint64_t>(host - base)) {
        (void)allocator_->free(id.value());
        return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                     "allocator returned a pointer outside its guest arena");
    }
    const auto offset = static_cast<std::uint64_t>(host - base);
    const auto guest_address = arena_base_ + offset;
    if (zero_initialize) std::memset(pointer.value(), 0, static_cast<std::size_t>(size));
    try {
        const auto [it, inserted] = guest_to_allocation_.emplace(guest_address, id.value());
        (void)it;
        if (!inserted) {
            (void)allocator_->free(id.value());
            return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                         "guest allocation base is already tracked");
        }
    } catch (const std::bad_alloc&) {
        (void)allocator_->free(id.value());
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "unable to track guest allocation metadata");
    }
    return Result<std::uint64_t>(guest_address);
}

Result<void> GuestXMemAllocator::free(std::uint64_t guest_address, bool scrub) {
    std::lock_guard lock(lock_);
    const auto found = guest_to_allocation_.find(guest_address);
    if (found == guest_to_allocation_.end())
        return Result<void>(RuntimeErrc::NotFound, "guest allocation base is unknown or already freed");
    const auto released = allocator_->free(found->second, scrub);
    if (!released.ok()) return released;
    guest_to_allocation_.erase(found);
    return Result<void>::ok_result();
}

Result<XMemAllocation> GuestXMemAllocator::query(std::uint64_t guest_address) const {
    std::lock_guard lock(lock_);
    const auto found = guest_to_allocation_.find(guest_address);
    if (found == guest_to_allocation_.end())
        return Result<XMemAllocation>(RuntimeErrc::NotFound, "guest allocation base is unknown or already freed");
    auto info = allocator_->info(found->second);
    if (!info.ok()) return Result<XMemAllocation>(info.errc(), info.context());
    return Result<XMemAllocation>(XMemAllocation{guest_address, info.value().size,
                                                  info.value().alignment, info.value().tag});
}

MemoryAllocator::Stats GuestXMemAllocator::stats() const {
    std::lock_guard lock(lock_);
    return allocator_->stats();
}

}  // namespace xbox2pc::rt
