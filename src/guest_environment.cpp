#include "xbox2pc/guest_environment.hpp"

#include <algorithm>
#include <limits>

namespace xbox2pc::rt::exec {
namespace {

Result<std::uint64_t> allocate_zeroed(AddressSpace& space,
                                      guest::GuestMemory& memory,
                                      std::uint64_t size,
                                      const char* name) {
    auto reserved = space.reserve_region_auto(size, name);
    if (!reserved.ok()) return Result<std::uint64_t>(reserved.errc(), reserved.context());
    auto committed = space.commit_region(reserved.value());
    if (!committed.ok()) {
        (void)space.release_region(reserved.value());
        return Result<std::uint64_t>(committed.errc(), committed.context());
    }
    const std::uint64_t rounded =
        ((size + space.page_size() - 1) / space.page_size()) * space.page_size();
    std::vector<std::uint8_t> zeros(64u * 1024u, 0);
    for (std::uint64_t offset = 0; offset < rounded;) {
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(zeros.size(), rounded - offset));
        auto cleared = memory.write(reserved.value() + offset, zeros.data(), chunk);
        if (!cleared.ok()) {
            (void)space.release_region(reserved.value());
            return Result<std::uint64_t>(cleared.errc(), cleared.context());
        }
        offset += chunk;
    }
    return Result<std::uint64_t>(reserved.value());
}

}  // namespace

GuestProcessEnvironment::GuestProcessEnvironment(AddressSpace& space)
    : space_(space), memory_(space) {}

GuestProcessEnvironment::~GuestProcessEnvironment() {
    if (peb_va_ != 0) (void)space_.release_region(peb_va_);
}

Result<void> GuestProcessEnvironment::initialize(std::uint64_t process_id) {
    if (process_id == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument, "process id must be nonzero");
    }
    if (initialized_) {
        return process_id_ == process_id
            ? Result<void>::ok_result()
            : Result<void>(RuntimeErrc::InvalidArgument, "PEB belongs to another process");
    }
    auto peb = allocate_zeroed(space_, memory_, kPageBytes, "guest-peb");
    if (!peb.ok()) return Result<void>(peb.errc(), peb.context());
    peb_va_ = peb.value();
    process_id_ = process_id;
    initialized_ = true;
    return Result<void>::ok_result();
}

Result<void> GuestProcessEnvironment::set_image_base(std::uint64_t image_base) {
    if (!initialized_) return Result<void>(RuntimeErrc::InvalidState, "PEB not initialized");
    return memory_.write_u64(peb_va_ + kPebImageBaseOffset, image_base);
}

Result<std::uint32_t> GuestProcessEnvironment::tls_index_for_image(
    std::uint64_t image_base, std::uint32_t preferred_index) {
    using Ret = Result<std::uint32_t>;
    if (!initialized_) return Ret(RuntimeErrc::InvalidState, "PEB not initialized");
    if (image_base == 0) return Ret(RuntimeErrc::InvalidArgument, "TLS image base must be nonzero");
    std::lock_guard<std::mutex> guard(tls_index_lock_);
    const auto existing = image_tls_indices_.find(image_base);
    if (existing != image_tls_indices_.end()) return Ret(existing->second);

    std::uint32_t selected = GuestThreadEnvironment::kTlsSlotCount;
    if (preferred_index < GuestThreadEnvironment::kTlsSlotCount &&
        !tls_index_used_[preferred_index]) {
        selected = preferred_index;
    } else {
        for (std::uint32_t i = 0; i < GuestThreadEnvironment::kTlsSlotCount; ++i) {
            if (!tls_index_used_[i]) {
                selected = i;
                break;
            }
        }
    }
    if (selected >= GuestThreadEnvironment::kTlsSlotCount) {
        return Ret(RuntimeErrc::OutOfResources, "process TLS module index table is full");
    }
    tls_index_used_[selected] = true;
    image_tls_indices_.emplace(image_base, selected);
    return Ret(selected);
}

GuestThreadEnvironment::GuestThreadEnvironment(AddressSpace& space,
                                                 GuestProcessEnvironment& process)
    : space_(space), process_(process), memory_(space) {}

GuestThreadEnvironment::~GuestThreadEnvironment() { release_all(); }

Result<std::uint64_t> GuestThreadEnvironment::allocate(std::uint64_t size,
                                                        const char* name) {
    auto allocation = allocate_zeroed(space_, memory_, size, name);
    if (allocation.ok()) allocations_.push_back(allocation.value());
    return allocation;
}

void GuestThreadEnvironment::release_all() noexcept {
    for (auto it = allocations_.rbegin(); it != allocations_.rend(); ++it) {
        (void)space_.release_region(*it);
    }
    allocations_.clear();
    tls_blocks_.clear();
    teb_va_ = tls_vector_va_ = 0;
    initialized_ = false;
}

Result<void> GuestThreadEnvironment::initialize(std::uint64_t thread_id) {
    if (initialized_ || !allocations_.empty()) {
        return Result<void>(RuntimeErrc::InvalidState, "thread environment already initialized");
    }
    if (!process_.initialized() || process_.process_id() == 0 || thread_id == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "initialized process environment and nonzero thread id required");
    }
    auto teb = allocate(kPageBytes, "guest-teb");
    if (!teb.ok()) return Result<void>(teb.errc(), teb.context());
    teb_va_ = teb.value();
    auto tls = allocate(kPageBytes, "guest-tls-vector");
    if (!tls.ok()) { release_all(); return Result<void>(tls.errc(), tls.context()); }
    tls_vector_va_ = tls.value();

    const Result<void> writes[] = {
        memory_.write_u64(teb_va_ + kTebSelfOffset, teb_va_),
        memory_.write_u64(teb_va_ + kTebProcessIdOffset, process_.process_id()),
        memory_.write_u64(teb_va_ + kTebThreadIdOffset, thread_id),
        memory_.write_u64(teb_va_ + kTebTlsVectorOffset, tls_vector_va_),
        memory_.write_u64(teb_va_ + kTebPebOffset, process_.peb_base())
    };
    for (const auto& result : writes) {
        if (!result.ok()) {
            const auto errc = result.errc();
            const auto context = result.context();
            release_all();
            return Result<void>(errc, context);
        }
    }
    initialized_ = true;
    return Result<void>::ok_result();
}

Result<void> GuestThreadEnvironment::set_stack_bounds(
    std::uint64_t stack_base, std::uint64_t stack_limit) {
    if (!initialized_) {
        return Result<void>(RuntimeErrc::InvalidState, "TEB not initialized");
    }
    if (stack_limit == 0 || stack_base <= stack_limit) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "stack base must be greater than a nonzero stack limit");
    }
    auto base = memory_.write_u64(teb_va_ + kTebStackBaseOffset, stack_base);
    if (!base.ok()) return base;
    return memory_.write_u64(teb_va_ + kTebStackLimitOffset, stack_limit);
}

Result<std::uint64_t> GuestThreadEnvironment::install_tls_module(
    std::uint32_t index, const std::uint8_t* template_bytes,
    std::size_t template_size, std::size_t zero_fill_bytes) {
    if (!initialized_) return Result<std::uint64_t>(RuntimeErrc::InvalidState, "TEB not initialized");
    if (index >= kTlsSlotCount || (template_size != 0 && template_bytes == nullptr) ||
        template_size > (1u << 20) || zero_fill_bytes > (1u << 20) ||
        template_size > std::numeric_limits<std::size_t>::max() - zero_fill_bytes) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "invalid TLS index, template, or size");
    }
    if (tls_blocks_.count(index) != 0) {
        return Result<std::uint64_t>(RuntimeErrc::AlreadyExists, "TLS index already installed");
    }
    const std::size_t total = std::max<std::size_t>(1, template_size + zero_fill_bytes);
    auto block = allocate(total, "guest-tls-block");
    if (!block.ok()) return block;
    if (template_size != 0) {
        auto copied = memory_.write(block.value(), template_bytes, template_size);
        if (!copied.ok()) {
            (void)space_.release_region(block.value());
            allocations_.pop_back();
            return Result<std::uint64_t>(copied.errc(), copied.context());
        }
    }
    auto slot = memory_.write_u64(tls_vector_va_ + static_cast<std::uint64_t>(index) * 8,
                                  block.value());
    if (!slot.ok()) {
        (void)space_.release_region(block.value());
        allocations_.pop_back();
        return Result<std::uint64_t>(slot.errc(), slot.context());
    }
    tls_blocks_.emplace(index, std::make_pair(block.value(), total));
    return block;
}

Result<void> GuestThreadEnvironment::set_last_error(std::uint32_t error) {
    if (!initialized_) {
        return Result<void>(RuntimeErrc::InvalidState, "TEB not initialized");
    }
    return memory_.write_u32(teb_va_ + kTebLastErrorValueOffset, error);
}

Result<std::uint32_t> GuestThreadEnvironment::last_error() const {
    if (!initialized_) {
        return Result<std::uint32_t>(RuntimeErrc::InvalidState, "TEB not initialized");
    }
    return memory_.read_u32(teb_va_ + kTebLastErrorValueOffset);
}

Result<void> GuestThreadEnvironment::read_tls(std::uint32_t index,
                                               std::uint64_t offset,
                                               void* destination,
                                               std::size_t length) const {
    const auto it = tls_blocks_.find(index);
    if (it == tls_blocks_.end()) return Result<void>(RuntimeErrc::NotFound, "TLS index not installed");
    if (destination == nullptr && length != 0) return Result<void>(RuntimeErrc::InvalidArgument, "null TLS destination");
    if (offset > it->second.second || length > it->second.second - offset) {
        return Result<void>(RuntimeErrc::InvalidArgument, "TLS read outside module block");
    }
    return memory_.read(it->second.first + offset, destination, length);
}

}  // namespace xbox2pc::rt::exec
