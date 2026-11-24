#include "xbox2pc/guest_environment.hpp"

#include <algorithm>
#include <limits>

namespace xbox2pc::rt::exec {

GuestThreadEnvironment::GuestThreadEnvironment(AddressSpace& space)
    : space_(space), memory_(space) {}

GuestThreadEnvironment::~GuestThreadEnvironment() { release_all(); }

Result<std::uint64_t> GuestThreadEnvironment::allocate(std::uint64_t size,
                                                        const char* name) {
    auto reserved = space_.reserve_region_auto(size, name);
    if (!reserved.ok()) return Result<std::uint64_t>(reserved.errc(), reserved.context());
    auto committed = space_.commit_region(reserved.value());
    if (!committed.ok()) {
        (void)space_.release_region(reserved.value());
        return Result<std::uint64_t>(committed.errc(), committed.context());
    }
    allocations_.push_back(reserved.value());
    const std::uint64_t rounded =
        ((size + space_.page_size() - 1) / space_.page_size()) * space_.page_size();
    std::vector<std::uint8_t> zeros(64u * 1024u, 0);
    for (std::uint64_t offset = 0; offset < rounded;) {
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(zeros.size(), rounded - offset));
        auto cleared = memory_.write(reserved.value() + offset, zeros.data(), chunk);
        if (!cleared.ok()) {
            (void)space_.release_region(reserved.value());
            allocations_.pop_back();
            return Result<std::uint64_t>(cleared.errc(), cleared.context());
        }
        offset += chunk;
    }
    return Result<std::uint64_t>(reserved.value());
}

void GuestThreadEnvironment::release_all() noexcept {
    for (auto it = allocations_.rbegin(); it != allocations_.rend(); ++it) {
        (void)space_.release_region(*it);
    }
    allocations_.clear();
    tls_blocks_.clear();
    teb_va_ = peb_va_ = tls_vector_va_ = 0;
    initialized_ = false;
}

Result<void> GuestThreadEnvironment::initialize(std::uint64_t process_id,
                                                 std::uint64_t thread_id) {
    if (initialized_ || !allocations_.empty()) {
        return Result<void>(RuntimeErrc::InvalidState, "guest environment already initialized");
    }
    if (process_id == 0 || thread_id == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "guest environment requires nonzero process and thread ids");
    }
    auto peb = allocate(kPageBytes, "guest-peb");
    if (!peb.ok()) return Result<void>(peb.errc(), peb.context());
    peb_va_ = peb.value();
    auto teb = allocate(kPageBytes, "guest-teb");
    if (!teb.ok()) { release_all(); return Result<void>(teb.errc(), teb.context()); }
    teb_va_ = teb.value();
    auto tls = allocate(kPageBytes, "guest-tls-vector");
    if (!tls.ok()) { release_all(); return Result<void>(tls.errc(), tls.context()); }
    tls_vector_va_ = tls.value();

    const Result<void> writes[] = {
        memory_.write_u64(teb_va_ + kTebSelfOffset, teb_va_),
        memory_.write_u64(teb_va_ + kTebTlsVectorOffset, tls_vector_va_),
        memory_.write_u64(teb_va_ + kTebPebOffset, peb_va_),
        memory_.write_u64(teb_va_ + kTebProcessIdOffset, process_id),
        memory_.write_u64(teb_va_ + kTebThreadIdOffset, thread_id)
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

Result<void> GuestThreadEnvironment::set_image_base(std::uint64_t image_base) {
    if (!initialized_) return Result<void>(RuntimeErrc::InvalidState, "guest environment not initialized");
    return memory_.write_u64(peb_va_ + kPebImageBaseOffset, image_base);
}

Result<std::uint64_t> GuestThreadEnvironment::install_tls_module(
    std::uint32_t index, const std::uint8_t* template_bytes,
    std::size_t template_size, std::size_t zero_fill_bytes) {
    if (!initialized_) return Result<std::uint64_t>(RuntimeErrc::InvalidState, "guest environment not initialized");
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
