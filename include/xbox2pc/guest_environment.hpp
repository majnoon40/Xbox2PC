#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "xbox2pc/guest_memory.hpp"

namespace xbox2pc::rt::exec {

// Minimal guest-visible x64 Windows process/thread environment.
// This models documented user-mode TEB/PEB fields; it is not a complete
// NT TEB/PEB implementation and does not configure the host CPU's GS base.
class GuestThreadEnvironment {
public:
    static constexpr std::uint64_t kPageBytes = 4096;
    static constexpr std::uint32_t kTlsSlotCount = 64;
    static constexpr std::uint64_t kTebSelfOffset = 0x30;
    static constexpr std::uint64_t kTebTlsVectorOffset = 0x58;
    static constexpr std::uint64_t kTebPebOffset = 0x60;
    static constexpr std::uint64_t kTebProcessIdOffset = 0x40;
    static constexpr std::uint64_t kTebThreadIdOffset = 0x48;
    static constexpr std::uint64_t kPebImageBaseOffset = 0x10;

    explicit GuestThreadEnvironment(AddressSpace& space);
    ~GuestThreadEnvironment();
    GuestThreadEnvironment(const GuestThreadEnvironment&) = delete;
    GuestThreadEnvironment& operator=(const GuestThreadEnvironment&) = delete;

    Result<void> initialize(std::uint64_t process_id, std::uint64_t thread_id);
    Result<void> set_image_base(std::uint64_t image_base);
    // Installs one module's TLS template at its loader-assigned index.
    // The block is template_bytes followed by zero_fill_bytes of zeroes.
    Result<std::uint64_t> install_tls_module(std::uint32_t index,
                                             const std::uint8_t* template_bytes,
                                             std::size_t template_size,
                                             std::size_t zero_fill_bytes);
    Result<void> read_tls(std::uint32_t index, std::uint64_t offset,
                          void* destination, std::size_t length) const;

    std::uint64_t teb_base() const { return teb_va_; }
    std::uint64_t peb_base() const { return peb_va_; }
    std::uint64_t tls_vector_base() const { return tls_vector_va_; }
    bool initialized() const { return initialized_; }

private:
    Result<std::uint64_t> allocate(std::uint64_t size, const char* name);
    void release_all() noexcept;

    AddressSpace& space_;
    guest::GuestMemory memory_;
    std::uint64_t teb_va_ = 0;
    std::uint64_t peb_va_ = 0;
    std::uint64_t tls_vector_va_ = 0;
    std::vector<std::uint64_t> allocations_;
    std::map<std::uint32_t, std::pair<std::uint64_t, std::uint64_t>> tls_blocks_;
    bool initialized_ = false;
};

}  // namespace xbox2pc::rt::exec
