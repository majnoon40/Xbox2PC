#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "xbox2pc/guest_memory.hpp"

namespace xbox2pc::rt::exec {

// Process-scoped, minimal x64 user-mode PEB storage. Share one instance
// between every ExecutionContext belonging to the same process.
class GuestProcessEnvironment {
public:
    static constexpr std::uint64_t kPageBytes = 4096;
    static constexpr std::uint64_t kPebImageBaseOffset = 0x10;

    explicit GuestProcessEnvironment(AddressSpace& space);
    ~GuestProcessEnvironment();
    GuestProcessEnvironment(const GuestProcessEnvironment&) = delete;
    GuestProcessEnvironment& operator=(const GuestProcessEnvironment&) = delete;

    Result<void> initialize(std::uint64_t process_id);
    Result<void> set_image_base(std::uint64_t image_base);
    std::uint64_t peb_base() const { return peb_va_; }
    std::uint64_t process_id() const { return process_id_; }
    bool initialized() const { return initialized_; }

private:
    AddressSpace& space_;
    guest::GuestMemory memory_;
    std::uint64_t peb_va_ = 0;
    std::uint64_t process_id_ = 0;
    bool initialized_ = false;
};

// Per-thread TEB and TLS vector. The PEB is borrowed from the shared
// process environment and is never released by this object.
class GuestThreadEnvironment {
public:
    static constexpr std::uint64_t kPageBytes = 4096;
    static constexpr std::uint32_t kTlsSlotCount = 64;
    static constexpr std::uint64_t kTebSelfOffset = 0x30;
    static constexpr std::uint64_t kTebProcessIdOffset = 0x40;
    static constexpr std::uint64_t kTebThreadIdOffset = 0x48;
    static constexpr std::uint64_t kTebTlsVectorOffset = 0x58;
    static constexpr std::uint64_t kTebPebOffset = 0x60;

    GuestThreadEnvironment(AddressSpace& space, GuestProcessEnvironment& process);
    ~GuestThreadEnvironment();
    GuestThreadEnvironment(const GuestThreadEnvironment&) = delete;
    GuestThreadEnvironment& operator=(const GuestThreadEnvironment&) = delete;

    Result<void> initialize(std::uint64_t thread_id);
    Result<std::uint64_t> install_tls_module(std::uint32_t index,
                                             const std::uint8_t* template_bytes,
                                             std::size_t template_size,
                                             std::size_t zero_fill_bytes);
    Result<void> read_tls(std::uint32_t index, std::uint64_t offset,
                          void* destination, std::size_t length) const;

    std::uint64_t teb_base() const { return teb_va_; }
    std::uint64_t peb_base() const { return process_.peb_base(); }
    std::uint64_t tls_vector_base() const { return tls_vector_va_; }
    bool initialized() const { return initialized_; }

private:
    Result<std::uint64_t> allocate(std::uint64_t size, const char* name);
    void release_all() noexcept;

    AddressSpace& space_;
    GuestProcessEnvironment& process_;
    guest::GuestMemory memory_;
    std::uint64_t teb_va_ = 0;
    std::uint64_t tls_vector_va_ = 0;
    std::vector<std::uint64_t> allocations_;
    std::map<std::uint32_t, std::pair<std::uint64_t, std::uint64_t>> tls_blocks_;
    bool initialized_ = false;
};

}  // namespace xbox2pc::rt::exec
