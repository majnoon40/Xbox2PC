// xbox2pc/src/guest_memory.cpp — M8 guest memory access implementation.

#include <array>
#include <algorithm>

#include "xbox2pc/guest_memory.hpp"

namespace xbox2pc::rt::guest {

const char* guest_mem_errc_to_name(GuestMemErrc e) {
    switch (e) {
        case GuestMemErrc::InvalidAddress: return "invalid-address";
        case GuestMemErrc::PermissionDenied: return "permission-denied";
        case GuestMemErrc::Overflow: return "overflow";
        case GuestMemErrc::TooLarge: return "too-large";
        case GuestMemErrc::CrossRegion: return "cross-region";
        case GuestMemErrc::NullPointer: return "null";
    }
    return "?";
}

RuntimeErrc guest_mem_errc_to_runtime(GuestMemErrc e) {
    switch (e) {
        case GuestMemErrc::InvalidAddress:
        case GuestMemErrc::NullPointer:
            return RuntimeErrc::NotFound;          // unmapped guest memory
        case GuestMemErrc::Overflow:
        case GuestMemErrc::TooLarge:
        case GuestMemErrc::CrossRegion:
            return RuntimeErrc::InvalidArgument;   // bad range
        case GuestMemErrc::PermissionDenied:
            return RuntimeErrc::PlatformError;  // protection refusal
    }
    return RuntimeErrc::PlatformError;
}

GuestRange GuestMemory::validate(std::uint64_t va, std::uint64_t len,
                                 bool want_write, bool want_exec) const {
    GuestRange r;
    r.va = va;
    r.len = len;
    if (va == 0) {
        r.err = GuestMemErrc::NullPointer;
        return r;
    }
    if (len == 0) {
        // Zero-length ranges are invalid (an existence probe passes 1).
        r.err = GuestMemErrc::Overflow;
        return r;
    }
    if (len > kMaxGuestOpBytes) {
        r.err = GuestMemErrc::TooLarge;
        return r;
    }
    // Overflow-safe bound: va + len - 1 must not wrap past 2^64-1.
    if (va > (~0ull) - (len - 1)) {
        r.err = GuestMemErrc::Overflow;
        return r;
    }
    // Single-region enforcement: M4's validate_access covers ONE range
    // only when it lies within one region; we first find the region(s).
    // Approach: check the FIRST byte and the LAST byte land in the same
    // region via M4's region lookup — use validate_access on both
    // endpoints and compare protection results; a cross-region range
    // still fails here only if one endpoint is invalid. To be exact,
    // use the region-boundary walk: validate access at va; then at
    // va+len-1; if both pass, additionally require the region covering
    // va to cover va+len-1 (region sizes are power-of... not guaranteed,
    // so walk: we rely on M4's translate() + the region extent check via
    // validate_access semantics: M4's validate_access(va, write, exec)
    // already checks region containment for THAT address. For a range,
    // we walk page-wise at 4096 steps only when the range spans pages.
    // Simpler and exact: use region lookup through stats of the space?
    // The public M4 API exposes validate_access per address; we walk
    // at page granularity (range <= 1 MiB => at most 256 checks).
    const std::uint64_t last = va + len - 1;
    // Endpoint permission checks (typed distinction).
    const auto head = space_.validate_access(va, want_write, want_exec);
    if (!head.ok()) {
        // Distinguish unmapped vs permission: an unmapped address also
        // fails validate_access; M4's error code carries it (NotFound =
        // unmapped; PermissionDenied = mapped, wrong flags).
        r.err = head.errc() == RuntimeErrc::NotFound
                    ? GuestMemErrc::InvalidAddress
                    : GuestMemErrc::PermissionDenied;
        return r;
    }
    const auto tail = space_.validate_access(last, want_write, want_exec);
    if (!tail.ok()) {
        r.err = tail.errc() == RuntimeErrc::NotFound
                    ? GuestMemErrc::InvalidAddress
                    : GuestMemErrc::PermissionDenied;
        return r;
    }
    // Cross-region: walk pages; every intermediate page must validate.
    // If an intermediate page fails, it's either a hole (InvalidAddress)
    // or a protection change mid-range — treat a HOLE as cross-region
    // invalid; a same-flags contiguous mapping passes.
    const std::uint64_t first_page = va & ~4095ull;
    const std::uint64_t last_page = last & ~4095ull;
    for (std::uint64_t p = first_page;;) {
        // Check the first byte of each page touched by the range. Do not
        // use p <= last_page with an unconditional increment: a valid
        // range ending in the top uint64 page would wrap p to zero and
        // loop forever.
        const std::uint64_t probe = p < va ? va : p;
        const auto mid = space_.validate_access(probe, want_write, want_exec);
        if (!mid.ok()) {
            r.err = mid.errc() == RuntimeErrc::NotFound
                        ? GuestMemErrc::CrossRegion
                        : GuestMemErrc::PermissionDenied;
            return r;
        }
        if (p == last_page) break;
        p += 4096;
    }
    return r;   // err stays NullPointer = valid
}

Result<void> GuestMemory::read(std::uint64_t va, void* dst,
                               std::uint64_t len) const {
    if (dst == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument, "null dst");
    }
    const auto r = validate(va, len, false, false);
    if (!r.ok()) {
        return Result<void>(guest_mem_errc_to_runtime(r.err),
                            "guest read [" + std::to_string(va) + ", +" +
                                std::to_string(len) + "): " +
                                guest_mem_errc_to_name(r.err));
    }
    // Byte-wise copy through the validated translate() path: translate
    // maps ONE address to ONE host byte pointer within its region; the
    // region guarantees contiguity, so we translate per page to never
    // walk across a region boundary in host memory.
    std::uint64_t p = va;
    auto* out = static_cast<std::uint8_t*>(dst);
    std::uint64_t remain = len;
    while (remain > 0) {
        const std::uint64_t page_off = p & 4095ull;
        const std::uint64_t chunk = std::min<std::uint64_t>(remain, 4096 - page_off);
        auto host = space_.translate(p);
        if (!host.ok()) {
            return Result<void>(host.errc(), "translate failed mid-read");
        }
        std::memcpy(out, host.value(), static_cast<std::size_t>(chunk));
        out += chunk;
        p += chunk;
        remain -= chunk;
    }
    return Result<void>::ok_result();
}

Result<void> GuestMemory::write(std::uint64_t va, const void* src,
                                std::uint64_t len) {
    if (src == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument, "null src");
    }
    const auto r = validate(va, len, true, false);
    if (!r.ok()) {
        return Result<void>(guest_mem_errc_to_runtime(r.err),
                            "guest write [" + std::to_string(va) + ", +" +
                                std::to_string(len) + "): " +
                                guest_mem_errc_to_name(r.err));
    }
    std::uint64_t p = va;
    auto* in = static_cast<const std::uint8_t*>(src);
    std::uint64_t remain = len;
    while (remain > 0) {
        const std::uint64_t page_off = p & 4095ull;
        const std::uint64_t chunk = std::min<std::uint64_t>(remain, 4096 - page_off);
        auto host = space_.translate(p);
        if (!host.ok()) {
            return Result<void>(host.errc(), "translate failed mid-write");
        }
        std::memcpy(host.value(), in, static_cast<std::size_t>(chunk));
        in += chunk;
        p += chunk;
        remain -= chunk;
    }
    return Result<void>::ok_result();
}

Result<std::uint8_t> GuestMemory::read_u8(std::uint64_t va) const {
    std::uint8_t v = 0;
    auto r = read(va, &v, 1);
    if (!r.ok()) return Result<std::uint8_t>(r.errc(), r.context());
    return Result<std::uint8_t>(v);
}

Result<std::uint16_t> GuestMemory::read_u16(std::uint64_t va) const {
    std::uint16_t v = 0;
    auto r = read(va, &v, 2);
    if (!r.ok()) return Result<std::uint16_t>(r.errc(), r.context());
    return Result<std::uint16_t>(v);
}

Result<std::uint32_t> GuestMemory::read_u32(std::uint64_t va) const {
    std::uint32_t v = 0;
    auto r = read(va, &v, 4);
    if (!r.ok()) return Result<std::uint32_t>(r.errc(), r.context());
    return Result<std::uint32_t>(v);
}

Result<std::uint64_t> GuestMemory::read_u64(std::uint64_t va) const {
    std::uint64_t v = 0;
    auto r = read(va, &v, 8);
    if (!r.ok()) return Result<std::uint64_t>(r.errc(), r.context());
    return Result<std::uint64_t>(v);
}

Result<void> GuestMemory::write_u8(std::uint64_t va, std::uint8_t v) {
    return write(va, &v, 1);
}

Result<void> GuestMemory::write_u16(std::uint64_t va, std::uint16_t v) {
    return write(va, &v, 2);
}

Result<void> GuestMemory::write_u32(std::uint64_t va, std::uint32_t v) {
    return write(va, &v, 4);
}

Result<void> GuestMemory::write_u64(std::uint64_t va, std::uint64_t v) {
    return write(va, &v, 8);
}

Result<std::string> GuestMemory::read_cstr(std::uint64_t va,
                                          std::uint64_t max_len) const {
    // Clamp: guest-controlled max_len never allocates unbounded.
    const std::uint64_t cap = std::min<std::uint64_t>(max_len, kMaxGuestOpBytes);
    if (cap == 0) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "zero max length");
    }
    // Read in bounded chunks (4 KiB), stop at NUL or cap.
    std::string out;
    out.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(cap, 4096)));
    std::uint64_t p = va;
    std::uint64_t read_total = 0;
    while (read_total < cap) {
        const std::uint64_t chunk = std::min<std::uint64_t>(
            4096 - (p & 4095ull), cap - read_total);
        // Validate the chunk as a read range (region + protection).
        const auto rng = validate(p, chunk, false, false);
        if (!rng.ok()) {
            return Result<std::string>(guest_mem_errc_to_runtime(rng.err),
                                       std::string("cstr read: ") +
                                           guest_mem_errc_to_name(rng.err));
        }
        std::array<std::uint8_t, 4096> buf{};
        auto r = read(p, buf.data(), chunk);
        if (!r.ok()) return Result<std::string>(r.errc(), r.context());
        for (std::uint64_t i = 0; i < chunk; ++i) {
            if (buf[static_cast<std::size_t>(i)] == 0) {
                return Result<std::string>(out);
            }
            out.push_back(static_cast<char>(buf[static_cast<std::size_t>(i)]));
        }
        p += chunk;
        read_total += chunk;
    }
    // Hit the cap without a NUL: invalid string.
    return Result<std::string>(RuntimeErrc::InvalidArgument,
                               "no NUL within " + std::to_string(cap) +
                                   " bytes");
}

}  // namespace xbox2pc::rt::guest
