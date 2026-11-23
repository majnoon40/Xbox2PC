#pragma once
// xbox2pc/guest_memory.hpp — M8 safe guest-memory access over M4.
//
// Design (docs/guest-memory.md):
//   - All guest accesses go through GuestMemory, which wraps a process's
//     AddressSpace (M4): every read/write/execute check is a region
//     lookup + permission validation — NO unchecked pointer arithmetic,
//     NO arbitrary guest-address-to-host-pointer conversion outside the
//     validated translate() path.
//   - Operations: typed reads/writes (u8/u16/u32/u64, plus memcpy-style
//     ranges), range validation, permission validation. Integer
//     overflow-safe: every (va, len) is checked as va + len - 1 with
//     64-bit overflow rejection BEFORE any host pointer math.
//   - Cross-region operations are REJECTED (a single range must live in
//     one region) — explicit, not silent.
//   - Errors distinguish InvalidAddress (unmapped) from PermissionDenied
//     (mapped, wrong protection) via a typed GuestMemoryError.
//   - W^X preserved: write checks require the region to be writable
//     (RW/Full); execution checks require RX/Full. The layer NEVER
//     flips protections itself — that is the loader's discipline.
//   - Bound: guest operations are capped at kMaxGuestOpBytes (1 MiB) —
//     no unbounded allocations from guest-controlled sizes.
//
// The API-bridge uses GuestMemory for every pointer dereference
// (marshalling), and the ABI stack writer/reader bind to it.

#include <cstdint>
#include <cstring>
#include <string>

#include "xbox2pc/memory_management.hpp"
#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt::guest {

// Maximum single guest operation (read/write) in bytes.
inline constexpr std::uint64_t kMaxGuestOpBytes = 1ull << 20;

// Typed access failures: unmapped vs permission vs overflow vs bound.
enum class GuestMemErrc : std::uint8_t {
    InvalidAddress = 0,   // not mapped in the address space
    PermissionDenied = 1, // mapped but protection refuses the access
    Overflow = 2,         // va + len overflows 2^64
    TooLarge = 3,         // len above kMaxGuestOpBytes
    CrossRegion = 4,      // range spans two regions
    NullPointer = 5,      // va == 0
};
const char* guest_mem_errc_to_name(GuestMemErrc e);
// Map onto the runtime error code used in Results (with context text).
RuntimeErrc guest_mem_errc_to_runtime(GuestMemErrc e);

// A validated single-region range. RAII is trivial (value type); the
// struct records the region identity so cross-region checks are O(1).
struct GuestRange {
    std::uint64_t va = 0;
    std::uint64_t len = 0;
    GuestMemErrc err = GuestMemErrc::NullPointer;   // NullPointer = unset
    bool ok() const { return err == GuestMemErrc::NullPointer; }
};

// Guest memory accessor for one process's address space. Multiple
// accessors may exist concurrently (AddressSpace is internally locked);
// the accessor itself is stateless beyond the space reference.
class GuestMemory {
public:
    explicit GuestMemory(AddressSpace& space) : space_(space) {}

    // ── validation ──
    // Validate a range for access with `want_write`/`want_exec` flags.
    // Returns a GuestRange: ok() means usable; otherwise err says why
    // (distinguishes unmapped from permission).
    GuestRange validate(std::uint64_t va, std::uint64_t len, bool want_write,
                        bool want_exec) const;

    // Permission check for one address (execute: RX/Full only).
    GuestRange validate_exec(std::uint64_t va) const {
        return validate(va, 1, false, true);
    }

    // ── raw byte ranges ──
    // Reads exactly len bytes into dst; typed errors on any failure.
    Result<void> read(std::uint64_t va, void* dst, std::uint64_t len) const;
    // Writes exactly len bytes from src.
    Result<void> write(std::uint64_t va, const void* src, std::uint64_t len);

    // ── typed ──
    Result<std::uint8_t> read_u8(std::uint64_t va) const;
    Result<std::uint16_t> read_u16(std::uint64_t va) const;
    Result<std::uint32_t> read_u32(std::uint64_t va) const;
    Result<std::uint64_t> read_u64(std::uint64_t va) const;
    Result<void> write_u8(std::uint64_t va, std::uint8_t v);
    Result<void> write_u16(std::uint64_t va, std::uint16_t v);
    Result<void> write_u32(std::uint64_t va, std::uint32_t v);
    Result<void> write_u64(std::uint64_t va, std::uint64_t v);

    // Read a NUL-terminated guest string, bounded (len includes NUL;
    // stops at max_len or first NUL; errors on hitting the bound without
    // NUL or crossing regions). Guest-controlled length never leads to
    // unbounded allocation.
    Result<std::string> read_cstr(std::uint64_t va, std::uint64_t max_len) const;

    // The wrapped space (tests/introspection).
    AddressSpace& space() { return space_; }
    const AddressSpace& space() const { return space_; }

private:
    AddressSpace& space_;
};

}  // namespace xbox2pc::rt::guest
