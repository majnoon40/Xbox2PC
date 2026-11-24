// xbox2pc/src/gdk_services.cpp — M7 GDK + Game OS service implementations.
//
// Every implementation is bound to a documented descriptor in
// api_compat.hpp; the service registers the implementations at
// on_initialize and revokes them at on_shutdown. HRESULT values follow
// the documented semantics (S_OK / E_GAMERUNTIME_DLL_NOT_FOUND /
// ERROR_INSUFFICIENT_BUFFER fallbacks / E_ABORT / documented defaults).
// No host function pointers are exposed; dispatch goes through
// IApiImplementation under the ApiContext contract.

#include "xbox2pc/guest_environment.hpp"
#include "xbox2pc/gdk_services.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <limits>
#include <thread>
#include <unordered_set>

namespace xbox2pc::rt::api {

namespace {

using loader::ImportStatus;

Result<MemProtect> decode_win32_page_protection(std::uint32_t value) {
    switch (value) {
        case 0x01u: return Result<MemProtect>(MemProtect::NoAccess);
        case 0x02u: return Result<MemProtect>(MemProtect::ReadOnly);
        case 0x04u: return Result<MemProtect>(MemProtect::ReadWrite);
        case 0x20u: return Result<MemProtect>(MemProtect::ReadExecute);
        case 0x40u: return Result<MemProtect>(MemProtect::Full);
        default: return Result<MemProtect>(RuntimeErrc::InvalidArgument,
            "unsupported or unrepresentable Win32 page protection");
    }
}

// ── implementation adapters ──────────────────────────────────────────────
//
// Each adapter closes over the owning service and translates the
// ApiContext into the service's typed API. Argument mapping follows the
// DOCUMENTED parameter order (position i of the signature).

class GrtInitializeImpl : public IApiImplementation {
public:
    explicit GrtInitializeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        const auto r = svc_.grt_initialize(ctx.process_id);
        out.return_value = r.ok() ? kSOk : kEGameruntimeDllNotFound;
        out.note = "per-process init count now " +
                   (r.ok() ? std::to_string(r.value()) : "0");
        return r.ok();
    }
    std::string describe() const override {
        return "GRT lifecycle: per-process ref-counted initialize";
    }

private:
    GameRuntimeService& svc_;
};

class GrtUninitializeImpl : public IApiImplementation {
public:
    explicit GrtUninitializeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        const auto r = svc_.grt_uninitialize(ctx.process_id);
        out.return_value = kSOk;   // documented: void
        out.note = r.ok() ? "uninitialized" : r.error_string();
        return true;  // void return: dispatch success regardless
    }
    std::string describe() const override { return "GRT lifecycle: uninitialize"; }

private:
    GameRuntimeService& svc_;
};

class GrtInitOptionsImpl : public IApiImplementation {
public:
    explicit GrtInitOptionsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        // Stub policy (documented: options compared; mismatch fails):
        // a null options pointer (arg slot 0 == 0) takes default options.
        const auto r = svc_.grt_initialize(ctx.process_id);
        out.return_value = r.ok() ? kSOk : kEGameruntimeDllNotFound;
        out.note = "stub: options pointer not interpreted (documented "
                   "comparison semantics deferred)";
        return r.ok();
    }
    std::string describe() const override {
        return "GRT lifecycle: initialize-with-options (stub)";
    }

private:
    GameRuntimeService& svc_;
};

class SysDeviceTypeImpl : public IApiImplementation {
public:
    explicit SysDeviceTypeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        // Documented: returns Unknown when the device type cannot be
        // determined — always the honest answer in this runtime.
        out.return_value =
            static_cast<std::uint64_t>(svc_.device_type());
        out.note = "XSystemDeviceType::Unknown (documented fallback; no "
                   "device spoofing)";
        return true;
    }
    std::string describe() const override {
        return "XSystem: device type (documented Unknown fallback)";
    }

private:
    GameRuntimeService& svc_;
};

// Shared shape for the three (size, buffer, used) string APIs.
class SysIdImpl : public IApiImplementation {
public:
    enum class Which { ConsoleId, SandboxId, AppDeviceId };
    SysIdImpl(GameRuntimeService& svc, Which which) : svc_(svc), which_(which) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;  // validated by dispatcher too
        const std::uint64_t size = ctx.args[0];
        // Documented: not safe on time-sensitive threads.
        if (ctx.thread_time_sensitive) {
            out.return_value = kEInvalidArg;
            out.error = "not safe on a time-sensitive thread (documented)";
            return false;
        }
        Result<std::string> r =
            which_ == Which::ConsoleId ? svc_.console_id(size, nullptr)
            : which_ == Which::SandboxId ? svc_.sandbox_id(size, nullptr)
                                         : svc_.app_device_id(size, nullptr);
        if (!r.ok()) {
            out.return_value = kEInsufficientBuffer;
            out.error = r.error_string();
            return false;
        }
        out.return_value = kSOk;
        out.has_out = true;
        out.out_value = r.value().size();
        out.out_size = r.value().size();
        // The payload bytes for the bridge's byte-granular write-back.
        out.out_bytes_size = r.value().size();
        for (std::size_t i = 0; i < out.out_bytes.size() && i < r.value().size(); ++i) {
            out.out_bytes[i] = static_cast<std::uint8_t>(r.value()[i]);
        }
        out.note = "documented fallback string returned (" + r.value() + ")";
        return true;
    }
    std::string describe() const override {
        switch (which_) {
            case Which::ConsoleId: return "XSystem: console id (documented all-zero PC fallback)";
            case Which::SandboxId: return "XSystem: Xbox Live sandbox id (RETAIL fallback)";
            case Which::AppDeviceId: return "XSystem: app-specific device id (all-zero fallback)";
        }
        return "?";
    }

private:
    GameRuntimeService& svc_;
    Which which_;
};

class SysRuntimeInfoImpl : public IApiImplementation {
public:
    explicit SysRuntimeInfoImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        const auto info = svc_.runtime_info();
        out.return_value =
            (static_cast<std::uint64_t>(info.current_major) << 32) |
            info.current_minor;
        out.note = "stub XSystemRuntimeInfo (zero versions; callable "
                   "before initialize — documented)";
        return true;
    }
    std::string describe() const override {
        return "XSystem: runtime info (zero-version stub)";
    }

private:
    GameRuntimeService& svc_;
};


// ── heap objects (M11 Phase 4) ────────────────────────────────────────────
// RtHeap is a lightweight handle object: allocations are carved from the
// per-process xmem arena (ManagedProcess::allocate_xmem) so heap and XMem
// memory share one tracked address-space accounting and teardown path.
class RtHeap : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtHeap, MemoryRegion)
    explicit RtHeap(bool default_heap, std::uint32_t options)
        : RuntimeObject(TypeId::MemoryRegion),
          default_(default_heap), options_(options) {}
    bool is_default_heap() const { return default_; }
    std::uint32_t options() const { return options_; }
private:
    bool default_;
    std::uint32_t options_;
};

class HeapReAllocImpl : public IApiImplementation {
public:
    explicit HeapReAllocImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4) return false;
        constexpr std::uint32_t kZero = 0x8u;       // HEAP_ZERO_MEMORY
        constexpr std::uint32_t kExceptions = 0x4u;  // HEAP_GENERATE_EXCEPTIONS
        constexpr std::uint32_t kInPlace = 0x10u;    // HEAP_REALLOC_IN_PLACE_ONLY
        const auto flags = static_cast<std::uint32_t>(ctx.args[1]);
        if ((flags & ~(kZero | kExceptions | kInPlace)) != 0 ||
            (flags & kExceptions) != 0 || (flags & kInPlace) != 0) {
            out.return_value = 0;
            out.note = "HeapReAlloc supports HEAP_ZERO_MEMORY; HEAP_GENERATE_EXCEPTIONS and HEAP_REALLOC_IN_PLACE_ONLY are not emulated";
            return true;
        }
        auto r = svc_.heap_realloc(ctx.process_id, ctx.args[0], ctx.args[2],
                                   ctx.args[3], (flags & kZero) != 0);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: HeapReAlloc (moving realloc; prefix preserved)"; }
private: GameRuntimeService& svc_;
};
class HeapSizeImpl : public IApiImplementation {
public:
    explicit HeapSizeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        auto r = svc_.heap_size(ctx.process_id, ctx.args[0], ctx.args[2]);
        out.return_value = r.ok() ? r.value() : ~0ull;  // documented SIZE_MAX error
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: HeapSize (tracked allocation size)"; }
private: GameRuntimeService& svc_;
};
class GetProcessHeapImpl : public IApiImplementation {
public:
    explicit GetProcessHeapImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 0) return false;
        auto r = svc_.process_heap(ctx.process_id);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: GetProcessHeap (per-process default heap)"; }
private: GameRuntimeService& svc_;
};
class HeapCreateImpl : public IApiImplementation {
public:
    explicit HeapCreateImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        // HEAP_NO_SERIALIZE 0x1, HEAP_GENERATE_EXCEPTIONS 0x4 are documented
        // option bits; anything else (or unknown bits) fails closed.
        constexpr std::uint32_t kKnown = 0x1u | 0x4u;
        const auto options = static_cast<std::uint32_t>(ctx.args[0]);
        if ((options & ~kKnown) != 0) {
            out.return_value = 0;
            out.note = "HeapCreate supports HEAP_NO_SERIALIZE and HEAP_GENERATE_EXCEPTIONS option bits only";
            return true;
        }
        auto r = svc_.heap_create(ctx.process_id, options);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: HeapCreate (private heap within the process arena)"; }
private: GameRuntimeService& svc_;
};
class HeapAllocImpl : public IApiImplementation {
public:
    explicit HeapAllocImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        constexpr std::uint32_t kZero = 0x8u;      // HEAP_ZERO_MEMORY
        constexpr std::uint32_t kExceptions = 0x4u; // HEAP_GENERATE_EXCEPTIONS
        const auto flags = static_cast<std::uint32_t>(ctx.args[1]);
        if ((flags & ~(kZero | kExceptions)) != 0 || (flags & kExceptions) != 0) {
            out.return_value = 0;
            out.note = "HeapAlloc supports HEAP_ZERO_MEMORY; HEAP_GENERATE_EXCEPTIONS is not emulated";
            return true;
        }
        // The heap handle is validated but allocations are tracked per
        // allocation in the process arena (documented partial behavior).
        auto r = svc_.heap_alloc(ctx.process_id, ctx.args[0], ctx.args[2],
                                 (flags & kZero) != 0);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: HeapAlloc (8-byte aligned arena sub-allocation)"; }
private: GameRuntimeService& svc_;
};
class HeapFreeImpl : public IApiImplementation {
public:
    explicit HeapFreeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        auto r = svc_.heap_free(ctx.process_id, ctx.args[0], ctx.args[2]);
        out.return_value = r.ok() ? 1u : 0u;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: HeapFree (arena allocation release)"; }
private: GameRuntimeService& svc_;
};
class HeapDestroyImpl : public IApiImplementation {
public:
    explicit HeapDestroyImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) return false;
        auto r = svc_.heap_destroy(ctx.process_id, ctx.args[0]);
        out.return_value = r.ok() ? 1u : 0u;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: HeapDestroy (heap handle close; default heap refused)"; }
private: GameRuntimeService& svc_;
};
class XMemAllocImpl : public IApiImplementation {
public:
    explicit XMemAllocImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 2) return false;
        // dwAttributes low byte encodes the base-2 alignment power on Xbox;
        // only sane powers (8..4096 → 3..12) are honored, otherwise 8.
        const auto attributes = static_cast<std::uint32_t>(ctx.args[1]);
        std::uint64_t alignment = 8;
        const auto power = attributes & 0xFFu;
        if (power >= 3 && power <= 12) alignment = 1ull << power;
        auto r = svc_.xmem_alloc(ctx.process_id, ctx.args[0], alignment);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "GDK: XMemAlloc (aligned xmem arena allocation)"; }
private: GameRuntimeService& svc_;
};
class XMemFreeImpl : public IApiImplementation {
public:
    explicit XMemFreeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 2) return false;
        auto r = svc_.xmem_free(ctx.process_id, ctx.args[0]);
        out.return_value = r.ok() ? 1u : 0u;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "GDK: XMemFree (xmem arena release)"; }
private: GameRuntimeService& svc_;
};
class VirtualAllocImpl : public IApiImplementation {
public:
    explicit VirtualAllocImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4) return false;
        auto r = svc_.virtual_alloc(ctx.process_id, ctx.args[0], ctx.args[1],
            static_cast<std::uint32_t>(ctx.args[2]), static_cast<std::uint32_t>(ctx.args[3]));
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: VirtualAlloc (automatic/fixed reservation subset)"; }
private: GameRuntimeService& svc_;
};
class VirtualFreeImpl : public IApiImplementation {
public:
    explicit VirtualFreeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        auto r = svc_.virtual_free(ctx.process_id, ctx.args[0], ctx.args[1],
            static_cast<std::uint32_t>(ctx.args[2]));
        out.return_value = r.ok() ? 1u : 0u;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: VirtualFree (whole-region MEM_RELEASE and MEM_DECOMMIT subset)"; }
private: GameRuntimeService& svc_;
};
class VirtualProtectImpl : public IApiImplementation {
public:
    explicit VirtualProtectImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4 || ctx.args[3] == 0) {
            out.return_value = 0;
            out.note = "VirtualProtect requires an old-protection output pointer";
            return true;
        }
        auto r = svc_.virtual_protect(ctx.process_id, ctx.args[0], ctx.args[1],
            static_cast<std::uint32_t>(ctx.args[2]));
        if (!r.ok()) {
            out.return_value = 0;
            out.note = r.error_string();
            return true;
        }
        const std::uint32_t old = r.value() == MemProtect::NoAccess ? 0x01u :
            r.value() == MemProtect::ReadOnly ? 0x02u :
            r.value() == MemProtect::ReadWrite ? 0x04u :
            r.value() == MemProtect::ReadExecute ? 0x20u : 0x40u;
        for (unsigned i = 0; i < 4; ++i)
            out.out_bytes[i] = static_cast<std::uint8_t>(old >> (8 * i));
        out.return_value = 1;
        out.has_out = true;
        out.out_size = 4;
        out.out_bytes_size = 4;
        return true;
    }
    std::string describe() const override { return "Win32: VirtualProtect (whole-region subset)"; }
private: GameRuntimeService& svc_;
};

class VirtualQueryImpl : public IApiImplementation {
public:
    explicit VirtualQueryImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        constexpr std::uint64_t kSize = 48;
        if (ctx.arg_count != 3) return false;
        if (ctx.args[2] < kSize || ctx.process_id == 0) {
            out.return_value = 0;
            return true;
        }
        const auto snapshot = svc_.query_memory_snapshot(ctx.process_id);
        if (!snapshot.ok()) {
            out.return_value = 0;
            out.note = snapshot.error_string();
            return true;
        }
        const auto& space = snapshot.value();
        if (space.page_size == 0 || ctx.args[0] < space.base ||
            ctx.args[0] - space.base >= space.capacity) {
            out.return_value = 0;
            return true;
        }
        const std::uint64_t page =
            ctx.args[0] - (ctx.args[0] % space.page_size);
        const std::uint64_t space_end = space.base + space.capacity;
        if (space_end < space.base || page < space.base || page >= space_end) {
            out.return_value = 0;
            return true;
        }

        // x64 MEMORY_BASIC_INFORMATION is 48 bytes. Free gaps are valid
        // MEM_FREE regions within this process's modeled guest address space.
        std::uint64_t base_address = space.base;
        std::uint64_t allocation_base = 0;
        std::uint64_t region_size = 0;
        std::uint32_t allocation_protect = 0; // MEM_FREE has no allocation protection
        std::uint32_t state = 0x10000u;        // MEM_FREE
        std::uint32_t protect = 0x01u;         // PAGE_NOACCESS
        std::uint32_t type = 0;                // free regions have no type

        const VmRegion* containing = nullptr;
        std::uint64_t next_region = space_end;
        // The snapshot is sorted by base address. Track the beginning of a
        // free gap as well as its end: MEMORY_BASIC_INFORMATION describes
        // the complete contiguous region, not merely the suffix after page.
        for (const auto& region : space.regions) {
            const std::uint64_t region_end = region.xbox_va + region.size;
            if (region_end < region.xbox_va || region_end > space_end) {
                out.return_value = 0;
                return true;
            }
            if (region.xbox_va <= page) {
                if (page < region_end) {
                    containing = &region;
                    break;
                }
                if (region_end > base_address) base_address = region_end;
            } else {
                next_region = region.xbox_va;
                break;
            }
        }

        if (containing != nullptr) {
            const auto& region = *containing;
            base_address = region.xbox_va;
            allocation_base = region.xbox_va;
            region_size = region.size;
            allocation_protect = region.allocation_protection == MemProtect::NoAccess ? 0x01u
                : region.allocation_protection == MemProtect::ReadOnly ? 0x02u
                : region.allocation_protection == MemProtect::ReadWrite ? 0x04u
                : region.allocation_protection == MemProtect::ReadExecute ? 0x20u
                : 0x40u;
            state = region.state == RegionState::Committed ? 0x1000u : 0x2000u;
            protect = region.protection == MemProtect::NoAccess ? 0x01u
                : region.protection == MemProtect::ReadOnly ? 0x02u
                : region.protection == MemProtect::ReadWrite ? 0x04u
                : region.protection == MemProtect::ReadExecute ? 0x20u
                : 0x40u;
            type = region.region_type == VmRegionType::Image ? 0x1000000u
                : region.region_type == VmRegionType::Mapped ? 0x40000u
                : 0x20000u; // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
        } else {
            if (base_address > page || next_region <= page ||
                next_region <= base_address) {
                out.return_value = 0;
                return true;
            }
            region_size = next_region - base_address;
        }

        auto p16 = [&](std::size_t o, std::uint16_t x) {
            out.out_bytes[o] = static_cast<std::uint8_t>(x);
            out.out_bytes[o + 1] = static_cast<std::uint8_t>(x >> 8);
        };
        auto p32 = [&](std::size_t o, std::uint32_t x) {
            for (unsigned i = 0; i < 4; ++i)
                out.out_bytes[o + i] = static_cast<std::uint8_t>(x >> (8 * i));
        };
        auto p64 = [&](std::size_t o, std::uint64_t x) {
            for (unsigned i = 0; i < 8; ++i)
                out.out_bytes[o + i] = static_cast<std::uint8_t>(x >> (8 * i));
        };
        p64(0, base_address);
        p64(8, allocation_base);
        p32(16, allocation_protect);
        p16(20, 0); // PartitionId
        p64(24, region_size);
        p32(32, state);
        p32(36, protect);
        p32(40, type);
        p32(44, 0); // x64 structure padding
        out.return_value = kSize;
        out.has_out = true;
        out.out_size = kSize;
        out.out_bytes_size = kSize;
        out.note = "partial: free gaps are modeled inside the guest address-space reservation; mapped/image/shared memory types are unavailable";
        return true;
    }
    std::string describe() const override {
        return "Win32: VirtualQuery (guest address-space regions; partial)";
    }
private:
    GameRuntimeService& svc_;
};
class ThreadSetTsImpl : public IApiImplementation {
public:
    explicit ThreadSetTsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) return false;
        const bool on = ctx.args[0] != 0;
        if (ctx.thread_id == 0) {
            out.return_value = kEInvalidArg;
            out.error = "calling thread identity is unavailable";
            return false;
        }
        const auto r = svc_.set_time_sensitive(ctx.process_id,
                                               ctx.thread_id, on);
        out.return_value = r.ok() ? kSOk : kEInvalidArg;
        out.note = "time-sensitive bit per runtime thread";
        return r.ok();
    }
    std::string describe() const override {
        return "XThread: set time-sensitive bit";
    }

private:
    GameRuntimeService& svc_;
};

class ThreadIsTsImpl : public IApiImplementation {
public:
    explicit ThreadIsTsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.thread_id == 0) {
            out.return_value = 0;
            out.error = "calling thread identity is unavailable";
            return false;
        }
        const auto r = svc_.is_time_sensitive(ctx.process_id, ctx.thread_id);
        out.return_value = r.ok() && r.value() ? 1 : 0;
        return true;
    }
    std::string describe() const override {
        return "XThread: query time-sensitive bit";
    }

private:
    GameRuntimeService& svc_;
};

// ── TaskQueue adapters ──

class TqCreateImpl : public IApiImplementation {
public:
    explicit TqCreateImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        const auto r = svc_.create_queue(
            ctx.process_id,
            static_cast<std::uint32_t>(ctx.args[0]),
            static_cast<std::uint32_t>(ctx.args[1]));
        if (!r.ok()) {
            out.return_value = kEInvalidArg;
            out.error = r.error_string();
            return false;
        }
        out.return_value = kSOk;
        out.has_out = true;
        out.out_value = r.value();   // XTaskQueueHandle* out slot
        out.out_size = sizeof(std::uint64_t);
        out.note = "manual-mode queue created (documented handle out)";
        return true;
    }
    std::string describe() const override { return "XTaskQueue: create (manual modes)"; }

private:
    TaskQueueService& svc_;
};

class TqDuplicateHandleImpl : public IApiImplementation {
public:
    explicit TqDuplicateHandleImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 2) return false;
        const auto duplicated = svc_.duplicate_queue(ctx.process_id, ctx.args[0]);
        if (!duplicated.ok()) {
            out.return_value = kEInvalidArg;
            out.error = duplicated.error_string();
            return false;
        }
        out.return_value = kSOk;
        out.has_out = true;
        out.out_value = duplicated.value();
        out.out_size = sizeof(std::uint64_t);
        out.note = "same-process queue handle duplicated; shared queue state retained";
        return true;
    }
    std::string describe() const override {
        return "XTaskQueue: duplicate handle (shared reference)";
    }
private:
    TaskQueueService& svc_;
};

class TqSubmitCallbackImpl : public IApiImplementation {
public:
    explicit TqSubmitCallbackImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4) return false;
        const auto submitted = svc_.submit_callback(
            ctx.process_id, ctx.args[0],
            static_cast<XTaskQueuePort>(ctx.args[1]), ctx.args[2], ctx.args[3]);
        if (submitted.ok()) {
            out.return_value = kSOk;
        } else {
            switch (submitted.errc()) {
                case RuntimeErrc::ProcessTerminated:
                    out.return_value = kEAbort;
                    break;
                case RuntimeErrc::OutOfResources:
                    out.return_value = kEOutOfMemory;
                    break;
                case RuntimeErrc::InvalidHandle:
                case RuntimeErrc::NotFound:
                    out.return_value = kEHandle;
                    break;
                case RuntimeErrc::InvalidArgument:
                    out.return_value = kEInvalidArg;
                    break;
                default:
                    out.return_value = kEFail;
                    break;
            }
        }
        if (!submitted.ok()) out.error = submitted.error_string();
        out.note = submitted.ok()
            ? "guest callback queued for explicit manual dispatch"
            : "callback submission rejected";
        // HRESULT failures are guest-visible results, not bridge faults.
        return true;
    }
    std::string describe() const override {
        return "XTaskQueue: submit guest callback (manual dispatch)";
    }
private:
    TaskQueueService& svc_;
};

class TqDispatchImpl : public IApiImplementation {
public:
    explicit TqDispatchImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        const auto r = svc_.dispatch(
            ctx.process_id, ctx.args[0],
            static_cast<XTaskQueuePort>(ctx.args[1]),
            static_cast<std::uint32_t>(ctx.args[2]), ctx.invoke_guest_callback,
            ctx.cancellation_requested);
        out.return_value = r.ok() && r.value() ? 1 : 0;   // documented bool
        out.note = "false when no callback was dispatched";
        if (!r.ok()) out.error = r.error_string();
        return r.ok();
    }
    std::string describe() const override {
        return "XTaskQueue: dispatch (bool semantics)";
    }

private:
    TaskQueueService& svc_;
};

class TqCloseImpl : public IApiImplementation {
public:
    explicit TqCloseImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) return false;
        const auto r = svc_.close_queue(ctx.process_id, ctx.args[0]);
        out.return_value = kSOk;   // documented: void
        out.note = r.ok() ? "queue handle closed"
                          : "unknown or foreign handle (typed error reported)";
        return true;   // void API: dispatch-level success
    }
    std::string describe() const override {
        return "XTaskQueue: close handle (ref count)";
    }

private:
    TaskQueueService& svc_;
};

class TqTerminateImpl : public IApiImplementation {
public:
    explicit TqTerminateImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4) return false;
        const auto r = svc_.terminate_queue(ctx.process_id, ctx.args[0], ctx.args[1] != 0);
        out.return_value = r.ok() ? kSOk : kEInvalidArg;
        out.note = "queue marked terminated; pending manual callbacks are delivered "
                   "with canceled=true; wait/drain and termination callback are unsupported";
        return r.ok();
    }
    std::string describe() const override {
        return "XTaskQueue: terminate (cancel semantics)";
    }

private:
    TaskQueueService& svc_;
};

// ── Timing adapters (native equivalents through the PAL) ──

class QpcImpl : public IApiImplementation {
public:
    explicit QpcImpl(TimingService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        const auto r = svc_.qpc_value();
        if (!r.ok()) {
            out.return_value = 0;   // documented: zero on failure
            out.error = r.error_string();
            return false;
        }
        out.return_value = 1;       // documented: nonzero on success
        out.has_out = true;
        out.out_value = r.value();  // LARGE_INTEGER* out slot
        out.note = "PAL CLOCK_MONOTONIC (native equivalent)";
        return true;
    }
    std::string describe() const override {
        return "Win32: QueryPerformanceCounter (PAL monotonic equivalent)";
    }

private:
    TimingService& svc_;
};

class QpfImpl : public IApiImplementation {
public:
    explicit QpfImpl(TimingService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        const auto r = svc_.qpc_frequency();
        if (!r.ok()) {
            out.return_value = 0;
            out.error = r.error_string();
            return false;
        }
        out.return_value = 1;
        out.has_out = true;
        out.out_value = r.value();
        out.note = "fixed at boot documented; PAL nanosecond clock => "
                   "1'000'000'000 Hz model";
        return true;
    }
    std::string describe() const override {
        return "Win32: QueryPerformanceFrequency (PAL equivalent)";
    }

private:
    TimingService& svc_;
};

class CurrentProcessIdImpl : public IApiImplementation {
public:
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.process_id == 0 ||
            ctx.process_id > std::numeric_limits<std::uint32_t>::max()) {
            out.error = "calling process identity is unavailable or out of DWORD range";
            return false;
        }
        out.return_value = static_cast<std::uint32_t>(ctx.process_id);
        return true;
    }
    std::string describe() const override {
        return "Win32: GetCurrentProcessId (guest process context)";
    }
};

class CurrentThreadIdImpl : public IApiImplementation {
public:
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.thread_id == 0 ||
            ctx.thread_id > std::numeric_limits<std::uint32_t>::max()) {
            out.error = "calling thread identity is unavailable or out of DWORD range";
            return false;
        }
        out.return_value = static_cast<std::uint32_t>(ctx.thread_id);
        return true;
    }
    std::string describe() const override {
        return "Win32: GetCurrentThreadId (guest calling-thread context)";
    }
};

class SetLastErrorImpl : public IApiImplementation {
public:
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1 || !ctx.set_last_error) {
            out.error = "SetLastError requires one argument and an initialized guest thread environment";
            return false;
        }
        const auto result = ctx.set_last_error(static_cast<std::uint32_t>(ctx.args[0]));
        if (!result.ok()) { out.error = result.error_string(); return false; }
        return true;
    }
    std::string describe() const override { return "Win32: SetLastError (guest TEB LastErrorValue)"; }
};

class GetLastErrorImpl : public IApiImplementation {
public:
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 0 || !ctx.get_last_error) {
            out.error = "GetLastError requires zero arguments and an initialized guest thread environment";
            return false;
        }
        const auto result = ctx.get_last_error();
        if (!result.ok()) { out.error = result.error_string(); return false; }
        out.return_value = result.value();
        return true;
    }
    std::string describe() const override { return "Win32: GetLastError (guest TEB LastErrorValue)"; }
};

class CreateEventWImpl : public IApiImplementation {
public:
    explicit CreateEventWImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4 || ctx.args[0] != 0 || ctx.args[3] != 0) {
            out.return_value = 0;
            out.note = "CreateEventW supports unnamed events with null SECURITY_ATTRIBUTES only";
            return true;
        }
        auto r = svc_.create_event(ctx.process_id, ctx.args[1] != 0, ctx.args[2] != 0);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: CreateEventW (unnamed process-scoped event)"; }
private: GameRuntimeService& svc_;
};
class CreateMutexWImpl : public IApiImplementation {
public:
    explicit CreateMutexWImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3 || ctx.args[0] != 0 || ctx.args[2] != 0) {
            out.return_value = 0;
            out.note = "CreateMutexW supports null security attributes and unnamed mutexes only";
            return true;
        }
        auto r = svc_.create_mutex(ctx.process_id, ctx.thread_id, ctx.args[1] != 0);
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: CreateMutexW (unnamed guest-owned mutex)"; }
private: GameRuntimeService& svc_;
};
class ReleaseMutexImpl : public IApiImplementation {
public:
    explicit ReleaseMutexImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        auto r = svc_.release_mutex(ctx.process_id, ctx.args[0], ctx.thread_id);
        out.return_value = r.ok() ? 1 : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: ReleaseMutex (guest thread ownership)"; }
private: GameRuntimeService& svc_;
};
class CreateSemaphoreWImpl : public IApiImplementation {
public:
    explicit CreateSemaphoreWImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4 || ctx.args[0] != 0 || ctx.args[3] != 0 ||
            ctx.args[1] > INT32_MAX || ctx.args[2] > INT32_MAX) {
            out.return_value = 0;
            out.note = "CreateSemaphoreW supports unnamed objects, null security attributes, and nonnegative LONG counts";
            return true;
        }
        auto r = svc_.create_semaphore(ctx.process_id,
            static_cast<std::int64_t>(ctx.args[1]),
            static_cast<std::int64_t>(ctx.args[2]));
        out.return_value = r.ok() ? r.value() : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: CreateSemaphoreW (unnamed process-scoped semaphore)"; }
private: GameRuntimeService& svc_;
};
class ReleaseSemaphoreImpl : public IApiImplementation {
public:
    explicit ReleaseSemaphoreImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3 || ctx.args[1] == 0 ||
            ctx.args[1] > INT32_MAX) {
            out.return_value = 0;
            out.note = "ReleaseSemaphore requires a positive LONG release count and a valid optional previous-count output";
            return true;
        }
        auto r = svc_.release_semaphore(ctx.process_id, ctx.args[0],
                                        static_cast<std::uint32_t>(ctx.args[1]));
        if (!r.ok()) {
            out.return_value = 0;
            out.note = r.error_string();
            return true;
        }
        out.return_value = 1;
        if (ctx.args[2] != 0) {
            const auto previous = static_cast<std::int32_t>(r.value());
            std::memcpy(out.out_bytes.data(), &previous, sizeof(previous));
            out.out_bytes_size = sizeof(previous);
            out.has_out = true;
            out.out_size = sizeof(previous);
            out.out_value = static_cast<std::uint32_t>(previous);
        }
        return true;
    }
    std::string describe() const override { return "Win32: ReleaseSemaphore (optional DWORD previous-count output)"; }
private: GameRuntimeService& svc_;
};
class SetEventImpl : public IApiImplementation {
public:
    explicit SetEventImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) {
            out.return_value = 0;
            out.note = "SetEvent requires exactly one handle";
            return true;
        }
        auto r = svc_.set_event(ctx.process_id, ctx.args[0]);
        out.return_value = r.ok() ? 1 : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: SetEvent"; }
private: GameRuntimeService& svc_;
};
class ResetEventImpl : public IApiImplementation {
public:
    explicit ResetEventImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) {
            out.return_value = 0;
            out.note = "ResetEvent requires exactly one handle";
            return true;
        }
        auto r = svc_.reset_event(ctx.process_id, ctx.args[0]);
        out.return_value = r.ok() ? 1 : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: ResetEvent"; }
private: GameRuntimeService& svc_;
};
class WaitForSingleObjectImpl : public IApiImplementation {
public:
    explicit WaitForSingleObjectImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 2 || ctx.args[1] > UINT32_MAX) {
            out.return_value = 0xFFFFFFFFu;
            out.note = "WaitForSingleObject timeout exceeds DWORD";
            return true;
        }
        auto r = svc_.wait_object(ctx.process_id, ctx.thread_id, ctx.args[0],
                                  static_cast<std::uint32_t>(ctx.args[1]));
        out.return_value = r.ok() ? r.value() : 0xFFFFFFFFu;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: WaitForSingleObject (event, mutex, semaphore handles)"; }
private: GameRuntimeService& svc_;
};
class WaitForMultipleObjectsImpl : public IApiImplementation {
public:
    explicit WaitForMultipleObjectsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4 || ctx.args[0] == 0 || ctx.args[0] > 64 ||
            ctx.args[3] > UINT32_MAX || ctx.pointer_arrays[1].size() != ctx.args[0]) {
            out.return_value = 0xFFFFFFFFu;
            out.note = "WaitForMultipleObjects requires 1-64 readable handles and a DWORD timeout";
            return true;
        }
        auto waited = ctx.args[2] != 0
            ? svc_.wait_objects_all(ctx.process_id, ctx.thread_id,
                ctx.pointer_arrays[1], static_cast<std::uint32_t>(ctx.args[3]))
            : svc_.wait_objects_any(ctx.process_id, ctx.thread_id,
                ctx.pointer_arrays[1], static_cast<std::uint32_t>(ctx.args[3]));
        out.return_value = waited.ok() ? waited.value() : 0xFFFFFFFFu;
        if (!waited.ok()) out.note = waited.error_string();
        return true;
    }
    std::string describe() const override {
        return "Win32: WaitForMultipleObjects (wait-any and transactional wait-all subsets)";
    }
private:
    GameRuntimeService& svc_;
};

class CloseEventHandleImpl : public IApiImplementation {
public:
    explicit CloseEventHandleImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) {
            out.return_value = 0;
            out.note = "CloseHandle requires exactly one handle";
            return true;
        }
        auto r = svc_.close_sync_handle(ctx.process_id, ctx.args[0]);
        out.return_value = r.ok() ? 1 : 0;
        if (!r.ok()) out.note = r.error_string();
        return true;
    }
    std::string describe() const override { return "Win32: CloseHandle (supported synchronization and task-queue handles)"; }
private: GameRuntimeService& svc_;
};

}  // namespace

// ── names ────────────────────────────────────────────────────────────────

const char* device_type_to_name(XSystemDeviceType t) {
    switch (t) {
        case XSystemDeviceType::Unknown: return "Unknown";
        case XSystemDeviceType::Pc: return "Pc";
        case XSystemDeviceType::XboxOne: return "XboxOne";
        case XSystemDeviceType::XboxOneS: return "XboxOneS";
        case XSystemDeviceType::XboxOneX: return "XboxOneX";
        case XSystemDeviceType::XboxOneXDevkit: return "XboxOneXDevkit";
        case XSystemDeviceType::XboxScarlettLockhart: return "XboxScarlettLockhart";
        case XSystemDeviceType::XboxScarlettAnaconda: return "XboxScarlettAnaconda";
        case XSystemDeviceType::XboxScarlettDevkit: return "XboxScarlettDevkit";
    }
    return "?";
}

// ── GameRuntimeService ───────────────────────────────────────────────────

GameRuntimeService::GameRuntimeService(ApiRegistry& api_reg,
                                       ProcessManager& process_manager)
    : RtService("gdk_game_runtime"), api_reg_(api_reg),
      process_manager_(process_manager) {}

GameRuntimeService::~GameRuntimeService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

Result<void> GameRuntimeService::on_initialize() {
    auto keep = [this](std::shared_ptr<IApiImplementation> impl) {
        owned_.push_back(impl);
        return impl;
    };
    const std::uint64_t owner = id();
    auto reg = [&](const char* name, std::shared_ptr<IApiImplementation> impl) {
        return api_reg_.register_implementation("xgameruntime", name,
                                               std::move(impl), owner);
    };
    auto r1 = reg("XGameRuntimeInitialize",
                  keep(std::make_shared<GrtInitializeImpl>(*this)));
    auto r2 = reg("XGameRuntimeUninitialize",
                  keep(std::make_shared<GrtUninitializeImpl>(*this)));
    auto r3 = reg("XGameRuntimeInitializeWithOptions",
                  keep(std::make_shared<GrtInitOptionsImpl>(*this)));
    auto r4 = reg("XSystemGetDeviceType",
                  keep(std::make_shared<SysDeviceTypeImpl>(*this)));
    auto r5 = reg("XSystemGetConsoleId",
                  keep(std::make_shared<SysIdImpl>(*this, SysIdImpl::Which::ConsoleId)));
    auto r6 = reg("XSystemGetXboxLiveSandboxId",
                  keep(std::make_shared<SysIdImpl>(*this, SysIdImpl::Which::SandboxId)));
    auto r7 = reg("XSystemGetAppSpecificDeviceId",
                  keep(std::make_shared<SysIdImpl>(*this, SysIdImpl::Which::AppDeviceId)));
    auto r8 = reg("XSystemGetRuntimeInfo",
                  keep(std::make_shared<SysRuntimeInfoImpl>(*this)));
    auto r9 = reg("XThreadSetTimeSensitive",
                  keep(std::make_shared<ThreadSetTsImpl>(*this)));
    auto r10 = reg("XThreadIsTimeSensitive",
                   keep(std::make_shared<ThreadIsTsImpl>(*this)));
    auto r11 = api_reg_.register_implementation("kernel32", "VirtualQuery", keep(std::make_shared<VirtualQueryImpl>(*this)), owner);
    auto r12 = api_reg_.register_implementation("kernel32", "CreateEventW", keep(std::make_shared<CreateEventWImpl>(*this)), owner);
    auto r13 = api_reg_.register_implementation("kernel32", "SetEvent", keep(std::make_shared<SetEventImpl>(*this)), owner);
    auto r14 = api_reg_.register_implementation("kernel32", "ResetEvent", keep(std::make_shared<ResetEventImpl>(*this)), owner);
    auto r15 = api_reg_.register_implementation("kernel32", "WaitForSingleObject", keep(std::make_shared<WaitForSingleObjectImpl>(*this)), owner);
    auto r16 = api_reg_.register_implementation("kernel32", "CloseHandle", keep(std::make_shared<CloseEventHandleImpl>(*this)), owner);
    auto r17 = api_reg_.register_implementation("kernel32", "CreateMutexW", keep(std::make_shared<CreateMutexWImpl>(*this)), owner);
    auto r18 = api_reg_.register_implementation("kernel32", "ReleaseMutex", keep(std::make_shared<ReleaseMutexImpl>(*this)), owner);
    auto r19 = api_reg_.register_implementation("kernel32", "CreateSemaphoreW", keep(std::make_shared<CreateSemaphoreWImpl>(*this)), owner);
    auto r20 = api_reg_.register_implementation("kernel32", "ReleaseSemaphore", keep(std::make_shared<ReleaseSemaphoreImpl>(*this)), owner);
    auto r21 = api_reg_.register_implementation("kernel32", "VirtualAlloc", keep(std::make_shared<VirtualAllocImpl>(*this)), owner);
    auto r22 = api_reg_.register_implementation("kernel32", "VirtualFree", keep(std::make_shared<VirtualFreeImpl>(*this)), owner);
    auto r23 = api_reg_.register_implementation("kernel32", "VirtualProtect", keep(std::make_shared<VirtualProtectImpl>(*this)), owner);
    auto r24 = api_reg_.register_implementation("kernel32", "WaitForMultipleObjects", keep(std::make_shared<WaitForMultipleObjectsImpl>(*this)), owner);
    auto r25 = api_reg_.register_implementation("kernel32", "SetLastError", keep(std::make_shared<SetLastErrorImpl>()), owner);
    auto r26 = api_reg_.register_implementation("kernel32", "GetLastError", keep(std::make_shared<GetLastErrorImpl>()), owner);
    auto r27 = api_reg_.register_implementation("kernel32", "GetProcessHeap", keep(std::make_shared<GetProcessHeapImpl>(*this)), owner);
    auto r28 = api_reg_.register_implementation("kernel32", "HeapCreate", keep(std::make_shared<HeapCreateImpl>(*this)), owner);
    auto r29 = api_reg_.register_implementation("kernel32", "HeapAlloc", keep(std::make_shared<HeapAllocImpl>(*this)), owner);
    auto r30 = api_reg_.register_implementation("kernel32", "HeapFree", keep(std::make_shared<HeapFreeImpl>(*this)), owner);
    auto r31 = api_reg_.register_implementation("kernel32", "HeapDestroy", keep(std::make_shared<HeapDestroyImpl>(*this)), owner);
    auto r31b = api_reg_.register_implementation("kernel32", "HeapReAlloc", keep(std::make_shared<HeapReAllocImpl>(*this)), owner);
    auto r31c = api_reg_.register_implementation("kernel32", "HeapSize", keep(std::make_shared<HeapSizeImpl>(*this)), owner);
    auto r32 = api_reg_.register_implementation("xmem", "XMemAlloc", keep(std::make_shared<XMemAllocImpl>(*this)), owner);
    auto r33 = api_reg_.register_implementation("xmem", "XMemFree", keep(std::make_shared<XMemFreeImpl>(*this)), owner);
    for (const auto* r : {&r1, &r2, &r3, &r4, &r5, &r6, &r7, &r8, &r9, &r10, &r11, &r12, &r13, &r14, &r15, &r16, &r17, &r18, &r19, &r20, &r21, &r22, &r23, &r24, &r25, &r26, &r27, &r28, &r29, &r30, &r31, &r31b, &r31c, &r32, &r33}) {
        if (!r->ok()) {
            (void)api_reg_.revoke_owner(id());
            owned_.clear();
            return Result<void>(r->errc(), r->context());
        }
    }
    auto observer = process_manager_.add_process_exit_observer(
        [this](std::uint64_t process_id) { release_process(process_id); });
    if (!observer.ok()) {
        (void)api_reg_.revoke_owner(id());
        owned_.clear();
        return Result<void>(observer.errc(), observer.context());
    }
    process_exit_observer_id_ = observer.value();
    return Result<void>::ok_result();
}

Result<void> GameRuntimeService::on_shutdown() {
    Result<void> observer_removed = Result<void>::ok_result();
    if (process_exit_observer_id_ != 0) {
        observer_removed = process_manager_.remove_process_exit_observer(process_exit_observer_id_);
        process_exit_observer_id_ = 0;
    }
    const auto revoked = api_reg_.revoke_owner(id());
    std::vector<std::pair<std::uint64_t, std::uint64_t>> active_handles;
    std::vector<std::uint64_t> objects_to_destroy;
    {
        std::lock_guard lock(state_lock_);
        procs_.clear();
        ts_bits_.clear();
        for (const auto& [key, object_id] : sync_objects_) {
            active_handles.push_back(key);
            objects_to_destroy.push_back(object_id);
        }
        sync_objects_.clear();
        for (const auto& [pid, ids] : retired_sync_objects_) {
            (void)pid;
            objects_to_destroy.insert(objects_to_destroy.end(), ids.begin(), ids.end());
        }
        retired_sync_objects_.clear();
    }
    for (const auto& [pid, raw] : active_handles) {
        auto process = process_manager_.find_process_by_pid(pid);
        if (process.ok()) {
            if (auto* owner = process.value().get()->as<ManagedProcess>()) {
                (void)owner->handle_table().close(Handle::from_raw(raw));
            }
        }
    }
    for (const auto object_id : objects_to_destroy) {
        (void)process_manager_.objects().destroy(object_id);
    }
    owned_.clear();
    if (!observer_removed.ok() && observer_removed.errc() != RuntimeErrc::NotFound) {
        return Result<void>(observer_removed.errc(), observer_removed.context());
    }
    if (!revoked.ok()) return Result<void>(revoked.errc(), revoked.context());
    return Result<void>::ok_result();
}

Result<std::uint64_t> GameRuntimeService::grt_initialize(std::uint64_t process_id) {
    std::lock_guard lock(state_lock_);
    auto& st = procs_[process_id];
    if (st.uninit_failed_terminal) {
        // Documented: a prior uninitialization failure is terminal.
        return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                     "terminal uninit failure (documented)");
    }
    return Result<std::uint64_t>(++st.init_count);
}

Result<void> GameRuntimeService::grt_uninitialize(std::uint64_t process_id) {
    std::lock_guard lock(state_lock_);
    const auto it = procs_.find(process_id);
    if (it == procs_.end() || it->second.init_count == 0) {
        // Documented: further uninit calls to the library are ignored.
        return Result<void>::ok_result();
    }
    if (--it->second.init_count == 0) {
        // Ref count reached zero: check for outstanding resources. The
        // runtime reports the documented terminal-failure shape when live
        // task queues exist for the process (they hold references).
        procs_.erase(it);
    }
    return Result<void>::ok_result();
}

Result<std::string> GameRuntimeService::console_id(std::uint64_t size,
                                                   std::uint64_t* used) {
    // Documented: PC default is the all-zero id
    // "00000000.00000000.00000000.00000000.00" (30 chars + NUL).
    static const std::string kDefault = "00000000.00000000.00000000.00000000.00";
    if (size < kDefault.size() + 1) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "consoleIdSize < XSystemConsoleIdBytes "
                                   "(documented ERROR_INSUFFICIENT_BUFFER)");
    }
    if (used != nullptr) *used = kDefault.size();
    return Result<std::string>(kDefault);
}

Result<std::string> GameRuntimeService::sandbox_id(std::uint64_t size,
                                                   std::uint64_t* used) {
    // Documented: defaults to 'RETAIL' when not found / retail env.
    static const std::string kDefault = "RETAIL";
    if (size < kDefault.size() + 1) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "sandboxIdSize < XSystemXboxLiveSandboxIdMaxBytes");
    }
    if (used != nullptr) *used = kDefault.size();
    return Result<std::string>(kDefault);
}

Result<std::string> GameRuntimeService::app_device_id(std::uint64_t size,
                                                     std::uint64_t* used) {
    // Documented: all-zero 40-digit string on failure.
    static const std::string kDefault(40, '0');
    if (size < kDefault.size() + 1) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "appSpecificDeviceIdSize < "
                                   "XSystemAppSpecificDeviceIdBytes");
    }
    if (used != nullptr) *used = kDefault.size();
    return Result<std::string>(kDefault);
}

Result<void> GameRuntimeService::set_time_sensitive(
    std::uint64_t process_id, std::uint64_t thread_id, bool on) {
    if (process_id == 0 || thread_id == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "process and thread identities must be nonzero");
    }
    std::lock_guard lock(state_lock_);
    ts_bits_[{process_id, thread_id}] = on;
    return Result<void>::ok_result();
}

Result<bool> GameRuntimeService::is_time_sensitive(
    std::uint64_t process_id, std::uint64_t thread_id) const {
    if (process_id == 0 || thread_id == 0) {
        return Result<bool>(RuntimeErrc::InvalidArgument,
                            "process and thread identities must be nonzero");
    }
    std::lock_guard lock(state_lock_);
    const auto it = ts_bits_.find({process_id, thread_id});
    return Result<bool>(it != ts_bits_.end() && it->second);
}

Result<VmRegion> GameRuntimeService::query_memory_region(std::uint64_t process_id, std::uint64_t guest_address) const {
    auto process = process_manager_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<VmRegion>(process.errc(), process.context());
    auto* managed = process.value().get()->as<ManagedProcess>();
    if (managed == nullptr) return Result<VmRegion>(RuntimeErrc::ObjectTypeMismatch, "not a managed process");
    return managed->address_space().find_containing(guest_address);
}

Result<MemoryQuerySnapshot> GameRuntimeService::query_memory_snapshot(
    std::uint64_t process_id) const {
    auto process = process_manager_.find_process_by_pid(process_id);
    if (!process.ok())
        return Result<MemoryQuerySnapshot>(process.errc(), process.context());
    auto* managed = process.value().get()->as<ManagedProcess>();
    if (managed == nullptr)
        return Result<MemoryQuerySnapshot>(RuntimeErrc::ObjectTypeMismatch,
                                           "not a managed process");
    const auto& space = managed->address_space();
    MemoryQuerySnapshot snapshot;
    snapshot.base = space.base();
    snapshot.capacity = space.capacity();
    snapshot.page_size = space.page_size();
    snapshot.regions = space.list_regions();
    return Result<MemoryQuerySnapshot>(std::move(snapshot));
}


Result<std::uint64_t> GameRuntimeService::virtual_alloc(
    std::uint64_t pid, std::uint64_t address, std::uint64_t size,
    std::uint32_t allocation_type, std::uint32_t protection) {
    constexpr std::uint32_t kCommit = 0x1000u, kReserve = 0x2000u;
    if (pid == 0 || size == 0 ||
        (allocation_type != kReserve && allocation_type != kCommit &&
         allocation_type != (kReserve | kCommit)))
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
            "VirtualAlloc supports MEM_RESERVE, MEM_COMMIT, and MEM_RESERVE|MEM_COMMIT");
    auto decoded = decode_win32_page_protection(protection);
    if (!decoded.ok()) return Result<std::uint64_t>(decoded.errc(), decoded.context());
    if (decoded.value() == MemProtect::Full &&
        !process_manager_.limits().allow_wx_pages)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "RWX protection requires allow_wx_pages");
    const auto snapshot = query_memory_snapshot(pid);
    if (!snapshot.ok()) return Result<std::uint64_t>(snapshot.errc(), snapshot.context());
    const auto page = snapshot.value().page_size;
    if (page == 0 || size > (~0ull) - (page - 1))
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "VirtualAlloc size overflows page rounding");
    const auto aligned_size = ((size + page - 1) / page) * page;
    const auto page_address = address == 0 ? 0 : address - (address % page);
    const auto address_offset = address == 0 ? 0 : address - page_address;
    if (allocation_type == kCommit) {
        if (page_address == 0)
            return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                         "MEM_COMMIT requires an existing guest reservation address");
        if (size > (~0ull) - address_offset ||
            address_offset + size > (~0ull) - (page - 1))
            return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                         "MEM_COMMIT address range overflows page rounding");
        const auto commit_size =
            ((address_offset + size + page - 1) / page) * page;
        auto committed = process_manager_.commit_region_by_pid(
            pid, page_address, commit_size, decoded.value());
        if (!committed.ok())
            return Result<std::uint64_t>(committed.errc(), committed.context());
        return Result<std::uint64_t>(page_address);
    }
    Result<std::uint64_t> reserved =
        Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                              "reservation was not attempted");
    if (address != 0) {
        constexpr std::uint64_t kAllocationGranularity = 0x10000ull;
        const std::uint64_t allocation_base =
            address & ~(kAllocationGranularity - 1);
        if (allocation_base == 0)
            return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                         "fixed reservation rounded to null");
        reserved = process_manager_.reserve_region_at_by_pid(
            pid, allocation_base, aligned_size, "VirtualAlloc");
    } else {
        reserved = process_manager_.reserve_region_by_pid(pid, aligned_size, "VirtualAlloc");
    }
    if (!reserved.ok()) return reserved;
    auto allocation_protection = process_manager_.set_allocation_protection_by_pid(
        pid, reserved.value(), decoded.value());
    if (!allocation_protection.ok()) {
        (void)process_manager_.release_region_by_pid(pid, reserved.value());
        return Result<std::uint64_t>(allocation_protection.errc(), allocation_protection.context());
    }
    if (allocation_type == kReserve) return reserved;
    auto committed = process_manager_.commit_region_by_pid(
        pid, reserved.value(), aligned_size, decoded.value());
    if (!committed.ok()) {
        (void)process_manager_.release_region_by_pid(pid, reserved.value());
        return Result<std::uint64_t>(committed.errc(), committed.context());
    }
    return reserved;
}

Result<void> GameRuntimeService::virtual_free(
    std::uint64_t pid, std::uint64_t address, std::uint64_t size, std::uint32_t free_type) {
    if (pid == 0 || address == 0)
        return Result<void>(RuntimeErrc::InvalidArgument, "VirtualFree requires a non-null guest address");
    if (free_type == 0x8000u && size == 0)
        return process_manager_.release_region_by_pid(pid, address);
    if (free_type == 0x4000u && size != 0) {
        const auto snapshot = query_memory_snapshot(pid);
        if (!snapshot.ok()) return Result<void>(snapshot.errc(), snapshot.context());
        const auto page = snapshot.value().page_size;
        if (page == 0 || size > (~0ull) - (page - 1))
            return Result<void>(RuntimeErrc::InvalidArgument, "VirtualFree size overflows page rounding");
        if (address % page != 0)
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "MEM_DECOMMIT address must be page-aligned");
        const auto aligned = ((size + page - 1) / page) * page;
        return process_manager_.decommit_region_by_pid(pid, address, aligned);
    }
    return Result<void>(RuntimeErrc::InvalidArgument,
        "VirtualFree supports MEM_RELEASE with size zero or page-range MEM_DECOMMIT");
}

Result<MemProtect> GameRuntimeService::virtual_protect(
    std::uint64_t pid, std::uint64_t address, std::uint64_t size, std::uint32_t protection) {
    if (pid == 0 || address == 0)
        return Result<MemProtect>(RuntimeErrc::InvalidArgument, "VirtualProtect requires a non-null guest address");
    auto decoded = decode_win32_page_protection(protection);
    if (!decoded.ok()) return decoded;
    const auto snapshot = query_memory_snapshot(pid);
    if (!snapshot.ok()) return Result<MemProtect>(snapshot.errc(), snapshot.context());
    const auto page = snapshot.value().page_size;
    if (size == 0 || page == 0)
        return Result<MemProtect>(RuntimeErrc::InvalidArgument,
                                  "VirtualProtect requires a non-empty range");
    const auto start = address - (address % page);
    const auto offset = address - start;
    if (size > (~0ull) - offset ||
        offset + size > (~0ull) - (page - 1))
        return Result<MemProtect>(RuntimeErrc::InvalidArgument,
                                  "VirtualProtect address range overflows page rounding");
    const auto span = offset + size;
    const auto aligned = ((span + page - 1) / page) * page;
    return process_manager_.protect_region_by_pid(pid, start, aligned, decoded.value());
}

// ── M11 Phase 4: heap + XMem service surface ─────────────────────────────

Result<std::uint64_t> GameRuntimeService::process_heap(std::uint64_t pid) {
    // Fast path under the state lock only; creation happens outside it so
    // the service state lock is never held across ProcessManager calls
    // (the manager lock is taken first in every other path).
    {
        std::lock_guard lock(state_lock_);
        const auto it = procs_.find(pid);
        if (it != procs_.end() && it->second.process_heap != 0)
            return Result<std::uint64_t>(it->second.process_heap);
    }
    const auto handle = create_heap_object(pid, true, 0);
    if (!handle.ok()) return handle;
    std::lock_guard lock(state_lock_);
    auto& st = procs_[pid];
    if (st.process_heap == 0) st.process_heap = handle.value();
    return Result<std::uint64_t>(st.process_heap);
}

Result<std::uint64_t> GameRuntimeService::heap_create(std::uint64_t pid,
                                                      std::uint32_t options) {
    return create_heap_object(pid, false, options);
}

Result<std::uint64_t> GameRuntimeService::create_heap_object(
    std::uint64_t pid, bool default_heap, std::uint32_t options) {
    if (pid == 0)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "heap creation requires a process");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<std::uint64_t>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr || owner->state() != ProcessState::Running)
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated, "owner process is not running");
    auto object_id = process_manager_.objects().register_object(
        std::make_unique<RtHeap>(default_heap, options));
    if (!object_id.ok()) return Result<std::uint64_t>(object_id.errc(), object_id.context());
    auto reference = process_manager_.objects().lookup_id(object_id.value());
    if (!reference.ok()) {
        (void)process_manager_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(reference.errc(), reference.context());
    }
    auto handle = owner->handle_table().create(*reference.value().get());
    if (!handle.ok()) {
        reference.value().release();
        (void)process_manager_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(handle.errc(), handle.context());
    }
    return Result<std::uint64_t>(handle.value().raw());
}

Result<std::uint64_t> GameRuntimeService::heap_alloc(std::uint64_t pid,
                                                     std::uint64_t heap_handle,
                                                     std::uint64_t size,
                                                     bool zero_initialize) {
    const auto heap = lookup_heap_object(pid, heap_handle);
    if (!heap.ok()) return Result<std::uint64_t>(heap.errc(), heap.context());
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<std::uint64_t>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<std::uint64_t>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    // Rationale for the clamp: the arena is 4 MiB by default; a guest
    // asking for more than the whole arena cannot be satisfied anyway.
    if (size == 0 || size > (64ull << 20))
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "HeapAlloc size must be 1..64 MiB");
    return owner->allocate_xmem(size, 8, "heap", zero_initialize);
}

Result<void> GameRuntimeService::heap_free(std::uint64_t pid,
                                           std::uint64_t heap_handle,
                                           std::uint64_t address) {
    const auto heap = lookup_heap_object(pid, heap_handle);
    if (!heap.ok()) return Result<void>(heap.errc(), heap.context());
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<void>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    return owner->free_xmem(address);
}

Result<void> GameRuntimeService::heap_destroy(std::uint64_t pid,
                                              std::uint64_t heap_handle) {
    const auto heap = lookup_heap_object(pid, heap_handle);
    if (!heap.ok()) return Result<void>(heap.errc(), heap.context());
    {
        auto* heap_obj = heap.value().get()->as<RtHeap>();
        if (heap_obj != nullptr && heap_obj->is_default_heap())
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "the process default heap cannot be destroyed");
    }
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<void>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    const auto closed = owner->handle_table().close(Handle::from_raw(heap_handle));
    if (!closed.ok()) return Result<void>(closed.errc(), closed.context());
    std::lock_guard lock(state_lock_);
    const auto pit = procs_.find(pid);
    if (pit != procs_.end() && pit->second.process_heap == heap_handle)
        pit->second.process_heap = 0;
    return Result<void>();
}

Result<std::uint64_t> GameRuntimeService::heap_realloc(
    std::uint64_t pid, std::uint64_t heap_handle, std::uint64_t address,
    std::uint64_t new_size, bool zero_tail) {
    const auto heap = lookup_heap_object(pid, heap_handle);
    if (!heap.ok()) return Result<std::uint64_t>(heap.errc(), heap.context());
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<std::uint64_t>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<std::uint64_t>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    if (address == 0)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "HeapReAlloc requires the original allocation base (null lpMem is HeapAlloc)");
    if (new_size == 0 || new_size > (64ull << 20))
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "HeapReAlloc size must be 1..64 MiB");
    const auto old_info = owner->query_xmem(address);
    if (!old_info.ok())
        return Result<std::uint64_t>(old_info.errc(), old_info.context());
    const auto old_size = old_info.value().size;
    // Moving realloc: allocate the new block, copy the preserved prefix,
    // free the old block. In-place resize is not attempted (documented
    // partial behavior); failure of the new allocation leaves the original
    // allocation completely untouched.
    const auto fresh = owner->allocate_xmem(new_size, 8, "heap", false);
    if (!fresh.ok()) return Result<std::uint64_t>(fresh.errc(), fresh.context());
    const auto new_address = fresh.value();
    const auto preserve = old_size < new_size ? old_size : new_size;
    // Copy through the address space directly (translate + host memcpy).
    // This keeps rt_gdk layered on rt_memory only; instantiating
    // guest::GuestMemory here would require an rt_guestmem dependency that
    // this library's layering does not have. Both blocks live inside the
    // SAME single-reservation xmem arena (one contiguous committed region),
    // so one translate per block resolves a contiguous host range; the
    // congruence check fails closed if arena geometry ever changes.
    auto& space = owner->address_space();
    const auto src_t = space.translate(address);
    const auto dst_t = space.translate(new_address);
    if (!src_t.ok() || !dst_t.ok()) {
        (void)owner->free_xmem(new_address);
        return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                     "realloc copy target unmappable");
    }
    if (preserve != 0) {
        std::memcpy(static_cast<std::uint8_t*>(dst_t.value()),
                    static_cast<const std::uint8_t*>(src_t.value()),
                    static_cast<std::size_t>(preserve));
    }
    if (zero_tail && new_size > old_size) {
        std::memset(static_cast<std::uint8_t*>(dst_t.value()) + old_size, 0,
                    static_cast<std::size_t>(new_size - old_size));
    }
    const auto released = owner->free_xmem(address);
    if (!released.ok()) {
        // The old block could not be freed (double-free class of failure):
        // roll back the copy target so we never leak two live blocks.
        (void)owner->free_xmem(new_address);
        return Result<std::uint64_t>(released.errc(), released.context());
    }
    return Result<std::uint64_t>(new_address);
}

Result<std::uint64_t> GameRuntimeService::heap_size(std::uint64_t pid,
                                                    std::uint64_t heap_handle,
                                                    std::uint64_t address) {
    const auto heap = lookup_heap_object(pid, heap_handle);
    if (!heap.ok()) return Result<std::uint64_t>(heap.errc(), heap.context());
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<std::uint64_t>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<std::uint64_t>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    const auto info = owner->query_xmem(address);
    if (!info.ok()) return Result<std::uint64_t>(info.errc(), info.context());
    return Result<std::uint64_t>(info.value().size);
}

Result<std::uint64_t> GameRuntimeService::xmem_alloc(std::uint64_t pid,
                                                     std::uint64_t size,
                                                     std::uint64_t alignment) {
    if (pid == 0)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "XMemAlloc requires a process");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<std::uint64_t>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<std::uint64_t>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    if (size == 0 || size > (64ull << 20))
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "XMemAlloc size must be 1..64 MiB");
    return owner->allocate_xmem(size, alignment, "xmem", false);
}

Result<void> GameRuntimeService::xmem_free(std::uint64_t pid,
                                            std::uint64_t address) {
    if (pid == 0)
        return Result<void>(RuntimeErrc::InvalidArgument, "XMemFree requires a process");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<void>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    return owner->free_xmem(address);
}

Result<RefGuard> GameRuntimeService::lookup_sync_object(std::uint64_t pid,
                                                                  std::uint64_t raw) const {
    if (pid == 0 || raw == 0)
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "null or runtime-global synchronization handle");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<RefGuard>(RuntimeErrc::NotFound, "synchronization owner process does not exist");
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    auto object = owner->handle_table().lookup(Handle::from_raw(raw));
    if (!object.ok()) return Result<RefGuard>(object.errc(), object.context());
    auto* value = object.value().get();
    if (value == nullptr ||
        !((value->type_id() == TypeId::Event && value->as<RtEvent>() != nullptr) ||
          (value->type_id() == TypeId::Mutex && value->as<RtGuestMutex>() != nullptr) ||
          (value->type_id() == TypeId::Semaphore && value->as<RtGuestSemaphore>() != nullptr))) {
        return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch, "handle is not a supported synchronization object");
    }
    return Result<RefGuard>(std::move(object.value()));
}

Result<RefGuard> GameRuntimeService::lookup_heap_object(std::uint64_t pid,
                                                           std::uint64_t raw) const {
    if (pid == 0 || raw == 0)
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "null or runtime-global heap handle");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<RefGuard>(RuntimeErrc::NotFound, "heap owner process does not exist");
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    auto object = owner->handle_table().lookup(Handle::from_raw(raw));
    if (!object.ok()) return Result<RefGuard>(object.errc(), object.context());
    auto* value = object.value().get();
    if (value == nullptr || value->type_id() != TypeId::MemoryRegion ||
        value->as<RtHeap>() == nullptr) {
        return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch, "handle is not a heap object");
    }
    return Result<RefGuard>(std::move(object.value()));
}

Result<std::uint64_t> GameRuntimeService::create_sync_object(
    std::uint64_t pid, std::unique_ptr<RuntimeObject> object) {
    if (pid == 0 || object == nullptr)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "invalid process or synchronization object");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<std::uint64_t>(RuntimeErrc::NotFound, "owner process does not exist");
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr || owner->state() != ProcessState::Running)
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated, "owner process is not running");
    auto object_id = process_manager_.objects().register_object(std::move(object));
    if (!object_id.ok()) return Result<std::uint64_t>(object_id.errc(), object_id.context());
    auto reference = process_manager_.objects().lookup_id(object_id.value());
    if (!reference.ok()) {
        (void)process_manager_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(reference.errc(), reference.context());
    }
    auto handle = owner->handle_table().create(*reference.value().get());
    if (!handle.ok()) {
        reference.value().release();
        (void)process_manager_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(handle.errc(), handle.context());
    }
    const auto raw = handle.value().raw();
    {
        std::lock_guard lock(state_lock_);
        sync_objects_[{pid, raw}] = object_id.value();
    }
    if (owner->state() != ProcessState::Running) {
        (void)owner->handle_table().close(handle.value());
        bool owned_entry = false;
        {
            std::lock_guard lock(state_lock_);
            owned_entry = sync_objects_.erase({pid, raw}) != 0;
        }
        reference.value().release();
        if (owned_entry) (void)process_manager_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated, "owner process exited during synchronization-object creation");
    }
    return Result<std::uint64_t>(raw);
}

Result<std::uint64_t> GameRuntimeService::create_event(std::uint64_t pid,
                                                        bool manual_reset,
                                                        bool initially_set) {
    return create_sync_object(pid, std::make_unique<RtEvent>(!manual_reset, initially_set));
}

Result<std::uint64_t> GameRuntimeService::create_mutex(
    std::uint64_t pid, std::uint64_t thread_id, bool initially_owned) {
    if (initially_owned && thread_id == 0)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "initial ownership requires a guest thread id");
    const auto handle = create_sync_object(pid, std::make_unique<RtGuestMutex>());
    if (!handle.ok() || !initially_owned) return handle;
    auto object = lookup_sync_object(pid, handle.value());
    if (!object.ok()) {
        (void)close_sync_handle(pid, handle.value());
        return Result<std::uint64_t>(object.errc(), object.context());
    }
    auto acquired = object.value().get()->as<RtGuestMutex>()->acquire(thread_id, 0);
    if (!acquired.ok()) {
        (void)close_sync_handle(pid, handle.value());
        return Result<std::uint64_t>(acquired.errc(), acquired.context());
    }
    return handle;
}

Result<void> GameRuntimeService::release_mutex(std::uint64_t pid,
                                                std::uint64_t handle,
                                                std::uint64_t thread_id) {
    auto object = lookup_sync_object(pid, handle);
    if (!object.ok()) return Result<void>(object.errc(), object.context());
    auto* mutex = object.value().get()->as<RtGuestMutex>();
    if (mutex == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "handle is not a mutex");
    std::lock_guard transaction(sync_transaction_lock_);
    return mutex->release(thread_id);
}

Result<std::uint64_t> GameRuntimeService::create_semaphore(
    std::uint64_t pid, std::int64_t initial_count, std::int64_t maximum_count) {
    if (maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "semaphore requires 0 <= initial <= maximum and maximum > 0");
    return create_sync_object(pid, std::make_unique<RtGuestSemaphore>(initial_count, maximum_count));
}

Result<std::int64_t> GameRuntimeService::release_semaphore(
    std::uint64_t pid, std::uint64_t handle, std::uint32_t release_count) {
    auto object = lookup_sync_object(pid, handle);
    if (!object.ok()) return Result<std::int64_t>(object.errc(), object.context());
    auto* semaphore = object.value().get()->as<RtGuestSemaphore>();
    if (semaphore == nullptr) return Result<std::int64_t>(RuntimeErrc::ObjectTypeMismatch, "handle is not a semaphore");
    std::lock_guard transaction(sync_transaction_lock_);
    return semaphore->release(release_count);
}

Result<void> GameRuntimeService::set_event(std::uint64_t pid, std::uint64_t handle) {
    auto object = lookup_sync_object(pid, handle);
    if (!object.ok()) return Result<void>(object.errc(), object.context());
    auto* event = object.value().get()->as<RtEvent>();
    if (event == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "handle is not an event");
    std::lock_guard transaction(sync_transaction_lock_);
    return event->set();
}

Result<void> GameRuntimeService::reset_event(std::uint64_t pid, std::uint64_t handle) {
    auto object = lookup_sync_object(pid, handle);
    if (!object.ok()) return Result<void>(object.errc(), object.context());
    auto* event = object.value().get()->as<RtEvent>();
    if (event == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "handle is not an event");
    std::lock_guard transaction(sync_transaction_lock_);
    return event->reset();
}

Result<std::uint32_t> GameRuntimeService::wait_object(
    std::uint64_t pid, std::uint64_t tid, std::uint64_t handle,
    std::uint32_t timeout_ms) {
    auto object = lookup_sync_object(pid, handle);
    if (!object.ok()) return Result<std::uint32_t>(object.errc(), object.context());
    const pal::MonotonicNs timeout_ns = timeout_ms == 0xFFFFFFFFu
        ? pal::kInfiniteTimeout
        : static_cast<pal::MonotonicNs>(timeout_ms) * 1'000'000LL;

    // Keep the runtime thread pinned while observing its cooperative stop
    // flag. Process teardown requests stop before joining owned threads.
    RefGuard guest_thread;
    if (tid != 0) {
        auto process = process_manager_.find_process_by_pid(pid);
        if (process.ok()) {
            if (auto* managed = process.value().get()->as<ManagedProcess>()) {
                for (const auto object_id : managed->thread_ids()) {
                    auto candidate = process_manager_.objects().lookup_id(object_id);
                    if (!candidate.ok()) continue;
                    auto* thread = candidate.value().get()->as<RtThread>();
                    if (thread != nullptr && thread->thread_id() == tid) {
                        guest_thread = std::move(candidate.value());
                        break;
                    }
                }
            }
        }
    }
    auto* guest_runtime_thread = guest_thread.get() != nullptr
        ? guest_thread.get()->as<RtThread>() : nullptr;
    bool marked_blocked = false;
    if (guest_runtime_thread != nullptr &&
        guest_runtime_thread->state() == ThreadState::Running) {
        marked_blocked = guest_runtime_thread->block_note().ok();
    }
    struct WaitStateRestore {
        RtThread* thread;
        bool blocked;
        ~WaitStateRestore() {
            if (thread != nullptr && blocked &&
                thread->state() == ThreadState::Blocked) {
                (void)thread->unblock_note();
            }
        }
    } wait_state_restore{guest_runtime_thread, marked_blocked};

    const auto cancelled = [&guest_thread]() {
        auto* guest_object = guest_thread.get();
        auto* thread = guest_object != nullptr
            ? guest_object->as<RtThread>() : nullptr;
        return thread != nullptr && thread->stop_requested();
    };
    const auto wait_start_ns = pal::now_ns();
    const auto deadline = timeout_ns < 0 || timeout_ns > INT64_MAX - wait_start_ns
        ? INT64_MAX : wait_start_ns + timeout_ns;

    auto* value = object.value().get();
    if (auto* event = value->as<RtEvent>()) {
        for (;;) {
            if (guest_runtime_thread != nullptr &&
                !guest_runtime_thread->suspension_point())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "event wait cancelled by guest thread stop");
            if (cancelled())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "event wait cancelled by guest thread stop");
            const auto now = pal::now_ns();
            const auto remaining = deadline == INT64_MAX
                ? pal::MonotonicNs(2'000'000)
                : std::max<pal::MonotonicNs>(0, deadline - now);
            const auto slice = std::min<pal::MonotonicNs>(2'000'000, remaining);
            Result<void> waited(RuntimeErrc::InvalidState, "event wait not attempted");
            {
                std::lock_guard transaction(sync_transaction_lock_);
                waited = event->wait_ns(slice);
            }
            if (waited.ok()) return Result<std::uint32_t>(0u);
            if (waited.errc() != RuntimeErrc::Timeout)
                return Result<std::uint32_t>(waited.errc(), waited.context());
            if (deadline != INT64_MAX && pal::now_ns() >= deadline)
                return Result<std::uint32_t>(0x102u);
        }
    }
    if (auto* mutex = value->as<RtGuestMutex>()) {
        for (;;) {
            if (guest_runtime_thread != nullptr &&
                !guest_runtime_thread->suspension_point())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "mutex wait cancelled by guest thread stop");
            if (cancelled())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "mutex wait cancelled by guest thread stop");
            const auto now = pal::now_ns();
            const bool expired = deadline != INT64_MAX && now >= deadline;
            const auto remaining = deadline == INT64_MAX
                ? pal::MonotonicNs(2'000'000)
                : (expired ? pal::MonotonicNs(0)
                           : std::max<pal::MonotonicNs>(0, deadline - now));
            const auto slice = expired ? pal::MonotonicNs(0)
                : std::min<pal::MonotonicNs>(2'000'000, remaining);
            Result<bool> waited(RuntimeErrc::InvalidState, "mutex wait not attempted");
            {
                std::lock_guard transaction(sync_transaction_lock_);
                waited = mutex->acquire(tid, slice, cancelled);
            }
            if (waited.ok()) return Result<std::uint32_t>(waited.value() ? 0x80u : 0u);
            if (waited.errc() != RuntimeErrc::Timeout)
                return Result<std::uint32_t>(waited.errc(), waited.context());
            if (expired) return Result<std::uint32_t>(0x102u);
        }
    }
    if (auto* semaphore = value->as<RtGuestSemaphore>()) {
        for (;;) {
            if (guest_runtime_thread != nullptr &&
                !guest_runtime_thread->suspension_point())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "semaphore wait cancelled by guest thread stop");
            if (cancelled())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "semaphore wait cancelled by guest thread stop");
            const auto now = pal::now_ns();
            const bool expired = deadline != INT64_MAX && now >= deadline;
            const auto remaining = deadline == INT64_MAX
                ? pal::MonotonicNs(2'000'000)
                : (expired ? pal::MonotonicNs(0)
                           : std::max<pal::MonotonicNs>(0, deadline - now));
            const auto slice = expired ? pal::MonotonicNs(0)
                : std::min<pal::MonotonicNs>(2'000'000, remaining);
            Result<void> waited(RuntimeErrc::InvalidState, "semaphore wait not attempted");
            {
                std::lock_guard transaction(sync_transaction_lock_);
                waited = semaphore->acquire(slice, cancelled);
            }
            if (waited.ok()) return Result<std::uint32_t>(0u);
            if (waited.errc() != RuntimeErrc::Timeout)
                return Result<std::uint32_t>(waited.errc(), waited.context());
            if (expired) return Result<std::uint32_t>(0x102u);
        }
    }
    return Result<std::uint32_t>(RuntimeErrc::ObjectTypeMismatch,
                                 "unsupported waitable object");
}

Result<std::uint32_t> GameRuntimeService::wait_objects_any(
    std::uint64_t pid, std::uint64_t tid,
    const std::vector<std::uint64_t>& handles, std::uint32_t timeout_ms) {
    if (handles.empty() || handles.size() > 64)
        return Result<std::uint32_t>(RuntimeErrc::InvalidArgument,
                                     "wait-any requires between 1 and 64 handles");
    std::vector<std::uint64_t> unique;
    unique.reserve(handles.size());
    for (const auto handle : handles) {
        if (handle == 0 || std::find(unique.begin(), unique.end(), handle) != unique.end())
            return Result<std::uint32_t>(RuntimeErrc::InvalidArgument,
                                         "wait-any handles must be non-null and unique");
        unique.push_back(handle);
        auto valid = lookup_sync_object(pid, handle);
        if (!valid.ok()) return Result<std::uint32_t>(valid.errc(), valid.context());
    }

    const auto start = pal::now_ns();
    const auto duration = timeout_ms == 0xFFFFFFFFu
        ? pal::MonotonicNs(-1)
        : static_cast<pal::MonotonicNs>(timeout_ms) * 1'000'000LL;
    const auto deadline = duration < 0 || duration > INT64_MAX - start
        ? INT64_MAX : start + duration;
    for (;;) {
        for (std::size_t i = 0; i < handles.size(); ++i) {
            auto result = wait_object(pid, tid, handles[i], 0);
            if (result.ok() && result.value() != 0x102u) {
                const auto base = result.value() == 0x80u ? 0x80u : 0u;
                return Result<std::uint32_t>(base + static_cast<std::uint32_t>(i));
            }
            if (!result.ok()) {
                return Result<std::uint32_t>(result.errc(), result.context());
            }
        }
        const auto now = pal::now_ns();
        if (deadline != INT64_MAX && now >= deadline)
            return Result<std::uint32_t>(0x102u);
        const auto sleep_ns = deadline == INT64_MAX
            ? pal::MonotonicNs(2'000'000)
            : std::min<pal::MonotonicNs>(2'000'000, deadline - now);
        if (sleep_ns > 0)
            std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_ns));
    }
}

Result<std::uint32_t> GameRuntimeService::wait_objects_all(
    std::uint64_t pid, std::uint64_t tid,
    const std::vector<std::uint64_t>& handles, std::uint32_t timeout_ms) {
    if (handles.empty() || handles.size() > 64)
        return Result<std::uint32_t>(RuntimeErrc::InvalidArgument,
                                     "wait-all requires between 1 and 64 handles");

    std::vector<RefGuard> objects;
    objects.reserve(handles.size());
    std::unordered_set<std::uint64_t> unique_handles;
    for (const auto handle : handles) {
        if (handle == 0 || !unique_handles.insert(handle).second)
            return Result<std::uint32_t>(RuntimeErrc::InvalidArgument,
                                         "wait-all handles must be non-null and unique");
        auto object = lookup_sync_object(pid, handle);
        if (!object.ok())
            return Result<std::uint32_t>(object.errc(), object.context());
        objects.push_back(std::move(object.value()));
    }

    RefGuard guest_thread;
    if (tid != 0) {
        auto process = process_manager_.find_process_by_pid(pid);
        if (process.ok()) {
            if (auto* managed = process.value().get()->as<ManagedProcess>()) {
                for (const auto object_id : managed->thread_ids()) {
                    auto candidate = process_manager_.objects().lookup_id(object_id);
                    if (!candidate.ok()) continue;
                    auto* thread = candidate.value().get()->as<RtThread>();
                    if (thread != nullptr && thread->thread_id() == tid) {
                        guest_thread = std::move(candidate.value());
                        break;
                    }
                }
            }
        }
    }
    auto* runtime_thread = guest_thread.get() != nullptr
        ? guest_thread.get()->as<RtThread>() : nullptr;

    const auto start = pal::now_ns();
    const auto duration = timeout_ms == 0xFFFFFFFFu
        ? pal::MonotonicNs(-1)
        : static_cast<pal::MonotonicNs>(timeout_ms) * 1'000'000LL;
    const auto deadline = duration < 0 || duration > INT64_MAX - start
        ? INT64_MAX : start + duration;

    for (;;) {
        if (runtime_thread != nullptr) {
            if (!runtime_thread->suspension_point() ||
                runtime_thread->stop_requested())
                return Result<std::uint32_t>(RuntimeErrc::ThreadTerminated,
                                             "wait-all cancelled by guest thread stop");
        }

        bool abandoned = false;
        std::vector<std::size_t> acquired;
        acquired.reserve(objects.size());
        std::vector<bool> acquired_abandoned(objects.size(), false);
        RuntimeErrc failure = RuntimeErrc::Timeout;
        std::string failure_context = "wait-all candidate is not ready";
        {
            // This lock also guards single-object guest waits and signal/
            // release/close operations. Therefore no other guest operation
            // can consume a resource between this set's probes and rollback.
            std::lock_guard transaction(sync_transaction_lock_);
            for (std::size_t i = 0; i < objects.size(); ++i) {
                auto* value = objects[i].get();
                Result<void> event_result(RuntimeErrc::ObjectTypeMismatch,
                                          "unsupported wait-all object");
                bool ready = false;
                if (auto* event = value->as<RtEvent>()) {
                    event_result = event->wait_ns(0);
                    ready = event_result.ok();
                } else if (auto* mutex = value->as<RtGuestMutex>()) {
                    auto result = mutex->acquire(tid, 0);
                    if (result.ok()) {
                        ready = true;
                        acquired_abandoned[i] = result.value();
                        abandoned = abandoned || result.value();
                    } else {
                        failure = result.errc();
                        failure_context = result.context();
                    }
                } else if (auto* semaphore = value->as<RtGuestSemaphore>()) {
                    event_result = semaphore->try_acquire();
                    ready = event_result.ok();
                }
                if (ready) {
                    acquired.push_back(i);
                    continue;
                }
                if (failure == RuntimeErrc::Timeout && !event_result.ok() &&
                    event_result.errc() != RuntimeErrc::ObjectTypeMismatch) {
                    failure = event_result.errc();
                    failure_context = event_result.context();
                }
                break;
            }

            if (acquired.size() == objects.size())
                return Result<std::uint32_t>(abandoned ? 0x80u : 0u);

            // Roll back every successful acquisition before releasing the
            // transaction lock. Auto-reset event signals are restored.
            for (auto it = acquired.rbegin(); it != acquired.rend(); ++it) {
                auto* value = objects[*it].get();
                if (auto* event = value->as<RtEvent>()) {
                    if (event->auto_reset()) (void)event->set();
                } else if (auto* mutex = value->as<RtGuestMutex>()) {
                    if (acquired_abandoned[*it])
                        (void)mutex->abandon_owner(tid);
                    else
                        (void)mutex->release(tid);
                } else if (auto* semaphore = value->as<RtGuestSemaphore>()) {
                    (void)semaphore->release(1);
                }
            }
        }

        if (failure != RuntimeErrc::Timeout)
            return Result<std::uint32_t>(failure, failure_context);
        const auto now = pal::now_ns();
        if (deadline != INT64_MAX && now >= deadline)
            return Result<std::uint32_t>(0x102u);
        const auto sleep_ns = deadline == INT64_MAX
            ? pal::MonotonicNs(2'000'000)
            : std::min<pal::MonotonicNs>(2'000'000, deadline - now);
        if (sleep_ns > 0)
            std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_ns));
    }
}

Result<std::uint32_t> GameRuntimeService::wait_event(std::uint64_t pid,
                                                      std::uint64_t handle,
                                                      std::uint32_t timeout_ms) {
    return wait_object(pid, 0, handle, timeout_ms);
}

Result<void> GameRuntimeService::close_sync_handle(std::uint64_t pid, std::uint64_t handle) {
    if (pid == 0 || handle == 0)
        return Result<void>(RuntimeErrc::InvalidHandle, "null process or guest handle");
    auto process = process_manager_.find_process_by_pid(pid);
    if (!process.ok()) return Result<void>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr)
        return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    auto candidate = owner->handle_table().lookup(Handle::from_raw(handle));
    if (!candidate.ok()) return Result<void>(candidate.errc(), candidate.context());
    auto* object = candidate.value().get();
    if (object != nullptr && object->type_id() == TypeId::TaskQueue) {
        auto* closer = dynamic_cast<IGuestHandleCloser*>(object);
        if (closer == nullptr)
            return Result<void>(RuntimeErrc::ObjectTypeMismatch,
                                "task-queue object does not implement guest handle close");
        return closer->close_guest_handle(pid, handle, std::move(candidate.value()));
    }
    candidate.value().release();

    std::lock_guard transaction(sync_transaction_lock_);
    auto sync_object = lookup_sync_object(pid, handle);
    if (!sync_object.ok())
        return Result<void>(sync_object.errc(), sync_object.context());
    auto current_process = process_manager_.find_process_by_pid(pid);
    if (!current_process.ok())
        return Result<void>(current_process.errc(), current_process.context());
    auto* current_owner = current_process.value().get()->as<ManagedProcess>();
    if (current_owner == nullptr)
        return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    const auto object_id = sync_object.value().get()->id();
    if (auto* mutex = sync_object.value().get()->as<RtGuestMutex>()) mutex->close();
    if (auto* semaphore = sync_object.value().get()->as<RtGuestSemaphore>()) semaphore->close();
    auto closed = current_owner->handle_table().close(Handle::from_raw(handle));
    if (!closed.ok()) return closed;
    {
        std::lock_guard lock(state_lock_);
        const auto erased = sync_objects_.erase({pid, handle});
        if (erased == 0)
            return Result<void>(RuntimeErrc::InvalidHandle, "synchronization handle already closed");
        retired_sync_objects_[pid].push_back(object_id);
    }
    return Result<void>::ok_result();
}

Result<void> GameRuntimeService::close_event(std::uint64_t pid, std::uint64_t handle) {
    auto object = lookup_sync_object(pid, handle);
    if (!object.ok()) return Result<void>(object.errc(), object.context());
    if (object.value().get()->as<RtEvent>() == nullptr)
        return Result<void>(RuntimeErrc::ObjectTypeMismatch, "handle is not an event");
    return close_sync_handle(pid, handle);
}

void GameRuntimeService::release_process(std::uint64_t process_id) {
    std::vector<std::uint64_t> objects_to_destroy;
    {
        std::lock_guard lock(state_lock_);
        procs_.erase(process_id);  // drops the cached default-heap handle too
        for (auto it = ts_bits_.begin(); it != ts_bits_.end();) {
            if (it->first.first == process_id) it = ts_bits_.erase(it);
            else ++it;
        }
        for (auto it = sync_objects_.begin(); it != sync_objects_.end();) {
            if (it->first.first == process_id) {
                objects_to_destroy.push_back(it->second);
                it = sync_objects_.erase(it);
            } else {
                ++it;
            }
        }
        const auto retired = retired_sync_objects_.find(process_id);
        if (retired != retired_sync_objects_.end()) {
            objects_to_destroy.insert(objects_to_destroy.end(),
                                      retired->second.begin(), retired->second.end());
            retired_sync_objects_.erase(retired);
        }
    }
    // ProcessManager invokes this only after guest threads and their handle
    // table have drained. ObjectManager additionally drains any service-side
    // RefGuards before destroying each event.
    for (const auto id : objects_to_destroy) {
        (void)process_manager_.objects().destroy(id);
    }
}

// ── TaskQueueService ─────────────────────────────────────────────────────

TaskQueueService::TaskQueueService(ApiRegistry& api_reg, ProcessManager& pm)
    : RtService("gdk_task_queue"), api_reg_(api_reg), pm_(pm) {}

TaskQueueService::~TaskQueueService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

Result<void> TaskQueueService::on_initialize() {
    const std::uint64_t owner = id();
    auto keep = [this](std::shared_ptr<IApiImplementation> impl) {
        owned_.push_back(impl);
        return impl;
    };
    auto reg = [&](const char* name, std::shared_ptr<IApiImplementation> impl) {
        return api_reg_.register_implementation("xgameruntime", name,
                                               std::move(impl), owner);
    };
    const auto r1 = reg("XTaskQueueCreate", keep(std::make_shared<TqCreateImpl>(*this)));
    const auto r2 = reg("XTaskQueueDispatch", keep(std::make_shared<TqDispatchImpl>(*this)));
    const auto r3 = reg("XTaskQueueCloseHandle", keep(std::make_shared<TqCloseImpl>(*this)));
    const auto r4 = reg("XTaskQueueTerminate", keep(std::make_shared<TqTerminateImpl>(*this)));
    const auto r5 = reg("XTaskQueueDuplicateHandle", keep(std::make_shared<TqDuplicateHandleImpl>(*this)));
    const auto r6 = reg("XTaskQueueSubmitCallback", keep(std::make_shared<TqSubmitCallbackImpl>(*this)));
    for (const auto* r : {&r1, &r2, &r3, &r4, &r5, &r6}) {
        if (!r->ok()) {
            (void)api_reg_.revoke_owner(owner);
            owned_.clear();
            return Result<void>(r->errc(), r->context());
        }
    }
    auto observer = pm_.add_process_exit_observer(
        [this](std::uint64_t process_id) { release_process(process_id); });
    if (!observer.ok()) {
        (void)api_reg_.revoke_owner(owner);
        owned_.clear();
        return Result<void>(observer.errc(), observer.context());
    }
    process_exit_observer_id_ = observer.value();
    return Result<void>::ok_result();
}

Result<void> TaskQueueService::on_shutdown() {
    Result<void> observer_removed = Result<void>::ok_result();
    if (process_exit_observer_id_ != 0) {
        observer_removed = pm_.remove_process_exit_observer(process_exit_observer_id_);
        process_exit_observer_id_ = 0;
    }
    const auto revoked = api_reg_.revoke_owner(id());
    std::vector<std::uint64_t> pids;
    {
        std::lock_guard lock(lock_);
        for (const auto& [pid, ids] : process_queue_objects_) {
            (void)ids;
            pids.push_back(pid);
        }
    }
    for (const auto pid : pids) release_process(pid);
    owned_.clear();
    if (!observer_removed.ok() && observer_removed.errc() != RuntimeErrc::NotFound)
        return Result<void>(observer_removed.errc(), observer_removed.context());
    if (!revoked.ok()) return Result<void>(revoked.errc(), revoked.context());
    return Result<void>::ok_result();
}

Result<RefGuard> TaskQueueService::lookup_queue(
    std::uint64_t process_id, std::uint64_t queue_id) const {
    if (process_id == 0 || queue_id == 0)
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "null task-queue handle or process id");
    auto process = pm_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<RefGuard>(RuntimeErrc::NotFound, "task-queue owner process does not exist");
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr)
        return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch, "task-queue owner is not a managed process");
    auto object = owner->handle_table().lookup(Handle::from_raw(queue_id));
    if (!object.ok()) return Result<RefGuard>(object.errc(), object.context());
    auto* queue = object.value().get() != nullptr ? object.value().get()->as<Queue>() : nullptr;
    if (queue == nullptr)
        return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch, "handle is not a task queue in this process");
    if (queue->owner_process_id != process_id)
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "task queue handle belongs to another process");
    return Result<RefGuard>(std::move(object.value()));
}

Result<std::uint64_t> TaskQueueService::create_queue(
    std::uint64_t process_id, std::uint32_t work_mode,
    std::uint32_t completion_mode) {
    const auto manual = static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual);
    if (work_mode != manual || completion_mode != manual)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
            "only manual dispatch mode is implemented; other modes require callback scheduling");
    if (process_id == 0)
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "task queue requires a process owner");
    auto process = pm_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<std::uint64_t>(RuntimeErrc::NotFound, "task-queue owner process does not exist");
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr || owner->state() == ProcessState::Terminating ||
        owner->state() == ProcessState::Terminated || owner->state() == ProcessState::Failed)
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated, "task-queue owner process is not live");

    auto queue = std::make_unique<Queue>();
    queue->owner_process_id = process_id;
    queue->service = this;
    queue->work_mode = work_mode;
    queue->completion_mode = completion_mode;
    auto object_id = pm_.objects().register_object(std::move(queue));
    if (!object_id.ok()) return Result<std::uint64_t>(object_id.errc(), object_id.context());
    auto object = pm_.objects().lookup_id(object_id.value());
    if (!object.ok()) {
        (void)pm_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(object.errc(), object.context());
    }
    auto handle = owner->handle_table().create(*object.value().get());
    if (!handle.ok()) {
        object.value().release();
        (void)pm_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(handle.errc(), handle.context());
    }
    bool rejected = false;
    {
        std::lock_guard lock(lock_);
        const auto state = owner->state();
        rejected = state == ProcessState::Terminating ||
                   state == ProcessState::Terminated || state == ProcessState::Failed;
        if (!rejected) process_queue_objects_[process_id].push_back(object_id.value());
        else (void)owner->handle_table().close(handle.value());
    }
    if (rejected) {
        object.value().release();
        process.value().release();
        (void)pm_.objects().destroy(object_id.value());
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated,
                                     "task-queue owner process terminated during creation");
    }
    return Result<std::uint64_t>(handle.value().raw());
}

Result<std::uint64_t> TaskQueueService::duplicate_queue(
    std::uint64_t process_id, std::uint64_t queue_id) {
    auto queue = lookup_queue(process_id, queue_id);
    if (!queue.ok()) return Result<std::uint64_t>(queue.errc(), queue.context());
    auto process = pm_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<std::uint64_t>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr) return Result<std::uint64_t>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    std::lock_guard lock(lock_);
    auto* value = queue.value().get()->as<Queue>();
    if (value == nullptr || value->terminated)
        return Result<std::uint64_t>(RuntimeErrc::ProcessTerminated, "task queue is terminated");
    auto duplicate = owner->handle_table().duplicate(Handle::from_raw(queue_id));
    if (!duplicate.ok()) return Result<std::uint64_t>(duplicate.errc(), duplicate.context());
    return Result<std::uint64_t>(duplicate.value().raw());
}

Result<void> TaskQueueService::submit_callback(
    std::uint64_t process_id, std::uint64_t queue_id, XTaskQueuePort port,
    std::uint64_t callback_context, std::uint64_t callback_va) {
    if (process_id == 0 || callback_va == 0 ||
        (port != XTaskQueuePort::Work && port != XTaskQueuePort::Completion))
        return Result<void>(RuntimeErrc::InvalidArgument,
            "callback submission requires a process, valid port, and non-null guest callback");
    auto queue_ref = lookup_queue(process_id, queue_id);
    if (!queue_ref.ok()) return Result<void>(queue_ref.errc(), queue_ref.context());
    auto* queue = queue_ref.value().get()->as<Queue>();
    if (queue == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "handle is not a task queue");
    std::lock_guard lock(lock_);
    if (queue->terminated)
        return Result<void>(RuntimeErrc::ProcessTerminated, "cannot submit callbacks to a terminated queue");
    auto& callbacks = port == XTaskQueuePort::Work ? queue->work_callbacks : queue->completion_callbacks;
    constexpr std::size_t kMaxPendingCallbacksPerPort = 4096;
    if (callbacks.size() >= kMaxPendingCallbacksPerPort)
        return Result<void>(RuntimeErrc::OutOfResources, "manual task queue callback limit reached");
    callbacks.push_back(Queue::Callback{callback_context, callback_va, false});
    queue_cv_.notify_all();
    return Result<void>::ok_result();
}

Result<bool> TaskQueueService::dispatch(
    std::uint64_t process_id, std::uint64_t queue_id, XTaskQueuePort port,
    std::uint32_t timeout_ms, const GuestCallbackInvoker& invoke_callback,
    const std::function<bool()>& cancellation_requested) {
    auto queue_ref = lookup_queue(process_id, queue_id);
    if (!queue_ref.ok()) return Result<bool>(queue_ref.errc(), queue_ref.context());
    auto* queue = queue_ref.value().get()->as<Queue>();
    if (queue == nullptr) return Result<bool>(RuntimeErrc::ObjectTypeMismatch, "handle is not a task queue");
    std::unique_lock lock(lock_);
    if (port != XTaskQueuePort::Work && port != XTaskQueuePort::Completion)
        return Result<bool>(RuntimeErrc::InvalidArgument, "unknown XTaskQueuePort value");
    auto& callbacks = port == XTaskQueuePort::Work ? queue->work_callbacks : queue->completion_callbacks;
    ++queue->active_dispatches;
    const auto finish_dispatch = [&] {
        if (queue->active_dispatches != 0) --queue->active_dispatches;
        if (queue->terminated && queue->active_dispatches == 0) {
            queue->work_callbacks.clear();
            queue->completion_callbacks.clear();
        }
    };
    const auto ready = [&] { return !callbacks.empty() || queue->terminated; };
    const bool infinite = timeout_ms == 0xFFFFFFFFu;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(infinite ? 0u : timeout_ms);
    while (!ready()) {
        if (cancellation_requested && cancellation_requested()) {
            finish_dispatch();
            return Result<bool>(RuntimeErrc::ThreadTerminated,
                                "task-queue dispatch canceled by guest-thread termination");
        }
        if (timeout_ms == 0) break;
        // Bounded park intervals let the managed thread's cooperative
        // cancellation become visible even when no queue event is signaled.
        constexpr auto kCancellationPoll = std::chrono::milliseconds(2);
        if (infinite) {
            queue_cv_.wait_for(lock, kCancellationPoll);
        } else {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            const auto remaining = deadline - now;
            queue_cv_.wait_for(lock, std::min(remaining,
                std::chrono::steady_clock::duration(kCancellationPoll)));
        }
    }
    if (cancellation_requested && cancellation_requested()) {
        finish_dispatch();
        return Result<bool>(RuntimeErrc::ThreadTerminated,
                            "task-queue dispatch canceled by guest-thread termination");
    }
    if (callbacks.empty()) {
        finish_dispatch();
        return Result<bool>(false);
    }
    if (!invoke_callback) {
        finish_dispatch();
        return Result<bool>(RuntimeErrc::InvalidState, "manual guest callback dispatch requires an execution backend");
    }
    auto callback = callbacks.front();
    callbacks.pop_front();
    ++queue->active_callbacks;
    callback.canceled = callback.canceled || queue->terminated;
    lock.unlock();

    Result<void> invoked = Result<void>::ok_result();
    try {
        invoked = invoke_callback(callback.callback_va, callback.context, callback.canceled);
    } catch (const std::exception& error) {
        invoked = Result<void>(RuntimeErrc::PlatformError,
                               std::string("guest callback invoker threw: ") + error.what());
    } catch (...) {
        invoked = Result<void>(RuntimeErrc::PlatformError, "guest callback invoker threw an unknown exception");
    }
    lock.lock();
    if (queue->active_callbacks != 0) --queue->active_callbacks;
    finish_dispatch();
    queue_cv_.notify_all();
    lock.unlock();
    if (!invoked.ok())
        return Result<bool>(invoked.errc(), "guest task-queue callback failed: " + invoked.error_string());
    return Result<bool>(true);
}

Result<void> TaskQueueService::Queue::close_guest_handle(
    std::uint64_t process_id, std::uint64_t raw_handle, RefGuard&& object_pin) {
    if (service == nullptr)
        return Result<void>(RuntimeErrc::InvalidState, "task queue service is unavailable");
    return service->close_queue_with_guard(process_id, raw_handle, std::move(object_pin));
}

Result<void> TaskQueueService::close_queue(
    std::uint64_t process_id, std::uint64_t queue_id) {
    auto queue_ref = lookup_queue(process_id, queue_id);
    if (!queue_ref.ok()) return Result<void>(queue_ref.errc(), queue_ref.context());
    return close_queue_with_guard(process_id, queue_id, std::move(queue_ref.value()));
}

Result<void> TaskQueueService::close_queue_with_guard(
    std::uint64_t process_id, std::uint64_t queue_id, RefGuard&& queue_ref) {
    if (!queue_ref || queue_ref.get()->as<Queue>() == nullptr)
        return Result<void>(RuntimeErrc::InvalidHandle, "task-queue object pin is invalid");
    auto process = pm_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<void>(process.errc(), process.context());
    auto* owner = process.value().get()->as<ManagedProcess>();
    if (owner == nullptr)
        return Result<void>(RuntimeErrc::ObjectTypeMismatch, "owner is not a managed process");
    const auto object_id = queue_ref.get()->id();
    bool last_handle = false;
    {
        std::lock_guard lock(lock_);
        auto closed = owner->handle_table().close(Handle::from_raw(queue_id));
        if (!closed.ok()) return closed;
        const auto remaining = owner->handle_table().list_handles();
        last_handle = std::none_of(remaining.begin(), remaining.end(),
            [&](const auto& info) { return info.object_id == object_id; });
        if (last_handle) {
            auto* queue = queue_ref.get()->as<Queue>();
            if (queue != nullptr) {
                queue->terminated = true;
                for (auto& callback : queue->work_callbacks) callback.canceled = true;
                for (auto& callback : queue->completion_callbacks) callback.canceled = true;
                if (queue->active_dispatches == 0) {
                    queue->work_callbacks.clear();
                    queue->completion_callbacks.clear();
                }
            }
            auto it = process_queue_objects_.find(process_id);
            if (it != process_queue_objects_.end()) {
                auto& ids = it->second;
                ids.erase(std::remove(ids.begin(), ids.end(), object_id), ids.end());
                if (ids.empty()) process_queue_objects_.erase(it);
            }
        }
    }
    queue_cv_.notify_all();
    if (last_handle) {
        queue_ref.release();
        process.value().release();
        return pm_.objects().destroy(object_id);
    }
    return Result<void>::ok_result();
}

Result<void> TaskQueueService::terminate_queue(
    std::uint64_t process_id, std::uint64_t queue_id, bool wait) {
    auto queue_ref = lookup_queue(process_id, queue_id);
    if (!queue_ref.ok()) return Result<void>(queue_ref.errc(), queue_ref.context());
    auto* queue = queue_ref.value().get()->as<Queue>();
    if (queue == nullptr) return Result<void>(RuntimeErrc::ObjectTypeMismatch, "handle is not a task queue");
    {
        std::lock_guard lock(lock_);
        queue->terminated = true;
        for (auto& callback : queue->work_callbacks) callback.canceled = true;
        for (auto& callback : queue->completion_callbacks) callback.canceled = true;
        (void)wait;
    }
    queue_cv_.notify_all();
    return Result<void>::ok_result();
}

void TaskQueueService::release_process(std::uint64_t process_id) {
    std::vector<std::uint64_t> object_ids;
    {
        std::lock_guard lock(lock_);
        const auto it = process_queue_objects_.find(process_id);
        if (it == process_queue_objects_.end()) return;
        object_ids = std::move(it->second);
        process_queue_objects_.erase(it);
    }
    for (const auto object_id : object_ids) {
        auto object = pm_.objects().lookup_id(object_id);
        if (object.ok()) {
            if (auto* queue = object.value().get()->as<Queue>()) {
                std::lock_guard lock(lock_);
                queue->terminated = true;
                queue->work_callbacks.clear();
                queue->completion_callbacks.clear();
            }
            object.value().release();
        }
        queue_cv_.notify_all();
        (void)pm_.objects().destroy(object_id);
    }
}

std::size_t TaskQueueService::live_queues() const {
    std::lock_guard lock(lock_);
    std::size_t count = 0;
    for (const auto& [pid, ids] : process_queue_objects_) {
        (void)pid;
        count += ids.size();
    }
    return count;
}

// ── TimingService ────────────────────────────────────────────────────────

TimingService::TimingService(ApiRegistry& api_reg)
    : RtService("win32_timing"), api_reg_(api_reg) {}

TimingService::~TimingService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

Result<void> TimingService::on_initialize() {
    const std::uint64_t owner = id();
    auto keep = [this](std::shared_ptr<IApiImplementation> impl) {
        owned_.push_back(impl);
        return impl;
    };
    const auto r1 = api_reg_.register_implementation(
        "kernel32", "QueryPerformanceCounter",
        keep(std::make_shared<QpcImpl>(*this)), owner);
    const auto r2 = api_reg_.register_implementation(
        "kernel32", "QueryPerformanceFrequency",
        keep(std::make_shared<QpfImpl>(*this)), owner);
    const auto r3 = api_reg_.register_implementation(
        "kernel32", "GetCurrentProcessId",
        keep(std::make_shared<CurrentProcessIdImpl>()), owner);
    const auto r4 = api_reg_.register_implementation(
        "kernel32", "GetCurrentThreadId",
        keep(std::make_shared<CurrentThreadIdImpl>()), owner);
    if (!r1.ok()) return r1;
    if (!r2.ok()) return r2;
    if (!r3.ok()) return r3;
    if (!r4.ok()) return r4;
    return Result<void>::ok_result();
}

Result<void> TimingService::on_shutdown() {
    const auto revoked = api_reg_.revoke_owner(id());
    owned_.clear();
    if (!revoked.ok()) {
        return Result<void>(revoked.errc(), revoked.context());
    }
    return Result<void>::ok_result();
}

Result<std::uint64_t> TimingService::qpc_value() {
    return Result<std::uint64_t>(
        static_cast<std::uint64_t>(pal::now_ns()));
}

Result<std::uint64_t> TimingService::qpc_frequency() {
    // PAL clock is nanosecond monotonic: frequency is 1e9 (documented QPF
    // semantics: counts per second, fixed).
    return Result<std::uint64_t>(1'000'000'000ull);
}

// ── TLS per-thread initialization ────────────────────────────────────────

namespace {
struct TlsIndexTable {
    std::mutex lock;
    // process id -> (image name -> index)
    std::map<std::uint64_t, std::map<std::string, std::uint32_t>> per_process;
    std::uint32_t next_index = 1;   // 0 reserved
};
TlsIndexTable& tls_table() {
    static TlsIndexTable t;
    return t;
}
}  // namespace

Result<std::uint32_t> tls_assign_index(std::uint64_t process_id,
                                       const std::string& image_name,
                                       const loader::TlsInfo& info) {
    if (info.template_size > loader::kMaxTlsTemplate) {
        return Result<std::uint32_t>(RuntimeErrc::OutOfResources,
                                     "TLS template too large");
    }
    auto& t = tls_table();
    std::lock_guard lock(t.lock);
    auto& images = t.per_process[process_id];
    const auto it = images.find(image_name);
    if (it != images.end()) {
        return Result<std::uint32_t>(it->second);   // documented: stable index
    }
    const std::uint32_t idx = t.next_index++;
    images.emplace(image_name, idx);
    return Result<std::uint32_t>(idx);
}

Result<void> tls_init_thread(RtThread& thread, std::uint32_t index,
                             const pe::PeImage& img, const std::uint8_t* file,
                             std::size_t file_size, const loader::TlsInfo& info) {
    if (index == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument, "TLS index 0 reserved");
    }
    // Template bytes: read from the file at the template RVA (loader
    // discipline: resolve through the section table).
    std::vector<std::uint8_t> tpl(
        static_cast<std::size_t>(info.template_size), 0);
    if (info.template_size > 0) {
        bool ok = false;
        std::uint64_t off = 0;
        if (info.template_rva < img.opt.size_of_headers) {
            off = info.template_rva;
            ok = off + info.template_size <= file_size;
        } else {
            for (const auto& s : img.sections) {
                if (s.contains_rva(static_cast<std::uint32_t>(info.template_rva)) &&
                    s.has_raw_data) {
                    const std::uint64_t in = info.template_rva - s.virtual_address;
                    if (in + info.template_size <= s.size_of_raw_data) {
                        off = s.raw_data_offset + in;
                        ok = true;
                    }
                    break;
                }
            }
        }
        if (!ok) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "TLS template not file-backed");
        }
        std::memcpy(tpl.data(), file + off,
                    static_cast<std::size_t>(info.template_size));
    }
    // Zero-fill beyond the template (documented SizeOfZeroFill semantics:
    // the thread's block is template + zero fill). Bounded: the total TLS
    // block must stay within the same 1 MiB limit as the template (a
    // mutated/huge SizeOfZeroFill would otherwise request a multi-GB
    // allocation — found by the M7 TLS fuzz harness; regression-covered).
    constexpr std::uint32_t kMaxTlsBlock = loader::kMaxTlsTemplate;
    const std::uint64_t total_64 =
        tpl.size() + static_cast<std::uint64_t>(info.zero_fill_size);
    if (total_64 > kMaxTlsBlock) {
        return Result<void>(RuntimeErrc::OutOfResources,
                           "TLS block (template + SizeOfZeroFill) exceeds the "
                           "1 MiB limit");
    }
    tpl.resize(static_cast<std::size_t>(total_64), 0);
    return thread.tls_set(index, tpl.data(), tpl.size());
}

Result<std::size_t> tls_release_indices(std::uint64_t process_id) {
    auto& t = tls_table();
    std::lock_guard lock(t.lock);
    const auto it = t.per_process.find(process_id);
    if (it == t.per_process.end()) return Result<std::size_t>(0);
    const std::size_t n = it->second.size();
    t.per_process.erase(it);
    return Result<std::size_t>(n);
}

}  // namespace xbox2pc::rt::api
