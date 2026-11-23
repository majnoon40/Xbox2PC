// xbox2pc/src/guest_cpu_state.cpp — M8 guest CPU state implementation.

#include "xbox2pc/guest_cpu_state.hpp"

#include <cstring>

namespace xbox2pc::rt::cpu {

namespace {
const char* const kGprNames[kGprCount] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
};
constexpr std::uint32_t kSnapshotMagic = 0x43503258u;   // "X2PC" LE
constexpr std::uint32_t kSnapshotKind = 0x53000000u | 1u;  // 'S', version 1
}  // namespace

const char* gpr_to_name(Gpr r) {
    return kGprNames[static_cast<std::size_t>(r)];
}

std::optional<Gpr> gpr_from_name(const std::string& name) {
    for (std::size_t i = 0; i < kGprCount; ++i) {
        if (name == kGprNames[i]) return static_cast<Gpr>(i);
    }
    return std::nullopt;
}

void CpuState::reset() {
    for (std::size_t i = 0; i < kGprCount; ++i) gprs[i] = 0;
    rip = 0;
    rflags = kRflagsReset;
    for (auto& x : xmm) x.fill(0);
    mxcsr = kMxcsrStandard;
    fcw = kFcwStandard;
}

std::vector<std::string> CpuState::validate() const {
    std::vector<std::string> problems;
    const std::uint64_t rsp = gprs[static_cast<std::size_t>(Gpr::Sp)];
    if (rsp == 0) {
        problems.push_back("RSP is zero");
    } else if (rsp <= 4096) {
        problems.push_back("RSP below the 4096 floor");
    } else if (rsp >= (1ull << 63)) {
        problems.push_back("RSP at/above 2^63 (non-canonical)");
    }
    if ((rsp & 7) != 0) {
        problems.push_back("RSP not 8-byte aligned");
    }
    if (rip == 0) {
        problems.push_back("RIP is zero");
    }
    if (rip >= (1ull << 63)) {
        problems.push_back("RIP at/above 2^63 (non-canonical)");
    }
    // RFLAGS: bit 1 must be 1; reserved bits 3/5/12..31 and upper 32 must
    // be zero for a canonical state we are willing to restore.
    if ((rflags & kFlagFixed1) == 0) {
        problems.push_back("RFLAGS bit 1 cleared (must be 1)");
    }
    const std::uint64_t bad = rflags & ~0x0000'0000'0000'0FD7ull;
    if (bad != 0) {
        problems.push_back("RFLAGS reserved bits set (value outside the "
                           "architectural mask)");
    }
    return problems;
}

// ── serialization ─────────────────────────────────────────────────────────
//
// Layout (all little-endian):
//   u32 magic 'X2PC' | u32 kind+version | 16×u64 GPRs | u64 RIP | u64 RFLAGS
//   | u32 MXCSR | u32 FCW | 16×16B XMM
// Total: 8 + 128 + 16 + 8 + 256 = 416 bytes.

std::vector<std::uint8_t> CpuSnapshot::serialize() const {
    std::vector<std::uint8_t> out;
    out.reserve(416);
    auto put32 = [&](std::uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    };
    auto put64 = [&](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    };
    put32(kSnapshotMagic);
    put32(kSnapshotKind);
    for (std::size_t i = 0; i < kGprCount; ++i) put64(state.gprs[i]);
    put64(state.rip);
    put64(state.rflags);
    put32(state.mxcsr);
    put32(state.fcw);
    for (const auto& x : state.xmm) {
        for (std::uint8_t b : x) out.push_back(b);
    }
    return out;
}

Result<CpuSnapshot> CpuSnapshot::deserialize(const std::uint8_t* data,
                                            std::size_t size) {
    if (data == nullptr) {
        return Result<CpuSnapshot>(RuntimeErrc::InvalidArgument, "null data");
    }
    if (size != 416) {
        return Result<CpuSnapshot>(RuntimeErrc::InvalidArgument,
                                   "snapshot size " + std::to_string(size) +
                                       " != 416");
    }
    auto get32 = [&](std::size_t off) {
        std::uint32_t v = 0;
        for (int i = 3; i >= 0; --i) {
            v = (v << 8) | data[off + static_cast<std::size_t>(i)];
        }
        return v;
    };
    auto get64 = [&](std::size_t off) {
        std::uint64_t v = 0;
        for (int i = 7; i >= 0; --i) {
            v = (v << 8) | data[off + static_cast<std::size_t>(i)];
        }
        return v;
    };
    if (get32(0) != kSnapshotMagic) {
        return Result<CpuSnapshot>(RuntimeErrc::InvalidArgument, "bad magic");
    }
    if (get32(4) != kSnapshotKind) {
        return Result<CpuSnapshot>(RuntimeErrc::InvalidArgument,
                                   "unsupported snapshot kind/version");
    }
    CpuSnapshot snap;
    std::size_t off = 8;
    for (std::size_t i = 0; i < kGprCount; ++i) {
        snap.state.gprs[i] = get64(off);
        off += 8;
    }
    snap.state.rip = get64(off);
    off += 8;
    snap.state.rflags = get64(off);
    off += 8;
    snap.state.mxcsr = get32(off);
    off += 4;
    snap.state.fcw = get32(off);
    off += 4;
    for (auto& x : snap.state.xmm) {
        std::memcpy(x.data(), data + off, 16);
        off += 16;
    }
    const auto problems = snap.state.validate();
    if (!problems.empty()) {
        return Result<CpuSnapshot>(RuntimeErrc::InvalidArgument,
                                   "deserialized state invalid: " +
                                       problems.front());
    }
    return Result<CpuSnapshot>(snap);
}

Result<void> snapshot_into(const CpuState& from, CpuSnapshot& out) {
    out.state = from;
    return Result<void>::ok_result();
}

Result<void> restore_into(const CpuSnapshot& snap, CpuState& to) {
    const auto problems = snap.state.validate();
    if (!problems.empty()) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "snapshot invalid: " + problems.front());
    }
    to = snap.state;
    return Result<void>::ok_result();
}

}  // namespace xbox2pc::rt::cpu
