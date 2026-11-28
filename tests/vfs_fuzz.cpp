// vfs_fuzz.cpp — M5 deterministic fuzz harnesses (no libFuzzer needed:
// seeded byte-mutation fuzz, fully reproducible). Run as a normal test
// binary; nonzero exit on any crash/hang-class bug. GoogleTest wraps the
// corpora so failures are visible in ctest output.
//
// Targets (spec §8.4):
//   * path normalization (random path strings — must reject/accept deterministically)
//   * package headers + entry tables (mutations of valid XPK containers)
//   * container readers (BoundedReader ops on adversarial sizes/offsets)
//
// Every fuzz case asserts the INVARIANT: parse yields a typed Result —
// never a crash, hang, or unbounded allocation (enforced by per-case
// caps + the whole-binary timeout in CI).

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "xbox2pc/packages.hpp"
#include "xbox2pc/vfs.hpp"

using namespace xbox2pc::rt;

namespace {

class MiniRng {
public:
    explicit MiniRng(std::uint64_t seed) : s_(seed) {}
    std::uint64_t next() {
        s_ ^= s_ << 13;
        s_ ^= s_ >> 7;
        s_ ^= s_ << 17;
        return s_;
    }
    std::uint8_t byte() { return static_cast<std::uint8_t>(next() >> 32); }
    // ASCII-heavy char generator (paths mostly printable).
    char path_char() {
        static const char pool[] =
            "abcdefghijklmnopqrstuvwxyzABC0123456789._-/~\\\\\x01\x7f";
        const std::uint64_t pick = next() % (sizeof(pool) - 1);
        return pool[pick];
    }

private:
    std::uint64_t s_;
};

}  // namespace

// ── path normalization fuzz ────────────────────────────────────────────────

TEST(VfsFuzzTest, PathNormalizationFuzz) {
    MiniRng rng(0xfeed'beef'cafe'0001ull);
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    for (int i = 0; i < 100000; ++i) {
        // Random length 0..40 of random path chars.
        std::string s;
        const int len = static_cast<int>(rng.next() % 41);
        for (int j = 0; j < len; ++j) s.push_back(rng.path_char());
        const auto p = VfsPath::parse(s);
        if (p.ok()) {
            ++accepted;
            // INVARIANT: the normalized form re-parses to ITSELF
            // (idempotence) and contains no empty/dot/dotdot components.
            const auto again = VfsPath::parse(p.value().str());
            ASSERT_TRUE(again.ok()) << "non-idempotent: " << s;
            ASSERT_EQ(again.value().str(), p.value().str()) << s;
            for (const auto& c : p.value().components()) {
                ASSERT_FALSE(c.empty());
                ASSERT_NE(c, ".");
                ASSERT_NE(c, "..");
            }
        } else {
            ++rejected;
        }
    }
    EXPECT_GT(accepted, 1000);   // plenty of valid random paths
    EXPECT_GT(rejected, 1000);   // plenty of hostile ones caught
}

// ── package header/entry fuzz ─────────────────────────────────────────────

TEST(VfsFuzzTest, PackageMutationFuzz) {
    MiniRng rng(0x5eed'0002'abcd'0003ull);
    const auto base = xpk_build({
        {"d", true, {}},
        {"d/sub", true, {}},
        {"d/sub/a.txt", false, "alpha"},
        {"d/sub/b.bin", false, std::string(64, 'B')},
        {"d/top.dat", false, std::string(16, '?')},
    });
    int ok_count = 0;
    int fail_count = 0;
    for (int iter = 0; iter < 20000; ++iter) {
        auto bytes = base;
        const int mutations = 1 + static_cast<int>(rng.next() % 6);
        for (int m = 0; m < mutations; ++m) {
            const std::size_t at = static_cast<std::size_t>(rng.next() % bytes.size());
            bytes[at] = rng.byte();
        }
        // Random truncation as an additional mutation class.
        if (rng.next() % 4 == 0) {
            bytes.resize(rng.next() % (bytes.size() + 1));
        }
        auto r = parse_package(bytes.data(), bytes.size(), "fuzz.xpk", {});
        if (r.ok()) {
            ++ok_count;
            // INVARIANT: every entry data read is bounds-safe.
            for (std::uint64_t e = 0; e < r.value()->info().entries.size(); ++e) {
                if (!r.value()->info().entries[e].is_directory) {
                    (void)r.value()->read_entry_data(e);
                }
            }
        } else {
            ++fail_count;
            // INVARIANT: failures are TYPED, never empty contexts.
            ASSERT_FALSE(r.context().empty()) << "untyped failure at iter " << iter;
        }
    }
    EXPECT_GT(fail_count, 100);
    EXPECT_GT(ok_count, 100);
}

// ── BoundedReader fuzz ──────────────────────────────────────────────────────

TEST(VfsFuzzTest, BoundedReaderFuzz) {
    MiniRng rng(0xbead'0004'dead'0005ull);
    // Scratch destination SEPARATE from the reader's buffer (the first
    // draft read into the source buffer itself — memcpy-param-overlap,
    // caught by ASan; the reader's contract is a plain memcpy).
    std::vector<std::uint8_t> scratch(64);
    for (int iter = 0; iter < 20000; ++iter) {
        const std::size_t size = static_cast<std::size_t>(rng.next() % 256);
        std::vector<std::uint8_t> buf(size);
        for (auto& b : buf) b = rng.byte();
        BoundedReader r(buf.data(), buf.size());
        // Random op mix: read_exact/read_some/seek/peek/int readers.
        for (int op = 0; op < 8; ++op) {
            const std::uint64_t n = rng.next() % 64;
            switch (rng.next() % 6) {
                case 0: (void)r.read_exact(scratch.data(), n); break;
                case 1: (void)r.read_some(scratch.data(), n); break;
                case 2: (void)r.seek(n); break;
                case 3: (void)r.peek(n, n); break;
                case 4: (void)r.u16le(); break;
                case 5: (void)r.u64le(); break;
            }
            // INVARIANT: position never exceeds size.
            ASSERT_LE(r.position(), r.size());
            ASSERT_LE(r.remaining(), r.size());
        }
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
