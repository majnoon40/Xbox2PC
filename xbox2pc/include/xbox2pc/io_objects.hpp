#pragma once
// xbox2pc/io_objects.hpp — M3 memory-region and file runtime objects.
//
// Both wrap PAL primitives into RuntimeObject subclasses so the object
// manager tracks them like any other runtime object:
//   - RtMemoryRegion: an anonymous PAL region with (reserve|commit) modes
//     and protect() changes; M3 models the ADDRESS SPACE side only — no
//     Xbox memory-partition semantics (documented exclusion).
//   - RtFile: typed wrapper over PAL file IO for runtime state persistence
//     and tests. This is a HOST-filesystem file object; Xbox filesystem
//     emulation is a later milestone.
//
// Safety: base()/size() from a destroyed region return typed errors (the
// object interface never hands out stale pointers — is_alive checked).

#include <cstdint>
#include <memory>
#include <string>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/platform.hpp"

namespace xbox2pc::rt {

// ── memory region ───────────────────────────────────────────────────────────

class RtMemoryRegion : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtMemoryRegion, MemoryRegion)

    enum class Mode { Reserved, Committed };

    // `size` is rounded up to host page size by the backend.
    RtMemoryRegion(std::uint64_t size, Mode mode, std::string name);

    // Typed access (refuse when destroying/destroyed — callers must hold a
    // RefGuard from the manager to guarantee lifetime).
    Result<void*> base();
    Result<std::uint64_t> size() const;
    Result<void> protect(bool read, bool write, bool exec);
    Mode mode() const { return mode_; }

    // Memory statistics for the process view.
    std::uint64_t reserved_size() const { return size_; }

private:
    void on_destroy() override;  // PAL region frees itself in its dtor

    const std::uint64_t size_;
    const Mode mode_;
    std::unique_ptr<pal::PalMemoryRegion> pal_;
};

// ── file ────────────────────────────────────────────────────────────────────

class RtFile : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtFile, File)

    // Opens (creates) a HOST file. path is host-relative — no Xbox path
    // translation exists in M3 (documented exclusion).
    RtFile(std::string host_path, pal::FileOpenMode mode, std::string name);

    Result<std::uint64_t> read(void* buf, std::uint64_t len);
    Result<std::uint64_t> write(const void* buf, std::uint64_t len);
    Result<std::uint64_t> seek(std::int64_t offset, bool from_end);
    Result<std::uint64_t> size() const;
    Result<void> close();

    bool is_open() const;
    const std::string& host_path() const { return path_; }

private:
    void on_destroy() override;  // closes if still open (errors surfaced)

    const std::string path_;
    std::unique_ptr<pal::PalFile> pal_;
};

}  // namespace xbox2pc::rt
