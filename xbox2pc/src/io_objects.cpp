// io_objects.cpp — RtMemoryRegion + RtFile implementation.

#include "xbox2pc/io_objects.hpp"

#include <utility>

namespace xbox2pc::rt {

// ── RtMemoryRegion ────────────────────────────────────────────────────────

RtMemoryRegion::RtMemoryRegion(std::uint64_t size, Mode mode, std::string name)
    : RuntimeObject(TypeId::MemoryRegion),
      size_(size),
      mode_(mode),
      pal_(mode == Mode::Reserved ? pal::reserve_memory(size)
                                  : pal::commit_memory(size)) {
    if (pal_ == nullptr) {
        // Allocation failure at construction is fatal to the object; the
        // manager still registers it (typed errors on every access) and
        // the failure is observable via base() -> OutOfResources.
        set_meta("alloc-failed", "true");
        return;
    }
    set_name(std::move(name));
}

Result<void*> RtMemoryRegion::base() {
    if (!is_alive()) {
        return Result<void*>(RuntimeErrc::ObjectDestroyed, "memory region destroyed");
    }
    if (pal_ == nullptr) {
        return Result<void*>(RuntimeErrc::OutOfResources, "region allocation failed");
    }
    return Result<void*>(pal_->base());
}

Result<std::uint64_t> RtMemoryRegion::size() const {
    if (!is_alive()) {
        return Result<std::uint64_t>(RuntimeErrc::ObjectDestroyed,
                                     "memory region destroyed");
    }
    return Result<std::uint64_t>(size_);
}

Result<void> RtMemoryRegion::protect(bool read, bool write, bool exec) {
    if (!is_alive()) {
        return Result<void>(RuntimeErrc::ObjectDestroyed, "memory region destroyed");
    }
    if (pal_ == nullptr) {
        return Result<void>(RuntimeErrc::OutOfResources, "region allocation failed");
    }
    return pal_->protect(read, write, exec);
}

void RtMemoryRegion::on_destroy() {
    // PAL region dtor unmaps; nothing extra.
}

// ── RtFile ─────────────────────────────────────────────────────────────────

RtFile::RtFile(std::string host_path, pal::FileOpenMode mode, std::string name)
    : RuntimeObject(TypeId::File), path_(std::move(host_path)) {
    set_name(std::move(name));
    set_meta("open-mode",
             mode == pal::FileOpenMode::ReadExisting      ? "read"
             : mode == pal::FileOpenMode::WriteNew         ? "write-new"
                                                           : "read-write-append");
    // Open eagerly; failures are recorded as metadata and every access
    // returns InvalidState with the recorded reason (errors never vanish).
    auto opened = pal::open_file(path_, mode);
    if (opened.ok()) {
        pal_ = std::move(opened.value());
    } else {
        set_meta("open-error", opened.error_string());
    }
}

Result<std::uint64_t> RtFile::read(void* buf, std::uint64_t len) {
    if (pal_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState, "file not opened");
    }
    return pal_->read(buf, len);
}

Result<std::uint64_t> RtFile::write(const void* buf, std::uint64_t len) {
    if (pal_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState, "file not opened");
    }
    return pal_->write(buf, len);
}

Result<std::uint64_t> RtFile::seek(std::int64_t offset, bool from_end) {
    if (pal_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState, "file not opened");
    }
    return pal_->seek(offset, from_end);
}

Result<std::uint64_t> RtFile::size() const {
    if (pal_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState, "file not opened");
    }
    return pal_->size();
}

Result<void> RtFile::close() {
    if (pal_ == nullptr) {
        return Result<void>(RuntimeErrc::InvalidState, "file not opened");
    }
    return pal_->close();
}

bool RtFile::is_open() const { return pal_ != nullptr && pal_->is_open(); }

void RtFile::on_destroy() {
    if (pal_ != nullptr && pal_->is_open()) {
        // Close errors on teardown are recorded, not silently discarded.
        const Result<void> r = pal_->close();
        if (!r.ok()) {
            set_meta("close-error", r.error_string());
        }
    }
}

}  // namespace xbox2pc::rt
