#pragma once
// xbox2pc/vfs_backends.hpp — M5 concrete VFS backends.
//
//   1. HostDirBackend: a DEV/TEST backend over ONE host root directory.
//      All host access goes through the PAL (stat/list/create/... helpers
//      added in M5); the backend NEVER sees or builds host paths from
//      user input directly — every child path is assembled from the fixed
//      root + the validated VfsPath components (components contain no
//      separators after parsing, so no host-path injection exists).
//      Read-only mode is enforced at the backend. Symlinks on the host
//      side are NOT followed by policy: PAL stat/list report them as
//      plain entries; opening a symlinked file through open() resolves on
//      the host — the backend rejects host symlinks when
//      reject_host_symlinks is set (default: yes — documented security
//      posture; "symlink escape" tests cover it).
//   2. MemoryBackend: fully in-memory tree (tests, synthetic packages,
//      scratch spaces). Deterministic, no host touch at all.
//
// Both are IVfsBackend implementations; mounting/precedence/isolation
// live in the namespace (vfs.hpp).

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/vfs.hpp"

namespace xbox2pc::rt {

// ── host-directory backend ─────────────────────────────────────────────────

class HostDirBackend : public IVfsBackend {
public:
    // `host_root` must be an existing host directory (validated through
    // the PAL; typed error otherwise). read_only disables mutations.
    HostDirBackend(std::string host_root, bool read_only);
    ~HostDirBackend() override;

    const char* backend_name() const override { return "host-dir"; }
    bool read_only() const override { return read_only_; }

    Result<VfsStat> stat(const VfsPath& rel) override;
    Result<std::unique_ptr<IVfsFileHandle>> open(const VfsPath& rel,
                                                 bool write) override;
    Result<void> create_file(const VfsPath& rel) override;
    Result<void> delete_file(const VfsPath& rel) override;
    Result<void> create_directory(const VfsPath& rel) override;
    Result<void> delete_directory(const VfsPath& rel) override;
    Result<std::vector<VfsDirEntry>> list(const VfsPath& rel) override;

    const std::string& host_root() const { return root_; }

private:
    // Root-confined host path assembly: root + '/' + components (the
    // components carry no separators — VfsPath::parse guarantees this).
    std::string host_path_for(const VfsPath& rel) const;
    // Symlink check on the final target (PAL stat; detects link targets).
    Result<void> reject_if_symlink(const std::string& host_path,
                                   const std::string& what) const;

    const std::string root_;
    const bool read_only_;
    const bool reject_symlinks_;
    bool root_valid_ = false;       // ctor validation result
    std::string root_error_;        // surfaced through every op when invalid
    mutable std::mutex io_lock_;   // serializes PAL calls on this backend
};

// ── in-memory backend ───────────────────────────────────────────────────────

class MemoryBackend : public IVfsBackend {
public:
    MemoryBackend();
    ~MemoryBackend() override;

    const char* backend_name() const override { return "memory"; }
    bool read_only() const override { return false; }
    // Deterministic ordering; entries stored as given (no folding).
    bool case_insensitive() const override { return false; }

    Result<VfsStat> stat(const VfsPath& rel) override;
    Result<std::unique_ptr<IVfsFileHandle>> open(const VfsPath& rel,
                                                 bool write) override;
    Result<void> create_file(const VfsPath& rel) override;
    Result<void> delete_file(const VfsPath& rel) override;
    Result<void> create_directory(const VfsPath& rel) override;
    Result<void> delete_directory(const VfsPath& rel) override;
    Result<std::vector<VfsDirEntry>> list(const VfsPath& rel) override;

    // Test/fixture helpers (not part of IVfsBackend): pre-populate a file
    // with content in one call.
    Result<void> seed_file(const VfsPath& rel, const std::string& content);

private:

private:
    struct Node {
        bool is_dir = false;
        // File payload as a SHARED string: the tree node and every open
        // handle reference the SAME storage (the M5 fix — the first draft
        // copied the payload at open, so writes through one handle were
        // invisible to others and to later opens).
        std::shared_ptr<std::string> data;
        std::map<std::string, Node> children;  // sorted (determinism)
    };

    Node root_;
    // shared_ptr (not a member mutex): file handles need a view of the
    // SAME lock to safely read payloads after the node may be erased
    // (POSIX-like unlink-while-open semantics) — std::mutex is neither
    // movable nor shareable as a member.
    std::shared_ptr<std::mutex> lock_ = std::make_shared<std::mutex>();

    // Node construction helpers (shared payload allocation).
    static Node file_node();
    static Node dir_node();
    Node* navigate(const Node* base, const VfsPath& rel) const;
    Node* navigate_mut(Node* base, const VfsPath& rel);
    // Parent access for create/delete validation.
    Node* parent_of(Node& root, const VfsPath& rel, std::string& last_out);
};

// The memory-backed file handle: position-tracked over the payload
// (shared with the backend's node via an offset-locked view).
class MemoryFileHandle : public IVfsFileHandle {
public:
    // Created by MemoryBackend::open; takes a shared payload reference and
    // the backend's shared tree lock.
    MemoryFileHandle(std::shared_ptr<std::string> payload, bool writable,
                     std::shared_ptr<std::mutex> backend_lock);
    ~MemoryFileHandle() override = default;

    Result<std::uint64_t> read(void* buf, std::uint64_t len) override;
    Result<std::uint64_t> write(const void* buf, std::uint64_t len) override;
    Result<std::uint64_t> seek(std::uint64_t position) override;
    std::uint64_t position() const override;
    std::uint64_t size() const override;

private:
    std::shared_ptr<std::string> data_;
    std::shared_ptr<std::mutex> lock_;  // backend tree lock (payload safety)
    std::uint64_t pos_ = 0;
    const bool writable_;
};

}  // namespace xbox2pc::rt
