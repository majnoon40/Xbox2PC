# M5 — Virtual Filesystem

## Responsibility

`vfs.hpp/.cpp` (library `xbox2pc_rt_vfs`) implements the path model, the
backend interface, mount management and namespaces; `vfs_backends.hpp/.cpp`
(`xbox2pc_rt_vfs_backends`) provides the host-directory and in-memory
backends; `vfs_process.hpp/.cpp` (`xbox2pc_rt_vfs_process`) wires namespaces
to M4 processes. Host filesystem access exists ONLY inside the PAL
(`pal_linux.cpp` — directory ops added in M5).

## Path model (security-critical; fuzzed)

Canonical paths are '/'-separated, rooted at "/", with a **258-component
/ 255-char-component / 4096-char-total** default policy (`VfsPathPolicy`,
configurable). `VfsPath::parse`:

- folds repeated separators, interior `/.`, trailing `/`;
- resolves `..` by cancellation — **`..` above the root is rejected**
  (`/..`, `/a/../../b` → typed `InvalidArgument`); traversal cannot escape;
- rejects control characters and DEL; backslashes are rejected unless the
  policy explicitly enables them as separators (default: strict);
- relative input is rooted ("/a" ≡ "a");
- output is the canonical component vector — **idempotent**
  (parse(str(parse(x))) == parse(x); fuzz-enforced).

**Symlinks:** the VFS itself has none (design decision — documented
Xbox-agnostic; the Xbox OS rule is not published in the consulted
sources). On the HOST backend, symlinks are DETECTED and REJECTED by
default (PAL `lstat` probe; `HostDirBackend::open/create` refuse them with
typed errors) — symlink escape through a host mount is impossible by
construction.

**Case policy:** paths are case-SENSITIVE by default (matching NTFS's
common console configuration is NOT claimed — Xbox's own rule is unknown
to us). The policy carries a per-mount case-insensitive flag; backends
may declare it (`IVfsBackend::case_insensitive`).

## Mounts & namespaces

A `VfsNamespace` is a mount table over backends:

- `mount(path, backend, read_only, precedence)`: read-only is forced when
  the backend is read-only; multiple mounts stack;
- **lookup**: longest-prefix (most-specific mount path wins), then higher
  precedence, then later mount order — fully deterministic;
- **unmount** refuses while files are open on the mount (typed
  `InvalidState` with the live count);
- `list()` merges the serving backend's listing with one-level sub-mounts
  (sub-mounts appear as directories);
- `walk()` is a bounded DFS (typed `OutOfResources` past `max_entries`).

## Backends

| Backend | Storage | Mutations |
|---|---|---|
| `HostDirBackend` | one host root directory (PAL only) | optional read-only mode |
| `MemoryBackend` | in-memory tree (sorted map = deterministic order) | full CRUD |
| `PackageVfsBackend` | a parsed container (M5 packages lib) | always read-only |

`HostDirBackend` confinement: host paths are assembled ONLY as
`root + '/' + validated components`; components cannot contain separators
after parsing, so no host-path injection or traversal is constructible.
The root must exist (validated in the ctor; invalid roots fail every
operation with typed `NotInitialized`).

`MemoryBackend` file payloads are **shared strings**: the tree node and
every open handle reference the same storage, so writes through one handle
are visible to all handles and to later opens (an early draft copied the
payload at open — found by a test, fixed and regression-locked). Deletion
of an open file keeps the handle's view alive (POSIX-like semantics).

## Process namespaces (M4 integration)

`VfsSession` (RuntimeObject) owns one namespace plus registered backend
objects. `create_process_with_vfs` attaches a session to a process
(session id recorded in process metadata); the `proc_*` bridges
(`vfs_process.hpp`) resolve the owning process BY HANDLE first, so every
operation is M4-handle-gated. Sessions start EMPTY — cross-process access
happens only by explicitly mounting the same backend object into both
(tests cover the isolation both ways).

File objects are `VfsFileObject` (TypeId::File) wrapped in M4
generation-protected handles with rights (read-only opens get no Write
right); **process termination closes the handle table (M4 ordering step
c) → objects destroyed → open counts balanced**. There is no second handle
system anywhere.

## Bugs found by testing/sanitizers during M5 (all fixed + regression-locked)

1. **Teardown use-after-free** (TSan): `VfsFileObject::on_destroy` touched
   the session-owned namespace after the session's destruction during
   manager teardown → the namespace Impl is now a `shared_ptr` and file
   objects keep a keep-alive token; the tracked-handle wrapper decrements
   through the token (teardown-order independent).
2. **Open-count leak**: raw backend handles returned by namespace `open`
   never decremented the mount's open-file count → unmount stayed refused
   forever → every handle is now a `TrackedFileHandle` whose destructor
   balances the count exactly once.
3. **Write invisibility**: memory-backend opens copied the payload →
   shared storage (see above).
4. **Root-node type**: the in-memory tree root defaulted to a file node →
   depth-1 creates failed.
5. **Builder/parser divergence**: the XPK builder did not materialize
   implicit parent directories, producing containers its own parser
   rejects (found by the benchmark fixture) → the builder now emits
   explicit directory entries for every ancestor.

## Known limitations

- One mount tree per namespace; no mount-time flags beyond
  read-only/precedence (no per-mount case override applied to LOOKUP yet —
  the flag is carried but `find_mount_for` compares exact paths; a
  case-insensitive resolution pass is future work).
- `walk()` materializes all paths; the bounded ceiling protects memory,
  but huge trees need a streaming visitor (future).
- No file locking, no sparse files, no timestamps (stat carries
  exists/dir/size only — matching what the runtime needs today).
- Host backend serializes all PAL calls with one mutex (correctness over
  throughput); concurrent read scaling is future work.

## Confirmed vs inferred

Confirmed (cited, host facts): Linux `stat`/`lstat`/`opendir` semantics
— https://man7.org/linux/man-pages/man2/lstat.2.html and
https://man7.org/linux/man-pages/man3/opendir.3.html

Inferred (xbox2pc design — no Xbox filesystem internals are claimed): the
path policy (separators, case default, depth/length limits), the mount
precedence rules, session-per-process namespaces, POSIX-like
unlink-while-open semantics. Xbox OS filesystem structure is proprietary
and explicitly not reproduced.
