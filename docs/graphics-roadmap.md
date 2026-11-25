# M11 graphics roadmap

## Current status

There is no `IGraphicsProvider` implementation or `NullGraphicsProvider`
backend in this branch yet. The existing API registry can classify documented
imports, but classification is not implementation and must not be reported as
graphics support.

The first M11 graphics milestone is a deterministic null provider. It is a
test boundary for import dispatch and object lifetime, not a renderer.

## Provider boundary

Graphics imports should resolve through `ApiRegistry` to an
`IGraphicsProvider` owned by the runtime. The provider is selected explicitly
at runtime. The initial implementation is `NullGraphicsProvider`.

The interface should model only operations whose public ABI and semantics are
supported by evidence. Every provider call should produce a trace record with
the API identity, guest thread/process identity, input summary, result, and
whether the operation is implemented or stubbed. Guest pointers must be
validated and marshalled through the existing guest-memory bridge.

Opaque device, queue, fence, and command-list objects must be represented by
runtime-owned objects and process-scoped handles. Do not expose host pointers
to guest code. Wrong-type, stale, and cross-process handles must fail.

## Null provider behavior

The null provider's initial contract is deliberately narrow:

- Device, queue, fence, and command-list handles are opaque runtime objects.
- Command-list calls are recorded; no commands are executed.
- Submission records the command-list reference and ordering.
- Fence completion is immediate only for operations whose documented contract
  permits that behavior; the returned/signaled value must match the requested
  value. If the exact semantics are not established, return an explicit
  unsupported result instead of inventing success.
- Unknown or unmodeled imports fail explicitly.
- Every call is traced.
- Compatibility reporting labels all null-provider behavior as
  `Stubbed`, never `Supported`.

The test-only DLL must be authored by this project. It must not include or
vendor Microsoft GDK binaries, headers, or redistributable runtime files.

## Path to a real backend

A future real backend can translate the documented subset to Vulkan, but that
is a separate milestone and requires its own conformance tests.

A plausible implementation sequence is:

1. Define the exact guest-facing ABI and public evidence for each import.
2. Implement object lifetime, synchronization, and command recording in the
   null provider.
3. Add provider conformance tests that run without a GPU.
4. Add a Vulkan provider behind the same interface.
5. Translate resource creation, descriptor/resource binding, command recording,
   barriers, queue submission, and fences while preserving guest-visible
   ordering and error behavior.
6. Build a shader pipeline for the shader formats actually encountered and
   legally available. DXIL/DXBC handling, shader model coverage, root-signature
   mapping, descriptor layouts, and unsupported shader features need explicit
   compatibility reporting.
7. Validate with project-owned synthetic workloads before considering any
   broader sample.

A D3D12-to-Vulkan mapping is not a simple one-to-one API rename. Resource
states, barriers, descriptor heaps, pipeline state, command-list semantics,
and synchronization must be modeled deliberately. Shader translation and
validation are independent workstreams; a Vulkan device alone does not imply
D3D12 or Xbox graphics compatibility.

## Non-goals

This roadmap does not implement GPU rendering, shader translation, audio,
networking, input, package handling, encrypted-content handling, or title-
specific patches. It makes no claim that a commercial title can run.
