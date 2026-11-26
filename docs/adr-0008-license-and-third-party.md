# ADR-0008: Project license and third-party policy

- Status: Proposed (the third-party policy is in force; the project license is undecided)
- Date: 2026-11-26
- Context: M12 P0, plan section 9.1 and Rule 4
- Deciders: maintainer (project license); xbox2pc runtime work (third-party policy)

## Context

The repository has no top-level LICENSE file. Nothing states the terms under
which the source may be used, modified or redistributed, and no document says
who may make that choice. Meanwhile M12 is about to add third-party code: a
forwarding provider used as an oracle for graphics work, a shader translator
used as a baseline, a windowing library, a disassembler for differential
testing. The plan's risk register lists licensing mistakes with LGPL and GPL
code as low-likelihood and high-impact (R10), and legal exposure from inputs
as the same (R7).

Today there is exactly one third-party component, the vendored GoogleTest
1.15.2 under BSD-3-Clause, linked into the test executables only
([third-party.md](third-party.md)).

## Decision drivers

1. A licensing mistake must be impossible to make by accident: every
   dependency visible, with its license and how it is linked.
2. The runtime must build, start and pass its tests with no LGPL component
   installed, so that its license can never be argued to cover Xbox2PC.
3. Nothing may be copied from a GPL project, emulators included; Rule 4 of the
   plan is explicit, and an accidental copy cannot be undone by deleting it.
4. The license of the project itself is the maintainer's decision. An agent
   working on the repository must not make it, explicitly or by leaving a
   plausible-looking file behind.

## Decision

### Third-party policy (in force)

1. Only permissive licenses, or LGPL loaded at run time. No GPL or AGPL code
   is linked, vendored or copied.
2. An LGPL component is dynamically loaded and never vendored; the tree must
   build and pass without it.
3. Every component gets a row in `docs/third-party.md` (name, version,
   license, link mode, location) and an ADR, in the same commit as the code
   that first uses it. The license is checked against the license text of the
   exact version adopted, not against what a project's web page says.
4. Microsoft binaries and GDK files are never vendored
   ([input-policy.md](input-policy.md)).
5. Concepts may be taken from the public documentation of any project and are
   reimplemented here; no source text is taken from a project whose license
   would not allow it.

### Project license (undecided)

This record does not choose a license and must not be read as one. Adding a
LICENSE file is a decision for the maintainer alone. The considerations, so
the choice can be made once and with the facts at hand:

- The project's own rules already assume a permissive posture: Rule 4 admits
  only permissive and dynamically linked LGPL code, and its only dependency
  is BSD-3-Clause. A permissive license (MIT or BSD-3-Clause) is consistent
  with that and imposes nothing on future contributors beyond attribution.
- A copyleft license would also be consistent with the rules as written, but
  it is a statement about what downstream distributors must do, and it should
  be made deliberately rather than by default.
- Either way, the third-party policy above is unaffected: permissive and
  dynamically linked LGPL components are compatible with both.

Until a license is chosen, the default of copyright applies: others have no
permission to use, modify or distribute the source beyond what the law allows,
and the repository makes no promise otherwise.

## Consequences

- A new dependency cannot be introduced quietly: the register, the ADR and
  the code arrive together or the pull request is incomplete.
- LGPL components have a build-time and a run-time boundary (a missing
  component is a reported condition, not a crash), which costs some design
  work in P3 and P4 and is what Rule 4 asks for.
- The missing LICENSE file stays an open item, named in the M12 pull request,
  until the maintainer decides. Nothing in M12 depends on the choice.

## Measurement provenance

None: this decision has no measurements. The inventory it rests on is
reproducible with `git ls-files third_party` and a search for license
headers outside `third_party/`, both empty of anything but GoogleTest at
commit 3aae2c7.
