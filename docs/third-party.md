# Third-party components

Rule 4 of the M12 plan: third-party code only with a compatible license, recorded here with name, version, license and link mode, and covered by an ADR. The record and the code that uses the component land in the same commit, so the repository never contains a dependency that is not listed.

## Rules

1. **License.** A permissive license (MIT, BSD, Apache-2.0, ISC and the like), or LGPL under rule 3. No GPL or AGPL code is linked, vendored or copied.
2. **No copying from GPL projects**, other emulators included. Their public documentation is reading for concepts; everything in this repository is written here.
3. **LGPL is used by dynamic linking only.** An LGPL component is loaded at run time, and the runtime must build, start and pass its tests without it installed. It is never linked statically and never vendored.
4. **Never vendored or committed:** Microsoft binaries, GDK files of any kind, and anything covered by [input-policy.md](input-policy.md).
5. **Each new component needs a row here and an ADR**, in the same commit as the code that first uses it. The ADR records why the component was chosen over writing the code here.

## Register

| Component | Version | License | Used for | Link mode | Location |
|---|---|---|---|---|---|
| GoogleTest (googletest and googlemock) | 1.15.2 (`GOOGLETEST_VERSION` in the vendored `CMakeLists.txt`; the upstream commit is not recorded) | BSD-3-Clause, "Copyright 2008, Google Inc. All rights reserved." ([upstream](https://github.com/google/googletest)) | the unit-test suites under `tests/` | vendored source, compiled into the test executables only (`target_link_libraries(... PRIVATE ... gtest)`); it is not part of `xbox2pc` or of any runtime library | `third_party/googletest/` |

That is the whole list. No source file outside `third_party/` carries a third-party license header, and no other directory holds vendored code.

## Build-time tools

The toolchain is not part of the product and is not in the register: GCC and Clang with LLD (C++ compiler and the PE link step), MinGW-w64 (the C++ exception sample), CMake and Ninja, and the Python interpreter for `scripts/`. Each is installed by CI or by the developer; none is committed, and a program they build is a fixture of ours, not a redistribution of the tool.

## Components named for later pillars

The M12 plan names components for work that does not exist yet, such as a forwarding provider used as an oracle, a shader translator used as a baseline, and a disassembler used for differential decoding. None of them is used at the time of writing, so none has a row. Each gets its row, with its license checked against the license text of the exact version that is adopted, in the commit that adopts it.

## Related decisions

- [ADR-0008: Project license and third-party policy](adr-0008-license-and-third-party.md)
- [input-policy.md](input-policy.md)
