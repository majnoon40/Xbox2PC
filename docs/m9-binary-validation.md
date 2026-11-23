# M9 binary validation — structural foundation

This increment adds a non-executing validator over the existing PE parser.
It reports individual stages rather than inventing a compatibility score.

Implemented:

- Null/empty input handling and parser-error containment.
- PE32+ and AMD64 identification.
- Section raw/virtual bounds and virtual-section overlap checks.
- Entry-point containment and executable-section checks.
- Writable-plus-executable section warnings.
- Import descriptor parse reporting.

Explicitly **NOT TESTED**: relocation application, TLS callback validation or
execution, guest memory mapping, instruction support, API resolution, and
runtime execution. A structurally valid result is not an Xbox compatibility
claim. This component never maps or executes supplied files.
