#!/usr/bin/env python3
"""Run the M12 rung fixtures through `xbox2pc run` and compare with goldens.

usage: rung_check.py --cli <xbox2pc> --dir <build/rungs> [--golden <dir>] [--update]

For every rung (B to G, plan section 3.2) it runs

    xbox2pc run <exe> --backend native --unimplemented trap --json <out>

and compares the fields of the report that the rung's SOURCE determines --
outcome, stage, unimplemented_calls, first_unimplemented, exit_code, the
guest fault name and the import counts -- with samples/rungs/golden/<rung>.json.

Status of a rung:
  passing   outcome == returned and exit_code equals the rung's contract
  blocked   stopped on an unimplemented import (--unimplemented=trap), or a
            blocker the fixture itself documents (rung F: the throw helper
            is a stub until P1); the report matches the committed golden
  CHANGED   the report differs from the golden: a regression or progress;
            `--update` rewrites the golden (never pass it in CI)
  FAIL      anything else

Exit status: 0 when every rung is passing or blocked as recorded, 1 otherwise.
The goldens depend on the fixtures' import sets and the runtime's registry,
not on code generation, so they are the same for clang 18.1.3 (CI) and
clang 18.1.8 (local).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

RUNGS = [
    # id, executable, contract exit code (None: not expressible before P3/P4)
    ("b", "rung_b_bootloop.exe", 60),
    ("c", "rung_c_assetload.exe", "asset:assets/rung_c.bin:0xFF"),
    ("d", "rung_d_gpucompute.exe", None),
    ("e", "rung_e_threads.exe", 36),
    ("f", "rung_f_cxxthrow.exe", 42),
    ("g", "rung_g_titlelike.exe", "asset:assets/rung_g.bin:0x3F"),
]
# Blockers a fixture documents in its own source: (rung, exit code, reason).
# The rung returns that code instead of its contract until the named work
# lands; rung_check reports it as blocked, never as passing.
DOCUMENTED_BLOCKERS = {
    "f": (99, "throw helper and frame handler are stubs until P1 section 4.5"),
}
COMPARED = ("outcome", "stage", "unimplemented_calls", "first_unimplemented",
            "exit_code", "fault", "imports")


def fnv1a(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def contract_exit(spec, fixtures: pathlib.Path):
    if spec is None:
        return None
    if isinstance(spec, int):
        return spec
    _, rel, mask = spec.split(":")
    return fnv1a((fixtures / rel).read_bytes()) & int(mask, 16)


def run_rung(cli: str, fixtures: pathlib.Path, exe: str):
    out = fixtures / (exe + ".run.json")
    proc = subprocess.run([cli, "run", str(fixtures / exe), "--backend", "native",
                           "--unimplemented", "trap", "--json", str(out)],
                          capture_output=True, text=True)
    try:
        report = json.loads(out.read_text())
    except (OSError, ValueError):
        report = {"outcome": "no-report", "error": proc.stderr.strip()[-200:]}
    view = {key: report.get(key) for key in COMPARED if key != "fault"}
    detail = report.get("detail", "") or ""
    view["fault"] = detail.split(" ", 1)[0] if detail else ""
    return proc.returncode, view, report


def classify(view, contract, rung_id):
    if view.get("outcome") == "returned" and contract is not None \
            and view.get("exit_code") == contract:
        return "passing"
    if view.get("outcome") == "faulted" and view.get("fault") == "unimplemented-api":
        return "blocked"
    blocker = DOCUMENTED_BLOCKERS.get(rung_id)
    if blocker and view.get("outcome") == "returned" and view.get("exit_code") == blocker[0]:
        return "blocked"
    return "FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", required=True, help="xbox2pc built with the native flag on")
    parser.add_argument("--dir", required=True, help="directory holding the built rungs")
    parser.add_argument("--golden", default=None, help="golden directory (default: samples/rungs/golden)")
    parser.add_argument("--update", action="store_true", help="rewrite the goldens from this run")
    args = parser.parse_args()

    fixtures = pathlib.Path(args.dir).resolve()
    golden_dir = pathlib.Path(args.golden).resolve() if args.golden else \
        pathlib.Path(__file__).resolve().parent.parent / "samples" / "rungs" / "golden"
    if args.update:
        golden_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    print(f"{'rung':<5} {'status':<10} {'exit':>4}  first unimplemented import / detail")
    for rung_id, exe, spec in RUNGS:
        contract = contract_exit(spec, fixtures)
        rc, view, report = run_rung(args.cli, fixtures, exe)
        status = classify(view, contract, rung_id)
        blocker = DOCUMENTED_BLOCKERS.get(rung_id)
        if status == "blocked" and blocker and view.get("exit_code") == blocker[0] \
                and not view.get("first_unimplemented"):
            reason = blocker[1]
        else:
            reason = view.get("first_unimplemented") or (report.get("error") or "")[:70]
        golden_path = golden_dir / f"{rung_id}.json"
        if args.update:
            golden = dict(view)
            golden["status"] = status
            golden["contract_exit"] = contract
            golden["source"] = exe
            golden_path.write_text(json.dumps(golden, indent=2, sort_keys=True) + "\n")
        elif golden_path.exists():
            golden = json.loads(golden_path.read_text())
            if {k: golden.get(k) for k in COMPARED} != view or golden.get("status") != status:
                status = "CHANGED"
                failures += 1
        else:
            status = "FAIL"
            reason = f"no golden for rung {rung_id}"
            failures += 1
        if status == "FAIL":
            failures += 1
        print(f"{rung_id:<5} {status:<10} {str(view.get('exit_code')):>4}  {reason}")
        if status == "CHANGED" and not args.update:
            print("      golden:", json.dumps({k: golden.get(k) for k in COMPARED}, sort_keys=True))
            print("      now:   ", json.dumps(view, sort_keys=True))
    print(f"{'rungs passing or blocked as recorded' if failures == 0 else 'rungs needing attention'}: "
          f"{len(RUNGS) - failures} of {len(RUNGS)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
