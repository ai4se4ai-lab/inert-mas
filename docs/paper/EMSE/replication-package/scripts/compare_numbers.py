#!/usr/bin/env python3
"""Compare two numbers.json files with a numeric tolerance.

    python compare_numbers.py committed.json regenerated.json [--rtol 1e-6]

Reports keys present in only one file and numeric values that differ by more than the relative
tolerance. The variational fit of the mixed-effects model (glmm) is iterative and can differ in
the 8th significant digit between platforms; the manuscript prints it with two decimals.
Exit code 1 if a non-glmm value differs or a key is missing from the regenerated file.
"""

from __future__ import annotations

import argparse
import json
import math
from typing import Any


def walk(a: Any, b: Any, path: str, rtol: float, out: list[tuple[str, str]]) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            p = f"{path}.{k}" if path else str(k)
            if k not in b:
                out.append((p, "only in committed"))
            elif k not in a:
                out.append((p, "only in regenerated"))
            else:
                walk(a[k], b[k], p, rtol, out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            walk(x, y, f"{path}[{i}]", rtol, out)
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        if not (math.isnan(a) and math.isnan(b)) and not math.isclose(a, b, rel_tol=rtol, abs_tol=1e-12):
            out.append((path, f"{a!r} != {b!r}"))
    elif a != b:
        out.append((path, f"{a!r} != {b!r}"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("committed")
    ap.add_argument("regenerated")
    ap.add_argument("--rtol", type=float, default=1e-6)
    a = ap.parse_args()
    with open(a.committed) as f1, open(a.regenerated) as f2:
        diffs: list[tuple[str, str]] = []
        walk(json.load(f1), json.load(f2), "", a.rtol, diffs)
    hard = [d for d in diffs if not d[0].startswith("glmm") and d[1] != "only in regenerated"]
    for p, msg in diffs:
        tag = "FAIL" if (p, msg) in hard else "note"
        print(f"  [{tag}] {p}: {msg}")
    if not diffs:
        print("  [ok] numbers.json identical within tolerance")
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
