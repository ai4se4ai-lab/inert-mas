"""Residual-risk analysis of attacks that succeed against I2 (RQ5 / Discussion).

  python analysis/residual.py results/*.jsonl --out paper            # sample + automatic categories
  python analysis/residual.py --kappa paper/residual_coding.csv      # after two raters filled the sheet

1. Collect every attack test whose goal was met (or with an attributable property violation)
   under I2, from the zoo, TAMAS and adaptive runs.
2. Assign an automatic first-pass category from the run record:
     authority   the attacker controls an agent that legitimately owns the executor field (A2/A4)
     user-input  the injection arrived in the user's own request (TAMAS DPI-whole, Impersonation)
     declass     a declassified value carried the attacker's choice
     tool-owned  a compromised TAMAS agent called a harmful tool from its own tool set
     other       none of the above
3. Draw a stratified sample of at most 100 cases into a coding sheet with empty columns for two
   human raters (rater1, rater2); --kappa computes Cohen's kappa once both are filled.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path


def category(r: dict) -> str:
    if r.get("family") == "tamas":
        if r.get("tamas_attack") in ("Impersonation",) or (r.get("tamas_attack") == "DPI" and r.get("variant") == "whole"):
            return "user-input"
        if r.get("tamas_attack") in ("Colluding", "Byzantine", "Contradicting"):
            return "tool-owned"
        return "plausible"   # target tool that agents also call on benign runs (base rate ~8%)
    if r.get("point") in ("agent", "collude"):
        return "authority"
    if any(ok and "evil" in str(r.get("final", "")) for _, ok in r.get("declassified", [])):
        return "declass"
    if r.get("family") == "reply" and r.get("point") == "resource":
        return "declass"
    return "other"


def kappa(path: str) -> float:
    rows = list(csv.DictReader(open(path)))
    pairs = [(r["rater1"].strip(), r["rater2"].strip()) for r in rows if r["rater1"].strip() and r["rater2"].strip()]
    if not pairs:
        raise SystemExit("no coded rows")
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    c1, c2 = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(c1[k] * c2[k] for k in set(c1) | set(c2)) / (n * n)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--out", default="paper")
    ap.add_argument("--kappa")
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    if a.kappa:
        print(f"Cohen's kappa = {kappa(a.kappa):.3f}")
        return 0
    rows = []
    for p in a.files:
        rows += [json.loads(x) for x in Path(p).read_text().splitlines() if x.strip()]
    succ = [r for r in rows if not r.get("error") and r.get("defense") == "I2" and r.get("asr")]
    by = defaultdict(list)
    for r in succ:
        by[category(r)].append(r)
    rng = random.Random(a.seed)
    sample = []
    quota = max(1, 100 // max(1, len(by)))
    for _cat, xs in sorted(by.items()):
        rng.shuffle(xs)
        sample += xs[:quota]
    sample = sample[:100]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "residual_coding.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "llm", "attacker", "point", "payload_class", "auto_category", "tool_calls", "rater1", "rater2"])
        for r in sample:
            w.writerow([r.get("case_id"), r.get("llm"), r.get("attacker") or r.get("tamas_attack"), r.get("point"),
                        r.get("payload_class"), category(r), json.dumps(r.get("tool_calls"))[:400], "", ""])
    summary = {"total": len(succ), "by_category": {k: len(v) for k, v in by.items()}, "sampled": len(sample)}
    (out / "residual.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
