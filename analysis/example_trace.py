"""Audited trace of the running example (chain3_email) under an indirect injection, for I1 and I2.

  python analysis/example_trace.py [--out paper]

Runs the benchmark-style override attack on e-mail 0 with the deterministic mock LLM (fully
susceptible), once without taint (I1) and once with all mechanisms (I2), and writes
<out>/tab_trace.tex: per slot, the context the controller showed, the reads it withheld, the label
it committed and the audit's verdict. The mock backend is used only to illustrate the mechanism; it
is never used for results. Output is deterministic (fixed seed, no clock in the table).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from inert.agents.llm import MockLLM  # noqa: E402
from inert.attacks.coverage import benchmark_suite  # noqa: E402
from inert.compiler import compile_model  # noqa: E402
from inert.eval.harness import run_case  # noqa: E402
from inert.eval.zoo import tasks  # noqa: E402
from inert.model import load_yaml  # noqa: E402

SHORT = {"trusted": "T", "user": "U", "agent_untrusted": "A", "external_untrusted": "X"}


def tt(x: str) -> str:
    return "\\texttt{" + x.replace("_", "\\_") + "}"


def trace(defense: str) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    ir = compile_model(load_yaml(ROOT / "models" / "zoo" / "chain3_email.inert.yaml"))
    task = tasks("email")[0]
    attack = benchmark_suite(ir, "email", "email/0")[0]
    r = run_case(ir, task, defense, attack, MockLLM(susceptibility=1.0), 0, keep_log=True)
    rows: dict[str, dict[str, Any]] = {}
    for e in r["log"]:
        k = e["kind"]
        if k == "request":
            rows.setdefault(e["slot"], {})["ctx"] = [(c["ref"], c["label"]) for c in e["context"]]
            rows[e["slot"]]["withheld"] = e["withheld"]
        elif k == "decision":
            rows.setdefault(e["slot"], {}).update(label=e.get("label"), reason=e["reason"])
        elif k == "tcb_value":
            rows.setdefault(e["slot"], {}).update(label=e["label"], reason=e["source"])
    return rows, r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "paper"))
    a = ap.parse_args()
    i1, r1 = trace("I1")
    i2, r2 = trace("I2")
    order = ["task", "intent", "fetch", "a1", "act", "do", "report"]

    def ctx(row: dict[str, Any]) -> str:
        shown = ", ".join(f"{tt(ref)}:{SHORT[lab]}" for ref, lab in row.get("ctx", []))
        held = ", ".join(tt(ref) for ref in row.get("withheld", []))
        held = "\\emph{withheld} " + held if held else ""
        return "; ".join(x for x in (shown, held) if x) or "--"

    lines = [r"\begin{tabular}{@{}lL{3.9cm}cL{3.9cm}c@{}}", r"\toprule",
             r"& \multicolumn{2}{c}{I1 (no taint)} & \multicolumn{2}{c}{I2 (all mechanisms)} \\",
             r"\cmidrule(lr){2-3}\cmidrule(l){4-5}",
             r"Slot & Context shown; withheld & Label & Context shown; withheld & Label \\", r"\midrule"]
    for s in order:
        lines.append(f"{tt(s)} & {ctx(i1.get(s, {}))} & {SHORT.get(i1.get(s, {}).get('label', ''), '--')} & "
                     f"{ctx(i2.get(s, {}))} & {SHORT.get(i2.get(s, {}).get('label', ''), '--')} \\\\")

    def verdict(r: dict[str, Any]) -> str:
        v = r.get("violation_detail") or {}
        return ("; ".join(d.replace("_", "\\_") for ds in v.values() for d in ds) or "none")
    lines += [r"\midrule",
              f"\\multicolumn{{5}}{{@{{}}L{{11.6cm}}@{{}}}}{{Audit (I1): {verdict(r1)}. Audit (I2): {verdict(r2)}. "
              f"Logs: {len(r1['log'])} and {len(r2['log'])} events, {r1['replay_decisions']} and {r2['replay_decisions']} "
              f"decisions replayed, hash chains {'intact' if r1['chain_ok'] and r2['chain_ok'] else 'broken'}.}} \\\\",
              r"\botrule", r"\end{tabular}"]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "tab_trace.tex").write_text("\n".join(lines) + "\n")
    print("wrote", out / "tab_trace.tex")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
