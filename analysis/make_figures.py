"""Statistical figures of the paper, regenerated from the archived result records.

  python analysis/make_figures.py results/final/**/shard_*.jsonl --assets paper

Reads only result records (append-only) and ``<assets>/numbers.json`` (written by make_assets.py for the
paired tests), and writes only ``<assets>/fig_*.pdf``. Every plotted value is computed from the records.
Randomness (bootstrap intervals, suite orderings) uses one seeded generator.

Figures
  fig_tradeoff     security-utility plane per condition and per LLM, and split violins of per-workflow
                   attack success and benign utility (RQ2/RQ4 overview)
  fig_propagation  B0 propagation versus team size per topology (line charts with bootstrap bands), and
                   exposure (infected agents) versus effect (attack success) per condition (RQ1)
  fig_ablation     ablation x attacker-model heatmap and first rejecting mechanism of I2 (RQ2)
  fig_discovery    discovery curves of distinct violated obligations versus LLM calls (RQ3)
  fig_cost         violins of tokens and latency per benign task (RQ4)
  fig_adaptive     adaptive attack success versus attempt budget, and forest plot of paired odds ratios (RQ5)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import matplotlib  # noqa: E402
from make_assets import load, wilson  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

# Reference palette (validated with the dataviz validator, light mode, white surface).
BLUE, ORANGE, AQUA, YELLOW, MAGENTA = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"
GRAY, INK, INK2, MUTED, GRID = "#898781", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
SEQ = ["#f4f8fe", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
MAIN = ["B0", "B1", "B2", "B3", "B4", "I1", "I2"]
FAMILY = {"B0": GRAY, "B1": ORANGE, "B2": ORANGE, "B3": ORANGE, "B4": ORANGE, "I1": BLUE, "I2": BLUE}
ATTACK_CRITERIA = ("EDGE", "SLOT", "SEL", "TAINT", "RECONF", "COLL", "BENCH")

plt.rcParams.update({
    "font.size": 7.5, "axes.titlesize": 8, "axes.labelsize": 7.5, "xtick.labelsize": 7, "ytick.labelsize": 7,
    "legend.fontsize": 7, "axes.edgecolor": "#c3c2b7", "axes.linewidth": 0.6, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
    "axes.axisbelow": True, "axes.spines.top": False, "axes.spines.right": False, "pdf.fonttype": 42,
    "lines.linewidth": 1.6, "legend.frameon": False, "axes.titleweight": "bold", "axes.titlelocation": "left",
})


def boot_ci(x: list[float], rng: np.random.Generator, b: int = 2000) -> tuple[float, float]:
    if not x:
        return float("nan"), float("nan")
    a = np.asarray(x, dtype=float)
    means = a[rng.integers(0, len(a), size=(b, len(a)))].mean(axis=1)
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def save(fig: Any, out: Path, name: str) -> None:
    fig.savefig(out / f"{name}.pdf", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def topo_size(name: str) -> tuple[str, int]:
    head = name.split("_")[0]
    return "".join(c for c in head if not c.isdigit()), int("".join(c for c in head if c.isdigit()))


# ------------------------------------------------------------------------------------------------ figures
def fig_tradeoff(zoo: list[dict[str, Any]], out: Path) -> None:
    att = defaultdict(list)
    ben = defaultdict(list)
    cell_a = defaultdict(lambda: defaultdict(list))   # defense -> (workflow, llm) -> asr
    cell_u = defaultdict(lambda: defaultdict(list))
    llm_a = defaultdict(lambda: defaultdict(list))
    llm_u = defaultdict(lambda: defaultdict(list))
    for r in zoo:
        d = r["defense"]
        key = (r["model_name"], r.get("llm"))
        if r.get("criterion") == "BENIGN":
            ben[d].append(float(r["utility"]))
            cell_u[d][key].append(float(r["utility"]))
            llm_u[d][r.get("llm")].append(float(r["utility"]))
        elif r.get("criterion") in ATTACK_CRITERIA:
            att[d].append(float(r["asr"]))
            cell_a[d][key].append(float(r["asr"]))
            llm_a[d][r.get("llm")].append(float(r["asr"]))
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(5.2, 2.9), gridspec_kw={"width_ratios": [1, 1.25]})
    offs = {"B0": (6, 4), "B1": (6, -9), "B2": (-14, 6), "B3": (6, 4), "B4": (6, 4), "I1": (-14, 6), "I2": (-14, 6)}
    for d in MAIN:
        for llm in llm_a[d]:
            ax.scatter(100 * np.mean(llm_u[d][llm]), 100 * np.mean(llm_a[d][llm]), s=9, color=FAMILY[d],
                       alpha=0.28, linewidths=0, zorder=2)
        ka, na = int(sum(att[d])), len(att[d])
        kb, nb = int(sum(ben[d])), len(ben[d])
        alo, ahi = wilson(ka, na)
        ulo, uhi = wilson(kb, nb)
        x, y = 100 * kb / nb, 100 * ka / na
        ax.errorbar(x, y, xerr=[[x - 100 * ulo], [100 * uhi - x]], yerr=[[y - 100 * alo], [100 * ahi - y]],
                    fmt="s" if d.startswith("I") else "o", ms=6.5, color=FAMILY[d], mec="white", mew=1.0,
                    elinewidth=0.9, capsize=1.5, zorder=4)
        ax.annotate(d, (x, y), textcoords="offset points", xytext=offs[d], fontsize=7, color=INK, zorder=5)
    ax.set_xlim(25, 100)
    ax.set_ylim(-5, 100)
    ax.set_xlabel("Benign utility (%)")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("(a) Security-utility plane")
    ax.annotate("better", xy=(97, 3), xytext=(52, 30), fontsize=6.8, color=MUTED,
                arrowprops={"arrowstyle": "->", "color": MUTED, "lw": 0.7})
    ax.legend(handles=[Line2D([], [], marker="o", ls="", color=GRAY, label="undefended (B0)"),
                       Line2D([], [], marker="o", ls="", color=ORANGE, label="baselines B1-B4"),
                       Line2D([], [], marker="s", ls="", color=BLUE, label="INERT I1, I2"),
                       Line2D([], [], marker="o", ls="", color=INK2, alpha=0.3, ms=3.5, label="one LLM")],
              loc="upper center", bbox_to_anchor=(0.5, -0.26), ncol=2, handletextpad=0.2, columnspacing=0.8)
    # split violins: left half attack success, right half benign utility, one value per (workflow, LLM)
    pos = np.arange(len(MAIN))
    for i, d in enumerate(MAIN):
        for vals, side, col in ((cell_a[d], -1, ORANGE), (cell_u[d], 1, BLUE)):
            v = 100 * np.array([np.mean(x) for x in vals.values()])
            if len(v) < 2:
                continue
            if np.ptp(v) == 0:
                v = v + np.random.default_rng(0).normal(0, 0.4, len(v))
            parts = bx.violinplot([v], positions=[i], widths=0.86, showextrema=False, bw_method=0.3)
            for b in parts["bodies"]:
                verts = b.get_paths()[0].vertices
                verts[:, 0] = np.clip(verts[:, 0], -np.inf, i) if side < 0 else np.clip(verts[:, 0], i, np.inf)
                b.set_facecolor(col)
                b.set_edgecolor("white")
                b.set_linewidth(0.5)
                b.set_alpha(0.78)
            q1, med, q3 = np.percentile(v, [25, 50, 75])
            xm = i + side * 0.11
            bx.plot([xm, xm], [q1, q3], color=INK, lw=1.3, solid_capstyle="round", zorder=3)
            bx.scatter([xm], [med], s=10, color="white", edgecolors=INK, linewidths=0.8, zorder=4)
    bx.set_xticks(pos, MAIN)
    bx.set_ylim(-4, 104)
    bx.set_ylabel("Rate per workflow and LLM (%)")
    bx.set_title("(b) Per workflow and LLM")
    bx.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=ORANGE, alpha=0.78, label="attack success (left half)"),
                       plt.Rectangle((0, 0), 1, 1, color=BLUE, alpha=0.78, label="benign utility (right half)"),
                       Line2D([], [], marker="o", color=INK, mfc="white", lw=1.3, ms=3.5, label="median and IQR")],
              loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=1, handlelength=1.2)
    fig.tight_layout(w_pad=1.6)
    save(fig, out, "fig_tradeoff")


def fig_propagation(zoo: list[dict[str, Any]], out: Path, rng: np.random.Generator) -> None:
    by = defaultdict(lambda: defaultdict(list))
    for r in zoo:
        if r["defense"] == "B0" and r.get("criterion") in ATTACK_CRITERIA:
            t, s = topo_size(r["model_name"])
            by[(t, s)]["asr"].append(100 * float(r["asr"]))
            by[(t, s)]["inf"].append(float(r.get("infected_agents", 0)))
            by[(t, s)]["depth"].append(float(r.get("depth", 0)))
    tops = sorted({t for t, _ in by})
    cols = dict(zip(tops, [BLUE, ORANGE, AQUA, YELLOW, MAGENTA], strict=False))
    marks = dict(zip(tops, ["o", "s", "^", "D", "v"], strict=False))
    label = {"pcr": "planner-coder-reviewer", "hierarchical": "hierarchical"}
    fig, axs = plt.subplots(2, 2, figsize=(5.2, 4.3))
    axs = axs.ravel()
    for ax, key, ttl, yl in ((axs[0], "asr", "(a) Attack success", "ASR under B0 (%)"),
                             (axs[1], "inf", "(b) Infected agents", "Agents with attacker content"),
                             (axs[2], "depth", "(c) Infection depth", "Longest infected chain")):
        for t in tops:
            xs = sorted(s for tt, s in by if tt == t)
            m = [np.mean(by[(t, s)][key]) for s in xs]
            ci = [boot_ci(by[(t, s)][key], rng) for s in xs]
            ax.fill_between(xs, [c[0] for c in ci], [c[1] for c in ci], color=cols[t], alpha=0.16, lw=0)
            ax.plot(xs, m, marker=marks[t], ms=4.2, color=cols[t], mec="white", mew=0.6)
        ax.set_xticks([3, 5, 8])
        ax.set_xlabel("Agents in the workflow")
        ax.set_ylabel(yl)
        ax.set_title(ttl)
    # exposure versus effect per condition
    ex = defaultdict(list)
    ef = defaultdict(list)
    for r in zoo:
        if r.get("criterion") in ATTACK_CRITERIA:
            ex[r["defense"]].append(float(r.get("infected_agents", 0)))
            ef[r["defense"]].append(float(r["asr"]))
    ax = axs[3]
    for i, d in enumerate(MAIN):
        lo, hi = boot_ci(ex[d], rng)
        ax.plot([lo, hi], [i, i], color=FAMILY[d], lw=2.2, solid_capstyle="round")
        ax.scatter([np.mean(ex[d])], [i], s=26, color=FAMILY[d], marker="s" if d.startswith("I") else "o",
                   edgecolors="white", linewidths=0.8, zorder=3)
        ax.annotate(f"ASR {100 * np.mean(ef[d]):.0f}%", (np.mean(ex[d]), i), textcoords="offset points",
                    xytext=(7, -1), fontsize=6.8, color=INK2, va="center")
    ax.set_yticks(range(len(MAIN)), MAIN)
    ax.invert_yaxis()
    ax.set_xlim(-0.1, 3.9)
    ax.set_xlabel("Mean infected agents (exposure)")
    ax.set_title("(d) Exposure vs. effect")
    h = [Line2D([], [], color=cols[t], marker=marks[t], ms=4, label=label.get(t, t)) for t in tops]
    fig.legend(handles=h, loc="lower center", bbox_to_anchor=(0.5, -0.01), ncol=3, handlelength=1.6)
    fig.tight_layout(w_pad=1.0, h_pad=1.0, rect=(0, 0.08, 1, 1))
    save(fig, out, "fig_propagation")


def fig_ablation(abl: list[dict[str, Any]], out: Path) -> None:
    conds = ["I1", "I2-tokens", "I2-key", "I2-validator", "I2-tsel", "I2-tacc", "I2"]
    names = {"I1": "I1 (no taint)", "I2-tokens": "I2 - tokens", "I2-key": "I2 - key match",
             "I2-validator": "I2 - validators", "I2-tsel": "I2 - taint@select", "I2-tacc": "I2 - taint@accept",
             "I2": "I2 full"}
    atts = ["A1", "A2", "A3", "A4", "A5"]
    cell = defaultdict(list)
    first = defaultdict(lambda: defaultdict(int))
    for r in abl:
        if r.get("criterion") in ATTACK_CRITERIA:
            cell[(r["defense"], r.get("attacker"))].append(float(r["asr"]))
            if r["defense"] == "I2":
                first[r.get("attacker")][r.get("first_reject") or "none"] += 1
    m = np.array([[100 * np.mean(cell[(c, a)]) if cell[(c, a)] else np.nan for a in atts] for c in conds])
    fig, (ax, bx) = plt.subplots(2, 1, figsize=(5.2, 4.6), gridspec_kw={"height_ratios": [1.2, 0.8]})
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("seq", SEQ)
    ax.imshow(m, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(len(conds)):
        for j in range(len(atts)):
            v = m[i, j]
            ax.text(j, i, f"{v:.0f}" if v >= 0.5 or v == 0 else "<1", ha="center", va="center", fontsize=6.8,
                    color="white" if v > 55 else INK)
    ax.set_xticks(range(len(atts)), ["A1\nindirect", "A2\ncompr.", "A3\ntamper", "A4\ncollude",
                                     "A5\nreconfig."], rotation=0, fontsize=6.8)
    ax.set_yticks(range(len(conds)), [names[c] for c in conds])
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(atts)), minor=True)
    ax.set_yticks(np.arange(-0.5, len(conds)), minor=True)
    ax.grid(which="minor", color="white", linewidth=2)
    ax.tick_params(which="minor", length=0)
    ax.set_title("(a) Attack success (%) per removed mechanism")
    reasons = ["TOKEN_INVALID", "KEY_STALE", "TOOL_METADATA_MISMATCH", "SCHEMA_INVALID", "TAINT_VIOLATION",
               "VALIDATOR_REJECT", "none"]
    rname = {"TOKEN_INVALID": "TokenInvalid", "KEY_STALE": "KeyStale", "TOOL_METADATA_MISMATCH": "ToolMetadataMismatch",
             "SCHEMA_INVALID": "SchemaInvalid", "TAINT_VIOLATION": "TaintViolation",
             "VALIDATOR_REJECT": "ValidatorReject", "none": "no rejection (effect blocked later)"}
    present = [x for x in reasons if any(first[a].get(x) for a in atts)]
    rcol = dict(zip([x for x in present if x != "none"], [BLUE, ORANGE, AQUA, YELLOW, MAGENTA, "#6250d6"],
                    strict=False))
    rcol["none"] = "#d9d8d2"
    left = np.zeros(len(atts))
    for x in present:
        share = np.array([100 * first[a].get(x, 0) / max(1, sum(first[a].values())) for a in atts])
        bx.barh(range(len(atts)), share, left=left, color=rcol[x], edgecolor="white", linewidth=1.0, height=0.66,
                label=rname[x])
        for j, (sh, lf) in enumerate(zip(share, left, strict=False)):
            if sh >= 14:
                bx.text(lf + sh / 2, j, f"{sh:.0f}", ha="center", va="center", fontsize=6.8,
                        color=INK if x in ("none", "SCHEMA_INVALID") or rcol[x] in (YELLOW, AQUA, MAGENTA) else "white")
        left += share
    bx.set_yticks(range(len(atts)), atts)
    bx.invert_yaxis()
    bx.set_xlim(0, 100)
    bx.set_xlabel("Share of I2 tests (%)")
    bx.set_title("(b) First rejecting check in I2")
    bx.grid(axis="y", visible=False)
    bx.legend(loc="upper center", bbox_to_anchor=(0.45, -0.28), ncol=3, handlelength=1.0, columnspacing=0.8)
    fig.tight_layout(h_pad=1.2)
    save(fig, out, "fig_ablation")


def fig_discovery(zoo: list[dict[str, Any]], out: Path, rng: np.random.Generator, reps: int = 200) -> None:
    fig = plt.figure(figsize=(5.2, 4.3))
    gs = fig.add_gridspec(2, 2, height_ratios=[1, 1])
    axs = [fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[0, 1]), fig.add_subplot(gs[1, :])]
    grid = np.linspace(0, 1, 101)
    for ax, tgt, ttl in ((axs[0], "B0", "(a) Against B0"), (axs[1], "B4", "(b) Against B4")):
        for suite, crits, col in (("generated", ATTACK_CRITERIA[:-1], BLUE), ("benchmark-style", ("BENCH",), ORANGE)):
            xs = [r for r in zoo if r["defense"] == tgt and r.get("criterion") in crits]
            calls = np.array([max(1, r.get("llm_calls", 0)) for r in xs], dtype=float)
            ids = [(r["model_name"], r.get("obligation")) if r["asr"] else None for r in xs]
            total = calls.sum()
            curves = []
            for _ in range(reps):
                perm = rng.permutation(len(xs))
                seen: set[Any] = set()
                cnt = np.empty(len(xs))
                for k, i in enumerate(perm):
                    if ids[i] is not None:
                        seen.add(ids[i])
                    cnt[k] = len(seen)
                cum = np.cumsum(calls[perm])
                curves.append(np.interp(grid * total, cum, cnt))
            c = np.array(curves)
            xk = grid * total / 1000
            ax.fill_between(xk, np.percentile(c, 2.5, axis=0), np.percentile(c, 97.5, axis=0), color=col, alpha=0.2, lw=0)
            ax.plot(xk, c.mean(axis=0), color=col)
            j = 100 if suite == "generated" else 100
            ax.annotate(f"{suite}: {int(c[0, -1])}", (xk[j], c.mean(axis=0)[j]), textcoords="offset points",
                        xytext=(-2, -11) if suite == "generated" else (4, 0),
                        ha="right" if suite == "generated" else "left", va="top" if suite == "generated" else "center",
                        fontsize=6.8, color=INK2)
        ax.set_xlabel("LLM calls of the target (thousands)")
        ax.set_ylabel("Distinct violated obligations")
        ax.set_title(ttl)
        ax.set_ylim(-20, 850)
    # per-criterion attack success against B0 and B4 with Wilson intervals
    ax = axs[2]
    crits = ["COLL", "SLOT", "SEL", "EDGE", "BENCH", "TAINT", "RECONF"]
    for tgt, col, mk, dy in (("B0", GRAY, "o", -0.13), ("B4", ORANGE, "D", 0.13)):
        for j, c in enumerate(crits):
            v = [float(r["asr"]) for r in zoo if r["defense"] == tgt and r.get("criterion") == c]
            lo, hi = wilson(int(sum(v)), len(v))
            ax.plot([100 * lo, 100 * hi], [j + dy, j + dy], color=col, lw=1.6)
            ax.scatter([100 * np.mean(v)], [j + dy], color=col, marker=mk, s=16, edgecolors="white", linewidths=0.6,
                       zorder=3, label=tgt if j == 0 else None)
    ax.set_yticks(range(len(crits)), ["BENCH (benchmark)" if c == "BENCH" else c for c in crits])
    ax.invert_yaxis()
    ax.set_xlim(0, 104)
    ax.set_xlabel("Attack success rate (%)")
    ax.set_title("(c) Per coverage criterion")
    ax.legend(loc="upper left", ncol=1, handletextpad=0.2)
    fig.tight_layout(w_pad=1.0, h_pad=1.2)
    save(fig, out, "fig_discovery")


def fig_cost(zoo: list[dict[str, Any]], out: Path) -> None:
    tok = defaultdict(list)
    sec = defaultdict(list)
    for r in zoo:
        if r.get("criterion") == "BENIGN":
            tok[r["defense"]].append(r.get("prompt_tokens", 0) + r.get("completion_tokens", 0))
            sec[r["defense"]].append(r["seconds"])
    fig, axs = plt.subplots(1, 2, figsize=(5.2, 2.4))
    for ax, data, yl, ttl in ((axs[0], tok, "Tokens per benign task", "(a) Tokens"),
                              (axs[1], sec, "Seconds per benign task", "(b) Wall-clock latency")):
        vals = [np.log10(np.maximum(1, np.array(data[d], dtype=float))) for d in MAIN]
        parts = ax.violinplot(vals, positions=range(len(MAIN)), widths=0.8, showextrema=False, bw_method=0.25)
        for b, d in zip(parts["bodies"], MAIN, strict=False):
            b.set_facecolor(FAMILY[d])
            b.set_edgecolor("white")
            b.set_alpha(0.75)
        for i, v in enumerate(vals):
            q1, med, q3 = np.percentile(v, [25, 50, 75])
            ax.plot([i, i], [q1, q3], color=INK, lw=2.2, solid_capstyle="round")
            ax.scatter([i], [med], s=12, color="white", edgecolors=INK, linewidths=0.8, zorder=3)
        meds = [10 ** np.percentile(v, 50) for v in vals]
        ax.set_xticks(range(len(MAIN)), [f"{d}\n{m / 1000:.1f}k" if m >= 1000 else f"{d}\n{m:.0f}" for d, m in zip(MAIN, meds, strict=True)])
        ticks = [t for t in (1, 3, 10, 30, 100, 300, 1000, 3000, 10000, 30000, 100000)]
        lo, hi = min(np.min(v) for v in vals), max(np.max(v) for v in vals)
        ax.set_yticks([np.log10(t) for t in ticks if lo - 0.3 <= np.log10(t) <= hi + 0.45],
                      [f"{t:,}" for t in ticks if lo - 0.3 <= np.log10(t) <= hi + 0.45])
        ax.set_ylim(lo - 0.15, hi + 0.15)
        ax.set_ylabel(yl + " (log)")
        ax.set_title(ttl)
    fig.tight_layout(w_pad=1.5)
    save(fig, out, "fig_cost")


def fig_adaptive(adaptive: list[dict[str, Any]], numbers: dict[str, Any], out: Path) -> None:
    fig, (ax, bx) = plt.subplots(2, 1, figsize=(5.2, 4.9), gridspec_kw={"height_ratios": [0.85, 1.15]})
    by = defaultdict(list)
    for r in adaptive:
        by[r["defense"]].append(r)
    style = {"B1": (ORANGE, "o"), "B4": (YELLOW, "D"), "B3": (AQUA, "^"), "I2": (BLUE, "s")}
    budget = max((r.get("attempts", 0) for r in adaptive), default=10)
    ks = np.arange(1, budget + 1)
    for d in ("B1", "B4", "B3", "I2"):
        rs = by.get(d, [])
        if not rs:
            continue
        y = [100 * np.mean([bool(r["asr"]) and r.get("attempts", budget) <= k for r in rs]) for k in ks]
        col, mk = style[d]
        ax.step(ks, y, where="post", color=col, lw=1.6)
        ax.scatter(ks, y, color=col, marker=mk, s=12, edgecolors="white", linewidths=0.5, zorder=3)
        if d != "B3":
            ax.annotate("B3, I2" if d == "I2" else d, (ks[-1], y[-1]), textcoords="offset points", xytext=(4, 0),
                        fontsize=6.8, va="center", color=INK)
    ax.set_xlabel("Attempt budget of the adaptive attacker")
    ax.set_ylabel("Cumulative attack success (%)")
    ax.set_xlim(0.7, budget + 1.4)
    ax.set_ylim(-4, 100)
    ax.set_xticks(ks)
    ax.set_title(f"(a) Adaptive attacker (A6), {len(by.get('I2', []))} cases each")
    # forest plot of paired odds ratios
    t = numbers.get("tests", {})
    rows = []
    for ref in ("B0", "B4"):
        for d in ("B1", "B2", "B3", "B4", "I1", "I2", "B0"):
            k = f"{d}_vs_{ref}"
            if k in t and "or" in t[k]:
                rows.append((f"{d} vs {ref}", t[k], ref))
    for i, (lab, v, ref) in enumerate(rows):
        col = GRAY if ref == "B0" else ORANGE
        if v["b"] == 0:
            bx.annotate("no successful attack (OR = 0)", (1.0e-3, i), textcoords="offset points", xytext=(6, 0),
                        fontsize=6.8, color=INK2, va="center")
            bx.scatter([1.0e-3], [i], marker="<", color=col, s=16, zorder=3)
            continue
        bx.plot([v["or_lo"], v["or_hi"]], [i, i], color=col, lw=1.8)
        bx.scatter([v["or"]], [i], color=col, marker="D" if lab.startswith("I") else "o", s=16,
                   edgecolors="white", linewidths=0.6, zorder=3)
    bx.axvline(1, color=INK2, lw=0.8, ls=(0, (3, 2)))
    bx.set_xscale("log")
    bx.set_xlim(8e-4, 20)
    bx.set_yticks(range(len(rows)), [r[0] for r in rows])
    bx.invert_yaxis()
    bx.set_xlabel("Paired odds ratio of attack success (log scale; < 1 favours the first condition)")
    bx.set_title("(b) Exact McNemar odds ratios, bootstrap 95% CI")
    bx.tick_params(axis="y", labelsize=7)
    fig.tight_layout(h_pad=1.4)
    save(fig, out, "fig_adaptive")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--assets", default="paper")
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    out = Path(a.assets)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(a.seed)
    rows = [r for r in load(a.files) if not r.get("error")]
    allzoo = [r for r in rows if r.get("family") != "tamas"]
    zoo = [r for r in allzoo if r.get("suite") in ("zoo-benign", "zoo-attack")]
    abl = [r for r in allzoo if r.get("suite") == "zoo-ablation"]
    adaptive = [r for r in allzoo if r.get("criterion") == "ADAPTIVE"]
    numbers_path = out / "numbers.json"
    numbers = json.loads(numbers_path.read_text()) if numbers_path.exists() else {}
    fig_tradeoff(zoo, out)
    fig_propagation(zoo, out, rng)
    fig_ablation(abl, out)
    fig_discovery(zoo, out, rng)
    fig_cost(zoo, out)
    fig_adaptive(adaptive, numbers, out)
    print("figures written to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
