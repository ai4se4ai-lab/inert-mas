"""Inject generated tables/numbers into the single-file manuscript.

  python analysis/fill_paper.py --assets paper --tex docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex \
         [--text analysis/paper_text.py]

Replaces the content between ``%<<name>>`` and ``%<</name>>`` markers. Tables come from
``<assets>/tab_<x>.tex``; prose blocks come from ``paper_text.render(numbers)`` so that every
number in the text is computed from numbers.json (no hand-typed results). Figures are copied.
"""
import argparse
import importlib.util
import json
import re
import shutil
from pathlib import Path


def replace_block(tex: str, name: str, body: str) -> str:
    pat = re.compile(r"(%<<" + re.escape(name) + r">>\n)(.*?)(%<</" + re.escape(name) + r">>)", re.S)
    if not pat.search(tex):
        raise SystemExit(f"marker {name} not found")
    return pat.sub(lambda m: m.group(1) + body.rstrip() + "\n" + m.group(3), tex)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--assets", default="paper")
    ap.add_argument("--tex", default="docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex")
    ap.add_argument("--text", default="analysis/paper_text.py")
    a = ap.parse_args()
    assets, tex_path = Path(a.assets), Path(a.tex)
    tex = tex_path.read_text(encoding="utf-8")
    for t in sorted(assets.glob("tab_*.tex")):
        if f"%<<{t.stem}>>" not in tex:  # shown as a figure in the manuscript (analysis/make_figures.py)
            print("not in manuscript, kept in assets:", t.name)
            continue
        tex = replace_block(tex, t.stem, t.read_text())
    numbers = json.loads((assets / "numbers.json").read_text())
    if Path(a.text).exists():
        spec = importlib.util.spec_from_file_location("paper_text", a.text)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        for name, body in mod.render(numbers).items():
            tex = replace_block(tex, name, body)
    figdir = tex_path.parent / "figures"
    figdir.mkdir(exist_ok=True)
    for f in assets.glob("fig_*.pdf"):
        shutil.copy(f, figdir / f.name)
    tex_path.write_text(tex, encoding="utf-8")
    print("filled", tex_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
