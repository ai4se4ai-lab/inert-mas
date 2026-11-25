#!/usr/bin/env bash
# Regenerate every result table, figure and number of the paper from the archived records into a
# scratch directory and compare them with the committed assets and the manuscript. Nothing in the
# repository is modified.
#
#   bash docs/paper/EMSE/replication-package/scripts/verify_results.sh [results-dir] [out-dir]
#
# Defaults: results-dir = results/final, out-dir = a fresh temporary directory.
# Needs: the analysis extra (pip install -e '.[analysis]'); pdftoppm (poppler) for the figure check.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../../../../.." && pwd)
cd "$ROOT"
PY=${PY:-$ROOT/.venv/bin/python}
[[ -x "$PY" ]] || PY=python3
SRC=${1:-results/final}
OUT=${2:-$(mktemp -d)}
PKG=docs/paper/EMSE/replication-package
TEX=docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex
FIGDIR=docs/paper/EMSE/Springer-Nature-LaTeX-template/figures
status=0
mkdir -p "$OUT"

echo "== 0. Integrity of the archived records ($SRC)"
if [[ -f $PKG/data/SHA256SUMS-results.txt && "$SRC" == "results/final" ]]; then
  if sha256sum --quiet -c $PKG/data/SHA256SUMS-results.txt; then echo "  [ok] 182 shard files match SHA256SUMS-results.txt"
  else echo "  [FAIL] checksum mismatch"; status=1; fi
else
  echo "  [skip] custom results directory; checksums not compared"
fi

mapfile -t FILES < <(find "$SRC" -name 'shard_*.jsonl' \
  \( -path '*/final/*' -o -path '*/tamas/*' -o -path '*/tamas-split2/*' -o -path '*/tamas-scope/*' \
     -o -path '*/seeds/*' -o -path '*/adaptive/*' \) | sort)
echo "  ${#FILES[@]} result files"

echo "== 1. Regenerate into $OUT (about 2 minutes)"
"$PY" analysis/make_assets.py "${FILES[@]}" --out "$OUT" > "$OUT/make_assets.log" 2>&1 || { echo "  [FAIL] make_assets"; status=1; }
"$PY" analysis/residual.py "${FILES[@]}" --out "$OUT" > "$OUT/residual.log" 2>&1 || { echo "  [FAIL] residual"; status=1; }
"$PY" analysis/make_figures.py "${FILES[@]}" --assets "$OUT" > "$OUT/make_figures.log" 2>&1 || { echo "  [FAIL] make_figures"; status=1; }

echo "== 2. Tables and residual-risk files (byte comparison with paper/)"
for f in paper/tab_*.tex paper/residual.json paper/residual_coding.csv; do
  b=$(basename "$f")
  if cmp -s "$f" "$OUT/$b"; then echo "  [ok] $b"; else echo "  [FAIL] $b differs"; status=1; fi
done

echo "== 3. numbers.json (numeric comparison with paper/numbers.json)"
"$PY" $PKG/scripts/compare_numbers.py paper/numbers.json "$OUT/numbers.json" || status=1

echo "== 4. Figures (rendered pixels, since PDF bytes carry a creation date)"
if command -v pdftoppm >/dev/null; then
  for f in "$OUT"/fig_*.pdf; do
    b=$(basename "$f")
    new=$(pdftoppm -r 60 -png "$f" | sha256sum)
    old=$(pdftoppm -r 60 -png "$FIGDIR/$b" | sha256sum)
    if [[ "$new" == "$old" ]]; then echo "  [ok] $b identical to the manuscript figure"
    else echo "  [FAIL] $b differs from $FIGDIR/$b"; status=1; fi
  done
else
  echo "  [skip] pdftoppm not installed; compare $OUT/fig_*.pdf with $FIGDIR/ by eye"
fi

echo "== 5. Manuscript (fill a copy of main.tex with the regenerated assets and diff)"
cp "$TEX" "$OUT/main.tex"
"$PY" analysis/fill_paper.py --assets "$OUT" --tex "$OUT/main.tex" > /dev/null
if diff -u "$TEX" "$OUT/main.tex" > "$OUT/main.diff"; then
  echo "  [ok] every table, count and data-driven sentence of main.tex is reproduced"
else
  echo "  [note] regenerated manuscript differs; see $OUT/main.diff and 'Known differences' in the package README:"
  grep -E '^[-+][^-+]' "$OUT/main.diff" | cut -c1-160 | sed 's/^/         /'
fi

echo
[[ $status -eq 0 ]] && echo "RESULT: all result assets reproduced (outputs in $OUT)" \
                    || echo "RESULT: some checks failed (outputs and logs in $OUT)"
exit $status
