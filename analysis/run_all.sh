#!/usr/bin/env bash
# Regenerate every table, figure and number of the paper from the archived result records.
#   bash analysis/run_all.sh [results-dir]   (default: hpc/fetched, i.e. results fetched from the clusters)
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=${1:-hpc/fetched}
PY=${PY:-.venv/bin/python}
mapfile -t FILES < <(find "$SRC" -path '*/outputs/*' -name 'shard_*.jsonl' \
  \( -path '*/final/*' -o -path '*/tamas/*' -o -path '*/tamas-split2/*' -o -path '*/tamas-scope/*' \
     -o -path '*/seeds/*' -o -path '*/adaptive/*' \) | sort)
echo "${#FILES[@]} result files"
$PY analysis/make_assets.py "${FILES[@]}" --out paper
$PY analysis/residual.py "${FILES[@]}" --out paper
$PY analysis/fill_paper.py --assets paper
bash docs/paper/EMSE/Springer-Nature-LaTeX-template/build.sh
