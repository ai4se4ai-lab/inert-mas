#!/usr/bin/env bash
# Replay the taxonomy pipeline (Section 3) offline from the cached API responses and check that it
# reproduces the published audit trail, corpus files and manuscript blocks exactly.
#
#   bash docs/paper/EMSE/replication-package/scripts/verify_taxonomy.sh
#
# The pipeline writes in place (audit/*.csv, corpus files, count macros and tree figures in main.tex).
# This script snapshots those files first, runs the pipeline, diffs, and restores the snapshot, so the
# repository is left exactly as published. No network access and no API key are needed.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../../../../.." && pwd)
cd "$ROOT"
export PY=${PY:-$ROOT/.venv/bin/python}
[[ -x "$PY" ]] || PY=python3
PKG=docs/paper/EMSE/replication-package
WORK=docs/paper/EMSE/relevant-work
TEX=docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex
SNAP=$(mktemp -d)
status=0

echo "== 0. Integrity of the cached API responses"
if sha256sum --quiet -c $PKG/data/SHA256SUMS-taxonomy-inputs.txt; then
  echo "  [ok] raw exports, coding spec and $(ls $WORK/snowball/cache | wc -l) cached responses match SHA256SUMS-taxonomy-inputs.txt"
else echo "  [FAIL] an input differs from the published one"; status=1; fi

echo "== 1. Snapshot published outputs to $SNAP"
mkdir -p "$SNAP/audit"
cp $WORK/audit/* "$SNAP/audit/"
cp $WORK/corpus_classification.csv $WORK/corpus_collection.json "$TEX" "$SNAP/"

echo "== 2. Run analysis/taxonomy_pipeline.sh (offline, about 10 seconds)"
if bash analysis/taxonomy_pipeline.sh > "$SNAP/pipeline.log" 2>&1; then
  echo "  [ok] pipeline finished; final audit exit code 0 (no manuscript table disagrees with its CSV)"
else
  echo "  [FAIL] pipeline or final audit failed; see $SNAP/pipeline.log"; status=1
fi

echo "== 3. Compare regenerated outputs with the published ones"
for f in $WORK/audit/*; do
  b=$(basename "$f")
  if cmp -s "$f" "$SNAP/audit/$b"; then echo "  [ok] audit/$b"; else echo "  [FAIL] audit/$b differs"; status=1; fi
done
for f in $WORK/corpus_classification.csv $WORK/corpus_collection.json "$TEX"; do
  b=$(basename "$f")
  if cmp -s "$f" "$SNAP/$b"; then echo "  [ok] $b"; else echo "  [FAIL] $b differs"; diff "$SNAP/$b" "$f" | head -20; status=1; fi
done

echo "== 4. Counts reported in Section 3.1 (from the regenerated files)"
"$PY" - <<'EOF'
import json
w = "docs/paper/EMSE/relevant-work"
s = json.load(open(f"{w}/audit/summary.json"))
b = json.load(open(f"{w}/audit/snowball_summary.json"))
c = json.load(open(f"{w}/corpus_collection.json"))
print(f"  first search : Q1 {s['Q1']} + Q2 {s['Q2']} = {s['records']} records, {s['duplicates']} duplicates, "
      f"{s['unique']} unique, {s['excluded']} excluded, {s['included']} included (seeds)")
print(f"  snowballing  : {b['seeds_resolved']}/{b['seeds']} seeds in OpenAlex, {b['candidates']} candidates, "
      f"link threshold {b['link_threshold']}, {b['included_snowballing']} included")
print(f"  scopus search: {b['scopus']['search_unique']} unique, {b['scopus']['search_rule_met_new']} new meeting criteria, "
      f"{b['scopus']['search_new_included']} included")
print(f"  corpus       : {s['included'] + b['included_snowballing'] + b['scopus']['search_new_included']} studies, "
      f"{s['leaves']} leaves, {s['attack_forms']} attack forms")
print("  link-threshold sensitivity (k: studies passing criteria and threshold):",
      ", ".join(f"{k}: {v}" for k, v in b["included_by_threshold"].items()))
EOF

echo "== 5. Restore the published files"
cp "$SNAP"/audit/* $WORK/audit/
cp "$SNAP/corpus_classification.csv" "$SNAP/corpus_collection.json" $WORK/
cp "$SNAP/main.tex" "$TEX"
echo "  restored"

echo
[[ $status -eq 0 ]] && echo "RESULT: taxonomy pipeline reproduces every published file" \
                    || echo "RESULT: differences found (log in $SNAP)"
exit $status
