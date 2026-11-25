#!/usr/bin/env bash
# Complete taxonomy pipeline (Section 3 of the manuscript), from the raw search exports to the corpus tree.
#   bash analysis/taxonomy_pipeline.sh            # offline: replays the cached API responses
#   bash analysis/taxonomy_pipeline.sh --fetch    # also queries OpenAlex and Scopus for anything not yet cached
# Keys are read from the environment and never written to disk (the cache omits them):
#   ELSEVIER_API_KEY (Scopus search and reference-list search; needed only to refetch), OPENALEX_API_KEY (optional).
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
$PY analysis/taxonomy_audit.py >/dev/null || true     # steps 1-3 (search, deduplication, screening)
if [[ "${1:-}" == "--fetch" ]]; then $PY analysis/snowball.py fetch; fi
$PY analysis/snowball.py screen >/dev/null            # steps 12-15 (seeds, candidates, screening, classification)
$PY analysis/taxonomy_audit.py >/dev/null || true     # recompute counts with the snowballing results
$PY analysis/corpus_tree.py                           # corpus tree, classification CSV, count macros
$PY analysis/channel_tree.py                          # channel tree (Figure of attack forms)
$PY analysis/taxonomy_audit.py                        # final run: fails on any inconsistency with the manuscript
