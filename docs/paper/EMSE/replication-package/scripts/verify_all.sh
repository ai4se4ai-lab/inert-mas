#!/usr/bin/env bash
# Run every reviewer check in order. Leaves the repository unchanged.
#   bash docs/paper/EMSE/replication-package/scripts/verify_all.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../../../../.." && pwd)
cd "$ROOT"
PY=${PY:-$ROOT/.venv/bin/python}
[[ -x "$PY" ]] || PY=python3
S=docs/paper/EMSE/replication-package/scripts
declare -A R

echo "######## A. Test suite (offline, mock LLM backend)"
"$PY" -m pytest -q && R[A]=ok || R[A]=FAIL
echo "######## B. Independent recount of the headline claims and the running example"
"$PY" $S/check_claims.py && R[B]=ok || R[B]=FAIL
echo "######## C. Regeneration of all result tables, numbers and figures"
bash $S/verify_results.sh && R[C]=ok || R[C]=FAIL
echo "######## D. Offline replay of the taxonomy pipeline"
bash $S/verify_taxonomy.sh && R[D]=ok || R[D]=FAIL

echo
echo "Summary: A tests ${R[A]} | B claims ${R[B]} | C results ${R[C]} | D taxonomy ${R[D]}"
[[ "${R[A]}${R[B]}${R[C]}${R[D]}" == "okokokok" ]]
