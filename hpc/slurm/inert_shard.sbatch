#!/usr/bin/env bash
# One INERT-MAS shard: one model on one GPU with a node-local Ollama server.
# Required env (sbatch --export): INERT_ROOT MODEL MANIFEST OUT PARALLEL SHARDS [SHARD_INDEX]
# Array jobs take SHARD_INDEX from SLURM_ARRAY_TASK_ID. Results are written to node-local
# $SLURM_TMPDIR, then copied to $OUT; a .done marker makes requeued shards resume/skip.
#SBATCH --job-name=inert-shard
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --output=%x-%A_%a.out
set -euo pipefail
module load StdEnv/2023 python/3.12.4 2>/dev/null || true
SHARD_INDEX=${SLURM_ARRAY_TASK_ID:-${SHARD_INDEX:-0}}
JOB=${SLURM_JOB_ID}
echo "host=$(hostname) job=$JOB model=$MODEL manifest=$MANIFEST shard=$SHARD_INDEX/$SHARDS gpu=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader | head -1)"
mkdir -p "$OUT" "$INERT_ROOT/logs"
DONE="$OUT/shard_${SHARD_INDEX}_of_${SHARDS}.done"
[ -f "$DONE" ] && { echo "already done: $DONE"; exit 0; }
LOG="$INERT_ROOT/logs/ollama_${JOB}_${SHARD_INDEX}.log"

runtime_local="${SLURM_TMPDIR:-/tmp}/inert-ollama"
mkdir -p "$runtime_local"
rsync -a --exclude=vulkan "$INERT_ROOT/ollama/runtime/" "$runtime_local/"
export OLLAMA_VULKAN=0 OLLAMA_LOAD_TIMEOUT=15m OLLAMA_NOPRUNE=1 OLLAMA_NO_CLOUD=1
export OLLAMA_HOST="127.0.0.1:$((20000 + (JOB + SHARD_INDEX) % 30000))"
export OLLAMA_NUM_PARALLEL="${PARALLEL:-8}" OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_KEEP_ALIVE=60m
export OLLAMA_MODELS="$INERT_ROOT/ollama/models" OLLAMA_CONTEXT_LENGTH=8192 OLLAMA_FLASH_ATTENTION=1
start_server() {
  "$runtime_local/bin/ollama" serve > "$LOG.$1" 2>&1 &
  SRV=$!
  curl --fail --silent --retry 30 --retry-connrefused --retry-delay 2 --retry-max-time 120 "http://$OLLAMA_HOST/api/version"; echo
  curl -s "http://$OLLAMA_HOST/api/generate" -d "{\"model\":\"$MODEL\",\"prompt\":\"\",\"keep_alive\":\"60m\",\"options\":{\"num_ctx\":8192}}" > /dev/null
  python3 - "$OLLAMA_HOST" "$MODEL" <<'PY'
import json, sys, urllib.request
ps = json.load(urllib.request.urlopen(f"http://{sys.argv[1]}/api/ps"))
m = [x for x in ps.get("models", []) if x["name"].startswith(sys.argv[2])]
assert m, f"model not loaded: {ps}"
size, vram = m[0]["size"], m[0].get("size_vram", 0)
print(f"residency size={size} vram={vram} ratio={vram/size:.3f} digest={m[0].get('digest','')}")
assert vram >= 0.98 * size, "model not fully GPU resident"
PY
}
# Ollama's GPU-discovery watchdog can time out on a cold node and fall back to CPU.
# Never run on CPU: restart the server (up to 4 attempts) until the model is fully GPU resident.
ok=0
for attempt in 1 2 3 4; do
  if start_server $attempt; then ok=1; break; fi
  echo "attempt $attempt: model not GPU resident, restarting ollama"
  kill $SRV 2>/dev/null || true; wait $SRV 2>/dev/null || true; sleep $((15 * attempt))
done
trap 'kill $SRV 2>/dev/null || true' EXIT
[ "$ok" = 1 ] || { echo "giving up: GPU not usable on $(hostname)"; exit 1; }

TMP="${SLURM_TMPDIR:-/tmp}/inert-out-$JOB-$SHARD_INDEX"
mkdir -p "$TMP"
# resume: start from any partial output already copied back
cp "$OUT/shard_${SHARD_INDEX}_of_${SHARDS}.jsonl" "$TMP/" 2>/dev/null || true
cd "$INERT_ROOT/repo"
export PYTHONPATH="$INERT_ROOT/repo/src:$INERT_ROOT/repo"
source "$INERT_ROOT/venv/bin/activate"
export INERT_COMMIT="$(cat "$INERT_ROOT/repo/COMMIT" 2>/dev/null || echo unknown)"
( while sleep 300; do cp "$TMP"/*.jsonl "$OUT/" 2>/dev/null || true; done ) & SYNC=$!
python -m inert.eval.cli run-manifest --manifest "$MANIFEST" --model "$MODEL" \
    --backend ollama --host "http://$OLLAMA_HOST" --shard "$SHARD_INDEX/$SHARDS" \
    --parallel "${PARALLEL:-8}" --out "$TMP/shard_${SHARD_INDEX}_of_${SHARDS}.jsonl" \
    ${EXTRA:+${EXTRA//;/ }} --meta "job=$JOB;site=$(hostname);image=ollama-$(\"$runtime_local/bin/ollama\" --version 2>/dev/null | tail -1 | tr ' ' '_')"
kill $SYNC 2>/dev/null || true
cp "$TMP"/*.jsonl "$OUT/"
touch "$DONE"
nvidia-smi --query-gpu=name,utilization.gpu,memory.used --format=csv,noheader
echo "done $(date -u +%FT%TZ)"
