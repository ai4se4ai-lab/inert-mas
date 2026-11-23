# Vendored code

| What | From | Commit | Where | Changes |
| --- | --- | --- | --- | --- |
| Guarded coordination kernel (`GraphController`, exact observations, request identities, per-episode budget, upstream gate, publication barrier) | `ai4se4ai-lab/safe-coordination-of-untrusted-ai-agents`, `src/vgc/graph.py` (MIT) | `f56c0e869c50041e8cdd86890e41cb822927d6de` (dev) | `src/inert/runtime/kernel.py` | Header and lint markers only |
| HPC session and fleet scripts (pattern) | same repository, `hpc/scripts/` | same | `hpc/scripts/` | Rewritten for this project: own work directory `/scratch/mbabaei/inert-mas`, manifest-based shards, array jobs |
| TAMAS data and evaluators | `microsoft/TAMAS` (code MIT, data CDLA-Permissive-2.0) | `545c112af9aab93b7ef2b0b60831d93c81c365c3` | `adapters/tamas/upstream/` | None (read-only; tools parsed with `ast`, never executed) |

INERT's additions live in `src/inert/runtime/controller.py`: dependency keys that include taint
labels, the plan hash and tool-metadata hashes; HMAC capability tokens; taint-aware context
selection and acceptance; reason-coded hash-chained logging; TCB execution of tool and
declassifier slots.
