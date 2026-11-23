# AGENTS.md: operating rules for coding agents

Copy this section verbatim into `AGENTS.md` at the repository root; the generator follows it on every task.

### Scope and order

1. Work phase by phase as in the Work plan; do not start a phase before the previous exit criteria pass in CI.
2. Each task ends with code, tests and a short entry in `CHANGELOG.md` naming the component (M1 to M7) and the acceptance test it satisfies.
3. When a requirement is ambiguous, write the question in `docs/open-questions.md` and choose the most conservative option; never silently widen scope.

### Engineering standards

- Python 3.11, `uv` for dependencies, Pydantic v2 for all schemas, `ruff` and `mypy --strict` on `src/inert/`, `pytest` with Hypothesis for property tests.
- No LLM call, heuristic classifier or network access inside `model/`, `compiler/`, `runtime/` or `audit/`: they are the trusted computing base.
- Canonical JSON and SHA-256 for every hash; never hash Python `repr` or unordered structures.
- All randomness goes through a seeded generator passed in explicitly; no global random state.
- Unit and integration tests run offline with the mock LLM backend; GPU tests are marked and excluded from CI.
- Benchmark code is never edited in place: vendor it under `adapters/<name>/upstream` at a pinned commit and put changes in `adapters/<name>/patches` with a reason.

### Experiment integrity

- Never fabricate, hand-edit or interpolate results; a failed shard is rerun or reported as failed.
- Every result file records git commit, image digest, model hash, decoding config, seed and benchmark version.
- `results/` is append-only; analysis reads it and writes only to `paper/`.
- Baselines get the same models, budgets, prompts (where applicable) and tool sets as INERT; any difference is documented in `docs/baselines.md`.
- Report every condition that was run, including ones where INERT does poorly.

### Security and ethics

- Code produced by attack tests runs only inside the Apptainer sandbox with no network and a throwaway filesystem.
- Payload libraries stay in the repository for replication but carry a dual-use notice; no payload targets real third-party services.
- Respect each benchmark's and model's license; list them in `LICENSES-THIRD-PARTY.md`.

## Project-specific notes

- The controller kernel is vendored from `safe-coordination-of-untrusted-ai-agents` (see `docs/vendored.md`); edit it only through a documented patch.
- HPC work goes only through `hpc/scripts/ssh-session.sh` and `hpc/scripts/fleet.py`; everything on the cluster lives under the project's own work directory.
