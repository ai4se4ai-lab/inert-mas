# INERT-MAS

**Injected but Inert: Model-Based Security Testing of Prompt-Injection Propagation in LLM Multi-Agent Systems.**

INERT is a model-driven toolchain for LLM multi-agent systems (MAS):

1. a designer writes the MAS as a typed model (`*.inert.yaml`), which is linted and compiled into a
   content-hashed plan (IR);
2. a small deterministic controller executes the plan; agents are untrusted *proposers* and every
   proposal passes a capability token, dependency-key, schema/validator and taint check;
3. the same IR drives a generator of prompt-injection attack tests from six coverage criteria;
4. every run leaves a hash-chained log from which the auditor re-checks every decision and the
   security properties P1-P6 without calling any LLM.

The controller kernel is vendored from
[safe-coordination-of-untrusted-ai-agents](https://github.com/ai4se4ai-lab/safe-coordination-of-untrusted-ai-agents)
(see `docs/vendored.md`).

## Layout

```
src/inert/model      M1 metamodel, YAML DSL, Mermaid importer, lint (L1-L6)
src/inert/compiler   M2 canonical IR, hashes, agent-graph / LangGraph export
src/inert/runtime    M3 controller (vendored kernel + keys, tokens, taint, reason codes)
src/inert/agents     M4 LLM backends (Ollama, OpenAI-compatible, mock) and agent wrapper
src/inert/tools      simulated sandbox tools with provenance labels (nothing is executed)
src/inert/attacks    M5 coverage criteria, payload library, mutators, adversaries, adaptive attacker
src/inert/audit      M6 hash-chained log, LLM-free replay, P1-P6 checkers
src/inert/eval       M7 topology zoo, harness, manifests, CLI
baselines/           B0 native, B1 detector, B2 tagging, B3 plan+quarantine, B4 permitted graph
adapters/tamas       TAMAS adapter (upstream data vendored read-only)
hpc/                 Alliance cluster scripts, SLURM template, manifests, Apptainer def
analysis/            tables, statistics, figures, paper filling (reads results, writes paper/)
docs/paper/EMSE      manuscript (single main.tex, single .bib)
```

## Quick start (offline, mock backend)

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,analysis]"
.venv/bin/pytest                                   # unit, property-based and integration tests
.venv/bin/inert lint models/examples/email_summary.inert.yaml
.venv/bin/inert gen-attacks --topology star --size 5 --family email --out suite.yaml
.venv/bin/inert run-manifest --manifest hpc/manifests/smoke.yaml --backend mock --out results/smoke.jsonl
.venv/bin/python analysis/make_assets.py results/smoke.jsonl --out /tmp/assets
```

The mock backend is deterministic and only exercises the pipeline; it is never used for results.

## With a real model (local Ollama)

```bash
inert run-manifest --manifest hpc/manifests/local_smoke.yaml --backend ollama \
      --host http://127.0.0.1:11434 --model qwen2.5:7b --parallel 8 --out results/local.jsonl
```

## On the Alliance clusters

```bash
bash hpc/scripts/ssh-session.sh connect all          # one MFA login per cluster, sockets in hpc/.ssh
python3 hpc/scripts/fleet.py probe                   # what is on each cluster
python3 hpc/scripts/fleet.py setup --sites rorqual   # copy Ollama runtime + models into the project dir
python3 hpc/scripts/fleet.py deploy --sites rorqual  # code + venv (Alliance wheelhouse)
python3 hpc/scripts/fleet.py array --site rorqual --model llama3.1:8b \
        --manifest hpc/manifests/final_zoo.yaml --shards 24 --throttle 12 --tag final --time 2:59:00
python3 hpc/scripts/fleet.py status && python3 hpc/scripts/fleet.py fetch
```

Everything on a cluster lives under the project's work directory (`hpc/config/clusters.json`).
Shards are resumable: a requeued shard skips finished cases and `.done` markers skip finished shards.

## Regenerating the paper

```bash
python analysis/make_assets.py results/final/*.jsonl --out paper
python analysis/fill_paper.py --assets paper
bash docs/paper/EMSE/Springer-Nature-LaTeX-template/build.sh
```

## Safety

Attack payloads target only the reserved example domain `evil.example`; `run_code` never executes
code. See `LICENSES-THIRD-PARTY.md` and the dual-use notice in `src/inert/attacks/__init__.py`.
