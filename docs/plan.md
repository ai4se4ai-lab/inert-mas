# INERT-MAS Development Plan — Model-Based Security Testing of Prompt-Injection Propagation (EMSE)

Nov 22, 2026 · @Majid

## Overview

Build **INERT-MAS**, a model-driven toolchain that (1) compiles a multi-agent system model into a controller-mediated runtime where agents are untrusted proposers, (2) generates prompt-injection attack test cases from that model using coverage criteria, and (3) evaluates both rigorously on public benchmarks on the Alliance (Compute Canada) clusters. Target venue: the *Empirical Software Engineering* special issue on software security testing.

- **Paper title:** *Injected but Inert: Model-Based Security Testing of Prompt-Injection Propagation in LLM Multi-Agent Systems*
- **Repository:** `ai4se4ai/inert-mas`
- **Builds on:** the JSS controller (dependency keys, owned contracts, release gate, replay log) and the MindPortalix model-to-LangGraph compiler. Recap them in about one page of the paper; the new contributions are below.

### Claims the prototype must make testable

1. **C1, structural prevention.** Control-flow hijacking, impersonation, replay and injected reconfiguration cannot change what executes or what is released, by construction.
2. **C2, bounded semantic propagation.** Taint-carrying dependency keys stop untrusted-derived free text from reaching instruction fields or executor slots, unless it passes a declared declassifier.
3. **C3, model-based test generation.** Attack suites generated from model coverage criteria find more successful attacks per unit cost than benchmark-provided attacks alone.
4. **C4, honest cost.** Utility loss, false rejections and runtime overhead are measured and reported against strong baselines.

### Paper contributions

1. A taxonomy of prompt-injection channels specific to agent collaboration, mapped to structural vs. semantic defenses.
2. A taint extension of dependency keys with a non-interference policy checked at acceptance and context selection.
3. Coverage criteria over MAS models and a generator that turns them into executable attack tests.
4. A large empirical study (benchmarks, topologies, open-weight models, adaptive attackers) with a replication package.
5. A replay-based audit that checks the security properties from logs alone, without re-running LLMs.

### Fit with the call

| Call aim | What this work provides |
| --- | --- |
| (1) Concepts, challenges, opportunities | Channel taxonomy; structural vs. semantic guarantee boundary |
| (2) Creating, managing, automating security tests | Model-coverage attack generation; replayable test oracles |
| (3) Rigorous evidence on existing techniques | Head-to-head study of existing defenses on established benchmarks |

### What the code generator delivers

A tested Python package, benchmark adapters, baseline reimplementations, Apptainer images, SLURM job templates, an analysis pipeline that regenerates every table and figure, and a Zenodo-ready replication package.

## Threat model and claim scope

The trusted computing base (TCB) is the compiler, controller, validators, policy engine and tool executors; every LLM agent, every tool output and every inter-agent message is untrusted. No LLM may run inside the TCB.

### Attacker models

| ID | Attacker | Capability | Source in literature |
| --- | --- | --- | --- |
| A1 | Indirect injection | Controls content returned by tools or the environment (web page, file, email, repo) | AgentDojo, MAS hijacking |
| A2 | Compromised agent | Fully controls one agent's outputs (Byzantine) | TAMAS |
| A3 | Message tamperer | Intercepts and rewrites inter-agent messages on the transport | Agent-in-the-Middle |
| A4 | Colluding agents | Two or more compromised agents coordinate | TAMAS |
| A5 | Reconfiguration | Registers or alters an agent or tool mid-run (incl. tool-metadata poisoning) | MCP tool-poisoning work |
| A6 | Adaptive | Knows the model, the controller and the policies; iterates with feedback | Required by reviewers; ControlValve paper |

**Out of scope:** compromise of the controller host, model-weight poisoning, side channels, attacks on the human operator.

### Security properties (checked on every run from the replay log)

| ID | Property | Mechanism | Guarantee type |
| --- | --- | --- | --- |
| P1 | Control-flow integrity: every executed transition is an edge of the compiled model | Controller owns structure | By construction |
| P2 | Authorship: every accepted value came from the agent authorized for that slot | Per-request capability tokens bound to slot | By construction |
| P3 | Freshness: no value accepted against a superseded key | Exact key match at acceptance | By construction |
| P4 | Contract integrity: instruction, schema, validator and tool metadata are the ones in force | Contract and tool-metadata hashes in key | By construction |
| P5 | Taint non-interference: no value tainted above a sink's level reaches an instruction field or executor slot without a declassifier | Taint labels in key + policy at acceptance and context selection | By construction, relative to declassifier correctness |
| P6 | Release integrity: only snapshots with nothing stale, nothing pending and all joint constraints satisfied are published | Release gate | By construction |

### What the paper must NOT claim

- Immunity to prompt injection. A schema-valid, untainted-looking value can still be wrong; the claim is that its effect is *bounded* to the slot's declared authority.
- Correctness of declassifiers. A declassifier (for example, extract an enum from untrusted text) is an LLM-free but still fallible component; measure how often attacks pass through one.
- Coverage of attacks on goals the model itself legitimately permits (for example, an agent allowed to send email sending a plausible but wrong email). Report these as *residual risk* with counts.

## Architecture and repository layout

One pipeline serves both the defense and the test generator: both read the same compiled intermediate representation (IR), so every attack test is traceable to a model element.

### Data flow

1. A designer writes a MAS model (`*.inert.yaml`, or a Mermaid statechart imported via the MindPortalix front end).
2. The parser builds a metamodel instance and runs static checks (reachability, taint paths, missing declassifiers).
3. The compiler emits a deterministic, content-hashed IR: slots, contracts, edges, context selectors, tool bindings, trust labels, policies.
4. The controller runtime executes the IR. It requests proposals from agents, applies the acceptance check (key, authorization, validator, taint policy) and logs every decision.
5. Agents call a local OpenAI-compatible endpoint (vLLM on the cluster GPUs). Tools run in an executor sandbox with recorded I/O.
6. The release gate publishes a snapshot only when properties P1 to P6 hold.
7. The attack generator reads the same IR, enumerates coverage obligations and emits an executable attack suite.
8. The evaluation harness runs suites against INERT and every baseline, then the auditor replays logs and checks P1 to P6 offline.

### Repository tree

```text
inert-mas/
  AGENTS.md                 # rules for coding agents (copy of the Operating rules section)
  README.md  LICENSE  CITATION.cff
  pyproject.toml            # uv-managed; python 3.11
  src/inert/
    model/                  # M1 metamodel, DSL schema, Mermaid importer, static checks
    compiler/               # M2 IR, canonical hashing, LangGraph export (for baselines)
    runtime/                # M3 controller: slots, keys, taint, acceptance, budget, release gate
    agents/                 # M4 agent wrappers, prompt templates, LLM client (vLLM / OpenAI-compatible)
    tools/                  # sandboxed tool executor, tool-metadata registry
    attacks/                # M5 coverage criteria, payload library, mutators, adaptive attacker
    audit/                  # M6 replay log schema, replayer, property checkers P1-P6
    eval/                   # M7 harness, metrics, condition registry
  baselines/
    b0_native/              # AutoGen / CrewAI / LangGraph undefended workflows
    b1_detector/            # injection-classifier filter
    b2_tagging/             # LLM Tagging (Prompt Infection defense)
    b3_planquarantine/      # CaMeL-style plan + quarantined LLM, extended to MAS
    b4_cfg_llm/             # ControlValve-style LLM-generated permitted graph
  adapters/
    tamas/  mas_hijack/  prompt_infection/  aitm/  agentdojo/   # one adapter per benchmark
  models/                   # MAS models: re-specified benchmark workflows + topology zoo
  hpc/
    apptainer/              # .def files; images built on a login node
    slurm/                  # array templates, vLLM launcher, resume logic
    manifests/              # experiment grids (YAML) -> job shards
  analysis/                 # notebooks-free scripts: stats, tables, figures (LaTeX output)
  tests/                    # unit, property-based, integration (no network)
  results/                  # immutable run outputs (git-ignored; archived to Zenodo)
  paper/                    # generated tables/figures consumed by the LaTeX manuscript
```

## Component specifications

Each component lists its purpose, its interface and the acceptance tests that must pass before the next phase starts.

### M1 Metamodel and DSL (`src/inert/model`)

- **Elements:** `Agent`, `Role`, `Slot`, `Contract` (instruction, output JSON Schema, validator ref, owner), `Edge` (producer slot to consumer slot), `ContextSelector`, `Tool` (name, schema, metadata hash, side-effect class), `TrustLevel`, `Declassifier`, `Policy`, `JointConstraint`, `ReleaseGate`.
- **Formats:** YAML DSL validated by Pydantic v2 models plus an exported JSON Schema; Mermaid statechart importer reusing the MindPortalix grammar.
- **Static checks (lint errors):** unreachable slot; cycle without budget; executor or instruction sink reachable from an untrusted source with no declassifier on the path; slot without owner; free-text output feeding an instruction field.
- **Acceptance:** round-trip YAML to model to YAML is identity; every lint rule has a passing and a failing fixture; all benchmark workflows re-specified as models pass lint.

### M2 Compiler and IR (`src/inert/compiler`)

- Emits a frozen IR with canonical JSON encoding (sorted keys, normalized Unicode, no floats in keys) and a SHA-256 hash per element and for the whole plan.
- Exports a LangGraph graph from the same IR so baselines B0 and B4 run the *same* workflow without the controller.
- **Acceptance:** compiling twice gives byte-identical IR; Hypothesis property test: semantically equal models give equal hashes, any field change gives a different hash.

### M3 Controller runtime (`src/inert/runtime`)

- **Dependency key** = hash(reads, selected-context hashes, contract hash, tool-metadata hashes, taint label set, plan hash).
- **Taint lattice:** `trusted < user < agent_untrusted < external_untrusted`; a value's label is the join of its inputs' labels; declassifiers (schema-bounded extraction: enum, integer range, regex-bounded identifier) lower the label and are logged.
- **Acceptance check (all must hold, in this order, logged with reason codes):**
  1. The capability token names this slot, this agent and this key (HMAC, single use).
  2. The key equals the slot's current key.
  3. The output parses against the slot schema and the owned validator accepts it.
  4. The taint policy allows the value's label at this slot and at every sink the value can reach.
- **Context selection:** tainted free text is delivered only inside a quoted data field, never in the instruction field; agents never see raw messages from other agents, only selected slot values.
- **Budget** per change; **release gate** checks P1 to P6 and joint constraints before publishing.
- **Acceptance:** unit test per reason code; Hypothesis state-machine test that random interleavings never accept a stale key; fault-injection test that forged tokens and replayed messages are always rejected.

### M4 Agents and LLM backend (`src/inert/agents`)

- OpenAI-compatible client pointed at a local vLLM server; model registry in YAML (name, weights path, context length, chat template).
- Fixed decoding config per experiment (temperature, top-p, seed); every request and response recorded in the replay log.
- **Acceptance:** a mock backend gives deterministic runs for all integration tests; switching models is a config change only.

### M5 Attack test generator (`src/inert/attacks`)

- **Coverage criteria over the IR:** edge coverage; slot by payload-class coverage; context-selector coverage; untrusted-source to sink taint-path coverage; reconfiguration-event coverage (agent or tool added, metadata changed).
- **Payload classes:** instruction override; fake error or traceback (MAS hijacking style); self-replicating infection; sender impersonation; message tampering; tool-metadata poisoning; colluding-agent scripts.
- **Mutators:** paraphrase, encoding (base64, homoglyphs), position (prefix, suffix, embedded), language switch.
- **Adaptive attacker:** an attacker LLM gets the model, the policy text and rejection reason codes, and iterates within a fixed query budget.
- **Output:** an attack test = (obligation id, injection point, payload, attacker goal, oracle); suites are YAML and fully replayable.
- **Acceptance:** generated suite reaches 100% of feasible obligations on the topology zoo; every test is executable against both INERT and B0.

### M6 Replay and audit (`src/inert/audit`)

- JSONL event log: proposal, acceptance or rejection (reason code), key, labels, release, with a hash chain over events.
- Replayer re-runs every controller decision from the log with no LLM calls and must reproduce the same decisions.
- Property checkers for P1 to P6 act as the test oracles; attack success is judged by the benchmark's own oracle *and* by P1 to P6.
- **Acceptance:** replay of 100% of logged runs reproduces decisions bit-for-bit; a tampered log is detected.

### M7 Evaluation harness (`src/inert/eval`)

- A condition registry (defense by benchmark by model by topology by seed); a single command runs one shard and writes immutable results with git commit, image digest and model hash.
- Analysis scripts in `analysis/` regenerate every LaTeX table and figure from `results/`.

## Benchmarks, adapters and baselines

TAMAS is the primary benchmark because it is multi-agent by design; the MAS-hijacking workflows give the strongest head-to-head result; the rest cover propagation, message tampering and a single-agent sanity check.

### Benchmarks

| Benchmark | What it tests | How INERT uses it | Adapter work | HPC notes |
| --- | --- | --- | --- | --- |
| [TAMAS](https://arxiv.org/abs/2511.05269) (Microsoft) | 300 adversarial instances, six attack types (impersonation, direct and indirect injection, contradicting, Byzantine, colluding agents), 211 tools, five domains | Primary: re-specify each scenario's MAS as an INERT model; run all six attack types plus benign tasks for utility | Map orchestrator and agents to slots and edges; reuse its tools and oracles | Pure Python; runs offline with local models |
| [MAS hijacking](https://arxiv.org/abs/2503.12188) (Triedman et al.) | Control-flow hijacking to code execution in AutoGen, CrewAI and MetaGPT | Re-implement the attacked workflows as INERT models; run their attack templates head-to-head with the native frameworks | Rebuild workflows; sandbox the code executor; replace live web content with recorded files | Code execution only inside the Apptainer sandbox |
| [Prompt Infection](https://arxiv.org/abs/2410.07283) | Self-replicating LLM-to-LLM injection across agents | Payload source for propagation; measures infected-agent count and blast radius | Port payloads into M5 payload library | No special needs |
| [Agent-in-the-Middle](https://aclanthology.org/2025.findings-acl.349/) | Interception and rewriting of inter-agent messages | Attacker model A3 on chain, star and hierarchical topologies | Implement the adversarial interceptor on the transport | Attacker LLM served by the same vLLM node |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | Single-agent tool use under indirect injection | Sanity check versus published CaMeL numbers | Wrap a single-agent suite as a one-agent model | Pure Python |
| [ACIArena](https://arxiv.org/abs/2604.07775) (optional) | Agent cascading injection across MAS | Generalization check if code and data are released | To be decided after checking the release | Open question |

Open question: confirm licenses and that TAMAS, ACIArena and the MAS-hijacking templates are publicly released before Phase 3; if not, contact the authors in Phase 0.

### Topology zoo (for RQ1 and RQ3)

Chain, star (orchestrator plus workers), hierarchical (two levels), debate (peer to peer), and the planner-coder-reviewer software-engineering workflow from the JSS study. Each topology comes in sizes of 3, 5 and 8 agents.

### Baselines and ablations

| ID | Condition | Purpose |
| --- | --- | --- |
| B0 | Native framework, no defense (AutoGen, CrewAI, LangGraph) | Lower bound |
| B1 | Prompt-injection classifier filtering every message and tool output | Detection-based defense |
| B2 | LLM Tagging (from Prompt Infection) | MAS-specific heuristic defense |
| B3 | CaMeL-style plan plus quarantined LLM, extended to several agents | Strongest single-agent design defense |
| B4 | ControlValve-style permitted graph generated by an LLM and enforced at runtime | Closest competitor |
| I1 | INERT structural only (P1 to P4, P6; no taint) | Isolates C1 |
| I2 | INERT full (adds taint, P5) | Isolates C2 |
| I2-x | I2 minus one mechanism each: tokens, key match, validator, taint at selection, taint at acceptance | Ablation for RQ2 |

B3 and B4 are reimplementations: document every design choice, and if the original authors release code, use theirs.

## Experimental design

Five research questions, one factorial grid, pre-registered hypotheses and paired statistics. Commit `analysis/preregistration.md` before the first full run.

### Research questions

| RQ | Question | Conditions | Primary metric | Hypothesis |
| --- | --- | --- | --- | --- |
| RQ1 | How do injections propagate across MAS topologies without a controller? | B0 on topology zoo and TAMAS | Attack success rate (ASR); infected agents; blast radius | Propagation grows with fan-out; chain topologies amplify tampering |
| RQ2 | Which INERT mechanism blocks which attack class? | I1, I2, I2-x ablations | ASR per attack class; first rejecting mechanism (reason code) | Structural attacks fall to near zero under I1; semantic propagation needs I2 |
| RQ3 | Does model-coverage test generation find more successful attacks than benchmark attacks alone? | M5 suites vs. benchmark suites, on B0 and B4 | Successful attacks per 1,000 LLM calls; unique obligations violated | Coverage suites find more distinct successful attacks at equal cost |
| RQ4 | What do defenses cost? | All B and I conditions on benign tasks | Utility (benign task success); false rejection rate; latency; tokens | INERT utility loss is comparable to B3 and lower than B1 false rejections |
| RQ5 | Do defenses survive adaptive attackers? | A6 against B1 to B4, I2 | ASR under a fixed attacker query budget | Structural properties hold; residual attacks concentrate at declassifiers |

### Factorial grid

- **Defense:** B0, B1, B2, B3, B4, I1, I2 (plus five I2-x ablations for RQ2 only).
- **Benchmark or suite:** TAMAS, MAS hijacking, Prompt Infection payloads, AiTM, AgentDojo, M5 generated suites.
- **Model:** at least three open-weight instruction-tuned families at two sizes (small around 8B, large around 70B), all with function calling. Fix exact checkpoints in Phase 0 and record their hashes.
- **Topology:** the zoo where the benchmark allows it.
- **Seeds:** 5 per cell for screening, 10 for the final reported cells.

### Metrics (all computed from logs)

- **ASR:** share of attack tests where the attacker goal is met (benchmark oracle) *or* any of P1 to P6 is violated.
- **Utility:** benign task success; **utility under attack:** task success with the attack present.
- **Propagation:** infected agents (an agent that emits attacker-derived instructions); blast radius (share of slots whose accepted values carry attacker taint); depth (longest infected path).
- **Containment:** steps from injection to first rejection; rejection reason code.
- **False rejection rate:** rejected benign proposals over benign proposals.
- **Cost:** wall-clock latency, prompt and completion tokens, GPU-seconds per task.
- **Coverage (RQ3):** feasible obligations covered; successful attacks per obligation class.

### Statistical analysis

- Binary outcomes (success, rejection): logistic mixed-effects model, defense and model as fixed effects, task and seed as random intercepts.
- Paired per-task comparisons against B0 and B4: McNemar's test; effect size as odds ratio with 95% bootstrap CI (10,000 resamples).
- Continuous outcomes (latency, tokens): Wilcoxon signed-rank with Cliff's delta.
- Multiple comparisons: Holm correction within each RQ.
- Report variance across seeds per cell, and run a power check after screening to confirm 10 seeds give stable estimates.
- Qualitative analysis: open-code a stratified sample of 100 successful attacks against I2 into a residual-risk taxonomy, with two raters and Cohen's kappa.

## HPC execution plan (Alliance clusters)

Run everything offline with open-weight models served by vLLM inside each GPU job; this makes the study reproducible and independent of API pricing and internet access.

### Cluster constraints that shape the design

- **Containers:** Apptainer only; Docker is not available. Build `.sif` images on a login node (or a VM with root) from the repo's `.def` files.
- **No Docker Compose:** every benchmark must run in a single container plus local processes. This is why multi-container suites (CVE-Bench style) are excluded.
- **Internet:** compute nodes on Rorqual and Trillium have no internet; Fir and Nibi are listed with access. Design for no internet everywhere: pre-download weights, datasets and pip wheels on a login node.
- **GPUs:** H100 80 GB on Fir, Nibi, Rorqual and Trillium; Nibi GPU nodes carry eight H100s each.

### Job anatomy

1. A SLURM array job, one task per shard (defense by model by benchmark slice by seed), sized to finish in under 3 hours so it fits backfill windows.
2. Each task starts a vLLM server on its GPUs (tensor parallel 1 for small models, 4 for around-70B models) on `localhost`, waits for the health check, then runs the harness.
3. The harness writes results to node-local `$SLURM_TMPDIR`, then copies them to `~/scratch/inert-results/<run-id>/`; a finished-marker file enables resume on requeue.
4. A nightly CPU job aggregates finished shards into Parquet on project storage and runs the replay auditor.

```bash
#!/bin/bash
#SBATCH --account=def-<pi>            # or rrg-<pi> after a RAC award
#SBATCH --gpus-per-node=h100:1
#SBATCH --cpus-per-task=8 --mem=64G --time=02:59:00
#SBATCH --array=0-499%40              # throttle concurrent tasks
module load apptainer
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export HF_HOME=$PROJECT/inert/hf-cache
SHARD=$(python hpc/manifests/shard.py --grid $GRID --index $SLURM_ARRAY_TASK_ID)
apptainer exec --nv -B $PROJECT,$SCRATCH hpc/apptainer/inert.sif \
  bash hpc/slurm/run_shard.sh "$SHARD"   # starts vLLM, waits, runs harness, copies results
```

### Budget estimate (rough; replace after the Phase 2 pilot)

GPU-hours ≈ cells × seeds × tasks per cell × GPU-seconds per task ÷ 3,600. Measure GPU-seconds per task in the pilot for each model size, then compute the full grid. If the total exceeds the default allocation, either narrow the grid (screen with 5 seeds, rerun only reported cells with 10) or apply to the Resource Allocation Competition.

### Reproducibility hygiene

- Pin the vLLM, framework and benchmark versions in the image; record the image digest, git commit, model weight hashes and decoding config in every result file.
- Keep a small fixed "smoke grid" (one model, three tasks per benchmark) that runs on every pull request on a CPU runner with the mock backend, and weekly on one GPU.
- Optional generalization check with one frontier API model on Fir or Nibi (internet allowed), limited to the final reported cells; report it separately because it is not replayable bit-for-bit.

## Work plan

Eight phases over about 16 weeks; no phase starts until the previous one's exit criteria pass in CI. Open question: the special issue's submission deadline, which sets the real end date.

1. **Phase 0, setup (week 1).** Repo skeleton, `AGENTS.md`, CI (ruff, mypy, pytest), Apptainer `.def`, model shortlist with hashes, benchmark availability and license check.
   - Exit: CI green on an empty package; the image builds on a login node; vLLM serves one model in an interactive GPU job.
2. **Phase 1, model and compiler, M1 and M2 (weeks 2 to 3).** DSL, Mermaid importer, static checks, canonical IR, LangGraph export.
   - Exit: all M1 and M2 acceptance tests pass; the JSS planner-coder-reviewer workflow compiles and lints clean.
3. **Phase 2, controller and audit, M3 and M6 (weeks 3 to 5).** Keys, tokens, taint, acceptance, release gate, replay log, P1 to P6 checkers; pilot run on one topology with one model.
   - Exit: state-machine and fault-injection tests pass; replay reproduces 100% of pilot decisions; GPU-seconds per task measured.
4. **Phase 3, benchmark adapters (weeks 5 to 7).** TAMAS, MAS hijacking, Prompt Infection, AiTM, AgentDojo; each workflow re-specified as a model.
   - Exit: each adapter reproduces the benchmark's published B0 numbers within a stated tolerance on one model, or the gap is documented.
5. **Phase 4, baselines (weeks 7 to 9).** B1 to B4 implemented against the same IR and adapters.
   - Exit: each baseline runs on the smoke grid; B3 on AgentDojo is compared with the published CaMeL result.
6. **Phase 5, attack generator, M5 (weeks 8 to 10).** Coverage criteria, payload library, mutators, adaptive attacker.
   - Exit: 100% of feasible obligations covered on the topology zoo; suites replay deterministically.
7. **Phase 6, full experiments (weeks 10 to 13).** Screening grid with 5 seeds, power check, final grid with 10 seeds, adaptive-attacker runs.
   - Exit: every reported cell complete; auditor passes on all logs; no unexplained failed shards.
8. **Phase 7, analysis and replication package (weeks 13 to 16).** Statistics, residual-risk coding, LaTeX tables and figures, Zenodo archive, README walkthrough.
   - Exit: one command regenerates every table and figure from archived results; a second person reproduces the smoke grid from the README alone.

## Operating rules for the code generator

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

## Risks, threats to validity and references

The biggest risk is not engineering but positioning: reviewers will compare INERT with CaMeL and ControlValve, and will test whether "prevents" is overclaimed.

### Project risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| ControlValve or a similar MAS defense publishes code first | Novelty weakened | Lead with designer-authored, versioned models, staleness and reconfiguration, taint propagation and model-based test generation; include B4 |
| Benchmark code or data not released (TAMAS, MAS-hijacking templates, ACIArena) | Missing primary evaluation | Check in Phase 0; contact authors; fall back to re-implementing from paper appendices and say so |
| Re-specifying workflows as models changes their behavior | Unfair comparison | Run B0 on the LangGraph export of the same IR; report adapter fidelity against published B0 numbers |
| Open-weight models too weak for benign utility | Utility results uninformative | Include a 70B-class model; report utility-under-attack relative to each model's benign utility |
| GPU budget overrun | Incomplete grid | Pilot measurement, screening with 5 seeds, throttled arrays, Resource Allocation Competition request |
| Overlap with the JSS manuscript | Desk rejection or reviewer concern | One-page recap and citation; all new contributions (taint, generator, study) stated explicitly |

### Threats to validity (draft for the paper)

- **Construct:** attack success depends on each benchmark's oracle; mitigated by also counting any P1 to P6 violation and by manual coding of a sample.
- **Internal:** baseline reimplementations may be weaker than the originals; mitigated by publishing them, matching published numbers where possible and using authors' code when released.
- **External:** results on open-weight models and the chosen frameworks may not transfer to frontier APIs or other orchestrators; mitigated by the optional API check and several model families.
- **Conclusion:** LLM nondeterminism; mitigated by 10 seeds, mixed-effects models, bootstrap CIs and replay logs.

### References (verified)

- Lee, Tiwari and Miranda. [Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems](https://arxiv.org/abs/2410.07283). arXiv 2410.07283.
- Triedman, Jha and Shmatikov. [Multi-Agent Systems Execute Arbitrary Malicious Code](https://arxiv.org/abs/2503.12188). arXiv 2503.12188.
- Jha, Triedman, Wagle and Shmatikov. [Breaking and Fixing Defenses Against Control-Flow Hijacking in Multi-Agent Systems](https://arxiv.org/abs/2510.17276) (ControlValve). arXiv 2510.17276.
- He et al. [Red-Teaming LLM Multi-Agent Systems via Communication Attacks](https://aclanthology.org/2025.findings-acl.349/) (Agent-in-the-Middle). Findings of ACL 2025.
- [TAMAS: Benchmarking Adversarial Risks in Multi-Agent LLM Systems](https://arxiv.org/abs/2511.05269). arXiv 2511.05269; code at github.com/microsoft/TAMAS.
- [ACIArena: Toward Unified Evaluation for Agent Cascading Injection](https://arxiv.org/abs/2604.07775). arXiv 2604.07775.
- Debenedetti et al. [AgentDojo](https://arxiv.org/abs/2406.13352). NeurIPS 2024 Datasets and Benchmarks.
- Debenedetti et al. [Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) (CaMeL). arXiv 2503.18813.
- Beurer-Kellner et al. [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837). arXiv 2506.08837.
- Alliance documentation: [Apptainer](https://docs.alliancecan.ca/wiki/Apptainer) and [Infrastructure renewal](https://docs.alliancecan.ca/wiki/Infrastructure_renewal).
