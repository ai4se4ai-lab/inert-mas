# Replication package

**Injected but Inert: Model-Based Security Testing of Prompt-Injection Propagation in LLM
Multi-Agent Systems** (manuscript submitted to *Empirical Software Engineering*)

This package lets reviewers check that the results reported for INERT and the taxonomy of Section 3
follow from the archived data and the published code. It adds verification scripts, checksums and
documentation to the repository; it does not duplicate the code or the data.

| Document | Content |
| --- | --- |
| this README | what is in the package, how to verify, provenance, known differences |
| [CLAIMS.md](CLAIMS.md) | every quantitative claim of the paper with its source and the command that checks it |
| [MAPPING.md](MAPPING.md) | approach, formulas, Algorithms 1 to 3, threat model and taxonomy mapped to the code and tests |
| [TAXONOMY_PIPELINE.md](TAXONOMY_PIPELINE.md) | the study-collection and classification pipeline behind Section 3, step by step |

---

## 1. Quick start for reviewers

```bash
git clone https://github.com/ai4se4ai/inert-mas.git && cd inert-mas      # or unpack the archive (Section 4)
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,analysis]"
bash docs/paper/EMSE/replication-package/scripts/verify_all.sh
```

`verify_all.sh` runs four checks and prints a one-line summary. None of them needs a GPU, a network
connection or an API key, and none modifies the repository.

| Check | Script | What it shows | Time |
| --- | --- | --- | --- |
| A. tests | `pytest` | 133 unit, property-based (Hypothesis) and integration tests of the linter, compiler, controller, audit and attack generator, with the deterministic mock LLM | ~1 min |
| B. claims | [scripts/check_claims.py](scripts/check_claims.py) | provenance of every record; an **independent** recount, with the Python standard library only, of the run counts, Table 6, RQ3, RQ5 and TAMAS headline numbers; the running example of Sections 2.7 and 5 | ~5 s |
| C. results | [scripts/verify_results.sh](scripts/verify_results.sh) | regenerates all tables, `numbers.json`, residual-risk files and the six statistical figures from the 182 archived shards and compares them with the committed assets and the manuscript | ~2 min |
| D. taxonomy | [scripts/verify_taxonomy.sh](scripts/verify_taxonomy.sh) | replays the taxonomy pipeline from the cached OpenAlex and Scopus responses and compares every audit file, corpus file and manuscript block | ~10 s |

Expected result on the published commit:

```text
Summary: A tests ok | B claims ok | C results ok | D taxonomy ok
```

Check C additionally prints the notes listed in Section 6 (known differences).

Requirements: Python ≥ 3.11 (tested with 3.12.3 on Linux aarch64), the packages in
[environment/requirements-lock.txt](environment/requirements-lock.txt) (exact versions used for the
paper), `sha256sum`, and `pdftoppm` (poppler-utils) for the pixel comparison of figures. LaTeX
(TeX Live 2026, `pdflatex`, `bibtex`) is needed only to rebuild the PDF.

## 2. What the package contains

```text
docs/paper/EMSE/replication-package/
  README.md                 this file
  CLAIMS.md                 claim -> source -> check
  MAPPING.md                paper -> code (approach, algorithms, taxonomy)
  TAXONOMY_PIPELINE.md      taxonomy pipeline
  scripts/
    verify_all.sh           runs A-D
    check_claims.py         independent recount and running-example checks
    verify_results.sh       regenerate result assets into a temp dir and compare
    compare_numbers.py      numeric comparison of numbers.json
    verify_taxonomy.sh      offline replay of the taxonomy pipeline, snapshot and restore
    build_archive.sh        builds the self-contained deposit archive (Section 4)
  data/
    SHA256SUMS-results.txt          182 result shards in results/final/
    SHA256SUMS-code-snapshots.txt   4 archived code snapshots in hpc/fetched/code/
    SHA256SUMS-taxonomy-inputs.txt  611 taxonomy inputs: raw exports, bibliographies, coding spec, API cache
  environment/
    requirements-lock.txt   exact Python package versions
```

Everything else the package refers to lives in the repository:

| Artifact | Location | Role |
| --- | --- | --- |
| INERT toolchain (trusted computing base, agents, attacks, harness) | [src/inert/](../../../../src/inert) | Sections 4 and 5 |
| baselines B0 to B4 | [baselines/](../../../../baselines), [docs/baselines.md](../../../baselines.md) | Table 5 |
| TAMAS adapter and pinned upstream data | [adapters/tamas/](../../../../adapters/tamas), [docs/benchmarks.md](../../../benchmarks.md) | Section 7.6 |
| 51 zoo models and the running example | [models/zoo/](../../../../models/zoo), [models/examples/](../../../../models/examples) | Sections 2.7, 6.2 |
| experiment manifests (case grids) | [hpc/manifests/final_*.yaml](../../../../hpc/manifests) | Section 6.3 |
| HPC job template and fleet scripts | [hpc/](../../../../hpc) | Section 6.3 |
| analysis scripts and pre-registration | [analysis/](../../../../analysis), [analysis/preregistration.md](../../../../analysis/preregistration.md) | Sections 6.4, 7 |
| generated tables, figures, numbers | [paper/](../../../../paper) | Section 7 |
| manuscript source and PDF | [Springer-Nature-LaTeX-template/](../Springer-Nature-LaTeX-template) | |
| taxonomy corpus, audit trail, API cache | [relevant-work/](../relevant-work) | Section 3 |
| design decisions, deviations, incidents | [docs/open-questions.md](../../../open-questions.md) | Section 9 |
| result records | `results/final/<site>/<tag>/<model>/shard_*.jsonl` | **git-ignored**: shipped in the archive (Section 4) |
| code snapshots that produced the records | `hpc/fetched/code/code-<hash>.tar.gz` | **git-ignored**: shipped in the archive |

## 3. Levels of replication

| Level | What a reviewer does | Needs | Covers |
| --- | --- | --- | --- |
| 0 Inspect | read CLAIMS.md and MAPPING.md, browse the audit CSVs | nothing | traceability of every claim |
| 1 Reproduce the analysis | `verify_all.sh` | CPU, ~5 min | every table, figure and number of Sections 3 and 7 from the archived records and cached API responses |
| 2 Re-execute the pipeline offline | `inert run-manifest --manifest hpc/manifests/smoke.yaml --backend mock --out /tmp/smoke.jsonl` then `python analysis/quick.py /tmp/smoke.jsonl` | CPU, minutes | the harness, all conditions and attack suites end to end, with a deterministic mock LLM (never used for results) |
| 3 Re-run a slice with a real model | `inert run-manifest --manifest hpc/manifests/final_zoo.yaml --backend ollama --model qwen2.5:7b --shard 0/12 --limit 500 --out /tmp/slice.jsonl`, compare with the corresponding records | one GPU, Ollama with the model digests of Section 5 | that the code produces records of the same kind; LLM outputs are not bit-reproducible across hardware and Ollama versions, so compare rates, not individual runs |
| 4 Full re-run | the seven final manifests for the six models (repository README, Section 9.2) | GPU cluster; at the observed throughput (repository README §9.2) roughly 90 GPU-hours for the ~89,000 cases of the four 8-24B models and 55-110 job-hours for the ~18,000 cases of the two 70B-class models | the whole study |
| 4' Taxonomy against live APIs | `ELSEVIER_API_KEY=... bash analysis/taxonomy_pipeline.sh --fetch` after moving the cache aside | network, Scopus key | how the literature changed since 2026-11-24 (counts will differ; see TAXONOMY_PIPELINE.md §6) |

## 4. The deposit archive

The result records (~280 MB uncompressed) and the code snapshots are git-ignored in the repository
by design (`results/` is append-only and archived read-only). The archive for deposit is built with

```bash
bash docs/paper/EMSE/replication-package/scripts/build_archive.sh
# -> docs/paper/EMSE/replication-package/dist/inert-mas-replication-<commit>.tar.xz  (+ .sha256)
```

It contains the committed repository at HEAD (`git archive`), `results/final/` and
`hpc/fetched/code/`, and refuses to run on a dirty working tree or if any checksum fails. It leaves
out `hpc/fetched/jobs.jsonl` and other fetched logs, which carry cluster account names. After
unpacking, all commands of this README work unchanged.

## 5. Provenance

Every result record carries a `meta` object, for example:

```json
{"git_commit": "4b4afc46...-dirty+code.f7992c899366", "backend": "ollama", "llm": "qwen2.5:7b",
 "model_digest": "845dbda0ea48...", "decoding": {"temperature": 0.0, "top_p": 1.0, "num_ctx": 8192,
 "num_predict": 768}, "manifest": "final-zoo", "manifest_sha256": "a70995e67bd0...", "shard": "0/12",
 "benchmark_versions": {"tamas": "545c112a"}, "job": "27446322", "site": "...", "image": "ollama-"}
```

| Field | How to check it |
| --- | --- |
| `git_commit` = commit + `code.<hash>` | the commit was dirty during deployment, so the `code.<hash>` suffix is authoritative: it names the content hash of the code tree deployed to the cluster, archived as `hpc/fetched/code/code-<hash>.tar.gz`. Four snapshots produced the records (79,249 / 19,747 / 6,336 / 1,050 records after de-duplication). `check_claims.py` verifies a snapshot exists for each. |
| `model_digest` | one Ollama digest per model, constant across all records (checked by `check_claims.py`): gemma2:9b `ff02c370…`, llama3.1:8b `46e0c10c…`, llama3.3:70b `a6eb4748…`, mistral-small:24b `8039dd90…`, qwen2.5:72b `424bad2c…`, qwen2.5:7b `845dbda0…` |
| `manifest_sha256` | equals the SHA-256 of the committed `hpc/manifests/final_*.yaml` for every record (checked) |
| `decoding`, `seed` | as stated in Section 6.3; the seed sub-study uses temperature 0.7 and top-p 0.9 |
| `benchmark_versions.tamas` | pinned upstream commit `545c112a`, see [adapters/tamas/upstream/COMMIT](../../../../adapters/tamas/upstream/COMMIT) |

The 147,400 raw lines in the shards contain rows repeated by resumed shards; analysis
de-duplicates them by (case, model), which gives the 106,382 runs of the paper with no failed run.
Development runs are not in `results/final/`. All deviations and incidents of the study (cluster
changes, failed jobs, the TAMAS DPI-split fix and re-run) are recorded in
[docs/open-questions.md](../../../open-questions.md).

## 6. Known differences

These are the only differences the checks report on the published commit. None changes a number
printed in the manuscript.

1. **One data-driven sentence of RQ2 is missing from the committed manuscript.** `make_assets.py`
   now writes a `first_reject_I2` entry that the committed `paper/numbers.json` predates. Filling
   the manuscript from regenerated assets adds to Section 7.2 the sentence "The first rejecting
   check (Figure 8b) confirms the mapping. Under I2, 89% of the A1 tests cause no rejection at
   all: …". The figure it refers to (Figure 8b) already shows these data and is pixel-identical.
   `verify_results.sh` prints this as a note.
2. **Mixed-model coefficients vary in the 7th-8th significant digit.** The variational Bayes fit of
   `statsmodels` is iterative and not bit-reproducible across runs; the standard deviations differ
   by about 1e-8. The manuscript prints two decimals, which are stable.
3. **Figure PDFs differ in bytes, not in content.** Matplotlib embeds a creation date. The script
   therefore compares rendered pixels (`pdftoppm -r 60`), which are identical for all six figures.
4. **The residual-risk coding sheet has empty rater columns.** `paper/residual_coding.csv` is a
   sampling frame for a two-rater coding; the manuscript reports the automatic categories of
   `residual.json` only and does not report inter-rater agreement.

## 7. Approach and taxonomy at a glance

- **Approach.** A designer writes a typed MAS model; the linter (L1-L6) and compiler produce a
  content-hashed plan; a deterministic controller without any LLM executes the plan as a reference
  monitor with three mediation points (context selection, authenticated acceptance, fail-closed
  tools) over a guarded coordination kernel; a hash-chained log lets an auditor recompute every
  decision and check properties P1-P6; an attack generator derives test obligations from the same
  plan under six coverage criteria. [MAPPING.md](MAPPING.md) links each formula and algorithm line
  to its code and test, and lists the few places where the code presents the pseudocode
  differently (Section 10 there).
- **Taxonomy.** 543 studies from a database search (127), snowballing (300) and a second database
  search (116), classified into 18 leaves; seven injection channels refined into 14 attack forms,
  each mapped to a control class, an INERT mechanism, a property and a coverage criterion;
  requirements R1-R8 and gaps G1-G5. [TAXONOMY_PIPELINE.md](TAXONOMY_PIPELINE.md) documents the
  pipeline and the manual decisions; [MAPPING.md §9](MAPPING.md#9-taxonomy-to-implementation-section-3)
  maps the taxonomy to the implementation.

## 8. Licenses, safety and ethics

- Code: MIT ([LICENSE](../../../../LICENSE)). Third-party components and data, including TAMAS
  (code MIT, data CDLA-Permissive-2.0) and the open-weight models (per model license), are listed
  in [LICENSES-THIRD-PARTY.md](../../../../LICENSES-THIRD-PARTY.md).
- Attack payloads target only the reserved domain `evil.example`; side-effect tools in the
  sandbox only record calls (`run_code` never executes code). The payload library carries a
  dual-use notice ([src/inert/attacks/__init__.py](../../../../src/inert/attacks/__init__.py)).
- The taxonomy API cache contains no credentials (keys are excluded from cache keys and bodies).
- Records contain no personal data: prompts and tasks are synthetic or from TAMAS.

## 9. Citing

See [CITATION.cff](../../../../CITATION.cff).
