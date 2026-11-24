# Changelog

## Unreleased (2026-11-23)
- M7 manuscript documentation: update author details and declarations, and rename the bibliography to `references.bib`; acceptance checks: bibliography target and citation keys resolve, Git whitespace validation.
- M3 documentation: remove the controller-kernel attribution paragraph from the README introduction; acceptance check: Git whitespace validation.
- M1-M7 repository publication: include implementation, tests, documentation, paper assets and HPC configuration; acceptance checks: Ruff, strict mypy, the offline pytest suite and the mock smoke manifest. Exclude generated Python package metadata from version control.
- M1-M7 README: expand the architecture, security mechanisms, results, usage and reproduction guides; acceptance checks: offline pytest suite and Git whitespace validation.

## 0.1.0 (2026-11-22)
- M1 metamodel, YAML DSL, Mermaid importer, lint L1-L6 (tests/test_model.py: round trip, one pass/fail fixture per rule).
- M2 compiler with canonical JSON and SHA-256 hashing, agent-graph and LangGraph exports (tests/test_compiler.py: byte-identical IR, Hypothesis hash sensitivity).
- M3 controller on the vendored vgc kernel: dependency keys with labels, HMAC capability tokens, taint selection and acceptance, reason codes (tests/test_runtime.py: one test per reason code, Hypothesis interleavings, fault injection).
- M4 LLM backends (Ollama, OpenAI-compatible, deterministic mock) and agent wrapper.
- M5 coverage criteria (EDGE, SLOT, SEL, TAINT, RECONF, COLL), payload library, mutators, adaptive attacker (tests/test_attacks.py: 100% feasible obligations covered, tests execute on INERT and B0).
- M6 hash-chained log, LLM-free replay, P1-P6 checkers (tests/test_audit.py: tamper detection, ablation surfaces violations).
- M7 harness, manifests, CLI; baselines B0-B4; TAMAS adapter; HPC fleet scripts.

## 0.2.0 (2026-11-24)
- Final study complete: 106,382 runs on six open-weight models (zoo, TAMAS, DPI-split re-run, I2S, seed and adaptive studies), 0 failed cases; archived read-only in `results/final/`.
- M3: capability key from a CSPRNG, only its commitment logged; `member_of` validator (task scope, I2S).
- TAMAS adapter: DPI provenance split at the injection marker (49/50 instances); I2S variant.
- HPC: GPU-residency retry, `--mem`, `--gres`, `--indices`; code snapshots per deployment.
- Analysis: one-command regeneration (`analysis/run_all.sh`), de-duplication of resumed shards, data-driven results prose, residual-risk categorization and coding sheet.
- M7 publication checks: 133 offline tests pass; Ruff, strict mypy, changed Python script parsing and analysis shell syntax checks pass.
