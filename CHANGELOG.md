# Changelog

## Unreleased (2026-11-23)
- M1-M7 repository publication: include implementation, tests, documentation, paper assets and HPC configuration; acceptance checks: Ruff, strict mypy, the offline pytest suite and the mock smoke manifest. Exclude generated Python package metadata from version control.

## 0.1.0 (2026-11-22)
- M1 metamodel, YAML DSL, Mermaid importer, lint L1-L6 (tests/test_model.py: round trip, one pass/fail fixture per rule).
- M2 compiler with canonical JSON and SHA-256 hashing, agent-graph and LangGraph exports (tests/test_compiler.py: byte-identical IR, Hypothesis hash sensitivity).
- M3 controller on the vendored vgc kernel: dependency keys with labels, HMAC capability tokens, taint selection and acceptance, reason codes (tests/test_runtime.py: one test per reason code, Hypothesis interleavings, fault injection).
- M4 LLM backends (Ollama, OpenAI-compatible, deterministic mock) and agent wrapper.
- M5 coverage criteria (EDGE, SLOT, SEL, TAINT, RECONF, COLL), payload library, mutators, adaptive attacker (tests/test_attacks.py: 100% feasible obligations covered, tests execute on INERT and B0).
- M6 hash-chained log, LLM-free replay, P1-P6 checkers (tests/test_audit.py: tamper detection, ablation surfaces violations).
- M7 harness, manifests, CLI; baselines B0-B4; TAMAS adapter; HPC fleet scripts.
