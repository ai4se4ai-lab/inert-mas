# Taxonomy pipeline (Section 3 of the manuscript)

This document describes how the corpus of 543 studies, the corpus tree, the seven injection
channels and the channel tree of Section 3 were produced, which script performs each step, which
judgments were made by hand, and how a reviewer can check every count and every decision.

Short version:

```bash
bash docs/paper/EMSE/replication-package/scripts/verify_taxonomy.sh   # offline, ~10 s, leaves the repo unchanged
```

It verifies the inputs against `data/SHA256SUMS-taxonomy-inputs.txt`, replays the whole pipeline
from the cached API responses, compares every regenerated file byte by byte with the published one,
prints the counts of Section 3.1 and restores the published files.

---

## 1. Overview

```text
 Raw search exports (Q1, Q2)                    OpenAlex + Scopus API responses (cached, 604 files)
 relevant-work/*.md                             relevant-work/snowball/cache/*.json
        │                                                  │
        ▼                                                  ▼
 ┌──────────────────────────┐    127 seeds    ┌───────────────────────────────────────────┐
 │ taxonomy_audit.py        │ ───────────────►│ snowball.py screen                        │
 │ steps 1-3: records,      │                 │ step 12 seed resolution                   │
 │ deduplication, screening │                 │ step 13 backward/forward candidates,      │
 │ steps 4-11: coding spec  │                 │         Scopus reference-list + search    │
 └──────────────────────────┘                 │ step 14 criteria, link threshold, manual  │
        │                                     │ step 15 classification into 18 leaves     │
        │                                     └───────────────────────────────────────────┘
        │                                                  │   manual decisions:
        │                                                  │   snowball/manual_screening.csv
        ▼                                                  ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ corpus_tree.py: corpus tree figure, corpus_classification.csv, corpus_collection.json, │
 │                 count macros (\NCorpus, \NSnow, ...) in main.tex                        │
 │ channel_tree.py: channel tree figure (14 attack forms) in main.tex                      │
 │ taxonomy_audit.py (final run): recomputes counts, checks every citation key and that   │
 │                 Tables 2 and 3 equal their CSVs; exits non-zero on any inconsistency    │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

Driver: [analysis/taxonomy_pipeline.sh](../../../../analysis/taxonomy_pipeline.sh). It is also
called by [analysis/run_all.sh](../../../../analysis/run_all.sh).

| Mode | Command | Needs |
| --- | --- | --- |
| offline replay (default) | `bash analysis/taxonomy_pipeline.sh` | Python 3.11+, the repository; no network |
| refetch anything not cached | `ELSEVIER_API_KEY=... bash analysis/taxonomy_pipeline.sh --fetch` | network; a Scopus key (optional `OPENALEX_API_KEY`) |

API keys are read from the environment only. The cache key of a response is a hash of the URL and
body **without** the key, so the cache contains no credentials and can be published.

## 2. Inputs

| Input | Path (under `docs/paper/EMSE/`) | Nature |
| --- | --- | --- |
| Q1 export, "prompt injection in multi-agent systems" | `relevant-work/prompt-injection-in-multi-agent-systems.md` | raw search result, 72 records |
| Q2 export, "taxonomy of injection channels in agent collaboration" | `relevant-work/taxonomy-of-injection-channels-in-agent-collaboration.md` | raw search result, 71 records |
| bibliography of the search studies | `relevant-work/injection_channel_taxonomy.bib`, `relevant-work/injection_channel_taxonomy.tex` | citation keys |
| manuscript bibliography | `Springer-Nature-LaTeX-template/references.bib` | every key cited by the trees must resolve |
| API cache | `relevant-work/snowball/cache/*.json` | every OpenAlex and Scopus response, with retrieval date |
| manual screening and classification of snowballing and Scopus studies | `relevant-work/snowball/manual_screening.csv` | coding spec (author, LLM-assisted, reviewed 2026-11-24) |
| coding spec of the first search (screening notes, codebook, classification, channel tree, evidence, requirements, gap ratings) | top of [analysis/taxonomy_audit.py](../../../../analysis/taxonomy_audit.py) and the `tree` in [analysis/corpus_tree.py](../../../../analysis/corpus_tree.py) | author coding, stated in code |

All of these are covered by `data/SHA256SUMS-taxonomy-inputs.txt` (611 files).

Parameters (constants at the top of [analysis/snowball.py](../../../../analysis/snowball.py)):

| Parameter | Value | Where |
| --- | --- | --- |
| search date | 2026-11-24 | `SEARCH_DATE` |
| publication window | 2022 to 2026 | `WINDOW` (criterion E2) |
| link threshold | at least 5 seeds | `LINK_THRESHOLD`; sensitivity for k = 1 to 6 reported |
| Scopus queries (Boolean form of Q1, Q2) | title, abstract, keywords, 2022-2026 | `SCOPUS_QUERIES` |
| screening rules | regular expressions for injection, multi-agent, attack/defense, agentic, LLM, off-topic | `PI`, `MULTI`, `ATTACK`, `AGENTIC`, `AGENT`, `SEC`, `LLM`, `OFF_TOPIC`; function `screen` |

## 3. Steps, outputs and counts

All outputs are in `docs/paper/EMSE/relevant-work/audit/` unless stated otherwise. The audit
[README](../relevant-work/audit/README.md) describes the columns of every file.

### Route 1: first database search (seeds)

| Step | What happens | Computed or coded | Output | Count in the paper |
| --- | --- | --- | --- | --- |
| 1 Search | parse the two exports: query, rank, title, year, venue, library, URL | computed | `01_search_records.csv` | Q1 72 + Q2 71 = 143 records |
| 2 Deduplication | normalized title (case, punctuation, whitespace) | computed | `02_deduplication.csv` | 6 duplicates, 137 unique |
| 3 Screening | inclusion I1 (I1a injection in agentic systems, I1b MAS security), exclusion E1-E5; a transparent title rule is run beside the decisions | decisions coded, rule computed | `03_screening.csv` | 127 included, 10 excluded (E1); the rule agrees on 132 of 137, each of the 5 differences has a written note |
| 4 Codebook | 3 categories, 6 subcategories, 18 leaves, each with a definition and the INERT element it informs | coded | `04_leaf_codebook.csv` | 18 leaves |
| 5 Classification | one leaf per search study (primary research focus) | coded | `05_classification.csv` | 127 classified |

### Route 2: backward and forward snowballing

| Step | What happens | Output | Count |
| --- | --- | --- | --- |
| 12 Seed resolution | match each of the 127 seeds in OpenAlex by DOI (with `DOI_OVERRIDES` for landing-page URLs) or title similarity | `12_seed_resolution.csv` | 122 resolved, 5 preprints not indexed |
| 13 Candidates | backward: works each seed cites; forward: works citing each seed (OpenAlex `cites:` filter) and Scopus reference-list search `REF("title")` for every seed (also reaches the 5 unresolved seeds); merged by DOI and title; abstracts from OpenAlex | `13_snowball_candidates.csv` | 9,254 candidates; 2,092 Scopus citing records |
| 14a Criteria | the screening criteria applied automatically to title and abstract | `14_snowball_screening.csv` (`title_abstract_rule`) | 1,617 met the criteria (7,637 excluded by E1-E3) |
| 14b Link threshold | keep candidates linked to at least 5 seeds | same file (`decision`, `criterion` E4) | 317 |
| 14c Manual check | duplicates, variants of seed studies, off-topic records | `snowball/manual_screening.csv` → `14_snowball_screening.csv` | 17 removed, **300 included** |

### Route 3: second database search (Scopus)

| Step | What happens | Output | Count |
| --- | --- | --- | --- |
| 13 Scopus search | Q1 and Q2 in Scopus Boolean syntax | `13_snowball_candidates.csv` (`scopus_search_hit`) | 294 + 102 records, 365 unique |
| 14 Criteria | same automatic criteria | `14_snowball_screening.csv` | 260 met, 105 excluded; 58 already found by routes 1 and 2 |
| 14 Manual check | the 202 new records screened by hand | `snowball/manual_screening.csv` | 86 excluded, **116 included** |

### Classification and trees

| Step | What happens | Output | Count |
| --- | --- | --- | --- |
| 15 Classification of routes 2 and 3 | each included study assigned to one of the existing 18 leaves with the codebook (no new leaf needed); a keyword classifier derived from the codebook is run beside it for transparency | `15_snowball_classification.csv` | 416 studies (300 snowballing, 116 Scopus); keyword classifier agrees on 167 (40%, reported in the paper) |
| Corpus tree | category > subcategory > leaf with n per leaf, representative citations and the INERT element informed | Figure 3 (`%<<corpus_tree>>` block of `main.tex`), `relevant-work/corpus_classification.csv`, `relevant-work/corpus_collection.json` | **543 studies** = 127 + 300 + 116 |
| Count macros | every number of Section 3.1 and Figure 2 | `%<<corpus_macros>>` block of `main.tex` | `\NCorpus`=543, `\NSnow`=300, `\NScopus`=116, ... |
| 6 Channel tree | 14 attack forms with channel, interface class, control class, mechanism, property, criterion and supporting studies; 2 forms (replay, inconsistent release) derived from the coordination model, not from a corpus study | `06_channel_tree.csv`, Figure 4 (`%<<channel_tree>>` block, written by `channel_tree.py`) | 14 forms |
| 7 Evidence | rows of Table 2 | `07_evidence_table.csv` | 14 study rows (the 10 rows of Table 2, three of which name two studies); checked equal to the manuscript table |
| 8 Requirements | R1-R8 with channels, attack forms, property, mechanism | `08_requirements.csv` | 8 |
| 9 Gap matrix | Table 3 with a rationale per rating | `09_gap_matrix.csv` | checked equal to the manuscript table |
| 10 Gaps | G1-G5 with families and requirements | `10_gaps.csv` | 5 |
| 11 Supplement | 22 works found by targeted searches after the corpus was fixed, used in related work only | `11_supplementary_studies.csv` | 22, of which 10 also found by snowballing |
| Summary | recomputed counts, unresolved citation keys, table mismatches | `summary.json`, `snowball_summary.json` | `unknown_keys`, `evidence_table_mismatch`, `gap_table_mismatch` all empty |

Link-threshold sensitivity (studies meeting the criteria and linked to at least k seeds, before the
manual check), from `snowball_summary.json`:

| k | 1 | 2 | 3 | 4 | 5 (used) | 6 |
| --- | --- | --- | --- | --- | --- | --- |
| studies | 1,617 | 1,026 | 705 | 503 | 317 | 219 |

## 4. From the taxonomy to INERT

The channel tree is the design document of INERT: each attack form names the mechanism, property
and coverage criterion that address it. [MAPPING.md, Section 9](MAPPING.md#9-taxonomy-to-implementation-section-3)
links each channel, attack form, requirement, gap and corpus leaf to the code and tests.

## 5. What was decided by hand, and how to check it

| Judgment | Where recorded | How to check |
| --- | --- | --- |
| screening of the 137 search records | `03_screening.csv` (`decision`, `criterion`, `note`) | compare with the title rule in the same file; read the 5 notes |
| leaf of each search study | `05_classification.csv` | read the leaf definitions in `04_leaf_codebook.csv` |
| manual check of the snowballing studies above the threshold and of the new Scopus records | `snowball/manual_screening.csv` (518 rows: `decision`, `reason_if_excluded`, `leaf`) | each row has an OpenAlex id; the criterion codes are those of Section 3.1 |
| leaf of each of the 416 snowballing and Scopus studies | `15_snowball_classification.csv` (`leaf`, `assigned_by`) next to `keyword_leaf` | inspect rows where `keyword_agrees` is `no` |
| channels, attack forms, control classes, mechanism mapping | `06_channel_tree.csv` with `supporting_studies` | look up the cited keys in `references.bib` |
| gap ratings | `09_gap_matrix.csv` (`rationale` per cell) | read the cited papers |

Manual decisions for routes 2 and 3 were made by the author with the assistance of an LLM and
reviewed by the author; the manuscript reports this in Section 3.1 and in the threats to validity.
They are recorded as data, so a reviewer can replace any decision in `manual_screening.csv`, rerun
`bash analysis/taxonomy_pipeline.sh` and see the effect on every count and on the trees.

## 6. Re-running against the live APIs

`--fetch` only fetches what is missing from the cache. To observe how the literature has changed
since the search date, move the cache aside and run with `--fetch`; counts will differ because
OpenAlex and Scopus keep indexing new works and citations. The published counts are tied to the
cached responses (each stores its retrieval date), not to the live services.
