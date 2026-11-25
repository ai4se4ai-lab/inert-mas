"""Audit trail of the taxonomy (Section 3): one CSV per step, regenerated from the raw search exports and the
coding spec below, so that reviewers can check every step from the search to the requirements and gaps.

  python analysis/taxonomy_audit.py [relevant-work-dir]

Writes <relevant-work-dir>/audit/:
  01_search_records.csv      every record returned by Q1 and Q2 (query, rank, title, year, venue, library, url)
  02_deduplication.csv       every record with its normalized title and duplicate status
  03_screening.csv           every unique record with the screening decision, the criterion and the title-rule check
  04_leaf_codebook.csv       definition of every category, subcategory and leaf and the INERT element it informs
  05_classification.csv      every included study with its leaf and where the paper cites it
  06_channel_tree.csv        every attack form of Figure 2 with channel, control class, mechanism, property,
                             criterion and the studies that report it
  07_evidence_table.csv      the rows of Table 2
  08_requirements.csv        requirements R1-R8 with channels, attack forms, properties and mechanisms
  09_gap_matrix.csv          Table 3 with a rationale per rating
  10_gaps.csv                gaps G1-G5 with the families and requirements they derive from
  11_supplementary_studies.csv  22 works found after the corpus was fixed, discussed in related work only
  summary.json               counts that the manuscript reports, recomputed

Steps 1-3 are computed from the exports. Steps 4-10 are author coding, stated explicitly here so it can be
checked against the papers.
"""

from __future__ import annotations

import collections
import csv
import difflib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus_tree import SEARCHES, SOURCES, _norm, tree  # noqa: E402

# ------------------------------------------------------------------------------------------------ step 3 rule
AGENT_RE = re.compile(r"agent|multi-agent|agentic|swarm|orchestrat|\bmcp\b|tool", re.I)
PI_RE = re.compile(r"prompt injection|injection", re.I)
FACETS = {
    "prompt injection": r"injection|prompt hacking",
    "agents or MAS": r"agent|multi-agent|agentic|swarm|\bMAS\b|orchestrat",
    "attack": r"attack|jailbreak|exploit|poison|hijack|leak|threat|siege|malicious|rogue",
    "defense": r"defen|guard|mitigat|protect|shield|safeguard|secur|isolation|access control|integrity",
    "evaluation": r"bench|evaluat|competition|arena|measur|red-team|testing",
    "survey or taxonomy": r"survey|taxonom|\bsok\b|review|landscape|challenges|perspectives",
}
INCLUDE_NOTES = {  # included although the title rule does not fire; reason from the paper's topic
    "Jamshidi2026SecurityEOAG": "OpenClaw is an autonomous agent framework; the study analyses its attack surface",
    "Rababah2024SoKPHBH": "prompt hacking covers prompt injection; SoK used for injection definitions",
    "Wan2024CYBERSECEVAL3ABJ": "benchmark includes prompt-injection test suites used for payload design",
    "Yan2026PropGuardSLAE": "LLM-MAS defense against propagation (MAS abbreviated in title)",
    "Wang2025MASShieldADAF": "LLM-MAS defense framework (MAS abbreviated in title)",
}
EXCLUSION = "E1: LLM security in general without an agent or multi-agent focus (survey of model-level attacks)"

# ------------------------------------------------------------------------------------------------ step 4 codebook
LEAF_DEF = {
    "Content and interpretation": "How injected content is crafted or interpreted by a model (payload design, "
                                  "modality, optimization)",
    "Peer influence and composition": "How one agent's output influences other agents (replication, composition, "
                                      "tampering of inter-agent messages)",
    "State and discovery": "Injection through persistent state or discovery/selection metadata (memory, "
                           "registration, tool selection)",
    "Execution and disclosure": "Attacks that end in code execution, tool misuse or data disclosure",
    "Topology and propagation": "How team topology and size shape propagation and error cascades",
    "Roles and trust boundaries": "Threat models and trade-offs defined by roles, authority and trust boundaries",
    "Shared and deployed workflows": "Security of deployed or shared multi-agent workflows and blackboards",
    "Planning and information flow": "Defenses that fix plans or track information flow before acting",
    "Identity and access control": "Defenses based on identity, registries, capabilities or access control",
    "Tool and execution boundaries": "Defenses or runtime checks at tool and execution boundaries",
    "Signals and monitoring": "Detection from signals, activations, logs or communication monitoring",
    "Collaborative defenses": "Defenses in which agents or graph models judge or prune other agents",
    "Prompt and model defenses": "Defenses by prompting, fine-tuning or guard models",
    "Multi-agent evaluation": "Benchmarks and evaluation frameworks for multi-agent security",
    "Agent tasks and competitions": "Benchmarks and competitions for single-agent injection",
    "Prompt and model evaluation": "Benchmarks for prompt injection against models or LLM applications",
    "Agent architectures and security": "Surveys and position papers on agent and agent-system security",
    "Injection and protocol taxonomies": "Taxonomies and surveys of prompt injection and agent protocols",
}

# ------------------------------------------------------------------------------------------------ step 5 channel tree
# (interface class, channel, attack form, control class, mechanism, property, criterion, supporting keys, note)
CHANNEL_TREE = [
    ("Entry", "C1 User request", "Injected suffix in the user's request (direct injection)", "semantic",
     "input label on the injected suffix", "P5", "TAINT", "perez2022ignore;liu2024formalizing;kavathekar2025tamas", ""),
    ("Entry", "C2 External content", "Data becomes a worker's sub-task (data-to-instruction)", "semantic",
     "taint check at context selection (MP1)", "P5", "SEL", "greshake2023indirect;zhan2024injecagent;"
     "debenedetti2024agentdojo", ""),
    ("Entry", "C2 External content", "Data becomes a recipient, path or command (data-to-executor)", "semantic",
     "taint check at acceptance and tool execution", "P5", "TAINT;EDGE", "debenedetti2025camel;zhang2025asb;"
     "naik2026omnileak", ""),
    ("Entry", "C3 Tool response", "Fake error or status routes control (control-flow hijack)", "structural",
     "fixed compiled plan", "P1", "EDGE", "triedman2025mas;jha2025controlvalve", ""),
    ("Collaboration", "C4 Peer message", "Payload copied from agent to agent (self-replication)", "semantic",
     "labels propagate inside envelopes", "P5", "EDGE;SEL", "lee2024promptinfection;Gu2024AgentSAAO", ""),
    ("Collaboration", "C4 Peer message", "Sender impersonation", "structural", "per-request capability tokens",
     "P2", "SLOT", "kavathekar2025tamas;Paul2026BeyondSIE", ""),
    ("Collaboration", "C4 Peer message", "Message rewritten in transit (agent-in-the-middle)", "structural",
     "MAC over request, key and value", "P2", "EDGE", "he2025aitm;Yan2025AttackTMAQ", ""),
    ("Collaboration", "C5 Coordination signal", "Replay of a stale approval or result", "structural",
     "exact dependency-key match", "P3", "RECONF", "", "derived from the kernel's freshness model; no corpus "
     "study reports replay against LLM MAS"),
    ("Collaboration", "C5 Coordination signal", "Release of an inconsistent snapshot", "structural",
     "publication barrier", "P6", "SLOT;COLL", "", "derived from the kernel's publication model"),
    ("Collaboration", "C5 Coordination signal", "Colluding agents agree on a protected decision", "residual",
     "owned validators narrow the choice", "P4", "COLL", "kavathekar2025tamas;Xie2025WhosTMAI", ""),
    ("Persistence and configuration", "C6 Shared state", "Poisoned record read in a later task or session",
     "semantic", "not mediated; cross-session memory is gap G5", "-", "-",
     "Chen2024AgentPoisonRLBS;Patlan2025CrossUserPUAK;Sunil2026MemoryPABF", ""),
    ("Persistence and configuration", "C7 Discovery metadata", "Poisoned tool description", "structural",
     "tool hash pinned in the contract", "P4", "RECONF", "invariant2025toolpoisoning;Song2025BeyondTPAE;"
     "Shi2025PromptIAR", ""),
    ("Persistence and configuration", "C7 Discovery metadata", "Rogue agent or provider registration",
     "structural", "ownership bound to the plan", "P2;P4", "RECONF", "Yu2026MisleadingTPO;Narajala2025SecuringGMAU",
     ""),
    ("Cross-cutting", "Any channel", "Compromised owner misuses its own authority", "residual",
     "owned validators; task scope (I2S, post hoc)", "P4", "SLOT;COLL", "kavathekar2025tamas;Wang2025ShadowsITAL", ""),
]

EVIDENCE_NOT_IN_TABLE = {"arif2026conjunctive", "Yu2026MisleadingTPO", "naik2026omnileak", "An2026ACIArenaTUH"}
EVIDENCE = [  # Table 2 (rows in EVIDENCE_NOT_IN_TABLE are kept here but cut from the printed table for space)
    ("greshake2023indirect", "case studies", "C2", "Author of retrieved data and caller have different authority",
     "input and tool labels"),
    ("zhan2024injecagent", "benchmark", "C3", "A permitted read exposes the agent to unauthorized instructions",
     "A1, environment labels"),
    ("lee2024promptinfection", "experiments", "C4", "Every receiving agent counts, including relays",
     "infection metrics, label propagation"),
    ("he2025aitm", "threat model", "C4", "Message integrity and sender authorization need separate checks",
     "A3, MAC, P2"),
    ("arif2026conjunctive", "experiments", "C4", "Per-component verdicts miss the meaning of combined inputs",
     "label join"),
    ("triedman2025mas", "experiments", "C3;C5", "Transitions need authorizing evidence", "P1, fake-error payloads"),
    ("jha2025controlvalve", "defense", "C5", "Allowed edge and allowed context are distinct obligations",
     "B4, EDGE vs SEL"),
    ("Yu2026MisleadingTPO", "planner study", "C7", "Claimed capabilities steer delegation before any task runs",
     "plan-bound owners"),
    ("invariant2025toolpoisoning;Narajala2025SecuringGMAU", "advisory; registry defense", "C7",
     "Tool identity must be tested apart from its arguments", "P4, RECONF"),
    ("Chen2024AgentPoisonRLBS;Patlan2025CrossUserPUAK", "retrieval poisoning; threat model", "C6",
     "Write provenance and current principal belong to the decision", "per-run envelopes, gap G5"),
    ("naik2026omnileak", "confidentiality study", "C4;C5", "Destination and provenance of released data must be "
     "audited", "executor sinks, audit"),
    ("kavathekar2025tamas", "benchmark", "C1;C2;C4", "Stratify by attacker placement and keep benign utility",
     "A1-A4, TAMAS study"),
    ("An2026ACIArenaTUH", "benchmark", "C2;C4;C7", "Separate the entry surface from the attack objective",
     "criteria vs goals"),
    ("debenedetti2025camel;li2025drift", "defenses", "C2;C3", "A fixed plan still needs a flow policy for tool "
     "arguments", "P5, baseline B3"),
]

REQUIREMENTS = [  # (id, name, statement, channels, property, mechanism)
    ("R1", "Structural mediation", "What executes, and when, is decided by a trusted component from an approved "
     "model, never by text", "C3;C5", "P1", "fixed compiled plan, kernel"),
    ("R2", "Request-bound authorship", "A value is accepted only from its slot's owner, for the current request, "
     "unaltered", "C4;C5;C7", "P2", "per-request HMAC capability tokens (Cap)"),
    ("R3", "Freshness", "Values for superseded questions are rejected", "C5", "P3", "dependency-key match (Fresh)"),
    ("R4", "Configuration integrity", "The metadata in force is the approved one", "C7", "P4",
     "contract and tool hashes (Contract, Exec)"),
    ("R5", "Provenance-bounded flow", "Untrusted-derived content reaches instruction, control and executor sinks "
     "only through declared declassifiers", "C1;C2;C3;C4", "P5", "labels in keys, selection C_q, Flow, Exec"),
    ("R6", "Consistent release", "Only complete, consistent results leave the system", "C5", "P6",
     "publication barrier (Pub)"),
    ("R7", "Verifiable evidence", "Every decision can be checked without trusting an LLM", "all", "P1-P6",
     "hash-chained log, LLM-free replay audit"),
    ("R8", "Channel coverage", "Every channel instance of the workflow model becomes a test obligation with an "
     "effect oracle", "C1;C2;C3;C4;C5;C7", "-", "obligation set O(P), six criteria"),
]

GAP_MATRIX = [  # (family, keys, ratings R1..R8 with F/H/N, rationale)
    ("Detection and guardrails", "inan2023llamaguard;li2025piguard;abdelnabi2025drift;zhu2025melon", "NNNNHNNN",
     "learned classifiers, activation probes or re-execution judge single runs; R5 only heuristically"),
    ("Prompt-level and training", "hines2024spotlighting;chen2025struq;wallace2024hierarchy;chen2025secalign",
     "NNNNHNNN",
     "separate data from instructions inside the model; R5 heuristically for one model"),
    ("Single-agent flow control", "debenedetti2025camel;wu2024ifc;li2025drift;an2025ipiguard;zhong2025rtbas;li2026ace",
     "HNNNFNHN",
     "plan fixed before data and flows tracked (R5) for one agent; plan from a privileged LLM (R1 partial); "
     "some provide auditable plans (R7 partial)"),
    ("Isolation and privilege control", "wu2025isolategpt;shi2025progent;kim2025pfi;tsai2025conseca", "HHNNHNHN",
     "trusted hub or policy layer mediates tool access (R1 partial), isolates apps or agents (R2 partial), restricts "
     "untrusted data (R5 partial); deterministic, human-checkable policies (R7 partial); per tool, not per workflow"),
    ("MAS control flow", "jha2025controlvalve", "HNNNHNNN",
     "LLM-generated control-flow graph enforced (R1 partial) with per-edge context rules (R5 partial)"),
    ("MAS monitors, data management", "Wang2025GSafeguardATAW;Miao2025BlindGuardSLAV;Mao2025AgentSafeSLY",
     "NHNNHNNN", "graph or anomaly models detect and prune propagation; information access by hierarchy (R5 partial); "
     "AgentSafe's ThreatSieve verifies the authority of information to prevent impersonation (R2 partial)"),
    ("Identity, registries, access control", "Zou2025BlockA2ATSAC;Narajala2025SecuringGMAU;Ji2026TamingVPAP",
     "NFNHNNHN", "verifiable identities and access control (R2); registry-based tool identity (R4 partial); "
     "ledger or logs (R7 partial)"),
    ("Model-driven security", "lodderstedt2002secureuml;jurjens2002umlsec;basin2006mds", "HHNNNNNN",
     "access-control infrastructure generated from models (R1, R2 partial); not for untrusted LLM components"),
    ("Injection benchmarks", "debenedetti2024agentdojo;zhan2024injecagent;evtimov2025wasp;kavathekar2025tamas;"
     "An2026ACIArenaTUH",
     "NNNNNNHH", "fixed injection points (R8 partial); deterministic checks in some (R7 partial)"),
    ("Structural workflow testing", "kahani2026structural", "NNNNNNNH",
     "coverage criteria over the structure of agentic workflows, not derived from injection channels (R8 partial)"),
    ("INERT", "this paper", "FFFFFFFF", "all requirements by design for channels C1 to C5 and C7 within a run "
     "(C1 when the request's provenance is segmented); C6 across sessions is limitation G5"),
]

GAPS = [
    ("G1", "Detection and guardrails; Prompt-level and training; MAS monitors, data management", "R5",
     "learned judgments that an adaptive attacker can probe", "checks contain no learned component"),
    ("G2", "Single-agent flow control", "R2;R3;R5", "flow control for one agent's plan only",
     "labels carried across agents inside dependency keys"),
    ("G3", "all families", "R1-R6", "no family combines structural mediation with flow control or uses the designed "
     "workflow", "all checks derived from one designer-authored model"),
    ("G4", "Injection benchmarks; Structural workflow testing", "R7;R8", "fixed injection points, structural coverage "
     "not derived from injection channels, LLM judges", "channel-derived obligations, effect oracles, replay audit"),
    ("G5", "all families", "C6", "cross-session shared state not mediated in a workflow policy (AgentSafe partitions "
     "memory by security level, outside a workflow model)",
     "limitation: INERT does not model long-lived memory"),
]

SUPPLEMENT = [  # works found by targeted searches after the corpus was fixed (not used to build the taxonomy)
    ("rossi2024categorization", "prompt-injection taxonomy", "arXiv:2402.00898", "Sec. 10.1, Table 9"),
    ("schulhoff2023hackaprompt", "prompt-hacking ontology", "EMNLP 2023, doi:10.18653/v1/2023.emnlp-main.302",
     "Sec. 10.1, Table 9"),
    ("deng2025agentsthreat", "agent-security survey", "ACM Comput. Surv. 57(7):182, arXiv:2406.02630", "Table 9"),
    ("hammond2025multiagent", "multi-agent risk taxonomy", "Cooperative AI Foundation TR #1, arXiv:2502.14143",
     "Sec. 10.1, Table 9"),
    ("cemri2025mast", "MAS failure taxonomy (MAST)", "NeurIPS 2025 D&B, arXiv:2503.13657", "Sec. 10.1, Table 9"),
    ("owasp2025agentic", "practitioner threat taxonomy", "https://genai.owasp.org (Feb 2025)", "Table 9"),
    ("mitre2025atlas", "practitioner threat taxonomy", "https://atlas.mitre.org", "Table 9"),
    ("humbatova2020taxonomy", "SE taxonomy method reference", "ICSE 2020, arXiv:1910.11015", "Sec. 10.1, Table 9"),
    ("wu2025isolategpt", "isolation and privilege control", "NDSS 2025, arXiv:2403.04960", "Sec. 10.3, Table 3"),
    ("shi2025progent", "isolation and privilege control", "arXiv:2504.11703", "Sec. 10.3, Table 3"),
    ("kim2025pfi", "isolation and privilege control", "arXiv:2503.15547", "Sec. 10.3, Table 3"),
    ("tsai2025conseca", "isolation and privilege control", "HotOS 2025, arXiv:2501.17070", "Sec. 10.3, Table 3"),
    ("zhong2025rtbas", "single-agent flow control", "arXiv:2502.08966", "Sec. 10.3, Table 3"),
    ("li2026ace", "single-agent flow control", "NDSS 2026, arXiv:2504.20984", "Sec. 10.3, Table 3"),
    ("zhu2025melon", "detection", "ICML 2025, PMLR 267:80310-80329, arXiv:2502.05174", "Sec. 10.3, Table 3"),
    ("abdelnabi2025drift", "detection", "SaTML 2025, arXiv:2406.00799", "Sec. 10.3, Table 3"),
    ("chen2025secalign", "prompt-level and training", "CCS 2025, doi:10.1145/3719027.3744836", "Sec. 10.3, Table 3"),
    ("zeng2024autodefense", "MAS collaborative defense", "arXiv:2403.04783", "Sec. 10.3"),
    ("ju2024flooding", "MAS propagation", "arXiv:2407.07791", "Sec. 10.2"),
    ("huang2025faulty", "MAS resilience", "ICML 2025, PMLR 267:26202-26226, arXiv:2408.00989", "Sec. 10.2"),
    ("evtimov2025wasp", "benchmark", "NeurIPS 2025 D&B, arXiv:2504.18575", "Sec. 10.4, Table 3"),
    ("andriushchenko2025agentharm", "benchmark", "ICLR 2025, arXiv:2410.09024", "Sec. 10.4"),
]


def write(path: Path, header: list[str], rows: list[list[object]]) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main() -> int:
    work = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/paper/EMSE/relevant-work")
    out = work / "audit"
    out.mkdir(exist_ok=True)
    # step 1: raw records
    records = []
    for q, name in SEARCHES.items():
        text = (work / name).read_text()
        for rank, m in enumerate(re.finditer(r"@(\w+)\{([^,]+),(.*?)\n\}", text, re.S), start=1):
            body = m.group(3) + "\n"

            def field(k: str, body: str = body) -> str:
                f = re.search(k + r"=\{(.*?)\},?\n", body, re.S)
                return f.group(1).strip() if f else ""
            url = field("url")
            records.append({"query": q, "rank": rank, "bibkey": m.group(2), "title": field("title"),
                            "year": field("year"), "venue": field("journal") or field("booktitle"),
                            "library": next((v for k, v in SOURCES if k in url), "other"), "url": url})
    write(out / "01_search_records.csv", ["record_id", "query", "rank", "bibkey", "title", "year", "venue",
                                          "library", "url"],
          [[f"{r['query']}-{r['rank']:03d}", r["query"], r["rank"], r["bibkey"], r["title"], r["year"], r["venue"],
            r["library"], r["url"]] for r in records])
    # step 2: deduplication
    first: dict[str, dict] = {}
    dedup = []
    for r in records:
        t = _norm(r["title"])
        dup = t in first
        first.setdefault(t, r)
        dedup.append([f"{r['query']}-{r['rank']:03d}", r["bibkey"], t, "yes" if dup else "no",
                      f"{first[t]['query']}-{first[t]['rank']:03d}" if dup else ""])
    write(out / "02_deduplication.csv", ["record_id", "bibkey", "normalized_title", "duplicate", "duplicate_of"], dedup)
    # step 3: screening
    classified = {r["bibkey"]: r for r in csv.DictReader((work / "corpus_classification.csv").open())}
    bib = (work / "injection_channel_taxonomy.bib").read_text()

    def bib_title(key: str) -> str:
        m = re.search(r"@\w+\{" + re.escape(key) + r",(.*?)\n\}", bib, re.S)
        t = re.search(r"title\s*=\s*\{(.*)\},?\n", m.group(1)) if m else None
        return _norm(t.group(1)) if t else ""
    included = {bib_title(k): k for k in classified}
    queries = collections.defaultdict(set)
    for r in records:
        queries[_norm(r["title"])].add(r["query"])
    screening, mismatch = [], 0
    for t, r in first.items():
        key = included.get(t, r["bibkey"])
        decision = "include" if t in included else "exclude"
        rule = "include" if (AGENT_RE.search(r["title"]) or PI_RE.search(r["title"])) else "exclude"
        facets = [f for f, rx in FACETS.items() if re.search(rx, r["title"], re.I)]
        note = INCLUDE_NOTES.get(key, "") if rule != decision else ""
        if rule != decision and not note:
            mismatch += 1
        screening.append([key, r["title"], r["year"], "+".join(sorted(queries[t])), r["library"], decision,
                          "I1" if decision == "include" else EXCLUSION, rule, "; ".join(facets), note])
    write(out / "03_screening.csv", ["bibkey", "title", "year", "queries", "library", "decision", "criterion",
                                     "title_rule_decision", "title_facets", "note_if_rule_differs"], screening)
    # step 4: codebook and classification
    book, cls = [], []
    tex = (work.parent / "Springer-Nature-LaTeX-template" / "main.tex").read_text()
    tree_block = re.search(r"%<<corpus_tree>>.*?%<</corpus_tree>>", tex, re.S)
    outside = tex.replace(tree_block.group(0), "") if tree_block else tex
    cited_text = {k.strip() for g in re.findall(r"\\cite[pt]?\{([^}]*)\}", outside) for k in g.split(",")}
    cited_tree = {k.strip() for g in re.findall(r"\\cite\{([^}]*)\}", tree_block.group(0) if tree_block else "")
                  for k in g.split(",")}
    titles = {bib_title(k): k for k in classified}
    raw_title = {_norm(r["title"]): r["title"] for r in records}
    for cat, _, subs in tree:
        for sub, leaves in subs:
            for leaf, keys, inf in leaves:
                book.append([cat, sub, leaf, LEAF_DEF[leaf], inf.replace("--", "-"), len(keys.split(","))])
                for k in keys.split(","):
                    where = ";".join(x for x, ok in (("text", k in cited_text), ("tree", k in cited_tree)) if ok)
                    t = next((raw_title[n] for n, kk in titles.items() if kk == k), "")
                    cls.append([k, t, cat, sub, leaf, inf.replace("--", "-"), where or "classification only",
                                classified[k]["queries"], classified[k]["source"]])
    write(out / "04_leaf_codebook.csv", ["category", "subcategory", "leaf", "definition", "informs_inert_element",
                                         "n_studies"], book)
    write(out / "05_classification.csv", ["bibkey", "title", "category", "subcategory", "leaf",
                                          "informs_inert_element", "cited_in_paper", "queries", "library"], cls)
    # steps 5-10: channel tree, evidence, requirements, gaps
    write(out / "06_channel_tree.csv", ["interface_class", "channel", "attack_form", "control_class",
                                        "inert_mechanism", "property", "coverage_criterion", "supporting_studies",
                                        "note"], [list(r) for r in CHANNEL_TREE])
    write(out / "07_evidence_table.csv", ["studies", "design", "channels", "implication", "inert_element",
                                          "in_printed_table"],
          [[*r, "no" if r[0] in EVIDENCE_NOT_IN_TABLE else "yes"] for r in EVIDENCE])
    printed = re.search(r"\\label\{tab:evidence\}(.*?)\\end\{tabular\*\}", tex, re.S)
    printed_keys = {k for g in re.findall(r"\\citep\{([^}]*)\}", printed.group(1) if printed else "")
                    for k in g.split(",")}
    audit_keys = {k for r in EVIDENCE if r[0] not in EVIDENCE_NOT_IN_TABLE for k in r[0].split(";")}
    gap_tab = re.search(r"\\label\{tab:gaps\}(.*?)\\end\{tabular\*\}", tex, re.S)
    sym_tex = {"cfull": "F", "chalf": "H", "cnone": "N"}
    printed_gap = {}
    for line in (gap_tab.group(1) if gap_tab else "").split("\\\\"):
        cells = [c.strip() for c in line.split("&")]
        if len(cells) == 10 and "\\cite" in cells[1]:
            keys = re.search(r"\\citep\{([^}]*)\}", cells[1]).group(1).replace(",", ";")
            printed_gap[cells[0].split("\n")[-1].strip()] = (keys, "".join(sym_tex[c.strip("\\ ")] for c in cells[2:]))
    gap_mismatch = sorted(f for f, k, r, _ in GAP_MATRIX if f != "INERT" and printed_gap.get(f) != (k, r))
    forms = collections.defaultdict(list)
    for r in CHANNEL_TREE:
        forms[r[1].split()[0]].append(r[2])
    reqs = []
    for rid, name, st, ch, prop, mech in REQUIREMENTS:
        fs = [f for c in ch.split(";") for f in forms.get(c, [])] if ch != "all" else ["all attack forms"]
        reqs.append([rid, name, st, ch, " | ".join(fs), prop, mech])
    write(out / "08_requirements.csv", ["id", "requirement", "statement", "channels", "attack_forms", "property",
                                        "inert_mechanism"], reqs)
    sym = {"F": "by design", "H": "partial", "N": "not addressed"}
    write(out / "09_gap_matrix.csv", ["family", "representative_studies"] + [f"R{i}" for i in range(1, 9)] +
          ["rationale"], [[f, k, *[sym[c] for c in r], why] for f, k, r, why in GAP_MATRIX])
    snow_titles = [_norm(r["title"]) for r in csv.DictReader((out / "15_snowball_classification.csv").open())] \
        if (out / "15_snowball_classification.csv").exists() else []
    refbib = (work.parent / "Springer-Nature-LaTeX-template" / "references.bib").read_text()

    def ref_title(key: str) -> str:
        m = re.search(r"@\w+\{" + re.escape(key) + r",(.*?)\n\}", refbib, re.S)
        t = re.search(r"title\s*=\s*\{(.*)\},?\n", m.group(1)) if m else None
        return _norm(re.sub(r"[{}]", "", t.group(1))) if t else ""
    aliases = {"shi2025progent": "progentsecuringaiagentswithprivilegecontrol"}  # arXiv v2 title
    supp_rows = []
    for r in SUPPLEMENT:
        t = aliases.get(r[0], ref_title(r[0]))
        hit = any(difflib.SequenceMatcher(None, t, x).ratio() > 0.85 for x in snow_titles)
        supp_rows.append([*r, "yes" if hit else "no"])
    write(out / "11_supplementary_studies.csv", ["bibkey", "role", "identifier_verified", "used_in",
                                                 "later_found_by_snowballing"], supp_rows)
    write(out / "10_gaps.csv", ["gap", "families", "requirements", "observation", "inert_response"],
          [list(g) for g in GAPS])
    # consistency checks against the corpus
    known = set(classified) | set(re.findall(r"@\w+\{([^,]+),",
                                             (work.parent / "Springer-Nature-LaTeX-template" / "references.bib")
                                             .read_text()))
    cited = {k for r in CHANNEL_TREE for k in r[7].split(";") if k} | \
            {k for r in EVIDENCE for k in r[0].split(";")} | \
            {k for r in GAP_MATRIX for k in r[1].split(";") if k != "this paper"}
    summary = {"supplementary": len(supp_rows), "supplementary_in_corpus": sum(r[-1] == "yes" for r in supp_rows),
               "Q1": sum(r["query"] == "Q1" for r in records), "Q2": sum(r["query"] == "Q2" for r in records),
               "records": len(records), "duplicates": sum(d[3] == "yes" for d in dedup), "unique": len(first),
               "included": sum(s[5] == "include" for s in screening),
               "excluded": sum(s[5] == "exclude" for s in screening),
               "title_rule_agrees": sum(s[5] == s[7] for s in screening),
               "rule_differs_with_note": sum(bool(s[9]) for s in screening),
               "rule_differs_without_note": mismatch, "leaves": len(book), "classified": len(cls),
               "attack_forms": len(CHANNEL_TREE), "attack_forms_without_corpus_support":
                   sum(not r[7] for r in CHANNEL_TREE), "unknown_keys": sorted(cited - known),
               "evidence_table_mismatch": sorted(printed_keys ^ audit_keys), "gap_table_mismatch": gap_mismatch}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary))
    return 0 if not (summary["unknown_keys"] or mismatch or summary["evidence_table_mismatch"]
                     or summary["gap_table_mismatch"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
