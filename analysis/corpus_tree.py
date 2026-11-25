"""Corpus tree of the taxonomy section: the classification of the corpus (category > subcategory > leaf),
the INERT element each leaf informs, and the generator of the TikZ figure and of the classification CSV.

  python analysis/corpus_tree.py [main.tex] [corpus_classification.csv]
"""

import json
import re
from pathlib import Path

tree = [
 ("Threats and propagation", "tier0", [
   ("Threat mechanisms", [
     ("Content and interpretation", "Gu2024AgentSAAO,Sehwag2026ASPISAAH,Yeo2025MultimodalPIBL,Pasquini2024NeuralELAL,greshake2023indirect,Wen2025RLIAU", "A1, payload classes and mutators"),
     ("Peer influence and composition", "shahroz2025siege,Yan2025AttackTMAQ,arif2026conjunctive,lee2024promptinfection,he2025aitm", "A2--A4, P2, label propagation (P5)"),
     ("State and discovery", "Chen2024AgentPoisonRLBS,Patlan2025CrossUserPUAK,Sunil2026MemoryPABF,Yu2026MisleadingTPO,Shi2025PromptIAR", "A5, P4, RECONF; gap G5 (memory)"),
     ("Execution and disclosure", "Pedro2023FromPIBE,Wang2025IPLAX,triedman2025mas,naik2026omnileak,Nagaraja2026WhenPCBF,Kao2026YouTMAZ", "executor sinks, effect oracle, P1"),
   ]),
   ("Collaboration structure", [
     ("Topology and propagation", "hagag2026architecture,Hu2026AttackingADAX,Le2026CrosslayerCOAI,Malla2026FromMTI,Xie2026FromSTBA,Zhu2025MASTERMSR,Yu2025NetSafeETBB", "topology zoo, RQ1 metrics"),
     ("Roles and trust boundaries", "Paul2026BeyondSIE,peigne2025securitytax,Liu2026TheCPT,Mitra2026WhereREC", "slot owners, capabilities (P2)"),
     ("Shared and deployed workflows", "Mitra2026AgenticCyOpsSMAH,Jamshidi2026SecurityEOAG,Wang2025ShadowsITAL,Nakamura2025TerrariumRTAR", "shared-state channel C6, envelopes"),
   ]),
 ]),
 ("Security defenses", "tier1", [
   ("Runtime controls", [
     ("Planning and information flow", "Mao2025AgentSafeSLY,jha2025controlvalve,debenedetti2025camel,li2025drift,an2025ipiguard,wu2024ifc,Hu2026TwinACI", "taint policy, declassifiers, B3, B4"),
     ("Identity and access control", "Tallam2026AuthorizationPIBH,Zou2025BlockA2ATSAC,Narajala2025SecuringGMAU,Ji2026TamingVPAP", "per-request tokens, pinned metadata"),
     ("Tool and execution boundaries", "Taheri2020MitigationARBP,Engelmann2022RV4JaCaRBL,Rashidi2026TheBOBQ,Li2026UniversalDFL", "tool sandbox, fail-closed execution"),
   ]),
   ("Detection and guardrails", [
     ("Signals and monitoring", "Malik2026ADLK,Cai2026CrossLayerSFBK,Alamsabi2026EmbeddingBasedDOX,Li2026MESAPVAS,Hashmi2026PromptIDBR,Shi2026SAIGuardCSN,Gosmar2025SentinelAFAJ,Xu2026WhenAGQ,Xie2025WhosTMAI", "baseline B1, reason codes"),
     ("Collaborative defenses", "Hossain2025AMLV,Miao2025BlindGuardSLAV,Luo2026DefendingLMV,Wang2025GSafeguardATAW,Kachuee2026MASGuardUGW,Wang2025MASShieldADAF,Zhang2026OpenEvoShieldDNZ,Gosmar2025PromptIDY,Yan2026PropGuardSLAE", "baselines B1, B2; gap G1"),
     ("Prompt and model defenses", "Shaheer2025BeyondTBAW,Chen2024DefenseAPBG,Li2024InjecGuardBABC,Piet2023JatmoPIAS,li2025piguard,Gosmar2026PromptIMAA,Ramakrishnan2025SecuringAAAA,chen2025struq", "baseline B2, quoted context"),
   ]),
 ]),
 ("Evaluation and foundations", "tier2", [
   ("Benchmarks and evaluation", [
     ("Multi-agent evaluation", "An2026ACIArenaTUH,Ogunjinmi2026AgenticARN,Carolina2025EvaluatingMDAX,MateoTorrejon2026GAMMAFACAG,Liu2026MADBenchBTU,Hagag2026ORBITAFAD,Zhang2024PsySafeACAN,kavathekar2025tamas,Sharma2025TowardsUQBD,Wang2026TrinityGuardAUF", "TAMAS adapter, attacker models"),
     ("Agent tasks and competitions", "zhang2025asb,Dziemian2026HowVAAN,zhan2024injecagent,Zou2025SecurityCIAD", "BENCH suite, adaptive attacker A6"),
     ("Prompt and model evaluation", "Yi2023BenchmarkingADAR,Wan2024CYBERSECEVAL3ABJ,liu2024formalizing,Li2024GenTelSafeAUAU,Liu2026LongPIBenchALAV,aal2025PromptIABT,Benjamin2024SystematicallyAPBK,Toyer2023TensorTIAM", "payload classes, ASR definition"),
   ]),
   ("Surveys and taxonomies", [
     ("Agent architectures and security", "Shahriar2025ASOE,Yu2025ASOL,Siu2026AgentSNZ,Xiang2026ArchitectingSAAP,Zhu2026BlockchainETAT,Luo2025LargeLMBI,Hossain2026OnUIS,Witt2025OpenCIBE,Rafe2026OrchestrationAVK,Xu2026SecurityAAJ,Wang2025SecurityOIBN,Owoputi2022SecurityOMD,Yang2026SoKWSJ,RahulDevT2026TowardSAG,Ling2026TowardSLG,Li2026TowardsSABM", "requirements R1--R8"),
     ("Injection and protocol taxonomies", "Cao2026ASSM,Yadav2025AdversialPIBA,Song2025BeyondTPAE,Mao2025FromLTAY,Ferrag2025FromPIB,McHugh2025PromptI2F,Prabhakarn2026PromptIAAZ,Geng2025PromptIABB,Mourad2026SecuringTPAQ,Rababah2024SoKPHBH,Wang2026TheLOT", "channel definitions C1--C7"),
   ]),
 ]),
]


SEARCHES = {  # raw exports of the two keyword searches (24 Nov 2026), in docs/paper/EMSE/relevant-work/
    "Q1": "prompt-injection-in-multi-agent-systems.md",
    "Q2": "taxonomy-of-injection-channels-in-agent-collaboration.md",
}
SOURCES = (("arxiv", "arXiv"), ("ieeexplore", "IEEE Xplore"), ("dl.acm", "ACM DL"),
           ("semanticscholar", "Semantic Scholar"), ("doi.org", "publisher DOI"))


def _norm(title: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]", "", re.sub(r"[{}]", "", title).lower())


def collection(work_dir):
    """Recompute the collection funnel from the raw search exports: records per query, duplicates,
    unique records per source library, and the records excluded at screening (not in the tree)."""
    import re
    recs = []
    for q, name in SEARCHES.items():
        text = (work_dir / name).read_text()
        for m in re.finditer(r"@\w+\{([^,]+),(.*?)\n\}", text, re.S):
            t = re.search(r"title=\{(.*)\},?\n", m.group(2))
            u = re.search(r"url=\{(.*?)\}", m.group(2))
            url = u.group(1) if u else ""
            src = next((v for k, v in SOURCES if k in url), "other")
            recs.append({"query": q, "key": m.group(1), "title": _norm(t.group(1) if t else ""), "source": src})
    unique: dict = {}
    for r in recs:
        unique.setdefault(r["title"], {**r, "queries": set()})["queries"].add(r["query"])
    return recs, unique


def main() -> int:
    """Write the corpus classification CSV and splice the tree into main.tex at %CORPUSTREE (or replace it)."""
    import collections
    import csv
    import re
    import sys
    from pathlib import Path
    tex_path = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/paper/EMSE/Springer-Nature-LaTeX-template/main.tex")
    csv_path = Path(sys.argv[2] if len(sys.argv) > 2 else "docs/paper/EMSE/relevant-work/corpus_classification.csv")
    tex = tex_path.read_text()
    begin, end = "%<<corpus_tree>>\n", "%<</corpus_tree>>"
    if "%CORPUSTREE" in tex:
        tex = tex.replace("%CORPUSTREE", begin + end)
    outside = re.sub(re.escape(begin) + r".*?" + re.escape(end), "", tex, flags=re.S)
    cited = {k.strip() for g in re.findall(r"\\cite[pt]?\{([^}]*)\}", outside) for k in g.split(",")}
    step, gap_sub, gap_cat, per_leaf = 0.62, 0.1, 0.24, 2
    snow_path = csv_path.parent / "audit" / "15_snowball_classification.csv"
    added = list(csv.DictReader(snow_path.open())) if snow_path.exists() else []
    snow = collections.Counter(r["leaf"] for r in added)  # snowballing and Scopus-search studies per leaf
    n_scopus = sum(r.get("found_by") == "Scopus search" for r in added)
    y, out, draws, rows = 0.0, [], [], []
    li = si = ci = 0
    for cat, tier, subs in tree:
        sub_ys = []
        for sub, leaves in subs:
            leaf_ys = []
            for name, cites, inf in leaves:
                ks = cites.split(",")
                shown = [k for k in ks if k in cited][:per_leaf]  # cite only studies discussed in the text
                rows += [(cat, sub, name, k, "yes" if k in shown else "no") for k in ks]
                cite = "~\\cite{" + ",".join(shown) + "}" if shown else ""
                out.append(f"\\node[leaf] (leaf{li}) at (40,{y:.3f}) {{\\textbf{{{name}}} ($n={len(ks) + snow.get(name, 0)}$)"
                           f"{cite}\\\\[-1pt]{{\\itshape$\\hookrightarrow$ {inf}}}}};")
                draws.append(f"\\draw[{tier}!72] (spine{si}) |- (leaf{li}.west);")
                leaf_ys.append(y)
                li += 1
                y -= step
            ys = sum(leaf_ys) / len(leaf_ys)
            sub_ys.append(ys)
            out += [f"\\node[sub,fill={tier}!6,draw={tier}!45] (sub{si}) at (19,{ys:.3f}) {{{sub}}};",
                    f"\\coordinate (spine{si}) at (38.5,{ys:.3f});"]
            draws += [f"\\draw[{tier}!72] (sub{si}.east)--(spine{si});", f"\\draw[{tier}!72] (split{ci}) |- (sub{si}.west);"]
            si += 1
            y -= gap_sub
        cy = sum(sub_ys) / len(sub_ys)
        out += [f"\\node[cat,fill={tier},text=white] (cat{ci}) at (3,{cy:.3f}) {{{cat}}};",
                f"\\coordinate (split{ci}) at (17.5,{cy:.3f});"]
        draws += [f"\\draw[{tier}!72] (cat{ci}.east)--(split{ci});", f"\\draw[black!45] (origin) |- (cat{ci}.west);"]
        ci += 1
        y -= gap_cat - gap_sub
    body = "\n".join(out + draws)
    tex = re.sub(re.escape(begin) + r".*?" + re.escape(end), lambda m: begin + body + "\n" + end, tex, flags=re.S)
    tex = _macros(tex, csv_path.parent / "audit", len(rows), len(added) - n_scopus, n_scopus)
    tex_path.write_text(tex)
    recs, unique = collection(csv_path.parent)
    bib = (csv_path.parent / "injection_channel_taxonomy.bib").read_text()

    def title_of(key: str) -> str:
        m = re.search(r"@\w+\{" + re.escape(key) + r",(.*?)\n\}", bib, re.S)
        t = re.search(r"title\s*=\s*\{(.*)\},?\n", m.group(1)) if m else None
        return _norm(t.group(1)) if t else ""
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "subcategory", "leaf", "bibkey", "cited_in_tree", "queries", "source"])
        for r in rows:
            u = unique.get(title_of(r[3]), {})
            w.writerow([*r, "+".join(sorted(u.get("queries", []))) or "missing", u.get("source", "missing")])
    included = {title_of(r[3]) for r in rows}
    funnel = {q: sum(r["query"] == q for r in recs) for q in SEARCHES}
    funnel.update(records=len(recs), duplicates=len(recs) - len(unique), unique=len(unique),
                  by_source=dict(collections.Counter(u["source"] for u in unique.values())),
                  excluded=sorted(u["key"] for t, u in unique.items() if t not in included),
                  included=len(rows), untraced=sorted(r[3] for r in rows if title_of(r[3]) not in unique),
                  by_category=dict(collections.Counter(r[0] for r in rows)))
    (csv_path.parent / "corpus_collection.json").write_text(json.dumps(funnel, indent=1))
    print(f"{len(rows)} studies, {sum(r[4] == 'yes' for r in rows)} cited in the tree")
    print(json.dumps({k: v for k, v in funnel.items() if k != "excluded"}), "excluded:", len(funnel["excluded"]))
    return 0


def _macros(tex: str, audit: Path, n_search: int, n_snow: int, n_scopus: int = 0) -> str:
    """Counts of the collection pipeline as LaTeX macros (between the %<<corpus_macros>> markers)."""
    a = json.loads((audit / "summary.json").read_text()) if (audit / "summary.json").exists() else {}
    b = json.loads((audit / "snowball_summary.json").read_text()) if (audit / "snowball_summary.json").exists() else {}
    k = b.get("link_threshold", 0)
    sc = b.get("scopus", {})
    rule = (b.get("included_by_threshold") or {}).get("1", 0)
    at_k = (b.get("included_by_threshold") or {}).get(str(k), 0)
    vals = {"NQone": a.get("Q1", 0), "NQtwo": a.get("Q2", 0), "NRecords": a.get("records", 0), "NDup": a.get("duplicates", 0),
            "NUnique": a.get("unique", 0), "NExcl": a.get("excluded", 0), "NSearch": n_search,
            "NSeedsResolved": b.get("seeds_resolved", 0), "NSeedsUnresolved": len(b.get("unresolved", [])),
            "NSnowCand": b.get("candidates", 0), "NSnowRule": rule, "NSnowRuleExcl": b.get("candidates", 0) - rule,
            "NLinkK": k, "NSnowAtK": at_k, "NSnowManualExcl": at_k - n_snow, "NSnow": n_snow,
            "NCorpus": n_search + n_snow + n_scopus,
            "NScQone": sc.get("search_records", {}).get("Q1", 0), "NScQtwo": sc.get("search_records", {}).get("Q2", 0),
            "NScUnique": sc.get("search_unique", 0), "NScRule": sc.get("search_rule_met", 0),
            "NScRuleExcl": sc.get("search_unique", 0) - sc.get("search_rule_met", 0),
            "NScKnown": sc.get("search_rule_met", 0) - sc.get("search_rule_met_new", 0),
            "NScNew": sc.get("search_rule_met_new", 0), "NScopus": n_scopus,
            "NScManualExcl": sc.get("search_rule_met_new", 0) - n_scopus,
            "NScCiting": sc.get("citing_records", 0), "NScOnly": sc.get("records", 0) - sc.get("mapped_to_openalex", 0),
            "NScUnresolvedCited": sc.get("unresolved_seeds_cited", 0),
            "NKeywordAgree": round(100 * b.get("keyword_classifier_agreement", 0)),
            "NSupp": a.get("supplementary", 0) - a.get("supplementary_in_corpus", 0),
            "NSuppSnow": a.get("supplementary_in_corpus", 0)}
    body = "\n".join(f"\\newcommand{{\\{k2}}}{{{v:,}}}".replace(",", "{,}") for k2, v in vals.items())
    begin, end = "%<<corpus_macros>>\n", "%<</corpus_macros>>"
    if begin not in tex:
        tex = tex.replace("%<<macros>>", begin + end + "\n%<<macros>>", 1)
    return re.sub(re.escape(begin) + r".*?" + re.escape(end), lambda m: begin + body + "\n" + end, tex, flags=re.S)


if __name__ == "__main__":
    raise SystemExit(main())
