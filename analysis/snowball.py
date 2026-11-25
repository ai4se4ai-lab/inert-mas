"""Backward and forward snowballing of the taxonomy corpus (Wohlin 2014), with every API response cached.

  python analysis/snowball.py fetch      # resolve seeds, fetch references and citations (network, cached)
  python analysis/snowball.py screen     # offline: candidates, screening, link threshold, classification

Sources: OpenAlex (open, no key; references from each seed's record, citations via cites: filters) and Scopus
(ELSEVIER_API_KEY, read from the environment and never written to disk; the cache key omits it). Scopus contributes
(i) forward snowballing by searching reference lists for each seed's title, REF("title"), which also reaches seeds
OpenAlex does not index, and (ii) a database search with the two queries translated to Scopus syntax. Scopus
abstracts and reference lists need an institutional entitlement, so abstracts come from OpenAlex by DOI.
All raw responses are stored under docs/paper/EMSE/relevant-work/snowball/cache/, so `screen` and every later step
run offline and reproducibly; only `fetch` of something not yet cached needs the network or a key.

Outputs (docs/paper/EMSE/relevant-work/audit/):
  12_seed_resolution.csv     each of the corpus studies with its resolved OpenAlex id and match quality
  13_snowball_candidates.csv every candidate reached by backward or forward snowballing, with its links to seeds
  14_snowball_screening.csv  every candidate in the window with the screening decision and the rule that made it
  15_snowball_classification.csv  every included candidate with its leaf and how the leaf was assigned
  snowball_summary.json      counts per step and the sensitivity of the result to the link threshold
"""

from __future__ import annotations

import collections
import csv
import difflib
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus_tree import _norm, tree  # noqa: E402

WORK = Path("docs/paper/EMSE/relevant-work")
CACHE = WORK / "snowball" / "cache"
AUDIT = WORK / "audit"
UA = {"User-Agent": "inert-taxonomy-pipeline/1.0", "Content-Type": "application/json"}
SEARCH_DATE = "2026-11-24"
WINDOW = (2022, 2026)  # LLM-agent era up to the search date
LINK_THRESHOLD = 5     # a candidate must be cited by or cite at least this many seeds (sensitivity k=1..6 reported)

# ------------------------------------------------------------------------------------------------ cached HTTP
def _get(url: str, body: dict | None = None, tries: int = 8, auth: str = "",
         headers: dict | None = None) -> object:
    key = hashlib.sha256((url + json.dumps(body, sort_keys=True)).encode()).hexdigest()[:24]
    path = CACHE / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text())["response"]
    if headers is not None and not headers:
        raise RuntimeError(f"not cached and ELSEVIER_API_KEY is not set: {url[:120]}")
    data = json.dumps(body).encode() if body is not None else None
    for i in range(tries):
        try:
            req = urllib.request.Request(url + auth, data=data, headers={**UA, **(headers or {})},
                                         method="POST" if body is not None else "GET")
            with urllib.request.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read())
            CACHE.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"url": url, "body": body, "retrieved": time.strftime("%Y-%m-%d"),
                                        "response": resp}))
            time.sleep(0.3)
            return resp
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(min(60, 3 * 2 ** i))
                continue
            if e.code == 404:
                return None
            raise RuntimeError(f"HTTP {e.code} on {url}: {e.read()[:300]!r}") from e
        except (urllib.error.URLError, TimeoutError):
            time.sleep(min(60, 3 * 2 ** i))
    raise RuntimeError(f"giving up on {url}")


# ------------------------------------------------------------------------------------------------ Scopus source
SCOPUS = "https://api.elsevier.com/content/search/scopus"
SC_FIELDS = "eid,dc:title,prism:doi,prism:coverDate,prism:publicationName,citedby-count,subtypeDescription"
SC_YEARS = f" AND PUBYEAR > {WINDOW[0] - 1} AND PUBYEAR < {WINDOW[1] + 1}"
SCOPUS_QUERIES = {  # the two search queries in Scopus Boolean syntax (title, abstract and keywords)
    "Q1": 'TITLE-ABS-KEY("prompt injection" AND (agent* OR "multi-agent" OR multiagent))',
    "Q2": 'TITLE-ABS-KEY((taxonom* OR channel* OR protocol*) AND (injection OR attack*) AND ("multi-agent" OR '
          '"agent collaboration" OR "agent communication") AND (LLM* OR "language model*"))',
}


def _sc_headers() -> dict:
    key = os.environ.get("ELSEVIER_API_KEY")
    return {"X-ELS-APIKey": key, "Accept": "application/json"} if key else {}


def _sc_pages(query: str) -> list[dict]:
    """All records of a Scopus search (25 per page, at most 5,000); fails loudly instead of truncating."""
    out, start = [], 0
    while True:
        url = SCOPUS + "?" + urllib.parse.urlencode({"query": query, "count": 25, "start": start, "field": SC_FIELDS})
        sr = (_get(url, headers=_sc_headers()) or {}).get("search-results", {})  # type: ignore[union-attr]
        total = int(sr.get("opensearch:totalResults") or 0)
        if total > 5000:
            raise RuntimeError(f"{total} Scopus results exceed the paging limit: {query[:120]}")
        res = [e for e in sr.get("entry", []) if "error" not in e]
        out += res
        start += 25
        if start >= total or not res:
            return out


def _sc_work(e: dict) -> dict:
    return {"eid": e.get("eid", ""), "title": e.get("dc:title") or "", "doi": (e.get("prism:doi") or "").lower(),
            "year": int((e.get("prism:coverDate") or "0")[:4] or 0), "venue": e.get("prism:publicationName") or "",
            "abstract": "", "type": e.get("subtypeDescription") or "", "scopus_cited_by": e.get("citedby-count")}


def _ref_phrase(title: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r'["{}\\]', " ", title)).strip()


# ------------------------------------------------------------------------------------------------ OpenAlex source
OA = "https://api.openalex.org"
OA_SELECT = "id,doi,display_name,publication_year,referenced_works,cited_by_count,type,primary_location"
OA_META = "id,doi,display_name,publication_year,type,primary_location,abstract_inverted_index"


def _abstract(inv: dict | None) -> str:
    if not inv:
        return ""
    pos = sorted((i, w) for w, idx in inv.items() for i in idx)
    return " ".join(w for _, w in pos)


def _oa(path: str) -> dict:
    key = os.environ.get("OPENALEX_API_KEY")  # optional; never written to disk (the cache key omits it)
    r = _get(OA + path, auth=f"&api_key={key}" if key else "")
    return r or {"results": [], "meta": {}}


def _oa_pages(path: str) -> list[dict]:
    """Page-number paging (allowed without a key up to 10,000 results); fails loudly instead of truncating."""
    out, page = [], 1
    while True:
        r = _oa(f"{path}&per-page=200&page={page}")
        res = r.get("results", [])
        out += res
        count = (r.get("meta") or {}).get("count", 0)
        if count > 10_000:
            raise RuntimeError(f"{count} results exceed the page-paging limit; split the query: {path[:120]}")
        if len(out) >= count or not res:
            return out
        page += 1


def _work(w: dict) -> dict:
    src = ((w.get("primary_location") or {}).get("source") or {})
    return {"paperId": w["id"].rsplit("/", 1)[-1], "title": w.get("display_name") or "",
            "year": w.get("publication_year"), "venue": src.get("display_name") or "",
            "doi": (w.get("doi") or "").replace("https://doi.org/", ""),
            "abstract": _abstract(w.get("abstract_inverted_index")), "type": w.get("type") or ""}


# ------------------------------------------------------------------------------------------------ seeds
def corpus() -> list[dict]:
    """The included studies with title and URL from the raw search exports."""
    rows = list(csv.DictReader((AUDIT / "03_screening.csv").open()))
    recs = {_norm(r["title"]): r for r in csv.DictReader((AUDIT / "01_search_records.csv").open())}
    out = []
    for r in rows:
        if r["decision"] == "include":
            rec = recs.get(_norm(r["title"]), {})
            out.append({"key": r["bibkey"], "title": r["title"], "year": r["year"], "url": rec.get("url", "")})
    return out


DOI_OVERRIDES = {  # seeds whose exported URL is a landing page without a DOI (checked by hand)
    "greshake2023indirect": "10.1145/3605764.3623985",
}


def seed_doi(url: str) -> str | None:
    m = re.search(r"arxiv\.org/(?:pdf|abs)/(\d{4}\.\d{4,5})", url)
    if m:
        return f"10.48550/arxiv.{m.group(1)}"
    m = re.search(r"doi\.org/(10\.[^\s]+)", url)
    return m.group(1).lower() if m else None


def resolve(seeds: list[dict]) -> list[dict]:
    dois = {s["key"]: DOI_OVERRIDES.get(s["key"]) or seed_doi(s["url"]) for s in seeds}
    by_doi: dict[str, dict] = {}
    wanted = sorted({d for d in dois.values() if d})
    for k in range(0, len(wanted), 50):
        r = _oa(f"/works?filter=doi:{'|'.join(wanted[k:k + 50])}&per-page=50&select={OA_SELECT}")
        for w in r.get("results", []):
            by_doi[(w.get("doi") or "").replace("https://doi.org/", "").lower()] = w
    out = []
    for s in seeds:
        w, how = by_doi.get(dois[s["key"]] or ""), "doi"
        if not w or _sim(w.get("display_name", ""), s["title"]) < 0.85:
            q = urllib.request.quote(re.sub(r"[^\w\s-]", " ", s["title"])[:250])
            r = _oa(f"/works?filter=title.search:{q}&per-page=5&select={OA_SELECT}")
            best = max(r.get("results", []), key=lambda x: _sim(x.get("display_name", ""), s["title"]), default=None)
            if best and _sim(best.get("display_name", ""), s["title"]) >= 0.85:
                w, how = best, "title search"
            else:
                w, how = (w if w else None), ("doi, title differs" if w else "unresolved")
        out.append({**s, "paperId": (w or {}).get("id", "").rsplit("/", 1)[-1], "work": w or {},
                    "s2_title": (w or {}).get("display_name", ""), "how": how,
                    "similarity": round(_sim((w or {}).get("display_name", ""), s["title"]), 3)})
    return out


def _sim(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def backward(seeds: list[dict]) -> dict[str, set[str]]:
    back = collections.defaultdict(set)
    for s in seeds:
        for ref in (s["work"] or {}).get("referenced_works") or []:
            back[ref.rsplit("/", 1)[-1]].add(s["key"])
    return back


def forward(seeds: list[dict]) -> tuple[dict[str, set[str]], dict[str, dict]]:
    fwd, meta = collections.defaultdict(set), {}
    ids = {s["paperId"]: s["key"] for s in seeds if s["paperId"]}
    keys = sorted(ids)
    for k in range(0, len(keys), 25):  # longer OR-lists exceed the URL limit
        chunk = keys[k:k + 25]
        for w in _oa_pages(f"/works?filter=cites:{'|'.join(chunk)},publication_year:{WINDOW[0]}-{WINDOW[1]}"
                           f"&select={OA_META},referenced_works"):
            wid = w["id"].rsplit("/", 1)[-1]
            meta[wid] = _work(w)
            for ref in w.get("referenced_works") or []:
                rid = ref.rsplit("/", 1)[-1]
                if rid in ids:
                    fwd[wid].add(ids[rid])
    return fwd, meta


def metadata(ids: list[str]) -> dict[str, dict]:
    out = {}
    for k in range(0, len(ids), 25):
        r = _oa(f"/works?filter=openalex:{'|'.join(ids[k:k + 25])}&per-page=25&select={OA_META}")
        for w in r.get("results", []):
            out[w["id"].rsplit("/", 1)[-1]] = _work(w)
    return out


def scopus(seeds: list[dict], meta: dict[str, dict]) -> tuple[dict[str, set[str]], dict[str, set[str]], dict]:
    """Forward links (citing work -> seeds) and search hits (record -> queries) from Scopus, keyed like OpenAlex
    candidates. Scopus records are mapped to OpenAlex works by DOI, else by normalized title; the rest are kept as
    Scopus-only records (key scopus:<eid>, no abstract)."""
    recs: dict[str, dict] = {}
    cites: dict[str, set[str]] = collections.defaultdict(set)
    hits: dict[str, set[str]] = collections.defaultdict(set)
    per_seed = {}
    for s in seeds:
        rows = _sc_pages(f'REF("{_ref_phrase(s["title"])}")' + SC_YEARS)
        per_seed[s["key"]] = len(rows)
        for e in rows:
            recs[e["eid"]] = _sc_work(e)
            cites[e["eid"]].add(s["key"])
    for q, query in SCOPUS_QUERIES.items():
        for e in _sc_pages(query + SC_YEARS):
            recs[e["eid"]] = _sc_work(e)
            hits[e["eid"]].add(q)
    # map to OpenAlex: known works first, then a DOI lookup for the rest
    by_doi = {m["doi"].lower(): k for k, m in meta.items() if m.get("doi")}
    by_title = {_norm(m["title"]): k for k, m in meta.items() if m.get("title")}
    for s in seeds:
        if s["paperId"]:
            w = s["work"]
            by_doi.setdefault((w.get("doi") or "").replace("https://doi.org/", "").lower(), s["paperId"])
            by_title.setdefault(_norm(w.get("display_name") or ""), s["paperId"])
    todo = sorted({r["doi"] for r in recs.values()
                   if r["doi"] and r["doi"] not in by_doi and _norm(r["title"]) not in by_title
                   and not re.search(r"[,|\s]", r["doi"])})
    for k in range(0, len(todo), 25):
        q = urllib.parse.quote("|".join(todo[k:k + 25]), safe="|/:")
        for w in _oa(f"/works?filter=doi:{q}&per-page=25&select={OA_META}").get("results", []):
            wid = w["id"].rsplit("/", 1)[-1]
            meta.setdefault(wid, _work(w))
            by_doi[(w.get("doi") or "").replace("https://doi.org/", "").lower()] = wid
    ident = {}
    for eid, r in recs.items():
        wid = by_doi.get(r["doi"]) if r["doi"] else None
        wid = wid or by_title.get(_norm(r["title"]))
        if not wid:
            wid = f"scopus:{eid}"
            meta[wid] = {k: r[k] for k in ("title", "year", "venue", "doi", "abstract", "type")} | {"paperId": wid}
        ident[eid] = wid
    fwd, srch = collections.defaultdict(set), collections.defaultdict(set)
    for eid, ks in cites.items():
        fwd[ident[eid]] |= ks
    for eid, qs in hits.items():
        srch[ident[eid]] |= qs
    stats = {"citing_records": len(cites), "search_records": {q: sum(q in v for v in hits.values())
                                                              for q in SCOPUS_QUERIES},
             "records": len(recs), "mapped_to_openalex": sum(not v.startswith("scopus:") for v in ident.values()),
             "citing_per_seed": per_seed}
    return fwd, srch, stats


# ------------------------------------------------------------------------------------------------ screening
PI = re.compile(r"prompt[- ]injection|injection attack|indirect injection|instruction injection", re.I)
MULTI = re.compile(r"multi-agent|multiagent|\bMAS\b|agent collaboration|collaborat\w* agents|inter-agent|agent-to-agent"
                   r"|agent communication|agent societ|agent network|swarm|multiple (?:LLM )?agents", re.I)
ATTACK = re.compile(r"attack|adversar|malicious|secur|defen[cs]|threat|poison|hijack|tamper|compromis|exploit"
                    r"|red[- ]team|byzantine|backdoor|jailbreak", re.I)
AGENTIC = re.compile(r"\bagent|agentic|\btool|LLM-integrated|plugin|application|assistant|\bMCP\b|workflow", re.I)
AGENT = re.compile(r"\bagent|multi-agent|agentic|\bLLM-based (?:system|application)|tool[- ](?:use|call|integrated|augmented)"
                   r"|\bMCP\b|model context protocol|orchestrat", re.I)
SEC = re.compile(r"attack|adversar|jailbreak|secur|defen[cs]|threat|malicious|poison|hijack|leak|red[- ]team|exploit"
                 r"|privacy|safety|trust|vulnerab|guard|robust", re.I)
LLM = re.compile(r"\bLLM|language model|GPT|foundation model|generative AI|\bAI agent", re.I)
OFF_TOPIC = re.compile(r"reinforcement learning agent|multi-agent reinforcement|robot (?:swarm|navigation)|"
                       r"autonomous vehicle|smart grid|blockchain consensus", re.I)


def screen(c: dict) -> tuple[str, str]:
    text = f"{c.get('title') or ''} {c.get('abstract') or ''}"
    y = c.get("year")
    if not y or not (WINDOW[0] <= y <= WINDOW[1]):
        return "exclude", "E2 outside the 2022-2026 window"
    if not LLM.search(text) and not PI.search(text):
        return "exclude", "E3 not about LLMs or LLM-based systems"
    if OFF_TOPIC.search(text) and not PI.search(text):
        return "exclude", "E3 agents in a non-LLM sense"
    if PI.search(text):
        if AGENTIC.search(text):
            return "include", "I1a prompt injection in agentic or tool-using systems"
        return "exclude", "E1c prompt injection outside agentic or tool-using systems"
    if MULTI.search(text) and ATTACK.search(text):
        return "include", "I1b attacks on or security of LLM multi-agent systems"
    if AGENT.search(text) and SEC.search(text):
        return "exclude", "E1b single-agent safety or security without injection"
    return "exclude", "E1 no injection or multi-agent security focus"


# ------------------------------------------------------------------------------------------------ classification
TYPE_CUES = [  # contribution type, tested in this order on the title, then on the abstract
    ("survey", r"survey|review|\bSoK\b|systemati[sz]ation|taxonom|landscape|overview|roadmap|position paper|"
               r"open (?:problems|challenges)|perspective|primer"),
    ("evaluation", r"benchmark|evaluat|arena|competition|testbed|toolkit|dataset|red[- ]team|measur|assess|"
                   r"empirical (?:study|analysis)|systematically analy"),
    ("defense", r"defen(?:[cs]|d)|mitigat|protect|secur(?:e|ing)\b|shield|guard|safeguard|robust|resist|detect|"
                r"immun|harden|prevent|counter|isolat|sanitiz|filter|firewall|verif|by design|architecture for"),
    ("attack", r"attack|exploit|hijack|inject|poison|jailbreak|threat|vulnerab|risk|malicious|leak|break|abus|"
               r"compromis|manipulat|backdoor|trojan|contagio|infect|steal|spoof|impersonat|tamper|trick|evad|"
               r"understanding|characteri[sz]|trust boundar"),
]
LEAF_CUES = {  # within a contribution type, first matching leaf wins (title first, then abstract)
    "survey": [("Injection and protocol taxonomies", r"taxonom|\bSoK\b|systemati[sz]ation|categori|protocol|"
                                                     r"prompt injection"),
               ("Agent architectures and security", r".")],
    "evaluation": [("Multi-agent evaluation", r"multi-agent|multiagent|\bMAS\b|agent collaboration"),
                   ("Agent tasks and competitions", r"agent|tool|web|competition|environment|computer[- ]use"),
                   ("Prompt and model evaluation", r".")],
    "defense": [("Collaborative defenses", r"multi-agent defen|agents? (?:to )?defen|guard agent|sentinel|debate|"
                                           r"consensus|byzantine|graph neural|\bGNN\b|multi-agent (?:framework|system)"
                                           r" (?:for|to) (?:defen|detect|protect)"),
                ("Signals and monitoring", r"detect|monitor|anomal|activation|latent|manifold|attention|embedding|"
                                           r"classif|forensic|trac(?:e|ing)|signal|audit"),
                ("Identity and access control", r"identity|access control|authori[sz]|authenticat|zero[- ]trust|"
                                                r"registry|credential|privilege|permission|blockchain"),
                ("Tool and execution boundaries", r"sandbox|runtime|execution|compile|isolat|harness|tool[- ]call|"
                                                  r"container|firewall"),
                ("Planning and information flow", r"information[- ]flow|taint|plan|control[- ]flow|integrity|formal|"
                                                  r"by design|architect|pattern|data[- ]flow|provenance|program"),
                ("Prompt and model defenses", r"fine-tun|distill|train|align|preference|instruction hierarch|begging|"
                                              r"spotlight|delimit|guard model|shield|prompt(?:ing)? (?:defen|engineer)"),
                ("Prompt and model defenses", r".")],
    "attack": [("Topology and propagation", r"topolog|cascade|network structure|society|societies|swarm|scale"),
               ("Roles and trust boundaries", r"trust boundar|who (?:speaks|acts)|authori[sz]|role|authority|"
                                              r"security tax|delegat"),
               ("Peer influence and composition", r"multi-agent|multiagent|\bMAS\b|inter-agent|agent-to-agent|"
                                                  r"infect|spread|contagio|propagat|communication|collu|byzantine|"
                                                  r"conjunctive|planning-phase|message"),
               ("State and discovery", r"memory|retriev|\bRAG\b|knowledge base|tool selection|registr|discover|"
                                       r"\bMCP\b|model context protocol|tool description|marketplace|skill"),
               ("Execution and disclosure", r"exfiltrat|leak|disclos|privacy|code execution|remote code|"
                                            r"privilege escalation|data|unauthori[sz]ed"),
               ("Shared and deployed workflows", r"real-world|deploy|case study|software development|enterprise|"
                                                 r"framework|workflow|cloud"),
               ("Content and interpretation", r".")],
}


def classify(c: dict) -> tuple[str, float, str]:
    """Hierarchical codebook decision: contribution type, then leaf. Returns leaf, confidence and path."""
    title, abstract = c.get("title") or "", c.get("abstract") or ""
    ctype, src = None, ""
    for field, text in (("title", title), ("abstract", abstract)):
        for t, rx in TYPE_CUES:
            if re.search(rx, text, re.I):
                ctype, src = t, field
                break
        if ctype:
            break
    if not ctype:
        ctype, src = "attack", "default"
    for field, text in (("title", title), ("abstract", abstract)):
        for leaf, rx in LEAF_CUES[ctype]:
            if rx != "." and re.search(rx, text, re.I):
                conf = 1.0 if (src == "title" and field == "title") else 0.5
                return leaf, conf, f"type {ctype} ({src}); leaf cue ({field})"
    leaf = LEAF_CUES[ctype][-1][0]
    return leaf, 0.25, f"type {ctype} ({src}); default leaf"


# ------------------------------------------------------------------------------------------------ commands
def collect() -> tuple[list[dict], dict, dict, dict, dict, dict, dict]:
    seeds = resolve(corpus())
    back = backward(seeds)
    fwd, meta = forward(seeds)
    seed_ids = {s["paperId"] for s in seeds if s["paperId"]}
    missing = sorted(p for p in back if p not in meta and p not in seed_ids)
    meta.update(metadata(missing))
    sc_fwd, sc_search, sc_stats = scopus(seeds, meta)
    return seeds, back, fwd, meta, sc_fwd, sc_search, sc_stats


def fetch() -> None:
    seeds, back, fwd, meta, sc_fwd, sc_search, st = collect()
    print("resolved", sum(bool(s["paperId"]) for s in seeds), "of", len(seeds), "| backward", len(back),
          "| forward (OpenAlex)", len(fwd), "| forward (Scopus)", len(sc_fwd), "| Scopus search", len(sc_search),
          "| metadata", len(meta))


def run_screen() -> dict:
    seeds, back, fwd_oa, meta, sc_fwd, sc_search, sc_stats = collect()
    fwd = collections.defaultdict(set, {k: set(v) for k, v in fwd_oa.items()})
    for k, v in sc_fwd.items():
        fwd[k] |= v
    with (AUDIT / "12_seed_resolution.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["bibkey", "title", "openalex_id", "resolved_by", "title_similarity", "references",
                    "cited_by_count", "scopus_citing_records"])
        w.writerows([[s["key"], s["title"], s["paperId"], s["how"], s["similarity"],
                      len((s["work"] or {}).get("referenced_works") or []), (s["work"] or {}).get("cited_by_count", ""),
                      sc_stats["citing_per_seed"].get(s["key"], 0)]
                     for s in seeds])
    seed_ids = {s["paperId"] for s in seeds if s["paperId"]}
    seed_titles = {_norm(s["title"]) for s in seeds}
    cands = sorted(p for p in set(back) | set(fwd) | set(sc_search)
                   if p not in seed_ids and p in meta and _norm(meta[p]["title"]) not in seed_titles)
    rows, screened = [], []
    for p in cands:
        m = meta[p]
        nlinks = len(back[p] | fwd[p])
        srch = "+".join(sorted(sc_search.get(p, ())))
        rows.append([p, m["title"], m["year"], len(back[p]), len(fwd_oa.get(p, ())), len(sc_fwd.get(p, ())),
                     nlinks, srch])
        dec, why = screen(m)
        rule = dec
        if dec == "include" and srch:
            why += f" (Scopus search {srch})"
        elif dec == "include" and nlinks < LINK_THRESHOLD:
            dec, why = "exclude", f"E4 linked to fewer than {LINK_THRESHOLD} seeds ({why.split(' ', 1)[0]} met)"
        screened.append({"id": p, "title": m["title"], "year": m["year"], "venue": m["venue"], "doi": m["doi"],
                         "links": nlinks, "backward": len(back[p]), "forward": len(fwd[p]), "rule": rule,
                         "search": srch, "via": "Scopus search" if srch and nlinks < LINK_THRESHOLD else "snowballing",
                         "decision": dec, "criterion": why, "abstract": m["abstract"]})
    with (AUDIT / "13_snowball_candidates.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "title", "year", "cited_by_n_seeds", "cites_n_seeds_openalex", "cites_n_seeds_scopus",
                    "linked_seeds", "scopus_search_hit"])
        w.writerows(rows)
    with (AUDIT / "14_snowball_screening.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "title", "year", "venue", "doi", "linked_seeds", "backward_links",
                    "forward_links", "scopus_search_hit", "title_abstract_rule", "decision", "criterion",
                    "has_abstract"])
        w.writerows([[s["id"], s["title"], s["year"], s["venue"], s["doi"], s["links"], s["backward"],
                      s["forward"], s["search"], s["rule"], s["decision"], s["criterion"],
                      "yes" if s["abstract"] else "no"]
                     for s in screened])
    # stage 2: manual screening and classification of the rule-included candidates (coding spec, see README)
    manual = {r["openalex_id"]: r for r in csv.DictReader((WORK / "snowball" / "manual_screening.csv").open())}
    seed_norm = [_norm(s["title"]) for s in seeds]
    for sc in screened:
        if sc["decision"] != "include":
            continue
        near = max((difflib.SequenceMatcher(None, _norm(sc["title"]), t).ratio() for t in seed_norm), default=0)
        if near >= 0.8:
            sc["decision"], sc["criterion"] = "exclude", "E5 already in the corpus under a variant title"
            continue
        m = manual.get(sc["id"])
        if m is None:
            sc["decision"], sc["criterion"] = "pending", "awaiting manual screening"
        elif m["decision"] == "exclude":
            sc["decision"], sc["criterion"] = "exclude", m["reason_if_excluded"] + " (manual)"
        else:
            sc["leaf"] = m["leaf"]
    pend = [s for s in screened if s["decision"] == "pending"]
    with (WORK / "snowball" / "pending_manual.csv").open("w", newline="") as f:  # worklist for the manual step
        w = csv.writer(f)
        w.writerow(["openalex_id", "title", "year", "venue", "found_by", "linked_seeds", "abstract"])
        w.writerows([[s["id"], s["title"], s["year"], s["venue"], s["via"], s["links"], s["abstract"]] for s in pend])
    inc = [s for s in screened if s["decision"] == "include"]
    cls = []
    for s in inc:
        auto, conf, how = classify(s)
        leaf = s["leaf"]
        cat, sub = next((c, sb) for c, _, subs in tree for sb, leaves in subs for lf, _, _ in leaves if lf == leaf)
        cls.append([s["id"], s["title"], s["year"], cat, sub, leaf, "author (LLM-assisted), codebook", auto, conf,
                    "yes" if auto == leaf else "no", s["links"], s["via"]])
    with (AUDIT / "15_snowball_classification.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["openalex_id", "title", "year", "category", "subcategory", "leaf", "assigned_by", "keyword_leaf",
                    "keyword_confidence", "keyword_agrees", "linked_seeds", "found_by"])
        w.writerows(cls)
    sens = {t: sum(1 for s in screened if s["rule"] == "include" and s["links"] >= t) for t in range(1, 7)}
    reasons = collections.Counter(s["criterion"].split(" (")[0] for s in screened)
    # Scopus search as a completeness check: where did each record that meets the criteria end up?
    seed_of = {p for p in sc_search if p in seed_ids or _norm(meta.get(p, {}).get("title", "")) in seed_titles}
    by_id = {s["id"]: s for s in screened}
    sc_rule = [p for p in sc_search if p in seed_of or by_id.get(p, {}).get("rule") == "include"]
    sc_new = [p for p in sc_rule if p not in seed_of and by_id[p]["links"] < LINK_THRESHOLD]
    oa_fwd_ids, back_ids = set(fwd_oa), set(back)
    scopus_summary = {
        "citing_records": sc_stats["citing_records"], "search_records": sc_stats["search_records"],
        "records": sc_stats["records"], "mapped_to_openalex": sc_stats["mapped_to_openalex"],
        "forward_links": sum(len(v) for v in sc_fwd.values()),
        "candidates_only_via_scopus": len(set(sc_fwd) - oa_fwd_ids - back_ids - seed_ids),
        "unresolved_seeds_cited": sum(1 for s in seeds if not s["paperId"] and sc_stats["citing_per_seed"].get(s["key"])),
        "search_unique": len(sc_search), "search_rule_met": len(sc_rule),
        "search_rule_met_already_seed": len(seed_of & set(sc_rule)),
        "search_rule_met_already_snowball": len(sc_rule) - len(seed_of & set(sc_rule)) - len(sc_new),
        "search_rule_met_new": len(sc_new),
        "search_new_included": sum(1 for p in sc_new if by_id[p]["decision"] == "include"),
    }
    summary = {"search_date": SEARCH_DATE, "source": "OpenAlex and Scopus", "seeds": len(seeds),
               "scopus": scopus_summary,
               "included_snowballing": sum(1 for c in cls if c[11] == "snowballing"),
               "included_scopus_search": sum(1 for c in cls if c[11] == "Scopus search"),
               "seeds_resolved": len(seed_ids), "unresolved": [s["key"] for s in seeds if not s["paperId"]],
               "backward_links": sum(len(v) for v in back.values()), "forward_links": sum(len(v) for v in fwd.values()),
               "backward_candidates": len(set(back) - seed_ids), "forward_candidates": len(set(fwd) - seed_ids),
               "candidates": len(cands), "included": len(inc), "link_threshold": LINK_THRESHOLD,
               "included_by_threshold": sens, "rule_met": sum(1 for s in screened if s["rule"] == "include"), "screening_reasons": dict(reasons),
               "by_leaf": dict(collections.Counter(c[5] for c in cls)),
               "pending_manual": sum(1 for s in screened if s["decision"] == "pending"),
               "keyword_classifier_agreement": round(sum(c[9] == "yes" for c in cls) / max(1, len(cls)), 3)}
    (AUDIT / "snowball_summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return summary


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "screen"
    if cmd == "fetch":
        fetch()
    else:
        run_screen()
