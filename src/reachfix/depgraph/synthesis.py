"""Turn a DepGraph router result into a cited answer (Phase 8).

Three things are kept apart:
- Evidence for the model: numbered graph facts [G1..] (readable dependency
  chains, relations) and advisory chunks [A1..] with their full text.
- Exact totals, never computed by the model. react-scripts alone has 177
  advisories in its tree, so the model gets the counts (from the router,
  over every row, before its cap) plus a capped list ranked worst severity
  first, instead of hundreds of rows to count.
- The citation block returned to the caller: every chain, every advisory
  with its osv.dev URL, and chunk previews. Previews are for display only;
  the model reasoned over the full text.

After generation, the answer is checked: citation markers must point at
evidence that exists, and every CVE / GHSA / MAL id in the answer must
appear in the evidence. An id that doesn't is flagged as ungrounded. So is
a "name@version" the evidence never pairs (a remediation answer's main
risk is a plausible but invented version).
"""

import re

from groq import Groq

from ..llm_client import DEFAULT_MODEL, generate_text

MAX_GRAPH_FACTS = 40
MAX_REMEDIATION_FACTS = 12  # each is a whole plan; keeps a project-wide question within Groq's 8K tokens/minute
SNIPPET_CHARS = 300
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
# The model sometimes writes ids with Unicode hyphens (U+2010-2012, e.g. a
# non-breaking hyphen inside "GHSA-33f9-...") and citations in full-width
# brackets (U+3010/3011), and slips zero-width spaces into markers. These break
# copy-paste, search, and the checks below, so they are normalized to "-" and
# "[ ]" and the zero-width spaces dropped. Narrow and non-breaking spaces
# (U+202F, U+00A0, e.g. "express\u202f@\u202f4.22.0") become plain spaces. Dashes
# are left alone.
ANSWER_NORMALIZATION = str.maketrans({"\u2010": "-", "\u2011": "-", "\u2012": "-", "\u3010": "[", "\u3011": "]",
                                      "\u200b": None, "\u202f": " ", "\u00a0": " "})
ADVISORY_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)\b", re.IGNORECASE)
# "jws @3.2.2" / "jws @ 3.2.2" -> "jws@3.2.2": the model sometimes spaces out package@version.
SPACED_VERSION_RE = re.compile(r"(?<=[\w.-]) ?@ ?(?=\d)")
# "[ G1 ]" / "[ G1, A2 ]" -> "[G1]" / "[G1, A2]": the model sometimes pads citation brackets.
PADDED_MARKERS_RE = re.compile(r"\[\s+([GA]\d+(?:\s*,\s*[GA]\d+)*)\s*\]|\[([GA]\d+(?:\s*,\s*[GA]\d+)*)\s+\]")
# "... without an override [Exact totals]." -> "... without an override.": the totals have no
# marker, but the model sometimes cites them like one.
TOTALS_CITATION_RE = re.compile(r"\s*\[\s*exact totals\s*\]", re.IGNORECASE)
MARKER_GROUP_RE = re.compile(r"\[([^\]]+)\]")
MARKER_RE = re.compile(r"\b([GA]\d+)\b")
PACKAGE_VERSION_RE = re.compile(r"(?<![\w/@.-])((?:@[\w.-]+/)?[\w.-]+)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]*[0-9A-Za-z])?)")
REMEDIATION_STATUS = {
    "in_range": "fixable by a lockfile refresh",
    "split": "fixable by a lockfile refresh (separate copies)",
    "upgrade_root": "the project itself must be upgraded",
    "blocked": "a dependent's declared range excludes every fixed version",
    "no_fix": "no fixed version exists",
}

SYSTEM_PROMPT = """You answer questions about npm dependency trees and security \
advisories using ONLY the evidence given: graph facts [G#], exact totals, and \
advisory text [A#]. Do not use outside knowledge.

- Cite every claim with the markers it rests on, e.g. [G2] or [A1].
- When you name a vulnerability, give its advisory id and CVE as written in \
the evidence. Never mention an id that is not in the evidence.
- When a dependency chain answers the question, quote it exactly as given.
- Use the exact totals as given; don't recount the listed facts, which may \
be a capped subset. The totals have no marker: cite only [G#] and [A#].
- If the evidence lists no vulnerability for something, say none is known in \
this dataset, not that it is safe.
- When a graph fact gives a remediation plan, give its steps with exactly \
the versions, ranges and overrides it states. Never suggest a version the \
evidence doesn't give. A fixed version is fixed only for the advisories in \
this dataset.
- If the evidence doesn't answer the question, say so plainly.
- Be concise: a short direct answer first, then the supporting details. List \
at most 10 advisories or paths (the most severe first) and summarize the rest \
with the exact totals."""


def short(node_id: str) -> str:
    return node_id.removeprefix("npm:")


def advisory_label(row: dict) -> str:
    cves = [a for a in row.get("aliases", []) if a.upper().startswith("CVE-")]
    return " / ".join([row["vulnerability_id"], *cves])


def vuln_tag(row: dict) -> str:
    severity = f", {row['severity']}" if row.get("severity") else ""
    return f"[VULNERABLE: {advisory_label(row)}{severity}]"


def chain(path: list[str]) -> str:
    """The plan's readable form: a → depends_on → b → depends_on → c."""
    return " → depends_on → ".join(short(n) for n in path)


def _rank(row: dict) -> tuple:
    return (SEVERITY_ORDER.get(row.get("severity"), 4), row.get("depth", 0), row["vulnerability_id"])


def _exposure_facts(result: dict) -> tuple[list[str], list[str], list[dict], list[str]]:
    """(facts, totals, advisories, chains) for exposure / affected_projects rows."""
    rows = result.get("results", [])
    # One row per (project, advisory, version); the same finding can arrive once per lockfile.
    best: dict[tuple, dict] = {}
    for row in rows:
        best.setdefault((row["project"], row["vulnerability_id"], row["version_id"]), row)
    ranked = sorted(best.values(), key=_rank)

    facts, chains = [], []
    for row in ranked:
        fix = f" Fixed in: {', '.join(short(v) for v in row['fixed_in'])}." if row.get("fixed_in") else " No fixed version listed."
        line = f"{chain(row['path'])} {vuln_tag(row)} {row.get('summary') or ''}.{fix}"
        chains.append(f"{chain(row['path'])} {vuln_tag(row)}")
        facts.append(line)

    totals = []
    for project, t in result.get("totals", {}).items():
        sev = ", ".join(f"{n} {s.lower()}" for s, n in t["by_severity"].items())
        totals.append(f"{short(project)}: {t['advisories']} advisories on {t['vulnerable_versions']} "
                      f"vulnerable versions ({sev}); deepest at {t['max_depth']} hops.")
    total_rows = result.get("total_results", len(rows))
    if not ranked:
        scope = ", ".join(short(p) for p in result.get("projects", [])) or "the named entities"
        totals.append(f"No known vulnerable dependency found for {scope} in this dataset.")
    if total_rows > len(rows):
        totals.append(f"Only the {len(rows)} most severe of {total_rows} (project, advisory, version) findings "
                      f"are listed as facts; the totals above cover all of them.")
    if len(facts) > MAX_GRAPH_FACTS:
        totals.append(f"Graph facts below show the {MAX_GRAPH_FACTS} most severe of {len(facts)}.")
    advisories = list({r["vulnerability_id"]: r for r in ranked}.values())
    return facts[:MAX_GRAPH_FACTS], totals, advisories, chains


def _path_facts(result: dict) -> tuple[list[str], list[str], list[dict], list[str]]:
    facts, chains, advisories = [], [], {}
    for row in result.get("results", []):
        tags = " ".join(vuln_tag(v) for v in row.get("vulnerabilities", []))
        chains.append(f"{chain(row['path'])} {tags}".strip())
        fixes = "; ".join(f"{v['vulnerability_id']} fixed in {', '.join(short(f) for f in v['fixed_in']) or 'no listed version'}"
                          for v in row.get("vulnerabilities", []))
        facts.append(f"{chains[-1]} ({row['depth']} hops).{(' ' + fixes + '.') if fixes else ''}")
        advisories.update({v["vulnerability_id"]: v for v in row.get("vulnerabilities", [])})
    totals = [f"{len(facts)} dependency paths found."] if facts else ["No dependency path found between them."]
    return facts[:MAX_GRAPH_FACTS], totals, list(advisories.values()), chains


def _neighbor_facts(result: dict) -> tuple[list[str], list[str], list[dict], list[str]]:
    labels = {a["vulnerability_id"]: advisory_label(a) for a in result.get("advisories", [])}
    facts = []
    for row in result.get("results", []):
        subj, obj = (row["source"]["name"], row["name"]) if row["direction"] == "out" else (row["name"], row["source"]["name"])
        line = f"{labels.get(subj, short(subj))} --{row['relation']}--> {labels.get(obj, short(obj))}"
        quotes = [p["evidence"] for p in row.get("provenance", []) if p.get("evidence")]
        if quotes:
            line += " (advisory text: " + " | ".join(f'"{q}"' for q in quotes) + ")"
        props = row.get("properties", {})
        if props.get("expression") and props.get("operator"):
            line += f" (license expression: {props['expression']})"
        facts.append(line)
    totals = [f"{len(facts)} relations found."] if facts else ["No such relation found in the graph."]
    return facts[:MAX_GRAPH_FACTS], totals, result.get("advisories", []), facts


def _hybrid_facts(result: dict) -> tuple[list[str], list[str], list[dict], list[str]]:
    advisories = result.get("advisories", [])
    ranked = sorted(advisories, key=lambda a: (SEVERITY_ORDER.get(a.get("severity"), 4), a["vulnerability_id"]))
    facts = [f"{advisory_label(a)} ({a.get('severity') or 'unlabeled'}): {a.get('summary') or ''}" for a in ranked]
    totals = [f"The named entities link to {len(advisories)} advisories in the graph; the text below comes only from them."]
    return facts[:MAX_GRAPH_FACTS], totals, ranked, []


def _remediation_facts(result: dict) -> tuple[list[str], list[str], list[dict], list[str]]:
    facts, chains, advisories = [], [], {}
    for row in result.get("results", []):
        plan = row["plan"]
        tags = " ".join(vuln_tag(a) for a in row["advisories"])
        chains.append(f"{chain(row['path'])} {tags}")
        lowest = ""
        if plan.get("lowest_safe_version"):
            lowest = f" Lowest version outside every targeted advisory's range: {plan['package']}@{plan['lowest_safe_version']}."
            # Say why the plan skips it, so the answer doesn't present both as the fix.
            others, target = plan.get("lowest_safe_still_affected_by"), plan.get("target_version")
            if others and target and target != plan["lowest_safe_version"]:
                count = f"{len(others)} other advisor{'y' if len(others) == 1 else 'ies'}"
                lowest = (f"{lowest[:-1]}, but it is still affected by {count} in this dataset, so the plan targets "
                          f"{plan['package']}@{target} instead.")
        facts.append(f"In {short(row['project'])}: {chains[-1]}. Status: {REMEDIATION_STATUS[plan['status']]}.{lowest} "
                     f"Plan: {' '.join(row['actions'])}")
        advisories.update({a["vulnerability_id"]: a for a in row["advisories"]})

    totals = []
    t = result.get("totals")
    if t:
        by_status = "; ".join(f"{REMEDIATION_STATUS[s]}: {n}" for s, n in t["by_status"].items())
        copies = "copy" if t["copies"] == 1 else "copies"
        totals.append(f"{t['copies']} vulnerable dependency {copies} planned across "
                      f"{', '.join(short(p) for p in t['projects'])}: {by_status}.")
        totals.append(f"{t['fully_resolved']} of {t['copies']} can be fixed without an npm override.")
    else:
        totals.append("No vulnerable dependency matched the question, so there is nothing to remediate in this dataset.")
    shown = min(len(facts), MAX_REMEDIATION_FACTS)
    if result.get("total_results", 0) > shown:
        totals.append(f"Plans below cover the {shown} most severe of {result['total_results']} copies.")
    kept = {a["vulnerability_id"] for row in result.get("results", [])[:shown] for a in row["advisories"]}
    return facts[:shown], totals, [a for a in advisories.values() if a["vulnerability_id"] in kept], chains


# Fixed replies for questions with no evidence to answer from. No advisory ids or versions, so
# check_answer has nothing to flag.
DECLINED_ANSWERS = {
    "off_topic": ("I can only answer questions about npm packages, their dependency trees and the security "
                  "advisories that affect them: for example, whether a project is exposed to a CVE, how a "
                  "package reaches a vulnerable dependency, or how to upgrade out of it."),
    "no_match": ("No advisory text in this dataset is close enough to that question to answer it. Try naming a "
                 "package, version or advisory id, or describing a kind of vulnerability (e.g. prototype "
                 "pollution, ReDoS, path traversal)."),
}


def build_evidence(result: dict) -> dict:
    """Everything synthesis shows the model and returns as citations, from a router result."""
    route = result["executed_route"]
    if route == "relational":
        builder = {"exposure": _exposure_facts, "affected_projects": _exposure_facts,
                   "dependency_path": _path_facts, "remediation": _remediation_facts}.get(result.get("executed_pattern") or result.get("pattern"), _neighbor_facts)
        facts, totals, advisories, chains = builder(result)
    elif route == "graph_guided_hybrid":
        facts, totals, advisories, chains = _hybrid_facts(result)
    else:
        facts, totals, advisories, chains = [], [], [], []
    chunks = result.get("chunks", [])
    return {"facts": facts, "totals": totals, "advisories": advisories, "chains": chains, "chunks": chunks}


def build_user_prompt(query: str, evidence: dict, warnings: list[str]) -> str:
    facts = "\n".join(f"[G{i}] {f}" for i, f in enumerate(evidence["facts"], 1)) or "(none)"
    totals = "\n".join(f"- {t}" for t in evidence["totals"]) or "(none)"
    chunks = "\n\n".join(
        f"[A{i}] {c['doc_id']} ({', '.join(c.get('affected_packages', []))}): {c.get('summary', '')}\n{c['text']}"
        for i, c in enumerate(evidence["chunks"], 1)) or "(none)"
    notes = "\n".join(f"- {w}" for w in warnings)
    return (f"Question: {query}\n\n"
            + (f"Retrieval notes:\n{notes}\n\n" if notes else "")
            + f"Exact totals:\n{totals}\n\nGraph facts:\n{facts}\n\nAdvisory text:\n{chunks}\n\nAnswer:")


def grounded_ids(evidence: dict) -> set[str]:
    ids = set()
    for a in evidence["advisories"]:
        ids.update([a["vulnerability_id"], *a.get("aliases", [])])
    for c in evidence["chunks"]:
        ids.update([c["doc_id"], *c.get("aliases", [])])
    for line in evidence["facts"]:
        ids.update(ADVISORY_ID_RE.findall(line))
    return {i.upper() for i in ids}


def ungrounded_versions(answer: str, evidence: dict) -> list[str]:
    """"name@version" mentions whose name and version never appear together in one evidence line."""
    lines = [*evidence["facts"], *evidence["totals"], *evidence["chains"], *(c["text"] for c in evidence["chunks"])]
    flagged = set()
    for name, version in PACKAGE_VERSION_RE.findall(answer):
        if not any(name in line and version in line for line in lines):
            flagged.add(f"{name}@{version}")
    return sorted(flagged)


def check_answer(answer: str, evidence: dict) -> dict:
    """Citation markers that point at nothing, and advisory ids or package versions not in the evidence."""
    valid = {f"G{i}" for i in range(1, len(evidence["facts"]) + 1)} | {f"A{i}" for i in range(1, len(evidence["chunks"]) + 1)}
    markers = {m for group in MARKER_GROUP_RE.findall(answer) for m in MARKER_RE.findall(group)}
    mentioned = {m.upper() for m in ADVISORY_ID_RE.findall(answer)}
    return {
        "unknown_markers": sorted(markers - valid),
        "ungrounded_ids": sorted(mentioned - grounded_ids(evidence)),
        "ungrounded_versions": ungrounded_versions(answer, evidence),
        "cited_markers": sorted(markers & valid),
    }


def citation_block(evidence: dict) -> dict:
    return {
        "dependency_chains": evidence["chains"],
        "advisories": [{"id": a["vulnerability_id"], "aliases": a.get("aliases", []), "severity": a.get("severity"),
                        "summary": a.get("summary"), "url": a.get("source_url")} for a in evidence["advisories"]],
        "chunks": [{"marker": f"A{i}", "chunk_id": c["chunk_id"], "advisory": c["doc_id"], "url": c.get("source_url"),
                    "snippet": c["text"][:SNIPPET_CHARS]} for i, c in enumerate(evidence["chunks"], 1)],
        "graph_facts": [{"marker": f"G{i}", "fact": f} for i, f in enumerate(evidence["facts"], 1)],
    }


def declined(result: dict) -> str | None:
    """Why there is nothing to answer from: "off_topic", "no_match" (nothing above the semantic floor), or None."""
    if result["executed_route"] == "off_topic":
        return "off_topic"
    if result["executed_route"] == "semantic" and not result.get("chunks"):
        return "no_match"
    return None


def synthesize_answer(result: dict, *, client: Groq, model_name: str = DEFAULT_MODEL) -> dict:
    evidence = build_evidence(result)
    if reason := declined(result):
        answer = DECLINED_ANSWERS[reason]  # no LLM call: there is no evidence to answer from
    else:
        prompt = build_user_prompt(result["query"], evidence, result.get("warnings", []))
        answer = generate_text(client, system_prompt=SYSTEM_PROMPT, user_prompt=prompt, model_name=model_name)
        answer = SPACED_VERSION_RE.sub("@", answer.translate(ANSWER_NORMALIZATION))
        answer = PADDED_MARKERS_RE.sub(lambda m: f"[{m[1] or m[2]}]", answer)
        answer = TOTALS_CITATION_RE.sub("", answer)
    return {
        "query": result["query"],
        "route": result["route"],
        "executed_route": result["executed_route"],
        "declined": reason,
        "answer": answer,
        "checks": check_answer(answer, evidence),
        "totals": evidence["totals"],
        "citations": citation_block(evidence),
        "warnings": result.get("warnings", []),
    }
