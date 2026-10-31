"""Run the DepGraph router over eval/depgraph_questions.yaml and score it.

For each question: did the classifier pick the expected route (and pattern
/ relation), did every named entity resolve, and did the retrieved results
pass the question's graph-derived `expect` checks. One Groq call per
question, plus one embedding call when a route searches text.

With --answers it also synthesizes each answer (Phase 8, one more Groq call
per question) and checks it: grounded (no advisory id or citation marker
that isn't in the evidence), cites at least one piece of evidence, and
mentions the expected facts (each expected advisory by GHSA id or CVE, and
expected versions / maintainers / licenses by name).

Output: eval/results/depgraph_router.json (depgraph_answers.json with --answers)

Usage:
    uv run python scripts/eval_depgraph_router.py [--ids exp-01,sem-02] [--variant NAME] [--answers]
"""

import argparse
import json
import re
from pathlib import Path

import yaml
from dotenv import load_dotenv

from reachfix.depgraph import load_context, route_query
from reachfix.depgraph.synthesis import synthesize_answer
from reachfix.extraction.schema import load_schema
from reachfix.llm_client import build_client
from reachfix.npm.advisory_index import DEFAULT_VARIANT, VARIANTS
from reachfix.npm.remediation import summarize
from reachfix.retrieval import build_embedding_client

ROOT = Path(__file__).resolve().parent.parent
DEPGRAPH = ROOT / "data" / "processed" / "depgraph"
QUESTIONS = ROOT / "eval" / "depgraph_questions.yaml"
OUT_PATH = ROOT / "eval" / "results" / "depgraph_router.json"
ANSWERS_OUT_PATH = ROOT / "eval" / "results" / "depgraph_answers.json"


def result_nodes(result: dict) -> set[str]:
    nodes = set()
    for row in result.get("results", []):
        nodes.update(v for k, v in row.items() if k in ("node_id", "project", "version_id") and isinstance(v, str))
        nodes.update(row.get("path", []))
    return nodes


def result_vulnerabilities(result: dict) -> set[str]:
    found = {row.get("vulnerability_id") for row in result.get("results", [])}
    found |= {row.get("node_id") for row in result.get("results", [])}
    found |= {a["vulnerability_id"] for a in result.get("advisories", []) if isinstance(a, dict)}
    found |= {a["vulnerability_id"] for row in result.get("results", []) for a in row.get("advisories", [])
              if isinstance(a, dict)}  # remediation rows
    return {f for f in found if f}


def check(expect: dict, result: dict, chunks_by_id: dict) -> list[str]:
    """Failed checks, as readable strings (empty = pass)."""
    failures = []
    if want := expect.get("vulnerabilities_include"):
        missing = set(want) - result_vulnerabilities(result)
        if missing:
            failures.append(f"missing advisories {sorted(missing)}")
    if want := expect.get("path"):
        if not any(row.get("path") == want for row in result.get("results", [])):
            failures.append(f"path not found: {' -> '.join(want)}")
    if want := expect.get("nodes_include"):
        missing = set(want) - result_nodes(result)
        if missing:
            failures.append(f"missing nodes {sorted(missing)}")
    if package := expect.get("chunks_affect_package"):
        chunks = result.get("chunks", [])
        stray = [c["chunk_id"] for c in chunks if package not in c.get("affected_packages", [])]
        if not chunks or stray:
            failures.append(f"chunks not about {package}: {stray or 'no chunks'}")
    if pattern := expect.get("top_chunk_matches"):
        chunks = result.get("chunks", [])
        top = chunks[0] if chunks else None
        if top is None or not re.search(pattern, f"{top.get('summary', '')}\n{top['text']}", re.IGNORECASE):
            failures.append(f"top chunk doesn't match /{pattern}/: {top['chunk_id'] if top else 'no chunks'}")
    if want := expect.get("remediation"):
        failures.extend(remediation_failures(want, result))
    if expect.get("no_evidence") and (result.get("chunks") or result.get("results")):
        failures.append(f"retrieved evidence for a question that should be declined ({result['executed_route']})")
    return failures


def remediation_failures(want: dict, result: dict) -> list[str]:
    plans = [r["plan"] for r in result.get("results", []) if r.get("version_id") == want["version_id"] and "plan" in r]
    if not plans:
        return [f"no remediation plan for {want['version_id']}"]
    plan, failures = plans[0], []
    if plan["status"] != want["status"]:
        failures.append(f"status {plan['status']}, expected {want['status']}")
    if "target_version" in want and plan.get("target_version") != want["target_version"]:
        failures.append(f"target {plan.get('target_version')}, expected {want['target_version']}")
    roots = {name: u["version"] for name, u in summarize(plan)["root"].items()} if plan["status"] in ("blocked", "no_fix") else {}
    for name, version in want.get("root", {}).items():
        if roots.get(name) != version:
            failures.append(f"project upgrade {name} -> {roots.get(name)}, expected {version}")
    return failures


def display_names(node_id: str) -> list[str]:
    """How an answer may name a node: "npm:qs@6.7.0" -> "qs@6.7.0" or "qs 6.7.0"; "npm-user:ljharb" -> "ljharb"."""
    name = node_id.split(":", 1)[1] if ":" in node_id else node_id
    package, _, version = name.rpartition("@")
    return [name, f"{package} {version}"] if node_id.startswith("npm:") and package else [name]


def expected_mentions(expect: dict, ctx) -> list[list[str]]:
    """Each expected fact as a list of acceptable spellings (any one counts)."""
    mentions = []
    for vuln_id in expect.get("vulnerabilities_include", []):
        aliases = (ctx.store.get_entity(vuln_id) or {}).get("properties", {}).get("aliases", [])
        mentions.append([vuln_id, *[a for a in aliases if a.startswith("CVE-")]])
    if path := expect.get("path"):
        mentions.append(display_names(path[-1]))
    mentions.extend(display_names(n) for n in expect.get("nodes_include", []))
    if want := expect.get("remediation"):
        if "target_version" in want:
            mentions.append([want["target_version"]])
        mentions.extend([version] for version in want.get("root", {}).values())
    return mentions


def answer_checks(answer: dict, expect: dict, ctx) -> dict:
    text = answer["answer"].lower()
    missing = [spellings[0] for spellings in expected_mentions(expect, ctx)
               if not any(s.lower() in text for s in spellings)]
    checks = answer["checks"]
    return {"grounded": not checks["ungrounded_ids"] and not checks["unknown_markers"] and not checks["ungrounded_versions"],
            "cites": bool(checks["cited_markers"]), "missing_mentions": missing,
            "ungrounded_ids": checks["ungrounded_ids"], "unknown_markers": checks["unknown_markers"],
            "ungrounded_versions": checks["ungrounded_versions"]}


def main() -> None:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ids", default=None)
    parser.add_argument("--variant", choices=sorted(VARIANTS), default=DEFAULT_VARIANT)
    parser.add_argument("--answers", action="store_true", help="Also synthesize and check each answer (Phase 8)")
    args = parser.parse_args()

    questions = yaml.safe_load(QUESTIONS.read_text(encoding="utf-8"))["questions"]
    if args.ids:
        wanted = set(args.ids.split(","))
        questions = [q for q in questions if q["id"] in wanted]

    ctx = load_context(DEPGRAPH, build_embedding_client(), args.variant)
    schema = load_schema(ROOT / "schema" / "v2.yaml")
    client = build_client()

    rows = []
    for q in questions:
        result = route_query(q["question"], client=client, ctx=ctx, schema=schema)
        route_ok = result["route"] == q["route"]
        pattern_ok = q["route"] != "relational" or result["pattern"] == q.get("pattern")
        relation_ok = "relation" not in q or result["relation"] == q["relation"]
        failures = check(q.get("expect", {}), result, ctx.chunks_by_id)
        rows.append({"id": q["id"], "question": q["question"], "expected_route": q["route"],
                     "route": result["route"], "executed_route": result["executed_route"],
                     "pattern": result["pattern"], "relation": result["relation"],
                     "entities": result["entities"], "warnings": result["warnings"],
                     "route_ok": route_ok, "pattern_ok": pattern_ok and relation_ok,
                     "checks_ok": not failures, "failures": failures,
                     "reasoning": result["classification_reasoning"]})
        if args.answers:
            answer = synthesize_answer(result, client=client)
            rows[-1]["answer"] = answer["answer"]
            rows[-1]["answer_checks"] = answer_checks(answer, q.get("expect", {}), ctx)
        mark = "ok " if route_ok and pattern_ok and relation_ok and not failures else "BAD"
        print(f"{mark} {q['id']:8} {result['route']}/{result['pattern'] or '-'}"
              f"{'/' + result['relation'] if result['relation'] else ''}  "
              f"entities={[e['name'] for e in result['entities']]}"
              + (f"  failures={failures}" if failures else "")
              + (f"  warnings={result['warnings']}" if result["warnings"] else ""), flush=True)
        if args.answers:
            ac = rows[-1]["answer_checks"]
            print(f"    answer: grounded={ac['grounded']} cites={ac['cites']}"
                  + (f" missing={ac['missing_mentions']}" if ac["missing_mentions"] else "")
                  + (f" ungrounded={ac['ungrounded_ids']} unknown_markers={ac['unknown_markers']}"
                     f" ungrounded_versions={ac['ungrounded_versions']}"
                     if not ac["grounded"] else ""), flush=True)

    n = len(rows)
    summary = {
        "questions": n,
        "route_accuracy": sum(r["route_ok"] for r in rows) / n,
        "pattern_accuracy": sum(r["route_ok"] and r["pattern_ok"] for r in rows) / n,
        "checks_passed": sum(r["checks_ok"] for r in rows),
        "fully_correct": sum(r["route_ok"] and r["pattern_ok"] and r["checks_ok"] for r in rows),
        "variant": args.variant,
    }
    if args.answers:
        acs = [r["answer_checks"] for r in rows]
        summary.update({"answers_grounded": sum(a["grounded"] for a in acs),
                        "answers_citing": sum(a["cites"] for a in acs),
                        "answers_with_all_expected_mentions": sum(not a["missing_mentions"] for a in acs)})
    out_path = ANSWERS_OUT_PATH if args.answers else OUT_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"summary": summary, "questions": rows}, indent=2), encoding="utf-8")
    print(f"\nroute {summary['route_accuracy']:.0%}, route+pattern {summary['pattern_accuracy']:.0%}, "
          f"checks passed {summary['checks_passed']}/{n}, fully correct {summary['fully_correct']}/{n}")
    if args.answers:
        print(f"answers: grounded {summary['answers_grounded']}/{n}, citing {summary['answers_citing']}/{n}, "
              f"all expected facts mentioned {summary['answers_with_all_expected_mentions']}/{n}")
    print(f"-> {out_path.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
