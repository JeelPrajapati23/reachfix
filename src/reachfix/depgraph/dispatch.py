"""Run a classified DepGraph query against the graph, the advisory index, or both.

Glue only: every retrieval step is an existing function (graph/exposure.py,
GraphStore.neighbors, retrieval/windows.search_chunks). Result rows carry
the node ids, paths and provenance that answer synthesis needs, so it never
has to query the graph again.

A project is a PackageVersion. Walks from it are scoped to one lockfile:
its own if it is a corpus root, otherwise each lockfile it is installed in.
A bare package name ("express") means its corpus-root versions if any,
else every version in a tree.
"""

from collections import Counter
from dataclasses import dataclass, field

from huggingface_hub import InferenceClient
from pydantic import BaseModel

from ..graph import GraphStore
from ..graph.exposure import dependency_paths, exposed_lockfiles, exposure
from ..npm.advisory_index import DEFAULT_VARIANT, embed_query
from ..npm.graph_load import LOCKFILE_DOC_PREFIX, root_of_lockfile
from ..npm.lookup import NodeLookup
from ..npm.releases import Releases
from ..npm.remediation import actions, is_resolved, plan_fix
from ..retrieval import VectorIndex
from ..retrieval.windows import search_chunks

MAX_ROWS = 200  # cap on result rows per query; totals are computed before the cap
MAX_PLANS = 40  # remediation rows carry whole plans, so they are capped lower
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}


@dataclass
class DepGraphContext:
    store: GraphStore
    lookup: NodeLookup
    index: VectorIndex
    chunks_by_id: dict[str, dict]
    embedding_client: InferenceClient | None
    variant: str = DEFAULT_VARIANT
    releases: Releases | None = None  # remediation's release metadata (scripts/build_remediation.py)
    chunks_by_advisory: dict[str, list[str]] = field(init=False)

    def __post_init__(self) -> None:
        self.chunks_by_advisory = {}
        for chunk_id, chunk in self.chunks_by_id.items():
            self.chunks_by_advisory.setdefault(chunk["doc_id"], []).append(chunk_id)


def node_type(ctx: DepGraphContext, node_id: str) -> str | None:
    entity = ctx.store.get_entity(node_id)
    return entity["entity_type"] if entity else None


def corpus_projects(ctx: DepGraphContext) -> list[str]:
    """The dataset's root projects, as node ids ("npm:express@4.17.1")."""
    return sorted(n for n, node in ctx.lookup.nodes.items() if node["properties"].get("is_root"))


def named(ctx: DepGraphContext, node_id: str) -> dict:
    entity = ctx.store.get_entity(node_id) or {}
    return {"node_id": node_id, "name": entity.get("canonical_name", node_id), "type": entity.get("entity_type")}


def resolve(ctx: DepGraphContext, names: list[str]) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """([(name as written, node ids)], warnings for names that matched nothing)."""
    resolved, warnings = [], []
    for name in names:
        ids = ctx.lookup.resolve(name)
        if ids:
            resolved.append((name, ids))
        else:
            warnings.append(f"no package, version or advisory matches {name!r}")
    return resolved, warnings


def project_versions(ctx: DepGraphContext, node_id: str) -> list[str]:
    """A PackageVersion as itself; a Package as its root versions, else all its in-tree versions."""
    kind = node_type(ctx, node_id)
    if kind == "PackageVersion":
        return [node_id]
    if kind != "Package":
        return []
    versions = [e["entity_id"] for e in ctx.store.neighbors(node_id, relation="VERSION_OF", direction="in")]
    in_tree = [v for v in versions if ctx.store.get_entity(v)["properties"].get("in_tree")]
    roots = [v for v in in_tree if ctx.store.get_entity(v)["properties"].get("is_root")]
    return sorted(roots or in_tree)


def lockfiles_for(ctx: DepGraphContext, version_id: str) -> list[str]:
    """The lockfile a walk from this version should follow: its own if it's a root, else every one containing it."""
    props = (ctx.store.get_entity(version_id) or {}).get("properties", {})
    own = LOCKFILE_DOC_PREFIX + version_id.removeprefix("npm:")
    if props.get("is_root"):
        return [own]
    return list(props.get("lockfile_doc_ids", []))


def split_entities(ctx: DepGraphContext, resolved) -> tuple[list[str], set[str]]:
    """(project version ids in query order, advisory ids) from resolved entities."""
    projects, advisories = [], set()
    for _, ids in resolved:
        for node_id in ids:
            kind = node_type(ctx, node_id)
            if kind == "Vulnerability":
                advisories.add(node_id)
            elif kind in ("Package", "PackageVersion"):
                projects.extend(v for v in project_versions(ctx, node_id) if v not in projects)
    return projects, advisories


def advisory_row(ctx: DepGraphContext, vuln_id: str) -> dict:
    props = (ctx.store.get_entity(vuln_id) or {}).get("properties", {})
    return {"vulnerability_id": vuln_id, "aliases": props.get("aliases", []), "severity": props.get("severity"),
            "summary": props.get("summary"), "source_url": props.get("source_url")}


def package_of(version_id: str) -> str:
    """"npm:@babel/core@7.0.0" -> "@babel/core"."""
    return version_id.removeprefix("npm:").rsplit("@", 1)[0]


def fixed_in(ctx: DepGraphContext, vuln_id: str, package: str) -> list[str]:
    """The advisory's FIXED_IN versions for one package (an advisory can cover several packages)."""
    return sorted(e["entity_id"] for e in ctx.store.neighbors(vuln_id, relation="FIXED_IN", direction="out")
                  if package_of(e["entity_id"]) == package)


def vulnerabilities_of(ctx: DepGraphContext, version_id: str) -> list[dict]:
    return [{**advisory_row(ctx, e["entity_id"]), "fixed_in": fixed_in(ctx, e["entity_id"], package_of(version_id))}
            for e in ctx.store.neighbors(version_id, relation="HAS_VULNERABILITY", direction="out")]


def by_severity(row: dict) -> tuple:
    """Worst first, then shallowest, so capping keeps the rows that matter most."""
    return (SEVERITY_ORDER.get(row.get("severity"), 4), row["depth"], row["vulnerability_id"], row["version_id"])


def exposure_totals(rows: list[dict]) -> dict[str, dict]:
    """Per project, over every row (not the capped list): advisories, vulnerable versions, severities, depth."""
    totals = {}
    for project in sorted({r["project"] for r in rows}):
        mine = [r for r in rows if r["project"] == project]
        advisories = {r["vulnerability_id"]: r.get("severity") or "UNLABELED" for r in mine}
        totals[project] = {
            "advisories": len(advisories),
            "vulnerable_versions": len({r["version_id"] for r in mine}),
            "by_severity": dict(sorted(Counter(advisories.values()).items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 4))),
            "max_depth": max(r["depth"] for r in mine),
        }
    return totals


def run_exposure(ctx: DepGraphContext, resolved) -> dict:
    projects, advisories = split_entities(ctx, resolved)
    rows = []
    for project in projects:
        for lockfile in lockfiles_for(ctx, project):
            for hit in exposure(ctx.store, project, lockfile, vulnerability_ids=advisories or None):
                rows.append({"project": project, "lockfile_doc_id": lockfile, **hit,
                             **advisory_row(ctx, hit["vulnerability_id"]),
                             "fixed_in": fixed_in(ctx, hit["vulnerability_id"], package_of(hit["version_id"]))})
    rows.sort(key=by_severity)
    return {"pattern": "exposure", "projects": projects, "advisories": sorted(advisories), "results": rows[:MAX_ROWS],
            "total_results": len(rows), "totals": exposure_totals(rows)}


def run_affected_projects(ctx: DepGraphContext, resolved, packages: set[str] | None = None) -> dict:
    """Which corpus projects reach each named advisory. packages, if given, limits it to those packages' versions."""
    _, advisories = split_entities(ctx, resolved)
    rows = []
    for vuln_id in sorted(advisories):
        for lockfile, versions in exposed_lockfiles(ctx.store, vuln_id).items():
            root = root_of_lockfile(lockfile)
            for hit in exposure(ctx.store, root, lockfile, vulnerability_ids={vuln_id}):
                if packages is not None and package_of(hit["version_id"]) not in packages:
                    continue
                rows.append({"project": root, "lockfile_doc_id": lockfile, **hit, **advisory_row(ctx, vuln_id),
                             "fixed_in": fixed_in(ctx, vuln_id, package_of(hit["version_id"]))})
    rows.sort(key=lambda r: (r["vulnerability_id"], r["project"], r["depth"]))
    return {"pattern": "affected_projects", "advisories": sorted(advisories), "results": rows[:MAX_ROWS],
            "total_results": len(rows), "totals": exposure_totals(rows)}


def run_dependency_path(ctx: DepGraphContext, resolved) -> dict:
    """Paths from the first named project to every version of the second named package."""
    if len(resolved) < 2:
        return {"pattern": "dependency_path", "results": [], "warning": "need a project and a dependency"}
    projects, _ = split_entities(ctx, resolved[:1])
    targets = set()
    for node_id in resolved[1][1]:
        if node_type(ctx, node_id) == "Package":  # any version of it, wherever it sits in the tree
            targets.update(e["entity_id"] for e in ctx.store.neighbors(node_id, relation="VERSION_OF", direction="in"))
        else:
            targets.add(node_id)
    rows = []
    for project in projects:
        for lockfile in lockfiles_for(ctx, project):
            paths = dependency_paths(ctx.store, project, lockfile)
            rows.extend({"project": project, "lockfile_doc_id": lockfile, "version_id": v, "path": paths[v],
                         "depth": len(paths[v]) - 1, "vulnerabilities": vulnerabilities_of(ctx, v)}
                        for v in sorted(targets & set(paths)))
    rows.sort(key=lambda r: (r["depth"], r["version_id"]))
    return {"pattern": "dependency_path", "results": rows[:MAX_ROWS], "total_results": len(rows)}


def remediation_scope(ctx: DepGraphContext, resolved) -> tuple[list[str], set[str], set[str], set[str]]:
    """(projects, advisories, dependency package names, dependency version ids) for a remediation question.

    The first named package with a corpus-root version is the project
    ("fix minimatch in mocha 8.4.0"); any other named package or version
    narrows which dependencies to fix. request@2.88.2 is itself a corpus
    root, so in "how can react-scripts drop request?" it counts as the
    dependency only because it is named second.
    """
    projects, advisories, packages, versions = [], set(), set(), set()
    for _, ids in resolved:
        for node_id in ids:
            kind = node_type(ctx, node_id)
            if kind == "Vulnerability":
                advisories.add(node_id)
                continue
            if kind not in ("Package", "PackageVersion"):
                continue
            roots = [v for v in project_versions(ctx, node_id)
                     if (ctx.store.get_entity(v) or {}).get("properties", {}).get("is_root")]
            if roots and not projects:
                projects = roots
            elif kind == "Package":
                packages.add(node_id.removeprefix("npm:"))
            else:
                versions.add(node_id)
    return projects, advisories, packages, versions


def remediation_totals(rows: list[dict]) -> dict:
    """Over every planned copy (not the capped list): how each can be fixed."""
    return {"copies": len(rows), "by_status": dict(Counter(r["plan"]["status"] for r in rows).most_common()),
            "fully_resolved": sum(r["resolved"] for r in rows), "projects": sorted({r["project"] for r in rows})}


def run_remediation(ctx: DepGraphContext, resolved) -> dict:
    """A fix plan for each vulnerable copy the question points at (npm/remediation.py)."""
    result = {"pattern": "remediation", "results": [], "total_results": 0}
    if ctx.releases is None:
        return {**result, "warning": "no release metadata loaded; run scripts/build_remediation.py"}
    projects, advisories, packages, versions = remediation_scope(ctx, resolved)
    if projects:
        lockfiles = [(p, lf) for p in projects for lf in lockfiles_for(ctx, p)]
    else:  # no project named: every lockfile holding the named advisory / dependency
        docs = set()
        for vuln_id in advisories:
            docs.update(exposed_lockfiles(ctx.store, vuln_id))
        for version in versions | {v for name in packages for v in project_versions(ctx, f"npm:{name}")}:
            docs.update(lockfiles_for(ctx, version))
        lockfiles = [(root_of_lockfile(d), d) for d in sorted(docs)]

    groups: dict[tuple[str, str, str], dict] = {}
    for project, lockfile in lockfiles:
        for hit in exposure(ctx.store, project, lockfile, vulnerability_ids=advisories or None):
            version_id = hit["version_id"]
            if (packages or versions) and package_of(version_id) not in packages and version_id not in versions:
                continue
            groups.setdefault((project, lockfile, version_id), {"path": hit["path"], "depth": hit["depth"]})

    missing_before = set(ctx.releases.missing)
    rows = []
    for (project, lockfile, version_id), group in groups.items():
        plan = plan_fix(ctx.store, ctx.releases, lockfile, version_id, advisories or None)
        rows.append({"project": project, "lockfile_doc_id": lockfile, "version_id": version_id, **group,
                     "advisories": [advisory_row(ctx, a) for a in plan["advisories"]],
                     "plan": plan, "actions": actions(plan), "resolved": is_resolved(plan)})
    worst = {id(r): min((SEVERITY_ORDER.get(a.get("severity"), 4) for a in r["advisories"]), default=4) for r in rows}
    rows.sort(key=lambda r: (worst[id(r)], r["depth"], r["version_id"]))
    result.update(results=rows[:MAX_PLANS], total_results=len(rows), totals=remediation_totals(rows))
    if new_missing := ctx.releases.missing - missing_before:
        result["warning"] = (f"release metadata missing for {sorted(new_missing)}; those plans may be "
                             f"incomplete (run scripts/fetch_release_metadata.py, then scripts/build_remediation.py)")
    return result


def run_neighbors(ctx: DepGraphContext, resolved, relation: str | None) -> dict:
    rows = []
    for _, ids in resolved:
        for node_id in ids:
            for edge in ctx.store.neighbors(node_id, relation=relation, direction="both"):
                rows.append({"source": named(ctx, node_id), **named(ctx, edge["entity_id"]),
                             "relation": edge["relation"], "direction": edge["direction"],
                             "confidence": edge["confidence"], "provenance": edge["provenance"],
                             "properties": edge.get("properties", {})})
    # Advisory endpoints come with their aliases, so an answer can name the CVE as well as the GHSA id.
    advisories = sorted({n for r in rows for n in (r["source"]["node_id"], r["node_id"])
                         if node_type(ctx, n) == "Vulnerability"})
    return {"pattern": "neighbors", "relation": relation, "results": rows[:MAX_ROWS], "total_results": len(rows),
            "advisories": [advisory_row(ctx, a) for a in advisories]}


def non_root_packages(ctx: DepGraphContext, resolved) -> set[str] | None:
    """Package names if every named package/version is a bare Package with no corpus-root version, else None."""
    names = set()
    for _, ids in resolved:
        for node_id in ids:
            kind = node_type(ctx, node_id)
            if kind == "PackageVersion":
                return None
            if kind == "Package":
                if any(ctx.store.get_entity(v)["properties"].get("is_root") for v in project_versions(ctx, node_id)):
                    return None
                names.add(node_id.removeprefix("npm:"))
    return names or None


def run_relational(ctx: DepGraphContext, decision: BaseModel, resolved) -> dict:
    pattern = decision.pattern or "neighbors"
    if pattern == "exposure":
        # "Which projects pull in a follow-redirects vulnerable to GHSA-x?" can come back as
        # `exposure`, but exposure walks down from a project, and a bare dependency name is
        # not one. With a named advisory and no project, answer upward instead.
        packages = non_root_packages(ctx, resolved)
        if packages and split_entities(ctx, resolved)[1]:
            result = run_affected_projects(ctx, resolved, packages)
            result["warning"] = (f"no named project is a corpus root; answered which projects reach the advisory "
                                 f"through {', '.join(sorted(packages))}")
            return result
        return run_exposure(ctx, resolved)
    if pattern == "affected_projects":
        return run_affected_projects(ctx, resolved)
    if pattern == "dependency_path":
        return run_dependency_path(ctx, resolved)
    if pattern == "remediation":
        return run_remediation(ctx, resolved)
    return run_neighbors(ctx, resolved, decision.relation)


def semantic_chunks(ctx: DepGraphContext, query: str, top_k: int, candidates: set[str] | None = None) -> list[dict]:
    return search_chunks(query, index=ctx.index, chunks_by_id=ctx.chunks_by_id, client=ctx.embedding_client,
                         top_k=top_k, candidate_chunk_ids=candidates,
                         query_vector=embed_query(ctx.embedding_client, query, ctx.variant))


def graph_advisories(ctx: DepGraphContext, resolved) -> set[str]:
    """Advisories the named entities point at.

    An advisory is itself. A package name means the advisories affecting that
    package ("what vulnerabilities has lodash had?"). A version means every
    advisory reachable in its dependency tree ("... the vulnerable packages
    in express@4.17.1").
    """
    found = set()
    for _, ids in resolved:
        for node_id in ids:
            kind = node_type(ctx, node_id)
            if kind == "Vulnerability":
                found.add(node_id)
            elif kind == "Package":
                found.update(e["entity_id"] for e in
                             ctx.store.neighbors(node_id, relation="AFFECTS_VERSION_RANGE", direction="in"))
            elif kind == "PackageVersion":
                for lockfile in lockfiles_for(ctx, node_id):
                    found.update(hit["vulnerability_id"] for hit in exposure(ctx.store, node_id, lockfile))
    return found


def run_graph_guided_hybrid(ctx: DepGraphContext, query: str, resolved, top_k: int) -> dict:
    advisories = graph_advisories(ctx, resolved)
    candidates = {c for a in advisories for c in ctx.chunks_by_advisory.get(a, [])}
    result = {"advisories": [advisory_row(ctx, a) for a in sorted(advisories)][:MAX_ROWS]}
    if not candidates:
        # Nothing in the graph to scope by: fall back to an unscoped semantic search.
        result["warning"] = "no advisories linked to the named entities; searched all advisories"
    result["chunks"] = semantic_chunks(ctx, query, top_k, candidates or None)
    return result
