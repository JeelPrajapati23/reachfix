"""MCP server: DepGraph exposure, dependency paths, fix plans, advisory search and lockfile scans as tools.

The same functions the API and scripts run (depgraph/dispatch.py,
depgraph/scan.py, views.plan_summaries), called directly instead of through
the LLM router: the MCP client is already an LLM, so it picks the tool and
names the entities itself. Only `ask` goes through the router and answer
synthesis (Groq). `search_advisories` embeds the query (locally). Everything
else is graph traversal and makes no provider call.

Results are trimmed for a model's context: node ids lose their "npm:" /
"project:" prefix, dependency paths become "a → b → c" chains, rows are
capped by `limit`, and totals are always over every row.

Artifacts load on the first tool call, not at startup, so a missing build
output comes back as a tool error the client can show instead of a server
that won't start.

Run: `uv run reachfix-mcp` (stdio) or `uv run reachfix-mcp --transport streamable-http --port 8001`.
"""

import argparse
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import groq
from dotenv import load_dotenv
from huggingface_hub.errors import HfHubHTTPError
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from .api.resources import DEFAULT_DEPGRAPH_DIR, LIVE_OSV_DIR, LIVE_RELEASES_DIR, REPO_ROOT, Resources
from .api.views import fix_plans, plan_summaries
from .depgraph import load_context, route_query
from .depgraph.dispatch import (corpus_projects, named, node_type, project_versions, run_affected_projects,
                                run_dependency_path, run_exposure, run_remediation, semantic_chunks)
from .depgraph.scan import run_scan
from .depgraph.synthesis import synthesize_answer
from .extraction.schema import load_schema
from .graph import graph_node
from .llm_client import build_client
from .npm.advisory_index import DEFAULT_VARIANT, index_path
from .npm.live_releases import RegistryClient
from .npm.osv import OsvClient
from .npm.sbom import load_scan_document
from .retrieval import build_embedding_client

INSTRUCTIONS = """\
reachfix answers supply-chain questions about npm dependency trees: which advisories reach a project and \
through which chain of transitive dependencies, which projects an advisory reaches, and the smallest upgrade \
that removes a vulnerable copy without breaking any dependent's declared range.

The dataset is 20 pinned npm projects (call list_projects), their full resolved lockfiles, and the OSV \
advisories for every installed version. Names resolve loosely: "express", "express@4.17.1", a GHSA id or a \
CVE id. For the user's own project, use scan_lockfile on its package-lock.json. "Safe" and "fixed" mean \
against the advisories in this dataset (plus live OSV for scans), not every advisory that exists."""

LIMIT_MAX = 200
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
# scan_lockfile with live=True queries OSV.dev and the npm registry.
READ_ONLY_OPEN = ToolAnnotations(read_only_hint=True, open_world_hint=True)
# Schema v2's edge types, for explore's relation filter.
Relation = Literal["DEPENDS_ON", "HAS_VULNERABILITY", "AFFECTS_VERSION_RANGE", "FIXED_IN", "VERSION_OF",
                   "MAINTAINED_BY", "LICENSED_UNDER", "EXPLOITABLE_WHEN"]


def load_mcp_resources(depgraph_dir: Path = DEFAULT_DEPGRAPH_DIR, variant: str = DEFAULT_VARIANT) -> Resources:
    """Like api.resources.load_resources, but without Groq (only `ask` needs it; see Server.client).

    Query embeddings run locally (retrieval/embeddings.py), so search_advisories needs no HF_TOKEN.
    """
    required = [depgraph_dir / name for name in ("graph.pkl", "nodes.jsonl", "advisory_chunks.jsonl")]
    missing = [p.name for p in required if not p.exists()]
    if not Path(f"{index_path(depgraph_dir, variant)}.vectors.npy").exists():
        missing.append(f"advisory index {variant!r}")
    if missing:
        raise FileNotFoundError(f"missing {', '.join(missing)} in {depgraph_dir}; run the build scripts "
                                f"(build_depgraph.py, build_advisory_index.py) first")
    return Resources(ctx=load_context(depgraph_dir, build_embedding_client(), variant), schema=load_schema(),
                     client=None, osv=OsvClient(LIVE_OSV_DIR), registry=RegistryClient(LIVE_RELEASES_DIR))


def short(node_id: str) -> str:
    return node_id.removeprefix("npm:").removeprefix("project:")


def chain(path: list[str]) -> str:
    return " → ".join(short(p) for p in path)


def hit_row(row: dict) -> dict:
    """An exposure / affected-projects / scan row: one vulnerable copy reached through one chain."""
    out = {
        "project": short(row["project"]),
        "vulnerable": short(row["version_id"]),
        "advisory": row["vulnerability_id"],
        "aliases": row.get("aliases", []),
        "severity": row.get("severity"),
        "summary": row.get("summary"),
        "chain": chain(row["path"]),
        "depth": row["depth"],
        "fixed_in": [short(v) for v in row.get("fixed_in", [])],
        "url": row.get("source_url"),
    }
    if row.get("dev_only"):
        out["dev_only"] = True
    return out


def plan_row(plan: dict) -> dict:
    """A views.plan_summaries entry without what only the graph panel draws."""
    steps = [{k: v for k, v in step.items() if v is not None and not (k == "kind" and v == "step")}
             for step in plan["steps"]]
    return {
        "project": short(plan["project"]),
        "vulnerable": short(plan["version_id"]),
        "chain": chain(plan["path"]),
        "advisories": [a["vulnerability_id"] for a in plan["advisories"]],
        "status": plan["status"],
        "label": plan["label"],
        "why": plan["why"],
        "steps": steps,
        "target_version": plan["target_version"],
        "fully_resolved": plan["resolved"],
        "override_fallback": plan["override"],
        **({"dev_only": True} if plan.get("dev_only") else {}),
    }


def page(result: dict, rows: list[dict], limit: int) -> dict:
    """Capped rows plus the counts over all of them, so the model knows what it isn't seeing."""
    out = {"total_results": result.get("total_results", len(rows)), "shown": min(limit, len(rows)),
           "results": rows[:limit]}
    if result.get("totals"):
        out["totals"] = result["totals"]
    warnings = [w for w in [result.get("warning"), *result.get("warnings", [])] if w]
    if warnings:
        out["warnings"] = warnings
    return out


def read_lockfile(path: str | None, lockfile: dict | str | None) -> dict:
    if (path is None) == (lockfile is None):
        raise ToolError("pass exactly one of `path` (a package-lock.json or the directory holding it) "
                        "and `lockfile` (its contents)")
    if isinstance(lockfile, dict):
        return lockfile
    if lockfile is not None:
        text, where = lockfile, "lockfile"
    else:
        file = Path(path).expanduser()
        if file.is_dir():
            file = file / "package-lock.json"
        if not file.is_file():
            raise ToolError(f"no such file: {file}")
        text, where = file.read_text(encoding="utf-8"), str(file)
    try:
        lock = json.loads(text)
    except json.JSONDecodeError as e:
        raise ToolError(f"{where} is not valid JSON: {e}")
    if not isinstance(lock, dict):
        raise ToolError(f"{where} is not a package-lock.json or SBOM object")
    return lock


class Server:
    """The artifacts the tools read, loaded once on first use (tools run in worker threads, hence the lock)."""

    def __init__(self, resources: Resources | None, loader: Callable[[], Resources]):
        self._resources = resources
        self._loader = loader
        self._lock = threading.Lock()

    @property
    def res(self) -> Resources:
        if self._resources is None:
            with self._lock:
                if self._resources is None:
                    try:
                        self._resources = self._loader()
                    except FileNotFoundError as e:
                        raise ToolError(str(e))
        return self._resources

    @property
    def client(self):
        res = self.res
        if res.client is None:
            try:
                res.client = build_client()
            except RuntimeError as e:
                raise ToolError(f"{e}; `ask` needs Groq, the other tools don't")
        return res.client

    def resolve(self, name: str, kinds: set[str], role: str) -> tuple[str, list[str]]:
        """(name, node ids) for the router's dispatch functions; a ToolError if nothing of the right kind matches."""
        ctx = self.res.ctx
        ids = ctx.lookup.resolve(name)
        if not ids:
            raise ToolError(f"no package, version or advisory in the dataset matches {name!r}")
        ids = [i for i in ids if node_type(ctx, i) in kinds]
        if not ids:
            raise ToolError(f"{name!r} is not a {role}")
        return name, ids


def create_server(resources: Resources | None = None,
                  loader: Callable[[], Resources] = load_mcp_resources) -> MCPServer:
    """Build the server. Pass `resources` directly (tests) or let the first tool call run `loader`."""
    state = Server(resources, loader)
    mcp = MCPServer("reachfix", instructions=INSTRUCTIONS)
    PACKAGE = {"Package", "PackageVersion"}
    ADVISORY = {"Vulnerability"}

    @mcp.tool(annotations=READ_ONLY)
    def list_projects() -> dict:
        """The 20 npm projects the dataset resolved full lockfiles for, and the dataset's size.

        Other tools accept any of these by name ("express") or name@version.
        """
        ctx = state.res.ctx
        roots = corpus_projects(ctx)
        types = [node["node_type"] for node in ctx.lookup.nodes.values()]
        return {"projects": [short(r) for r in roots],
                "dataset": {"package_versions": types.count("PackageVersion"),
                            "advisories": types.count("Vulnerability"),
                            "graph_edges": ctx.store.edge_count(),
                            "advisory_chunks": len(ctx.chunks_by_id),
                            "fix_plans_available": ctx.releases is not None}}

    @mcp.tool(annotations=READ_ONLY)
    def project_exposure(project: str, advisory: str | None = None, limit: int = 25) -> dict:
        """Which advisories reach a project, and through which chain of dependencies.

        One row per (vulnerable installed version, advisory), worst severity
        and shallowest first. `totals` counts every row, not just those shown.

        Args:
            project: a package or name@version, e.g. "react-scripts" or "axios@0.21.1". A package
                that is not one of the 20 projects is walked in every lockfile it's installed in.
            advisory: only this advisory (GHSA or CVE id), to answer "is X exposed to Y?".
            limit: rows to return (totals still cover all of them).
        """
        resolved = [state.resolve(project, PACKAGE, "package or package version")]
        if advisory:
            resolved.append(state.resolve(advisory, ADVISORY, "GHSA/CVE advisory id"))
        result = run_exposure(state.res.ctx, resolved)
        return page(result, [hit_row(r) for r in result["results"]], max(1, min(limit, LIMIT_MAX)))

    @mcp.tool(annotations=READ_ONLY)
    def affected_projects(advisory: str, limit: int = 25) -> dict:
        """Which of the dataset's projects an advisory reaches, with the dependency chain to each vulnerable copy.

        A CVE can map to several advisories (e.g. an incomplete-fix
        follow-up); all of them are included.

        Args:
            advisory: a GHSA or CVE id.
            limit: rows to return (totals still cover all of them).
        """
        result = run_affected_projects(state.res.ctx, [state.resolve(advisory, ADVISORY, "GHSA/CVE advisory id")])
        return page(result, [hit_row(r) for r in result["results"]], max(1, min(limit, LIMIT_MAX)))

    @mcp.tool(annotations=READ_ONLY)
    def dependency_path(project: str, dependency: str, limit: int = 25) -> dict:
        """How a project pulls in a dependency: the chain to each installed version of it, and that version's advisories.

        Args:
            project: a package or name@version, e.g. "webpack" or "webpack@4.46.0".
            dependency: a package (every version of it in the tree) or one name@version.
            limit: rows to return.
        """
        ctx = state.res.ctx
        resolved = [state.resolve(project, PACKAGE, "package or package version"),
                    state.resolve(dependency, PACKAGE, "package or package version")]
        result = run_dependency_path(ctx, resolved)
        rows = [{"project": short(r["project"]), "dependency": short(r["version_id"]), "chain": chain(r["path"]),
                 "depth": r["depth"],
                 "advisories": [{"advisory": v["vulnerability_id"], "severity": v["severity"],
                                 "summary": v["summary"], "fixed_in": [short(f) for f in v["fixed_in"]]}
                                for v in r["vulnerabilities"]]} for r in result["results"]]
        return page(result, rows, max(1, min(limit, LIMIT_MAX)))

    @mcp.tool(annotations=READ_ONLY)
    def plan_fix(project: str | None = None, dependency: str | None = None, advisory: str | None = None,
                 limit: int = 10) -> dict:
        """The smallest upgrade that removes vulnerable copies from a project's lockfile, without breaking any
        dependent's declared semver range.

        Each plan has a status: in_range (a lockfile refresh picks up a fix),
        split (dependents need different copies), blocked (some dependent's
        range excludes every fix, so that dependent is upgraded too, up to the
        project if needed), no_fix, or upgrade_root. `steps` are the commands;
        `override_fallback` is an npm `overrides` entry that works regardless.
        The planner is greedy, not a solver, and "fixed" means clear of the
        advisories in this dataset.

        Name at least one of project / dependency / advisory. With no project,
        every dataset project holding the dependency or advisory is planned.
        For the user's own project, use scan_lockfile instead.

        Args:
            project: one of the dataset's projects (see list_projects).
            dependency: only fix this package (or name@version) in the tree.
            advisory: only fix copies affected by this GHSA/CVE id.
            limit: plans to return (at most 10; totals cover all of them).
        """
        if not (project or dependency or advisory):
            raise ToolError("name at least one of project, dependency, advisory")
        ctx = state.res.ctx
        resolved = []
        if project:
            name, ids = state.resolve(project, PACKAGE, "package or package version")
            if not any((ctx.store.get_entity(v) or {}).get("properties", {}).get("is_root")
                       for i in ids for v in project_versions(ctx, i)):
                raise ToolError(f"{project!r} is not one of the dataset's projects (see list_projects); pass it as "
                                f"`dependency`, or scan the user's own package-lock.json with scan_lockfile")
            resolved.append((name, ids))
        if dependency:
            resolved.append(state.resolve(dependency, PACKAGE, "package or package version"))
        if advisory:
            resolved.append(state.resolve(advisory, ADVISORY, "GHSA/CVE advisory id"))
        result = run_remediation(ctx, resolved)
        return page(result, [plan_row(p) for p in plan_summaries(result["results"])], max(1, min(limit, 10)))

    @mcp.tool(annotations=READ_ONLY)
    def search_advisories(query: str, package: str | None = None, top_k: int = 5) -> dict:
        """Semantic search over OSV advisory text: what a vulnerability is, how it's exploited, what triggers it.

        Returns the best-matching advisory passages with their ids, severity
        and osv.dev link. Use this for "what" and "how" questions; use the
        graph tools for "which projects" and "through what".

        Args:
            query: natural-language description, e.g. "prototype pollution through merge of untrusted objects".
            package: only advisories affecting this package.
            top_k: passages to return (1-20).
        """
        ctx = state.res.ctx
        if ctx.embedding_client is None:
            raise ToolError("no embedding client is configured; search_advisories needs one to embed the query")
        candidates = None
        if package:
            _, ids = state.resolve(package, {"Package"}, "package name (without @version)")
            names = {i.removeprefix("npm:") for i in ids}
            candidates = {c for c, chunk in ctx.chunks_by_id.items() if names & set(chunk["affected_packages"])}
            if not candidates:
                return {"results": [], "warnings": [f"no advisory text for {package!r} in the dataset"]}
        try:
            hits = semantic_chunks(ctx, query, max(1, min(top_k, 20)), candidates)
        except HfHubHTTPError as e:
            raise ToolError(f"Hugging Face embedding call failed: {e}")
        return {"results": [{"advisory": h["doc_id"], "passage": h["chunk_id"], "score": round(h["score"], 3),
                             "aliases": h.get("aliases", []), "severity": h.get("severity"),
                             "summary": h.get("summary"), "packages": h.get("affected_packages", []),
                             "text": h["text"], "url": h.get("source_url")} for h in hits]}

    @mcp.tool(annotations=READ_ONLY)
    def explore(entity: str, relation: Relation | None = None, limit: int = 50) -> dict:
        """A node and its direct neighbors in the knowledge graph.

        Node types: Package, PackageVersion, Vulnerability (advisory),
        Maintainer, License, ExploitCondition. Relations: DEPENDS_ON (version
        → version), HAS_VULNERABILITY (version → advisory),
        AFFECTS_VERSION_RANGE / FIXED_IN (advisory → package / version),
        VERSION_OF, MAINTAINED_BY, LICENSED_UNDER, EXPLOITABLE_WHEN (advisory →
        condition an LLM extracted from the advisory text, with quoted evidence).
        DEPENDS_ON edges are merged across all 20 lockfiles; for one project's
        tree use project_exposure or dependency_path.

        Args:
            entity: a package, name@version, or GHSA/CVE id.
            relation: only edges of this type.
            limit: neighbors to return.
        """
        ctx = state.res.ctx
        ids = ctx.lookup.resolve(entity)
        if not ids:
            raise ToolError(f"no package, version or advisory in the dataset matches {entity!r}")
        nodes = []
        for node_id in ids:
            edges = ctx.store.neighbors(node_id, relation=relation, direction="both")
            neighbors = []
            for e in edges[:max(1, min(limit, LIMIT_MAX))]:
                other = named(ctx, e["entity_id"])
                row = {"relation": e["relation"], "direction": e["direction"], "node": short(other["node_id"]),
                       "type": other["type"]}
                if other["name"] not in (other["node_id"], row["node"]):  # a condition's id says nothing
                    row["name"] = other["name"]
                if evidence := [p["evidence"] for p in e["provenance"] if p.get("evidence")]:
                    row["evidence"] = evidence[:2]  # LLM-extracted edges quote the advisory text they rest on
                neighbors.append(row)
            nodes.append({**graph_node(ctx.store, node_id), "entity_id": short(node_id),
                          "total_neighbors": len(edges), "neighbors": neighbors})
        return {"matches": nodes}

    @mcp.tool(annotations=READ_ONLY_OPEN)
    def scan_lockfile(path: str | None = None, lockfile: dict | str | None = None, live: bool = True,
                      limit: int = 25) -> dict:
        """Scan the user's own package-lock.json (lockfileVersion 2 or 3) or an SBOM of it (CycloneDX or
        SPDX 2.x JSON, e.g. from `npm sbom`): every advisory that reaches it, through which chain, and a
        fix plan (package.json edits and commands) per vulnerable copy.

        With live=True, versions outside the dataset are checked on OSV.dev and
        release metadata the fix plans need is fetched from the npm registry.
        `coverage` says how many installed versions were checked. No LLM call.

        Args:
            path: a package-lock.json or SBOM file, or the project directory holding a package-lock.json
                (on the server's machine).
            lockfile: the lockfile's or SBOM's contents (a JSON object) instead of a path.
            live: query OSV.dev and the npm registry (False: dataset only, no network).
            limit: exposure rows to return (totals cover all of them; up to 10 fix plans).
        """
        res = state.res
        lock = read_lockfile(path, lockfile)
        try:
            upload = load_scan_document(res.ctx.store, lock, res.ctx.releases.packages if res.ctx.releases else None,
                                        res.osv if live else None, res.registry if live else None)
        except ValueError as e:
            raise ToolError(str(e))
        result = run_scan(res.ctx, upload, registry=res.registry if live else None)
        out = page(result, [hit_row(r) for r in result["results"]], max(1, min(limit, LIMIT_MAX)))
        remediation = result["remediation"]
        return {"project": {k: v for k, v in result["project"].items() if k != "id"},
                "coverage": result["coverage"], **out,
                "fix_plans": [plan_row(p) for p in plan_summaries(remediation["results"])] if remediation else [],
                "fix_plan_totals": remediation["totals"] if remediation else None}

    @mcp.tool(annotations=READ_ONLY)
    def ask(question: str, top_k: int = 5) -> dict:
        """Answer a free-form question with reachfix's own router and a cited answer (uses Groq).

        Prefer the specific tools; this is for questions that mix graph facts
        and advisory text, or to get reachfix's own answer with its [G#]
        (graph fact) and [A#] (advisory text) citations.

        Args:
            question: e.g. "Is axios@0.21.1 exposed to CVE-2022-0155, and how do I fix it?"
            top_k: advisory passages to retrieve (1-20).
        """
        res = state.res
        client = state.client
        try:
            result = route_query(question, client=client, ctx=res.ctx, schema=res.schema,
                                 top_k=max(1, min(top_k, 20)))
            answer = synthesize_answer(result, client=client)
        except (groq.APIError, HfHubHTTPError) as e:
            raise ToolError(f"upstream provider error: {e}")
        return {"answer": answer["answer"], "citations": answer["citations"], "totals": answer["totals"],
                "checks": answer["checks"], "declined": answer["declined"], "route": result["executed_route"],
                "pattern": result["executed_pattern"], "warnings": answer["warnings"],
                "fix_plans": [plan_row(p) for p in fix_plans(result)]}

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve reachfix's DepGraph tools over MCP.")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env")  # clients may start the server from any working directory
    server = create_server()
    if args.transport == "stdio":
        server.run()
    else:
        server.run("streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
