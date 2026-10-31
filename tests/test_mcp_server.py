"""Synthetic fixtures only — no real artifacts, no Groq/HF calls."""
import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from reachfix.api import Resources
from reachfix.depgraph import DepGraphContext
from reachfix.graph import NetworkXGraphStore
from reachfix.mcp_server import chain, create_server
from reachfix.npm.graph_load import to_entity
from reachfix.npm.lookup import NodeLookup

# axios@0.21.1 (a corpus root) -> follow-redirects@1.13.1 [GHSA-74fj / CVE-2022-0155, fixed in 1.14.7]
LOCKFILE = "lockfile:npm:axios@0.21.1"
NODES = [
    {"node_id": "npm:axios", "node_type": "Package", "name": "axios", "aliases": ["axios"], "properties": {}},
    {"node_id": "npm:axios@0.21.1", "node_type": "PackageVersion", "name": "axios@0.21.1",
     "aliases": ["axios@0.21.1"], "properties": {"is_root": True, "in_tree": True}},
    {"node_id": "npm:follow-redirects", "node_type": "Package", "name": "follow-redirects",
     "aliases": ["follow-redirects"], "properties": {}},
    {"node_id": "npm:follow-redirects@1.13.1", "node_type": "PackageVersion", "name": "follow-redirects@1.13.1",
     "aliases": ["follow-redirects@1.13.1"], "properties": {"in_tree": True, "lockfile_doc_ids": [LOCKFILE]}},
    {"node_id": "npm:follow-redirects@1.14.7", "node_type": "PackageVersion", "name": "follow-redirects@1.14.7",
     "aliases": ["follow-redirects@1.14.7"], "properties": {}},
    {"node_id": "GHSA-74fj-2j2h-c42q", "node_type": "Vulnerability", "name": "GHSA-74fj-2j2h-c42q",
     "aliases": ["GHSA-74fj-2j2h-c42q", "CVE-2022-0155"],
     "properties": {"aliases": ["CVE-2022-0155"], "severity": "HIGH", "summary": "Exposure of private headers",
                    "source_url": "https://osv.dev/vulnerability/GHSA-74fj-2j2h-c42q"}},
    {"node_id": "GHSA-74fj-2j2h-c42q::cond::0", "node_type": "ExploitCondition",
     "name": "a redirect crosses to another host", "aliases": [], "properties": {}},
]
EDGES = [
    {"subject_id": "npm:axios@0.21.1", "relation": "VERSION_OF", "object_id": "npm:axios", "source_doc_id": "axios"},
    {"subject_id": "npm:follow-redirects@1.13.1", "relation": "VERSION_OF", "object_id": "npm:follow-redirects",
     "source_doc_id": "follow-redirects"},
    {"subject_id": "npm:axios@0.21.1", "relation": "DEPENDS_ON", "object_id": "npm:follow-redirects@1.13.1",
     "source_doc_id": LOCKFILE, "properties": {"lockfile_doc_ids": [LOCKFILE]}},
    {"subject_id": "npm:follow-redirects@1.13.1", "relation": "HAS_VULNERABILITY", "object_id": "GHSA-74fj-2j2h-c42q",
     "source_doc_id": "GHSA-74fj-2j2h-c42q", "properties": {"lockfile_doc_ids": [LOCKFILE]}},
    {"subject_id": "GHSA-74fj-2j2h-c42q", "relation": "AFFECTS_VERSION_RANGE", "object_id": "npm:follow-redirects",
     "source_doc_id": "GHSA-74fj-2j2h-c42q", "properties": {"versions": [], "ranges": [
         {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.14.7"}]}]}},
    {"subject_id": "GHSA-74fj-2j2h-c42q", "relation": "FIXED_IN", "object_id": "npm:follow-redirects@1.14.7",
     "source_doc_id": "GHSA-74fj-2j2h-c42q"},
    {"subject_id": "GHSA-74fj-2j2h-c42q", "relation": "EXPLOITABLE_WHEN", "object_id": "GHSA-74fj-2j2h-c42q::cond::0",
     "provenance": [{"source_doc_id": "GHSA-74fj-2j2h-c42q", "extraction_method": "llm",
                     "evidence": "when a redirect crosses to another host"}]},
]
LOCK = {"name": "my-app", "lockfileVersion": 3, "packages": {
    "": {"name": "my-app", "version": "0.1.0", "dependencies": {"axios": "^0.21.1"}},
    "node_modules/axios": {"version": "0.21.1", "dependencies": {"follow-redirects": "^1.10.0"}},
    "node_modules/follow-redirects": {"version": "1.13.1"},
}}


@pytest.fixture
def server():
    store = NetworkXGraphStore()
    store.load([to_entity(n) for n in NODES], EDGES)
    ctx = DepGraphContext(store=store, lookup=NodeLookup(NODES), index=None, chunks_by_id={}, embedding_client=None)
    return create_server(Resources(ctx=ctx, schema=None, client=None))


def call(server, name, **arguments) -> dict:
    result = asyncio.run(server.call_tool(name, arguments))
    assert not result.is_error
    return json.loads(result.content[0].text)


def test_every_tool_is_read_only():
    tools = asyncio.run(create_server(loader=lambda: pytest.fail("listing tools must not load data")).list_tools())
    assert {t.name for t in tools} == {"list_projects", "project_exposure", "affected_projects", "dependency_path",
                                       "plan_fix", "search_advisories", "explore", "scan_lockfile", "ask"}
    assert all(t.annotations.read_only_hint for t in tools)


def test_list_projects_lists_corpus_roots(server):
    body = call(server, "list_projects")
    assert body["projects"] == ["axios@0.21.1"]
    assert body["dataset"]["advisories"] == 1 and body["dataset"]["fix_plans_available"] is False


def test_project_exposure_gives_the_chain_and_fix(server):
    body = call(server, "project_exposure", project="axios", advisory="cve-2022-0155")
    [row] = body["results"]
    assert row["chain"] == "axios@0.21.1 → follow-redirects@1.13.1"
    assert row["advisory"] == "GHSA-74fj-2j2h-c42q" and row["aliases"] == ["CVE-2022-0155"]
    assert row["fixed_in"] == ["follow-redirects@1.14.7"]
    assert body["total_results"] == 1 and body["totals"]["npm:axios@0.21.1"]["by_severity"] == {"HIGH": 1}


def test_limit_caps_rows_but_not_totals(server):
    body = call(server, "project_exposure", project="axios@0.21.1", limit=0)
    assert body["shown"] == 1  # limit is clamped to at least one row
    assert body["total_results"] == 1


def test_affected_projects_walks_up_from_an_advisory(server):
    [row] = call(server, "affected_projects", advisory="GHSA-74fj-2j2h-c42q")["results"]
    assert row["project"] == "axios@0.21.1" and row["depth"] == 1


def test_dependency_path_lists_the_dependencys_advisories(server):
    [row] = call(server, "dependency_path", project="axios", dependency="follow-redirects")["results"]
    assert row["dependency"] == "follow-redirects@1.13.1"
    assert row["advisories"][0]["fixed_in"] == ["follow-redirects@1.14.7"]


@pytest.mark.parametrize("name, arguments, message", [
    ("project_exposure", {"project": "left-pad"}, "no package, version or advisory"),
    ("project_exposure", {"project": "axios", "advisory": "axios"}, "not a GHSA/CVE advisory id"),
    ("affected_projects", {"advisory": "follow-redirects"}, "not a GHSA/CVE advisory id"),
    ("plan_fix", {}, "name at least one"),
    ("plan_fix", {"project": "follow-redirects"}, "not one of the dataset's projects"),
    ("search_advisories", {"query": "redirect leaks headers"}, "no embedding client"),
    ("scan_lockfile", {}, "exactly one of"),
    ("scan_lockfile", {"lockfile": "{not json"}, "not valid JSON"),
    ("scan_lockfile", {"lockfile": [1, 2]}, "valid dictionary"),
    ("scan_lockfile", {"lockfile": {"lockfileVersion": 1}}, "v2 or v3"),
])
def test_bad_input_is_a_tool_error(server, name, arguments, message):
    with pytest.raises(ToolError, match=message):
        asyncio.run(server.call_tool(name, arguments))


def test_missing_artifacts_are_a_tool_error_not_a_crash():
    def loader():
        raise FileNotFoundError("missing graph.pkl")
    with pytest.raises(ToolError, match="missing graph.pkl"):
        asyncio.run(create_server(loader=loader).call_tool("list_projects", {}))


def test_plan_fix_without_release_metadata_warns(server):
    body = call(server, "plan_fix", project="axios")
    assert body["results"] == [] and "no release metadata" in body["warnings"][0]


def test_explore_names_conditions_and_quotes_their_evidence(server):
    [node] = call(server, "explore", entity="CVE-2022-0155", relation="EXPLOITABLE_WHEN")["matches"]
    assert node["entity_id"] == "GHSA-74fj-2j2h-c42q" and node["total_neighbors"] == 1
    [neighbor] = node["neighbors"]
    assert neighbor["name"] == "a redirect crosses to another host"
    assert neighbor["evidence"] == ["when a redirect crosses to another host"]


def test_scan_lockfile_reads_a_project_directory(server, tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
    body = call(server, "scan_lockfile", path=str(tmp_path), live=False)

    assert body["project"] == {"name": "my-app", "version": "0.1.0"}
    [row] = body["results"]
    assert row["chain"] == "my-app@0.1.0 → axios@0.21.1 → follow-redirects@1.13.1"
    assert body["coverage"]["unchecked"] == 0
    assert body["fix_plans"] == [] and "no release metadata" in body["warnings"][-1]


@pytest.mark.parametrize("lockfile", [LOCK, json.dumps(LOCK)])
def test_scan_lockfile_takes_contents_as_an_object_or_a_string(server, lockfile):
    body = call(server, "scan_lockfile", lockfile=lockfile, live=False)
    assert body["total_results"] == 1


def test_scan_lockfile_reads_an_sbom_file(server, tmp_path):
    sbom = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "documentDescribes": ["R"],
            "packages": [{"SPDXID": s, "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]}
                         for s, purl in (("R", "pkg:npm/my-app@0.1.0"), ("A", "pkg:npm/axios@0.21.1"),
                                         ("F", "pkg:npm/follow-redirects@1.13.1"))],
            "relationships": [{"spdxElementId": "A", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "R"},
                              {"spdxElementId": "F", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "A"}]}
    (tmp_path / "sbom.spdx.json").write_text(json.dumps(sbom), encoding="utf-8")
    body = call(server, "scan_lockfile", path=str(tmp_path / "sbom.spdx.json"), live=False)

    assert body["results"][0]["chain"] == "my-app@0.1.0 → axios@0.21.1 → follow-redirects@1.13.1"
    assert body["coverage"]["sbom"]["format"] == "SPDX-2.3"


def test_chain_drops_id_prefixes():
    assert chain(["project:my-app@0.1.0", "npm:@babel/core@7.0.0"]) == "my-app@0.1.0 → @babel/core@7.0.0"
