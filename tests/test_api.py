"""Synthetic fixtures only — no real artifacts, no Groq/HF calls."""
import pytest
from fastapi.testclient import TestClient

import reachfix.api.app as app_module
from reachfix.api import Resources, create_app
from reachfix.api.views import fix_plans, plan_display, result_subgraph
from reachfix.depgraph import DepGraphContext
from reachfix.graph import NetworkXGraphStore
from reachfix.npm.graph_load import to_entity
from reachfix.npm.lookup import NodeLookup

# axios@0.21.1 -> follow-redirects@1.13.1 [GHSA-74fj / CVE-2022-0155]
NODES = [
    {"node_id": "npm:axios@0.21.1", "node_type": "PackageVersion", "name": "axios@0.21.1",
     "aliases": ["axios@0.21.1"], "properties": {"is_root": True, "in_tree": True}},
    {"node_id": "npm:follow-redirects@1.13.1", "node_type": "PackageVersion", "name": "follow-redirects@1.13.1",
     "aliases": ["follow-redirects@1.13.1"], "properties": {"in_tree": True}},
    {"node_id": "GHSA-74fj-2j2h-c42q", "node_type": "Vulnerability", "name": "GHSA-74fj-2j2h-c42q",
     "aliases": ["GHSA-74fj-2j2h-c42q", "CVE-2022-0155"],
     "properties": {"aliases": ["CVE-2022-0155"], "severity": "HIGH", "summary": "Exposure of private headers"}},
]
EDGES = [
    {"subject_id": "npm:axios@0.21.1", "relation": "DEPENDS_ON", "object_id": "npm:follow-redirects@1.13.1",
     "source_doc_id": "lockfile:npm:axios@0.21.1", "properties": {"lockfile_doc_ids": ["lockfile:npm:axios@0.21.1"]}},
    {"subject_id": "npm:follow-redirects@1.13.1", "relation": "HAS_VULNERABILITY", "object_id": "GHSA-74fj-2j2h-c42q",
     "source_doc_id": "GHSA-74fj-2j2h-c42q", "properties": {"lockfile_doc_ids": ["lockfile:npm:axios@0.21.1"]}},
]
PATH = ["npm:axios@0.21.1", "npm:follow-redirects@1.13.1"]
EXPOSURE_RESULT = {
    "query": "Is axios@0.21.1 exposed to CVE-2022-0155?", "route": "relational", "executed_route": "relational",
    "pattern": "exposure", "executed_pattern": "exposure", "classification_reasoning": "names a project and a CVE",
    "warnings": [], "results": [{"project": PATH[0], "version_id": PATH[1], "vulnerability_id": "GHSA-74fj-2j2h-c42q",
                                 "path": PATH, "depth": 1}],
}


@pytest.fixture
def store():
    store = NetworkXGraphStore()
    store.load([to_entity(n) for n in NODES], EDGES)
    return store


@pytest.fixture
def client(store):
    ctx = DepGraphContext(store=store, lookup=NodeLookup(NODES), index=None,
                          chunks_by_id={"GHSA-74fj-2j2h-c42q::0": {"chunk_id": "GHSA-74fj-2j2h-c42q::0",
                                                                     "doc_id": "GHSA-74fj-2j2h-c42q"}},
                          embedding_client=None)
    with TestClient(create_app(Resources(ctx=ctx, schema=None, client=None))) as test_client:
        yield test_client


def test_health_reports_sizes(client, monkeypatch):
    monkeypatch.setenv("REACHFIX_VERSION", "abc123")
    assert client.get("/health").json() == {"status": "ok", "nodes": 3, "edges": 2, "advisory_chunks": 1,
                                            "remediation": False, "version": "abc123"}


def test_index_serves_demo_page(client):
    resp = client.get("/")
    assert resp.status_code == 200 and "reachfix" in resp.text
    assert 'id="scan-file"' in resp.text and "/scan?live=" in resp.text


def test_explore_resolves_a_cve_to_its_advisory(client):
    body = client.get("/graph/explore", params={"entity": "cve-2022-0155"}).json()

    assert body["entity_id"] == "GHSA-74fj-2j2h-c42q" and body["matches"] == ["GHSA-74fj-2j2h-c42q"]
    assert {n["entity_id"] for n in body["nodes"]} == {"GHSA-74fj-2j2h-c42q", "npm:follow-redirects@1.13.1"}
    assert body["edges"][0]["relation"] == "HAS_VULNERABILITY"


def test_explore_unknown_entity_is_404(client):
    assert client.get("/graph/explore", params={"entity": "left-pad@9.9.9"}).status_code == 404


def test_query_returns_answer_citations_and_subgraph(client, monkeypatch):
    monkeypatch.setattr(app_module, "route_query", lambda *a, **k: dict(EXPOSURE_RESULT))
    monkeypatch.setattr(app_module, "synthesize_answer", lambda result, **k: {
        "query": result["query"], "route": result["route"], "executed_route": result["executed_route"],
        "answer": "Yes, through follow-redirects@1.13.1 [G1].", "checks": {}, "totals": [], "citations": {},
        "warnings": []})

    body = client.post("/query", json={"query": EXPOSURE_RESULT["query"]}).json()

    assert body["answer"].startswith("Yes") and body["executed_pattern"] == "exposure"
    assert body["classification_reasoning"] == "names a project and a CVE"
    assert body["subgraph"]["edges"] == [
        {"source": PATH[0], "target": PATH[1], "relation": "DEPENDS_ON"},
        {"source": PATH[1], "target": "GHSA-74fj-2j2h-c42q", "relation": "HAS_VULNERABILITY"},
    ]


def test_query_rejects_empty_query(client):
    assert client.post("/query", json={"query": ""}).status_code == 422


def test_result_subgraph_remediation_rows_link_to_their_advisories(store):
    result = {"executed_route": "relational", "executed_pattern": "remediation", "results": [
        {"version_id": PATH[1], "path": PATH, "advisories": [{"vulnerability_id": "GHSA-74fj-2j2h-c42q"}]}]}
    edges = result_subgraph(result, store)["edges"]
    assert [(e["source"], e["relation"]) for e in edges] == [(PATH[0], "DEPENDS_ON"), (PATH[1], "HAS_VULNERABILITY")]


def test_result_subgraph_orients_neighbor_rows(store):
    result = {"executed_route": "relational", "executed_pattern": "neighbors", "results": [
        {"source": {"node_id": "GHSA-74fj-2j2h-c42q"}, "node_id": PATH[1], "relation": "HAS_VULNERABILITY",
         "direction": "in"}]}
    assert result_subgraph(result, store)["edges"] == [
        {"source": PATH[1], "target": "GHSA-74fj-2j2h-c42q", "relation": "HAS_VULNERABILITY"}]


def test_result_subgraph_is_empty_for_text_routes(store):
    assert result_subgraph({"executed_route": "semantic", "chunks": []}, store) == {"nodes": [], "edges": []}
    assert result_subgraph({"executed_route": "graph_guided_hybrid", "advisories": []}, store)["edges"] == []


@pytest.fixture
def scan_client():
    """The same graph plus follow-redirects' OSV range, which upload matching reads."""
    store = NetworkXGraphStore()
    store.load([to_entity(n) for n in NODES], EDGES + [
        {"subject_id": "GHSA-74fj-2j2h-c42q", "relation": "AFFECTS_VERSION_RANGE", "object_id": "npm:follow-redirects",
         "source_doc_id": "GHSA-74fj-2j2h-c42q", "properties": {"versions": [], "ranges": [
             {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.14.7"}]}]}}])
    ctx = DepGraphContext(store=store, lookup=NodeLookup(NODES), index=None, chunks_by_id={}, embedding_client=None)
    with TestClient(create_app(Resources(ctx=ctx, schema=None, client=None))) as test_client:
        yield test_client


def test_scan_reports_exposure_and_subgraph_for_an_uploaded_lockfile(scan_client):
    lock = {"name": "my-app", "lockfileVersion": 3, "packages": {
        "": {"name": "my-app", "version": "0.1.0", "dependencies": {"axios": "^0.21.1"}},
        "node_modules/axios": {"version": "0.21.1", "dependencies": {"follow-redirects": "^1.10.0"}},
        "node_modules/follow-redirects": {"version": "1.13.1"},
    }}
    body = scan_client.post("/scan", json=lock).json()

    assert body["project"]["id"] == "project:my-app@0.1.0" and body["total_results"] == 1
    assert body["results"][0]["path"] == ["project:my-app@0.1.0", *PATH]
    assert body["coverage"] == {"versions": 2, "checked": 2, "unchecked": 0, "unchecked_examples": [],
                                "live_osv": None, "sbom": None}
    assert body["remediation"] is None  # no release metadata in this fixture
    assert {(e["source"], e["relation"]) for e in body["subgraph"]["edges"]} == {
        ("project:my-app@0.1.0", "DEPENDS_ON"), (PATH[0], "DEPENDS_ON"), (PATH[1], "HAS_VULNERABILITY")}


def test_scan_takes_an_sbom(scan_client):
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"bom-ref": "root", "name": "dir", "purl": "pkg:npm/my-app@0.1.0"}},
            "components": [{"bom-ref": "a", "purl": "pkg:npm/axios@0.21.1"},
                           {"bom-ref": "f", "purl": "pkg:npm/follow-redirects@1.13.1"}],
            "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["f"]}]}
    body = scan_client.post("/scan?live=false", json=sbom).json()

    assert body["results"][0]["path"] == ["project:my-app@0.1.0", *PATH]
    assert body["coverage"]["sbom"]["format"] == "CycloneDX 1.5"


def test_scan_rejects_a_v1_lockfile(scan_client):
    resp = scan_client.post("/scan", json={"lockfileVersion": 1, "dependencies": {}})
    assert resp.status_code == 422 and "v2 or v3" in resp.json()["detail"]


def test_result_subgraph_nodes_carry_display_properties(store):
    nodes = {n["entity_id"]: n for n in result_subgraph(EXPOSURE_RESULT, store)["nodes"]}
    advisory = nodes["GHSA-74fj-2j2h-c42q"]
    assert advisory["severity"] == "HIGH" and advisory["cves"] == ["CVE-2022-0155"]
    assert advisory["summary"] == "Exposure of private headers"
    assert nodes[PATH[0]]["is_root"] is True and "is_root" not in nodes[PATH[1]]


# express@4.17.1 pins path-to-regexp "0.1.7", so the fix upgrades express to a release declaring ~0.1.12.
BLOCKED_PLAN = {
    "version_id": "npm:path-to-regexp@0.1.7", "package": "path-to-regexp", "current_version": "0.1.7",
    "status": "blocked", "target_version": "0.1.13",
    "override": {"package": "path-to-regexp", "version": "0.1.13", "outside_ranges": ["npm:express@4.17.1"]},
    "dependents": [{"dependent": "npm:express@4.17.1", "dep_name": "path-to-regexp", "range": "0.1.7", "admits": None,
                    "upgrade": {
        "version_id": "npm:express@4.17.1", "package": "express", "current_version": "4.17.1",
        "status": "upgrade_root", "target_version": "4.22.0"}}],
}


def test_fix_plans_map_path_nodes_to_their_upgrades():
    result = {"executed_pattern": "remediation", "results": [{
        "project": "npm:express@4.17.1", "version_id": "npm:path-to-regexp@0.1.7",
        "path": ["npm:express@4.17.1", "npm:path-to-regexp@0.1.7"], "plan": BLOCKED_PLAN,
        "actions": ["Upgrade express itself from 4.17.1 to 4.22.0."], "resolved": True,
        "advisories": [{"vulnerability_id": "GHSA-9wv6-86v2-598j", "severity": "HIGH", "summary": "x"}]}]}

    [plan] = fix_plans(result)
    assert plan["status"] == "blocked" and plan["resolved"] and plan["override"]["version"] == "0.1.13"
    assert plan["upgrades"] == {"npm:path-to-regexp@0.1.7": "npm:path-to-regexp@0.1.13",
                                "npm:express@4.17.1": "npm:express@4.22.0"}
    assert plan["advisories"] == [{"vulnerability_id": "GHSA-9wv6-86v2-598j", "severity": "HIGH"}]
    assert fix_plans({**result, "executed_pattern": "exposure"}) == []


def test_fix_plans_skip_an_uploaded_projects_manifest_edit():
    manifest_edit = {"version_id": "project:my-app@0.1.0", "dep_name": "path-to-regexp", "current_range": "0.1.7",
                     "status": "edit_manifest", "target_version": "0.1.13", "suggested_range": "^0.1.13"}
    plan = {**BLOCKED_PLAN, "dependents": [{**BLOCKED_PLAN["dependents"][0], "upgrade": manifest_edit}]}
    [summary] = fix_plans({"executed_pattern": "remediation", "results": [{
        "project": "project:my-app@0.1.0", "version_id": plan["version_id"], "path": [], "plan": plan,
        "actions": [], "resolved": True, "advisories": []}]})
    assert summary["upgrades"] == {"npm:path-to-regexp@0.1.7": "npm:path-to-regexp@0.1.13"}


def test_plan_display_upgrade_of_the_blocking_root():
    shown = plan_display(BLOCKED_PLAN)
    assert shown["label"] == "upgrade the project"
    assert shown["why"] == ('path-to-regexp@0.1.13 is the lowest fixed version, but express@4.17.1 ("0.1.7") '
                            'excludes every fixed version.')
    assert [(s["text"], s["command"]) for s in shown["steps"]] == [
        ("Upgrade express 4.17.1 → 4.22.0.", "npm install express@4.22.0")]


def test_plan_display_uploaded_project_edits_its_package_json():
    manifest_edit = {"version_id": "project:my-app@0.1.0", "dep_name": "path-to-regexp", "current_range": "0.1.7",
                     "status": "edit_manifest", "target_version": "0.1.13", "suggested_range": "^0.1.13"}
    plan = {**BLOCKED_PLAN, "dependents": [{**BLOCKED_PLAN["dependents"][0], "dependent": "project:my-app@0.1.0",
                                            "upgrade": manifest_edit}]}
    shown = plan_display(plan)
    assert shown["label"] == "edit package.json" and "my-app@0.1.0 (\"0.1.7\")" in shown["why"]
    assert [s["command"] for s in shown["steps"]] == ['"path-to-regexp": "^0.1.13"', "npm install"]


def test_plan_display_in_range_is_a_lockfile_refresh():
    plan = {"version_id": "npm:follow-redirects@1.13.1", "package": "follow-redirects", "current_version": "1.13.1",
            "status": "in_range", "target_version": "1.16.0", "dependents": []}
    shown = plan_display(plan)
    assert shown["label"] == "refresh the lockfile"
    assert shown["steps"] == [{"text": "Refresh the lockfile:", "command": "npm update follow-redirects", "kind": "step"}]
