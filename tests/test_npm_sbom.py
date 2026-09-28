import pytest

from reachfix.depgraph.scan import run_scan
from reachfix.graph import NetworkXGraphStore
from reachfix.graph.exposure import exposure
from reachfix.npm.dependencies import resolve_dependencies
from reachfix.npm.graph_load import to_entity
from reachfix.npm.sbom import (load_scan_document, parse_cyclonedx, parse_purl, parse_spdx, sbom_format,
                               to_lockfile)
from test_npm_upload import base_store, context, lockfile, releases


def cyclonedx(components, dependencies, root_purl="pkg:npm/app@1.0.0"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            # npm names the root component after its directory; the purl is right.
            "metadata": {"component": {"bom-ref": "app@1.0.0", "name": "some-dir", "version": "1.0.0",
                                       "purl": root_purl}},
            "components": components, "dependencies": dependencies}


def component(name, version, dev=False, purl=None):
    return {"bom-ref": f"{name}@{version}", "name": name, "version": version,
            "purl": purl or f"pkg:npm/{name.replace('@', '%40')}@{version}",
            "properties": [{"name": "cdx:npm:package:development", "value": "true"}] if dev else []}


# app -> mid@1.0.0 -> lib@1.0.0; app -> lib@2.0.0 (so mid's lib must nest); app -(dev)-> tool@2.0.0
APP = cyclonedx(
    [component("mid", "1.0.0"), component("lib", "1.0.0"), component("lib", "2.0.0"),
     component("tool", "2.0.0", dev=True)],
    [{"ref": "app@1.0.0", "dependsOn": ["mid@1.0.0", "lib@2.0.0", "tool@2.0.0"]},
     {"ref": "mid@1.0.0", "dependsOn": ["lib@1.0.0"]}])


def no_ranges(name, version, dep_name):
    return None


def edges_of(lock):
    """(source, dep, target version, spec, type) for every dependency between installed packages."""
    return {(f"{d.source.name}@{d.source.version}", d.dep_name, d.target.version, d.spec, d.dependency_type)
            for d in resolve_dependencies(lock) if d.target}


@pytest.mark.parametrize("purl, expected", [
    ("pkg:npm/lodash@4.17.21", ("lodash", "4.17.21")),
    ("pkg:npm/%40babel/core@7.12.3?vcs_url=x#sub", ("@babel/core", "7.12.3")),
    ("pkg:pypi/requests@2.0.0", None),
    ("pkg:npm/lodash", None),
    (None, None),
])
def test_parse_purl(purl, expected):
    assert parse_purl(purl) == expected


def test_sbom_format():
    assert sbom_format(APP) == "cyclonedx"
    assert sbom_format({"spdxVersion": "SPDX-2.3"}) == "spdx"
    assert sbom_format({"spdxVersion": "SPDX-3.0"}) is None
    assert sbom_format(lockfile()) is None


def test_cyclonedx_root_comes_from_the_purl_and_dev_from_npm_property():
    g = parse_cyclonedx(APP)
    assert (g.root_name, g.root_version) == ("app", "1.0.0")
    assert g.edges[""] == [("mid@1.0.0", "prod"), ("lib@2.0.0", "prod"), ("tool@2.0.0", "dev")]
    assert g.components["tool@2.0.0"].dev


def test_cyclonedx_skips_non_npm_and_reads_nested_components():
    doc = cyclonedx([{**component("a", "1.0.0"), "components": [component("@s/b", "2.0.0")]},
                     {"bom-ref": "py", "name": "requests", "purl": "pkg:pypi/requests@2.0.0"}],
                    [{"ref": "app@1.0.0", "dependsOn": ["a@1.0.0", "py"]}, {"ref": "a@1.0.0", "dependsOn": ["@s/b@2.0.0"]}])
    g = parse_cyclonedx(doc)
    assert set(g.components) == {"a@1.0.0", "@s/b@2.0.0"} and g.components["@s/b@2.0.0"].name == "@s/b"
    assert g.skipped == 1
    assert g.edges == {"": [("a@1.0.0", "prod")], "a@1.0.0": [("@s/b@2.0.0", "prod")]}


def test_spdx_relationship_directions_and_types():
    def pkg(spdx_id, name, version):
        return {"SPDXID": spdx_id, "name": name, "versionInfo": version,
                "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:npm/{name}@{version}"}]}
    doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
           "packages": [pkg("R", "app", "1.0.0"), pkg("M", "mid", "1.0.0"), pkg("L", "lib", "1.0.0"),
                        pkg("T", "tool", "2.0.0"), {"SPDXID": "X", "name": "no-purl"}],
           "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "R"},
                             {"spdxElementId": "M", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "R"},
                             {"spdxElementId": "T", "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": "R"},
                             {"spdxElementId": "M", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "L"}]}
    g = parse_spdx(doc)
    assert (g.root_name, g.root_version, g.skipped) == ("app", "1.0.0", 1)
    assert g.edges == {"": [("M", "prod"), ("T", "dev")], "M": [("L", "prod")]}


def test_layout_resolves_every_sbom_edge_to_its_own_target():
    lock, summary = to_lockfile(parse_cyclonedx(APP), lambda n, v, d: "^1.0.0" if (n, d) == ("mid", "lib") else None)
    packages = lock["packages"]
    # lib@2.0.0 is the project's, so mid's lib@1.0.0 nests under mid.
    assert packages["node_modules/lib"]["version"] == "2.0.0"
    assert packages["node_modules/mid/node_modules/lib"]["version"] == "1.0.0"
    assert packages["node_modules/tool"]["dev"] is True and "dev" not in packages["node_modules/mid"]
    # The project's ranges are assumed to be npm's default caret.
    assert packages[""]["dependencies"] == {"mid": "^1.0.0", "lib": "^2.0.0"}
    assert packages[""]["devDependencies"] == {"tool": "^2.0.0"}
    assert edges_of(lock) == {("mid@1.0.0", "lib", "1.0.0", "^1.0.0", "prod")}
    assert summary["ranges_from_manifests"] == 1 and summary["ranges_pinned"] == 0


def test_unknown_range_is_pinned_to_the_installed_version():
    lock, summary = to_lockfile(parse_cyclonedx(APP), no_ranges)
    assert lock["packages"]["node_modules/mid"]["dependencies"] == {"lib": "1.0.0"}
    assert summary["ranges_pinned"] == 1


def test_sbom_without_dependencies_scans_every_component_as_direct():
    doc = cyclonedx([component("a", "1.0.0"), component("b", "1.0.0"), component("b", "2.0.0")], [])
    lock, summary = to_lockfile(parse_cyclonedx(doc), no_ranges)
    assert lock["packages"][""]["dependencies"] == {"a": "^1.0.0", "b": "^1.0.0"}
    # A second version of a direct dependency can't be one too.
    assert summary["attached_to_project"] == 2 and summary["not_scanned"] == 1


def test_cycles_are_placed_once():
    doc = cyclonedx([component("a", "1.0.0"), component("b", "1.0.0")],
                    [{"ref": "app@1.0.0", "dependsOn": ["a@1.0.0"]},
                     {"ref": "a@1.0.0", "dependsOn": ["b@1.0.0"]}, {"ref": "b@1.0.0", "dependsOn": ["a@1.0.0"]}])
    lock, _ = to_lockfile(parse_cyclonedx(doc), no_ranges)
    assert set(lock["packages"]) == {"", "node_modules/a", "node_modules/b"}
    assert {(s, d, v) for s, d, v, *_ in edges_of(lock)} == {("a@1.0.0", "b", "1.0.0"), ("b@1.0.0", "a", "1.0.0")}


def test_known_types_come_back_and_missing_peers_are_restored():
    doc = cyclonedx([component("plugin", "1.0.0"), component("host", "4.0.0"), component("opt", "1.0.0")],
                    [{"ref": "app@1.0.0", "dependsOn": ["plugin@1.0.0", "host@4.0.0"]},
                     {"ref": "plugin@1.0.0", "dependsOn": ["opt@1.0.0"]}])  # the SBOM lost plugin's peer on host

    def typed(name, version):
        return {"opt": ("^1.0.0", "optional"), "host": ("^4.0.0", "peer")} if name == "plugin" else None

    lock, summary = to_lockfile(parse_cyclonedx(doc), lambda n, v, d: (typed(n, v) or {}).get(d, (None,))[0], typed)
    plugin = lock["packages"]["node_modules/plugin"]
    assert plugin["optionalDependencies"] == {"opt": "^1.0.0"} and plugin["peerDependencies"] == {"host": "^4.0.0"}
    assert summary["peers_added"] == 1


def test_scan_of_an_sbom_matches_the_lockfile_scan():
    """The upload tests' lockfile, as an SBOM: same exposure, same fix plan."""
    base, rel = base_store(), releases()
    sbom = cyclonedx([component("mid", "1.0.0"), component("lib", "1.0.0"), component("tool", "2.0.0", dev=True)],
                     [{"ref": "app@1.0.0", "dependsOn": ["mid@1.0.0", "lib@1.0.0", "tool@2.0.0"]},
                      {"ref": "mid@1.0.0", "dependsOn": ["lib@1.0.0"]}])
    from_lock = run_scan(context(base, rel), load_scan_document(base, lockfile(root_lib="^1.0.0")))
    upload = load_scan_document(base, sbom, rel.packages)
    from_sbom = run_scan(context(base, rel), upload)

    def rows(r):
        return sorted((x["version_id"], x["vulnerability_id"], tuple(x["path"])) for x in r["results"])
    assert rows(from_sbom) == rows(from_lock)
    assert ([p["plan"]["status"] for p in from_sbom["remediation"]["results"]]
            == [p["plan"]["status"] for p in from_lock["remediation"]["results"]])
    assert from_sbom["coverage"]["sbom"]["format"] == "CycloneDX 1.5"
    assert from_lock["coverage"]["sbom"] is None
    assert any("^<installed version>" in w for w in from_sbom["warnings"])


def test_ranges_are_fetched_live_only_for_packages_nothing_else_knows():
    class Registry:
        asked = []

        def fetch(self, names):
            self.asked.extend(names)
            return {"mid": {"versions": ["1.0.0"], "complete": True,
                            "manifests": {"1.0.0": {"dependencies": {"lib": "~1.0.0"}, "deprecated": None}}}}, {}

    sbom = cyclonedx([component("mid", "1.0.0"), component("lib", "1.0.0")],
                     [{"ref": "app@1.0.0", "dependsOn": ["mid@1.0.0"]}, {"ref": "mid@1.0.0", "dependsOn": ["lib@1.0.0"]}])
    registry = Registry()
    upload = load_scan_document(base_store(), sbom, {}, registry=registry)
    assert registry.asked == ["mid"]  # lib has no dependencies, so its range is never needed
    edge = next(e for e in upload.store.neighbors("npm:mid@1.0.0", relation="DEPENDS_ON", direction="out"))
    assert edge["properties"]["declared_spec"] == "~1.0.0"


def test_corpus_versions_take_ranges_from_the_graph():
    store = base_store()
    store.load([to_entity({"node_id": "npm:mid@1.0.0", "node_type": "PackageVersion", "name": "mid@1.0.0",
                           "aliases": [], "properties": {"in_tree": True}})],
               [{"subject_id": "npm:mid@1.0.0", "relation": "DEPENDS_ON", "object_id": "npm:lib@1.0.0",
                 "source_doc_id": "lockfile:x", "properties": {"dep_name": "lib", "declared_spec": "1.0.x",
                                                               "dependency_type": "prod"}}])
    sbom = cyclonedx([component("mid", "1.0.0"), component("lib", "1.0.0")],
                     [{"ref": "app@1.0.0", "dependsOn": ["mid@1.0.0"]}, {"ref": "mid@1.0.0", "dependsOn": ["lib@1.0.0"]}])
    upload = load_scan_document(store, sbom)
    hits = exposure(upload.store, upload.root_id, upload.lockfile_doc_id)
    assert [h["path"] for h in hits] == [["project:app@1.0.0", "npm:mid@1.0.0", "npm:lib@1.0.0"]]
    assert upload.source["ranges_from_manifests"] == 1


@pytest.mark.parametrize("doc, message", [
    ({"lockfileVersion": 1, "dependencies": {}}, "need v2 or v3"),
    ({"hello": "world"}, "not a package-lock.json"),
    (cyclonedx([{"bom-ref": "py", "purl": "pkg:pypi/requests@2.0.0"}], []), "no npm components"),
])
def test_unreadable_documents_raise_value_error(doc, message):
    with pytest.raises(ValueError, match=message):
        load_scan_document(NetworkXGraphStore(), doc)
