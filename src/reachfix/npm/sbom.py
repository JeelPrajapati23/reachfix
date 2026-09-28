"""Scan an SBOM (CycloneDX or SPDX 2.x JSON) like a package-lock.json.

An SBOM lists the installed packages and who depends on whom, but not
where each copy sits in node_modules or which range each dependent
declared. So it is converted into a lockfile that npm.upload.load_upload
reads unchanged:

- Layout: each dependency is placed where Node would find it from its
  dependent: hoisted to the top-level node_modules if that name is free,
  nested under the dependent if another version holds it. The dependency
  walk then resolves every SBOM edge to its exact target.
- Declared ranges, which remediation needs, come from the dependent
  version's own manifest: the corpus graph's DEPENDS_ON edges, then the
  loaded release metadata, then (live) the npm registry. The project's own
  package.json isn't in the SBOM, so each direct dependency is taken as
  declared "^<installed version>", what `npm install` writes by default (a
  warning says so). A transitive range that can't be found is pinned to the
  installed version, which can only make a plan more conservative (it may
  upgrade a dependent that didn't need it); the count is a warning.
- Dependency types: CycloneDX has none, and npm's SBOMs leave out peer
  dependencies (all of them in SPDX, and in CycloneDX when installed with
  --legacy-peer-deps). For versions in the corpus the graph knows each
  dependency's real type and range, so those edges get their type back,
  and their peer dependencies are added wherever the peer is installed and
  visible, as npm would resolve it. Release metadata merges the types, so
  other versions keep what the SBOM says.

Only npm components (pkg:npm purls) are scanned; others are counted.
"""

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import unquote

from ..graph.store import GraphStore
from .dependencies import resolve_install_path
from .lockfile import NODE_MODULES
from .upload import MAX_PACKAGES, OsvLookup, Upload, load_upload
from .vulnerabilities import version_id

MAX_REGISTRY_FETCHES = 300
PROJECT_RANGE_PREFIX = "^"  # npm's default save-prefix; the SBOM doesn't record the project's ranges
# SPDX "A <type> B": the direction and dependency type it means (dependent, dependency).
SPDX_RELATIONS = {
    "DEPENDS_ON": ("forward", "prod"),
    "DEPENDENCY_OF": ("reverse", "prod"),
    "RUNTIME_DEPENDENCY_OF": ("reverse", "prod"),
    "OPTIONAL_DEPENDENCY_OF": ("reverse", "optional"),
    "DEV_DEPENDENCY_OF": ("reverse", "dev"),
    "BUILD_DEPENDENCY_OF": ("reverse", "dev"),
    "TEST_DEPENDENCY_OF": ("reverse", "dev"),
}


class ReleaseFetcher(Protocol):
    """npm.live_releases.RegistryClient, or a fake in tests."""

    def fetch(self, names) -> tuple[dict[str, dict], dict[str, str]]: ...


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    dev: bool = False  # flagged dev by the SBOM itself (npm's cdx:npm:package:development)


@dataclass
class SbomGraph:
    format: str                        # "CycloneDX 1.5", "SPDX-2.3"
    root_name: str
    root_version: str | None
    components: dict[str, Component]   # ref -> npm component
    edges: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # ref (or ROOT) -> [(ref, type)]
    skipped: int = 0                   # non-npm or unparseable components


ROOT = ""  # the project's ref in SbomGraph.edges


def sbom_format(doc: object) -> str | None:
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if str(doc.get("spdxVersion", "")).startswith("SPDX-2"):
            return "spdx"
    return None


def parse_purl(purl: object) -> tuple[str, str] | None:
    """"pkg:npm/%40scope/name@1.2.3?x=y#z" -> ("@scope/name", "1.2.3"); None unless an npm purl with a version."""
    if not isinstance(purl, str) or not purl.startswith("pkg:npm/"):
        return None
    body = purl[len("pkg:npm/"):].split("#")[0].split("?")[0]
    name, at, version = body.rpartition("@")
    if not at or not name or not version:
        return None
    return unquote(name), unquote(version)


def _add_edge(g: SbomGraph, src: str, dst: str, dep_type: str) -> None:
    if dst != src and dst != ROOT:
        g.edges.setdefault(src, []).append((dst, dep_type))


def parse_cyclonedx(doc: dict) -> SbomGraph:
    meta = (doc.get("metadata") or {}).get("component") or {}
    root_ref = meta.get("bom-ref")
    # npm names the root after its directory; the purl carries the package name.
    root_name, root_version = parse_purl(meta.get("purl")) or (meta.get("name") or "project", meta.get("version"))
    g = SbomGraph(f"CycloneDX {doc.get('specVersion', '')}".strip(), root_name, root_version, {})

    def walk(components: Iterable) -> Iterable[dict]:
        for c in components or ():
            if isinstance(c, dict):
                yield c
                yield from walk(c.get("components"))  # CycloneDX allows nested components

    for c in walk(doc.get("components")):
        ref, parsed = c.get("bom-ref"), parse_purl(c.get("purl"))
        if parsed is None or not ref or ref == root_ref:
            g.skipped += ref != root_ref
            continue
        props = {p.get("name"): p.get("value") for p in c.get("properties") or () if isinstance(p, dict)}
        g.components[ref] = Component(*parsed, dev=props.get("cdx:npm:package:development") == "true")
    for d in doc.get("dependencies") or ():
        if not isinstance(d, dict):
            continue
        src = ROOT if d.get("ref") == root_ref else d.get("ref")
        for dst in d.get("dependsOn") or ():
            if (src == ROOT or src in g.components) and dst in g.components:
                _add_edge(g, src, dst, "dev" if src == ROOT and g.components[dst].dev else "prod")
    return g


def parse_spdx(doc: dict) -> SbomGraph:
    described = list(doc.get("documentDescribes") or ())
    rels = [r for r in doc.get("relationships") or () if isinstance(r, dict)]
    described += [r.get("relatedSpdxElement") for r in rels
                  if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == doc.get("SPDXID")]
    packages = {p.get("SPDXID"): p for p in doc.get("packages") or () if isinstance(p, dict) and p.get("SPDXID")}
    root_id = next((d for d in described if d in packages), None)
    root_pkg = packages.get(root_id, {})
    root_purl = next((parse_purl(r.get("referenceLocator")) for r in root_pkg.get("externalRefs") or ()
                      if r.get("referenceType") == "purl"), None)
    root_name, root_version = root_purl or (root_pkg.get("name") or doc.get("name") or "project",
                                            root_pkg.get("versionInfo"))
    g = SbomGraph(doc.get("spdxVersion", "SPDX"), root_name, root_version, {})

    for spdx_id, p in packages.items():
        if spdx_id == root_id:
            continue
        purl = next((parse_purl(r.get("referenceLocator")) for r in p.get("externalRefs") or ()
                     if r.get("referenceType") == "purl"), None)
        if purl is None:
            g.skipped += 1
            continue
        g.components[spdx_id] = Component(*purl)
    for r in rels:
        kind = SPDX_RELATIONS.get(r.get("relationshipType"))
        if kind is None:
            continue
        a, b = r.get("spdxElementId"), r.get("relatedSpdxElement")
        src, dst = (a, b) if kind[0] == "forward" else (b, a)
        src = ROOT if src == root_id else src
        if (src == ROOT or src in g.components) and dst in g.components:
            _add_edge(g, src, dst, kind[1])
    return g


# (dependent name, dependent version, dependency name) -> declared spec, or None if unknown
SpecLookup = Callable[[str, str, str], str | None]
# (name, version) -> {dependency name: (declared spec, dependency type)} when the types are known, else None
TypedLookup = Callable[[str, str], dict[str, tuple[str, str]] | None]
TYPE_FIELDS = {"prod": "dependencies", "optional": "optionalDependencies", "peer": "peerDependencies"}


def to_lockfile(g: SbomGraph, spec_for: SpecLookup, typed: TypedLookup = lambda name, version: None
                ) -> tuple[dict, dict]:
    """The SBOM as a lockfileVersion 3 dict, plus a summary of how it was built (see the module docstring)."""
    if not g.components:
        raise ValueError(f"{g.format}: no npm components (pkg:npm purls) to scan")
    edges = {src: list(dict.fromkeys(deps)) for src, deps in g.edges.items()}
    # The project's node_modules holds one version per name.
    direct: dict[str, str] = {}
    root_edges, unplaced = [], []
    for ref, dep_type in edges.get(ROOT, ()):
        name = g.components[ref].name
        if direct.setdefault(name, ref) == ref:
            root_edges.append((ref, dep_type))
        else:
            unplaced.append(ref)
    edges[ROOT] = root_edges

    # Anything no edge reaches from the project (an SBOM without dependency data, or several roots)
    # becomes a direct dependency, so it is still scanned: first those nothing depends on, then one
    # member of each remaining cycle.
    reached: set[str] = set()

    def reach(starts: Iterable[str]) -> None:
        todo = deque(starts)
        while todo:
            ref = todo.popleft()
            if ref not in reached:
                reached.add(ref)
                todo.extend(dst for dst, _ in edges.get(ref, ()))

    reach(ref for ref, _ in root_edges)
    has_incoming = {dst for deps in edges.values() for dst, _ in deps}
    attached = 0
    while unreached := [ref for ref in g.components if ref not in reached and ref not in unplaced]:
        for ref in [r for r in unreached if r not in has_incoming] or unreached[:1]:
            name = g.components[ref].name
            if name in direct:
                unplaced.append(ref)  # a second version of a direct dependency can't be one
                continue
            direct[name] = ref
            edges[ROOT].append((ref, "dev" if g.components[ref].dev else "prod"))
            attached += 1
            reach([ref])

    # Dev-only: not reachable from the project through its non-dev dependencies.
    prod, todo = set(), deque(dst for dst, t in edges.get(ROOT, ()) if t != "dev")
    while todo:
        ref = todo.popleft()
        if ref not in prod:
            prod.add(ref)
            todo.extend(dst for dst, t in edges.get(ref, ()) if t != "dev")

    root = {"name": g.root_name, **({"version": g.root_version} if g.root_version else {})}
    packages: dict[str, dict] = {"": root}
    stats = {"edges": 0, "ranges_found": 0, "ranges_pinned": 0, "peers_added": 0}
    fields = {"prod": "dependencies", "dev": "devDependencies", "optional": "optionalDependencies"}
    for ref, dep_type in edges[ROOT]:
        c = g.components[ref]
        root.setdefault(fields.get(dep_type, "dependencies"), {})[c.name] = PROJECT_RANGE_PREFIX + c.version

    def entry(ref: str) -> dict:
        c = g.components[ref]
        return {"name": c.name, "version": c.version, **({} if ref in prod else {"dev": True})}

    path_ref: dict[str, str] = {}
    queue = deque([("", ROOT)])
    while queue:
        parent_path, parent_ref = queue.popleft()
        for ref, dep_type in edges.get(parent_ref, ()):
            c = g.components[ref]
            if parent_ref != ROOT:
                parent = g.components[parent_ref]
                spec = spec_for(parent.name, parent.version, c.name)
                known_type = ((typed(parent.name, parent.version) or {}).get(c.name) or (None, None))[1]
                stats["edges"] += 1
                stats["ranges_found" if spec else "ranges_pinned"] += 1
                field_name = TYPE_FIELDS.get(known_type or dep_type, "dependencies")
                packages[parent_path].setdefault(field_name, {})[c.name] = spec or c.version
            found = resolve_install_path(parent_path, c.name, packages)
            if found is not None and path_ref[found] == ref:
                continue  # the dependent already sees this copy
            if found is None:
                path = NODE_MODULES + c.name  # nothing visible: hoist to the top
            elif parent_path:
                path = f"{parent_path}/{NODE_MODULES}{c.name}"  # another version is visible: nest
            else:
                raise ValueError(f"{g.format}: the project depends on two versions of {c.name}")
            if len(packages) > MAX_PACKAGES:
                raise ValueError(f"{g.format}: more than {MAX_PACKAGES} installed copies; the limit is {MAX_PACKAGES}")
            packages[path] = entry(ref)
            path_ref[path] = ref
            queue.append((path, ref))

    # Peer dependencies the SBOM left out, for versions whose declared peers are known: add each one that
    # resolves to an installed copy from where the dependent sits.
    for path, ref in path_ref.items():
        c, pkg = g.components[ref], packages[path]
        declared_here = {name for f in TYPE_FIELDS.values() for name in pkg.get(f, {})}
        for dep_name, (spec, dep_type) in (typed(c.name, c.version) or {}).items():
            if dep_type == "peer" and dep_name not in declared_here and resolve_install_path(path, dep_name, packages):
                pkg.setdefault("peerDependencies", {})[dep_name] = spec
                stats["peers_added"] += 1

    lock = {"name": g.root_name, **({"version": g.root_version} if g.root_version else {}),
            "lockfileVersion": 3, "requires": True, "packages": packages}
    summary = {"format": g.format, "components": len(g.components), "skipped_components": g.skipped,
               "dependency_edges": stats["edges"], "ranges_from_manifests": stats["ranges_found"],
               "ranges_pinned": stats["ranges_pinned"], "peers_added": stats["peers_added"],
               "attached_to_project": attached,
               "not_scanned": sum(ref not in reached for ref in unplaced)}
    return lock, summary


class DeclaredRanges:
    """Declared dependency specs per (name, version): corpus graph edges, then release metadata, then the registry."""

    def __init__(self, base: GraphStore, releases: dict[str, dict] | None, registry: ReleaseFetcher | None = None):
        self.base = base
        self.packages = dict(releases or {})  # a copy: fetched packages must not leak into the shared context
        self.registry = registry
        self.fetch_failed: dict[str, str] = {}
        self._graph_cache: dict[tuple[str, str], dict[str, str] | None] = {}

    def prefetch(self, g: SbomGraph) -> None:
        """Fetch, in one batch, the packages whose ranges neither the graph nor the loaded metadata has."""
        if self.registry is None:
            return
        need = sorted({c.name for ref, c in g.components.items() if g.edges.get(ref)
                       and self._from_graph(c.name, c.version) is None and self._manifest(c.name, c.version) is None})
        if need:
            got, errors = self.registry.fetch(need[:MAX_REGISTRY_FETCHES])
            self.packages.update(got)
            self.fetch_failed.update(errors)

    def typed(self, name: str, version: str) -> dict[str, tuple[str, str]] | None:
        """A corpus version's declared deps with their types, from its DEPENDS_ON edges; None outside the corpus."""
        key = (name, version)
        if key not in self._graph_cache:
            vid = version_id(name, version)
            node = self.base.get_entity(vid)
            self._graph_cache[key] = None if not (node or {}).get("properties", {}).get("in_tree") else {
                e["properties"]["dep_name"]: (e["properties"]["declared_spec"], e["properties"]["dependency_type"])
                for e in self.base.neighbors(vid, relation="DEPENDS_ON", direction="out")
                if e.get("properties", {}).get("declared_spec")}
        return self._graph_cache[key]

    def _from_graph(self, name: str, version: str) -> dict[str, str] | None:
        typed = self.typed(name, version)
        return None if typed is None else {dep: spec for dep, (spec, _) in typed.items()}

    def _manifest(self, name: str, version: str) -> dict[str, str] | None:
        found = self.packages.get(name, {}).get("manifests", {}).get(version)
        return None if found is None else found.get("dependencies") or {}

    def __call__(self, name: str, version: str, dep_name: str) -> str | None:
        for source in (self._from_graph, self._manifest):
            declared = source(name, version)
            if declared and dep_name in declared:
                return declared[dep_name]
        return None


def load_sbom(base: GraphStore, doc: dict, releases: dict[str, dict] | None = None,
              osv: OsvLookup | None = None, registry: ReleaseFetcher | None = None) -> Upload:
    """Convert an SBOM and scan it like an upload (npm.upload.load_upload). Raises ValueError if it can't be read."""
    g = parse_cyclonedx(doc) if sbom_format(doc) == "cyclonedx" else parse_spdx(doc)
    ranges = DeclaredRanges(base, releases, registry)
    ranges.prefetch(g)
    lock, summary = to_lockfile(g, ranges, ranges.typed)
    upload = load_upload(base, lock, osv)
    upload.source = summary
    upload.warnings.append(f"an SBOM doesn't include your package.json, so its direct dependencies are assumed "
                           f"to be declared as \"{PROJECT_RANGE_PREFIX}<installed version>\" (npm's default); "
                           f"fix plans for them rely on that")
    if summary["skipped_components"]:
        upload.warnings.append(f"{summary['skipped_components']} SBOM components are not npm packages (no pkg:npm "
                               f"purl) and were not scanned")
    if summary["ranges_pinned"]:
        upload.warnings.append(f"the declared range of {summary['ranges_pinned']} of {summary['dependency_edges']} "
                               f"dependencies wasn't found (SBOMs don't record ranges), so they are taken as the "
                               f"installed version; fix plans touching them may upgrade more than needed")
    if ranges.fetch_failed:
        upload.warnings.append(f"registry fetch failed for {len(ranges.fetch_failed)} packages while looking up "
                               f"declared ranges (e.g. {', '.join(sorted(ranges.fetch_failed)[:3])})")
    if summary["not_scanned"]:
        upload.warnings.append(f"{summary['not_scanned']} components are a second version of a direct dependency "
                               f"with no dependency path in the SBOM, so they were not scanned")
    if summary["attached_to_project"]:
        upload.warnings.append(f"{summary['attached_to_project']} components had no dependency path from the "
                               f"project in the SBOM, so they are scanned as direct dependencies")
    return upload


def load_scan_document(base: GraphStore, doc: object, releases: dict[str, dict] | None = None,
                       osv: OsvLookup | None = None, registry: ReleaseFetcher | None = None) -> Upload:
    """A package-lock.json (v2/v3), CycloneDX JSON or SPDX 2.x JSON document, loaded for run_scan."""
    if sbom_format(doc):
        return load_sbom(base, doc, releases, osv, registry)
    if isinstance(doc, dict) and "lockfileVersion" in doc:
        return load_upload(base, doc, osv)  # validates v2/v3 itself
    raise ValueError("not a package-lock.json (lockfileVersion 2 or 3), CycloneDX JSON or SPDX 2.x JSON document")
