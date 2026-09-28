"""Scan your own package-lock.json, or an SBOM of it, against the DepGraph advisories and plan fixes.

Takes a package-lock.json (lockfileVersion 2 or 3) or a CycloneDX / SPDX 2.x
JSON SBOM (e.g. `npm sbom --sbom-format cyclonedx`; see npm/sbom.py for how
it is converted).

Layers the lockfile over data/processed/depgraph/graph.pkl, lists every
vulnerable version it reaches (worst severity first, with the dependency
chain), and prints a remediation plan per vulnerable copy from
releases.json. No Groq or HF calls. Versions outside the dataset are
looked up on OSV.dev (cached in data/raw/osv/live/), and release metadata
the plans need is fetched from the npm registry (cached for a day in
data/raw/npm/live_releases/). With --offline, only the dataset is used
(see the coverage line and the incomplete plans).

Usage:
    uv run python scripts/scan_lockfile.py path/to/package-lock.json [--offline] [--json] [--show N]
    uv run python scripts/scan_lockfile.py path/to/sbom.cdx.json
"""

import argparse
import json
from pathlib import Path

from reachfix.depgraph import DepGraphContext
from reachfix.depgraph.scan import run_scan
from reachfix.graph import NetworkXGraphStore
from reachfix.npm.live_releases import RegistryClient
from reachfix.npm.osv import OsvClient
from reachfix.npm.releases import Releases
from reachfix.npm.sbom import load_scan_document

ROOT = Path(__file__).resolve().parent.parent
DEPGRAPH_DIR = ROOT / "data" / "processed" / "depgraph"
LIVE_OSV_DIR = ROOT / "data" / "raw" / "osv" / "live"
LIVE_RELEASES_DIR = ROOT / "data" / "raw" / "npm" / "live_releases"


def chain(path: list[str]) -> str:
    return " -> ".join(p.removeprefix("npm:").removeprefix("project:") for p in path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("lockfile", type=Path, help="package-lock.json, or a CycloneDX / SPDX JSON SBOM")
    parser.add_argument("--offline", action="store_true", help="no OSV or registry calls; dataset only")
    parser.add_argument("--json", action="store_true", help="print the full result")
    parser.add_argument("--show", type=int, default=10, help="exposure rows and plans to print")
    args = parser.parse_args()

    releases_path = DEPGRAPH_DIR / "releases.json"
    ctx = DepGraphContext(store=NetworkXGraphStore.from_file(DEPGRAPH_DIR / "graph.pkl"), lookup=None, index=None,
                          chunks_by_id={}, embedding_client=None,
                          releases=Releases.from_file(releases_path) if releases_path.exists() else None)
    registry = None if args.offline else RegistryClient(LIVE_RELEASES_DIR)
    try:
        upload = load_scan_document(ctx.store, json.loads(args.lockfile.read_text(encoding="utf-8")),
                                    ctx.releases.packages if ctx.releases else None,
                                    None if args.offline else OsvClient(LIVE_OSV_DIR), registry)
    except (ValueError, json.JSONDecodeError) as e:
        raise SystemExit(f"{args.lockfile}: {e}")
    result = run_scan(ctx, upload, registry=registry)
    if args.json:
        print(json.dumps(result, indent=2))
        return

    totals, coverage = result["totals"], result["coverage"]
    print(f"{result['project']['id'].removeprefix('project:')}: {totals['advisories']} advisories on "
          f"{totals['vulnerable_versions']} vulnerable versions {totals['by_severity']}, "
          f"{totals['dev_only_advisories']} only via devDependencies")
    if sbom := coverage["sbom"]:
        print(f"sbom: {sbom['format']}, {sbom['components']} npm components; {sbom['ranges_from_manifests']} of "
              f"{sbom['dependency_edges']} declared ranges found, {sbom['peers_added']} peer dependencies restored")
    print(f"coverage: {coverage['checked']} of {coverage['versions']} installed versions were checked against OSV")
    if live := coverage["live_osv"]:
        print(f"live OSV: queried {live['queried']} versions, {live['advisories_added']} advisories not in the "
              f"dataset; matching agrees with OSV on {live['agree']} pairs "
              f"({live['only_ours']} only ours, {live['only_osv']} only OSV's)")
    for warning in result["warnings"]:
        print(f"warning: {warning}")

    for row in result["results"][:args.show]:
        dev = " [dev]" if row["dev_only"] else ""
        print(f"\n{row['severity'] or 'UNLABELED':9} {row['vulnerability_id']} {row['summary']}{dev}")
        print(f"          {chain(row['path'])}")

    remediation = result["remediation"]
    if remediation:
        print(f"\nfix plans: {remediation['totals']['by_status']}, "
              f"{remediation['totals']['fully_resolved']} of {remediation['total_results']} fully resolved, "
              f"release metadata fetched for {remediation['totals']['releases_fetched']} packages")
        for row in remediation["results"][:args.show]:
            print(f"\n{row['version_id'].removeprefix('npm:')} [{', '.join(a['vulnerability_id'] for a in row['advisories'])}]: "
                  f"{row['plan']['status']}")
            for line in row["actions"]:
                print(f"  {line}")


if __name__ == "__main__":
    main()
