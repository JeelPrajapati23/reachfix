"""FastAPI service: ask DepGraph questions and explore the graph over HTTP.

A thin HTTP layer over the same route_query -> synthesize_answer path
scripts/ask_depgraph.py runs; no retrieval logic lives here. Handlers are
plain `def`, not `async def`, so FastAPI runs the blocking Groq/HF calls in
its threadpool instead of stalling the event loop.

Endpoints:
    GET  /                 chat + graph-visualization page
    GET  /health           graph / advisory-index sizes
    POST /query            routed, cited answer + the subgraph it traversed (+ fix plans)
    POST /scan             exposure + fix plans for an uploaded package-lock.json
    GET  /graph/explore    ego-subgraph around a package, version or advisory

Rebuilding the data is done with the scripts/ build steps, not over HTTP.
"""

import os
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

import groq
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from huggingface_hub.errors import HfHubHTTPError
from pydantic import BaseModel, Field

from ..depgraph import route_query
from ..depgraph.scan import run_scan
from ..depgraph.synthesis import synthesize_answer
from ..graph import ego_subgraph
from ..npm.sbom import load_scan_document
from .ratelimit import QueryLimiter, client_ip
from .resources import Resources, load_resources
from .views import fix_plans, plan_summaries, result_subgraph

STATIC_DIR = Path(__file__).parent / "static"


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=20)


def create_app(resources: Resources | None = None, loader: Callable[[], Resources] = load_resources,
               query_limiter: QueryLimiter | None = None) -> FastAPI:
    """Build the app. Pass `resources` directly (tests) or let startup call `loader`.

    `query_limiter` caps /query (the only endpoint spending Groq tokens); by default it comes from
    the REACHFIX_QUERY_LIMIT_* environment variables, and is off when they are unset.
    """
    limiter = query_limiter if query_limiter is not None else QueryLimiter.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.resources = resources if resources is not None else loader()
        yield

    app = FastAPI(title="reachfix", lifespan=lifespan)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    def health(request: Request) -> dict:
        ctx = request.app.state.resources.ctx
        return {
            "status": "ok",
            "nodes": ctx.store.node_count(),
            "edges": ctx.store.edge_count(),
            "advisory_chunks": len(ctx.chunks_by_id),
            "remediation": ctx.releases is not None,
            "version": os.environ.get("REACHFIX_VERSION", "dev"),  # the image's commit (Dockerfile)
        }

    @app.post("/query")
    def query(body: QueryRequest, request: Request) -> dict:
        if limiter is not None and (refused := limiter.acquire(client_ip(request))):
            raise HTTPException(status_code=429, detail=refused)
        res: Resources = request.app.state.resources
        try:
            result = route_query(body.query, client=res.client, ctx=res.ctx, schema=res.schema, top_k=body.top_k)
            answer = synthesize_answer(result, client=res.client)
        except (groq.APIError, HfHubHTTPError) as e:
            raise HTTPException(status_code=502, detail=f"upstream provider error: {e}")

        return {
            **answer,
            "pattern": result["pattern"],
            "executed_pattern": result["executed_pattern"],
            "classification_reasoning": result["classification_reasoning"],
            "subgraph": result_subgraph(result, res.ctx.store),
            "fix_plans": fix_plans(result),
        }

    @app.post("/scan")
    def scan(
        request: Request,
        lock: dict = Body(description="package-lock.json (lockfileVersion 2 or 3), CycloneDX JSON or SPDX 2.x JSON"),
        live: bool = Query(default=True, description="query OSV.dev and the npm registry for what the dataset lacks"),
    ) -> dict:
        # No LLM or embedding call. With live, versions outside the dataset are queried on OSV.dev and
        # missing release metadata is fetched from the npm registry; failures come back as warnings.
        res: Resources = request.app.state.resources
        try:
            upload = load_scan_document(res.ctx.store, lock, res.ctx.releases.packages if res.ctx.releases else None,
                                        res.osv if live else None, res.registry if live else None)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        result = run_scan(res.ctx, upload, registry=res.registry if live else None)
        plans = plan_summaries(result["remediation"]["results"]) if result["remediation"] else []
        return {**result, "subgraph": result_subgraph(result, upload.store), "fix_plans": plans}

    @app.get("/graph/explore")
    def graph_explore(
        request: Request,
        entity: str = Query(min_length=1, description="package, name@version, or GHSA/CVE id"),
        depth: int = Query(default=1, ge=1, le=3),
        max_nodes: int = Query(default=200, ge=1, le=1000),
    ) -> dict:
        store = request.app.state.resources.ctx.store
        matches = request.app.state.resources.ctx.lookup.resolve(entity)
        if not matches:
            raise HTTPException(status_code=404, detail=f"no package, version or advisory matches {entity!r}")
        # A CVE can map to several advisories; the first is drawn and all are listed.
        return {"entity_id": matches[0], "matches": matches,
                **ego_subgraph(store, matches[0], depth=depth, max_nodes=max_nodes)}

    return app
