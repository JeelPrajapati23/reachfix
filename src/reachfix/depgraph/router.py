"""DepGraph router: classify a query, then dispatch it to the graph, the advisory index, or both.

Plain Python: one LLM call classifies, and a plain if/elif dispatches. Every result records the route, the classifier's
reasoning and how each named entity resolved, so a wrong answer can be
traced to classification, resolution or retrieval.

Two off-topic guardrails: an off_topic route, and a similarity floor on
semantic search (per index variant). An off_topic question is declined
unless its advisory-text match clears a second, higher floor; a semantic
question with nothing above the floor gets no chunks. Either way synthesis
declines without an LLM call.
"""

import json
from pathlib import Path

import groq
from groq import Groq
from huggingface_hub import InferenceClient
from pydantic import BaseModel, ValidationError

from ..extraction.schema import Schema
from ..graph import NetworkXGraphStore
from ..llm_client import DEFAULT_MODEL, generate_json
from ..npm.advisory_index import DEFAULT_VARIANT, VARIANTS, index_path
from ..npm.lookup import NodeLookup
from ..npm.releases import Releases
from ..retrieval import VectorIndex
from .classify import build_classification_prompt, build_decision_model
from .dispatch import (DepGraphContext, corpus_projects, resolve, run_graph_guided_hybrid, run_relational,
                       semantic_chunks)

CLASSIFY_ATTEMPTS = 2
JSON_VALIDATE_FAILED = "json_validate_failed"  # Groq's error code when JSON mode gets a non-JSON reply
FALLBACK_REASONING = "classifier returned invalid output twice; fell back to semantic search"


def classify_query(query: str, *, client: Groq, schema: Schema, model_name: str = DEFAULT_MODEL) -> BaseModel:
    """Classify `query`, retrying once on invalid output, then falling back to semantic.

    Groq's JSON mode doesn't enforce enum values, so a misspelled route,
    pattern or relation fails validation. Semantic search needs no entities,
    so it can always run. A reply that isn't JSON at all (the model refusing
    a prompt-injection attempt in prose) comes back from Groq as a 400
    json_validate_failed and is treated the same way.
    """
    decision_model = build_decision_model(schema)
    system_prompt = build_classification_prompt(schema)
    for _ in range(CLASSIFY_ATTEMPTS):
        try:
            raw = generate_json(client, system_prompt=system_prompt, user_prompt=query, model_name=model_name)
        except groq.BadRequestError as e:
            if JSON_VALIDATE_FAILED not in str(e):
                raise
            continue
        try:
            return decision_model.model_validate_json(raw)
        except ValidationError:
            continue
    return decision_model(route="semantic", entities=[], reasoning=FALLBACK_REASONING)


def floored_chunks(ctx: DepGraphContext, query: str, top_k: int, floor: float | None) -> dict:
    """Semantic search, minus chunks scoring under `floor` (None: keep every chunk).

    Nearest-neighbour search always returns top_k chunks, however unrelated
    the question. The floor drops those; if none is left, the result has no
    chunks and synthesis declines instead of answering from noise.
    """
    chunks = semantic_chunks(ctx, query, top_k)
    if floor is None:
        return {"chunks": chunks}
    kept = [c for c in chunks if c["score"] >= floor]
    if chunks and not kept:
        return {"chunks": [], "warning": f"no advisory text is close to the question "
                                         f"(best match {chunks[0]['score']:.2f}, floor {floor:.2f})"}
    return {"chunks": kept}


def off_topic(ctx: DepGraphContext, query: str, top_k: int) -> tuple[str, dict]:
    """Decline, unless advisory text matches the question past the variant's off-topic floor.

    The classifier sometimes calls a terse security question ("are there any
    command injection bugs?") off_topic. Those score well above anything
    really off topic, so a strong match overrides the classifier.
    """
    variant = VARIANTS.get(ctx.variant)
    if variant is None or variant.off_topic_min_score is None:
        return "off_topic", {}
    result = floored_chunks(ctx, query, top_k, variant.min_score)
    if max((c["score"] for c in result["chunks"]), default=0.0) < variant.off_topic_min_score:
        return "off_topic", {}  # synthesis declines without an LLM call
    return "semantic", {"chunks": result["chunks"], "warning": "classified off_topic, but advisory text matches "
                                                               "the question closely; answered from it"}


def route_query(query: str, *, client: Groq, ctx: DepGraphContext, schema: Schema,
                model_name: str = DEFAULT_MODEL, top_k: int = 5) -> dict:
    decision = classify_query(query, client=client, schema=schema, model_name=model_name)
    resolved, warnings = resolve(ctx, decision.entities)

    if decision.route == "off_topic" and not resolved:
        executed, result = off_topic(ctx, query, top_k)
    elif decision.route == "relational" and resolved:
        executed, result = "relational", run_relational(ctx, decision, resolved)
    elif decision.route == "graph_guided_hybrid" and resolved:
        executed, result = "graph_guided_hybrid", run_graph_guided_hybrid(ctx, query, resolved, top_k)
    else:
        if decision.route == "off_topic":
            warnings.append("classified off_topic but names a known package, version or advisory; "
                            "ran semantic search instead")
        elif decision.route != "semantic":
            warnings.append(f"{decision.route} route needs a known entity; fell back to semantic search")
        variant = VARIANTS.get(ctx.variant)
        executed, result = "semantic", floored_chunks(ctx, query, top_k, variant.min_score if variant else None)
    if executed == "semantic":
        # Unnamed-project questions ("is my project exposed?") land here; synthesis offers these as
        # projects the user can name, so its example is a real one rather than an invented one.
        result["dataset_projects"] = [p.removeprefix("npm:") for p in corpus_projects(ctx)]
    # Dispatch can run a different pattern than classified (see run_relational); keep both.
    executed_pattern = result.pop("pattern", None)

    return {
        "query": query,
        "route": decision.route,
        "executed_route": executed,
        "pattern": decision.pattern,
        "executed_pattern": executed_pattern,
        "relation": decision.relation,
        "classification_reasoning": decision.reasoning,
        "entities": [{"name": name, "node_ids": ids} for name, ids in resolved],
        "warnings": warnings + ([result.pop("warning")] if "warning" in result else []),
        **result,
    }


def load_context(depgraph_dir: Path, embedding_client: InferenceClient, variant: str = DEFAULT_VARIANT) -> DepGraphContext:
    """Everything the router needs, from the Phase 2-6 build outputs, plus Phase 9's releases.json if built."""
    def read_jsonl(name):
        return [json.loads(line) for line in (depgraph_dir / name).read_text(encoding="utf-8").splitlines() if line]

    return DepGraphContext(
        store=NetworkXGraphStore.from_file(depgraph_dir / "graph.pkl"),
        lookup=NodeLookup(read_jsonl("nodes.jsonl")),
        index=VectorIndex.from_file(index_path(depgraph_dir, variant)),
        chunks_by_id={c["chunk_id"]: c for c in read_jsonl("advisory_chunks.jsonl")},
        embedding_client=embedding_client,
        variant=variant,
        releases=Releases.from_file(depgraph_dir / "releases.json") if (depgraph_dir / "releases.json").exists() else None,
    )
