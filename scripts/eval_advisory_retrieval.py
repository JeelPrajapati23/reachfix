"""Compare advisory index variants on label-free retrieval checks.

Runs the package, vulnerability-class and deep query sets from
reachfix.npm.retrieval_eval against each built index variant
(scripts/build_advisory_index.py, both --variant values). Package and
class queries report precision@k over distinct advisories, deep queries
hit@k and mean reciprocal rank. Query embeddings are cached in
.cache/embeddings/ like chunk embeddings.

Deep queries are checked first with MiniLM's own tokenizer: a query
counts only if, in every relevant advisory, its detail starts past the
first MINILM_PIECES word-pieces of the raw chunk text, where an embedding
of the whole chunk has already stopped reading (with the summary/packages
prefix in front, as in the windowed variant, it starts later still).
The rest are reported as shallow and not scored.

Output: eval/results/advisory_retrieval.json

Usage:
    uv run python scripts/eval_advisory_retrieval.py [--k 5]
"""

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import hf_hub_download
from tokenizers import Tokenizer

from reachfix.npm import retrieval_eval as ev
from reachfix.npm.advisory_index import MINILM, VARIANTS, index_path
from reachfix.npm.corpus import read_jsonl
from reachfix.retrieval import VectorIndex, build_embedding_client, embed_chunks
from reachfix.retrieval.windows import search_chunks

ROOT = Path(__file__).resolve().parent.parent
DEPGRAPH = ROOT / "data" / "processed" / "depgraph"
CACHE_ROOT = ROOT / ".cache" / "embeddings"
OUT_PATH = ROOT / "eval" / "results" / "advisory_retrieval.json"
MINILM_PIECES = 256  # all-MiniLM-L6-v2's input length, [CLS] and [SEP] included


def deep_query_depths(chunks: list[dict], texts: dict[str, str]) -> list[dict]:
    """Per deep query: its relevant advisories and where (in word-pieces) each one's detail starts."""
    tokenizer = Tokenizer.from_file(hf_hub_download(MINILM, "tokenizer.json"))
    tokenizer.no_padding()
    tokenizer.no_truncation()
    rows = []
    for query, pattern in ev.DEEP_QUERIES:
        relevant = ev.class_relevance(pattern, texts)
        depths: dict[str, int] = {}
        for chunk in chunks:
            if not relevant(chunk):
                continue
            text = chunk["text"]
            offset = ev.evidence_offset(text, pattern)
            if offset is not None:  # +1 for [CLS]
                pieces = len(tokenizer.encode(text[:offset], add_special_tokens=False).ids) + 1
                depths[chunk["doc_id"]] = min(pieces, depths.get(chunk["doc_id"], pieces))
        for doc_id in texts:  # a match only in the summary is as shallow as it gets
            if relevant({"doc_id": doc_id}):
                depths.setdefault(doc_id, 0)
        rows.append({"query": query, "pattern": pattern, "evidence_pieces": depths,
                     "deep": bool(depths) and min(depths.values()) >= MINILM_PIECES - 1})
    return rows


def main() -> None:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args()

    chunks = read_jsonl(DEPGRAPH / "advisory_chunks.jsonl")
    chunks_by_id = {c["chunk_id"]: c for c in chunks}
    texts = ev.advisory_text(chunks)
    pkg_queries = ev.package_queries(chunks)
    depths = deep_query_depths(chunks, texts)
    deep_queries = [(d["query"], d["pattern"]) for d in depths if d["deep"]]
    queries = [q for q, _ in pkg_queries] + [q for q, _ in ev.CLASS_QUERIES] + [q for q, _ in deep_queries]

    client = build_embedding_client()
    report = {"k": args.k, "deep_query_depths": depths, "variants": {}}
    for variant, options in VARIANTS.items():
        path = index_path(DEPGRAPH, variant)
        if not Path(f"{path}.ids.json").exists():
            print(f"  ! {variant} index not built; run scripts/build_advisory_index.py --variant {variant}")
            continue
        index = VectorIndex.from_file(path)
        # Queries go through the variant's own model (cached like chunks).
        try:
            ids, vectors = embed_chunks([{"chunk_id": f"query::{q}", "text": q} for q in queries], client=client,
                                        model_name=options.model, output_dimensionality=options.dimensions,
                                        cache_root=CACHE_ROOT)
        except Exception as exc:  # e.g. bge-m3 on HF with no token or no credits left
            print(f"  ! {variant} skipped: query embedding failed ({type(exc).__name__}: {exc})")
            continue
        query_vectors = {i.removeprefix("query::"): v for i, v in zip(ids, vectors)}

        def top(query):
            # Over-fetch chunks, then keep the first k distinct advisories.
            hits = search_chunks(query, index=index, chunks_by_id=chunks_by_id, client=client,
                                 top_k=args.k * 3, query_vector=query_vectors[query])
            return ev.distinct_advisories(hits, args.k)

        pkg_scores = [ev.precision(top(q), lambda r, p=p: p in r["affected_packages"]) for q, p in pkg_queries]
        class_rows = []
        for q, pattern in ev.CLASS_QUERIES:
            score = ev.precision(top(q), ev.class_relevance(pattern, texts))
            class_rows.append({"query": q, "precision": round(score, 2),
                               "base_rate": round(ev.class_base_rate(pattern, texts), 2)})
        deep_rows = []
        for q, pattern in deep_queries:
            results = top(q)
            rr = ev.reciprocal_rank(results, ev.class_relevance(pattern, texts))
            deep_rows.append({"query": q, "reciprocal_rank": round(rr, 3)})
        report["variants"][variant] = {
            "packages": ev.summarize(pkg_scores),
            "classes": ev.summarize([r["precision"] for r in class_rows]),
            "class_queries": class_rows,
            "deep": {"queries": len(deep_rows),
                     "hit_at_k": round(sum(r["reciprocal_rank"] > 0 for r in deep_rows) / len(deep_rows), 3)
                     if deep_rows else None,
                     "mrr": round(sum(r["reciprocal_rank"] for r in deep_rows) / len(deep_rows), 3)
                     if deep_rows else None},
            "deep_queries": deep_rows,
        }

    if not report["variants"]:
        raise SystemExit("No index built; nothing to evaluate.")
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    shallow = [d for d in depths if not d["deep"]]
    print(f"deep queries: {len(deep_queries)} of {len(depths)} have their detail past word-piece "
          f"{MINILM_PIECES} in every relevant advisory")
    for d in shallow:
        print(f"  shallow, not scored: {d['query']}  {d['evidence_pieces'] or 'no match'}")
    print(f"\nprecision@{args.k} over distinct advisories ({len(pkg_queries)} package queries, "
          f"{len(ev.CLASS_QUERIES)} class queries); deep: hit@{args.k} and MRR\n")
    for variant, r in report["variants"].items():
        deep = r["deep"]
        deep_cells = f"deep hit {deep['hit_at_k']:.3f} mrr {deep['mrr']:.3f}" if deep["queries"] else "deep -"
        print(f"{variant:16} packages {r['packages']['mean_precision']:.3f} "
              f"(all relevant {r['packages']['all_relevant']}, none {r['packages']['none_relevant']})   "
              f"classes {r['classes']['mean_precision']:.3f}   {deep_cells}")
    print(f"\nclass queries ({' / '.join(report['variants'])}; base = share of advisories that are relevant):")
    variants = report["variants"]
    for i, (q, _) in enumerate(ev.CLASS_QUERIES):
        cells = "  ".join(f"{v['class_queries'][i]['precision']:.2f}" for v in variants.values())
        base = next(iter(variants.values()))["class_queries"][i]["base_rate"]
        print(f"  {cells}  base {base:.2f}  {q}")
    if deep_queries:
        print(f"\ndeep queries ({' / '.join(variants)}; reciprocal rank, 0 = not in top {args.k}):")
        for i, (q, _) in enumerate(deep_queries):
            cells = "  ".join(f"{v['deep_queries'][i]['reciprocal_rank']:.2f}" for v in variants.values())
            print(f"  {cells}  {q}")
    print(f"\n->{OUT_PATH.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
