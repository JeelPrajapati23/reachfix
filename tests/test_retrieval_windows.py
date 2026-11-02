import numpy as np

from reachfix.npm.advisory import embedding_prefix
from reachfix.npm.advisory_index import advisory_windows
from reachfix.npm.retrieval_eval import (
    DEEP_QUERIES,
    class_relevance,
    distinct_advisories,
    evidence_offset,
    package_queries,
    precision,
    reciprocal_rank,
)
from reachfix.retrieval import VectorIndex
from reachfix.retrieval.windows import embedding_windows, parent_chunk_id, rollup, search_chunks


def words(n, start=0):
    return " ".join(f"w{i}" for i in range(start, start + n))


def test_short_text_is_one_window_with_prefix():
    [w] = embedding_windows("GHSA-a::0", words(50), prefix="Summary\nPackages: qs")
    assert w["chunk_id"] == "GHSA-a::0#w0"
    assert w["text"].startswith("Summary\nPackages: qs\nw0 ") and w["text"].endswith("w49")


def test_long_text_splits_into_overlapping_windows_covering_everything():
    windows = embedding_windows("c", words(200), max_words=110, overlap=20)

    bodies = [w["text"].split() for w in windows]
    assert [len(b) for b in bodies] == [110, 110]
    assert bodies[0][-20:] == bodies[1][:20]  # overlap
    assert bodies[-1][-1] == "w199"           # nothing dropped


def test_edge_lengths_and_whole_chunk_mode():
    assert len(embedding_windows("c", words(110), max_words=110)) == 1
    assert len(embedding_windows("c", words(111), max_words=110)) == 2
    assert len(embedding_windows("c", words(500), max_words=None)) == 1


def test_parent_chunk_id_keeps_chunk_ids_with_colons():
    assert parent_chunk_id("GHSA-74fj-2j2h-c42q::3#w2") == "GHSA-74fj-2j2h-c42q::3"


def test_rollup_keeps_best_window_per_parent():
    hits = [("a#w1", 0.9), ("b#w0", 0.8), ("a#w0", 0.7), ("c#w0", 0.6)]
    assert rollup(hits, top_k=2) == [("a", 0.9, "a#w1"), ("b", 0.8, "b#w0")]


def test_search_chunks_rolls_up_and_respects_candidates():
    # 2-d vectors: query points at x.
    index = VectorIndex(["a#w0", "a#w1", "b#w0", "c#w0"], np.array([[0.2, 1], [1, 0.1], [1, 0.3], [1, 0]]))
    chunks = {c: {"chunk_id": c, "doc_id": c.upper()} for c in "abc"}

    results = search_chunks("q", index=index, chunks_by_id=chunks, client=None, top_k=2, query_vector=[1, 0])
    assert [(r["chunk_id"], r["matched_window"]) for r in results] == [("c", "c#w0"), ("a", "a#w1")]

    scoped = search_chunks("q", index=index, chunks_by_id=chunks, client=None, top_k=5, query_vector=[1, 0],
                           candidate_chunk_ids={"b"})
    assert [r["chunk_id"] for r in scoped] == ["b"]


def test_advisory_prefix_and_variants():
    chunk = {"chunk_id": "GHSA-a::0", "summary": "ReDoS in foo", "affected_packages": ["foo", "foo-lite"],
             "text": words(300)}
    assert embedding_prefix(chunk) == "ReDoS in foo\nPackages: foo, foo-lite"

    windowed = advisory_windows([chunk], "minilm_windowed")
    whole = advisory_windows([chunk], "minilm_whole")
    bge = advisory_windows([chunk], "bge_m3_whole")
    assert len(windowed) == 4 and all(w["text"].startswith("ReDoS in foo") for w in windowed)
    assert len(whole) == 1 and whole[0]["text"].startswith("w0")
    assert len(bge) == 1 and bge[0]["text"].startswith("ReDoS in foo") and bge[0]["text"].endswith("w299")


def test_eval_helpers():
    chunks = [{"chunk_id": f"G{i}::0", "doc_id": f"G{i}", "affected_packages": ["qs"] if i < 3 else ["ws"],
               "summary": "s", "text": "Regular Expression Denial of Service" if i == 0 else "x"} for i in range(4)]
    assert package_queries(chunks) == [("what security vulnerabilities has qs had?", "qs")]

    results = [{"doc_id": "G0"}, {"doc_id": "G0"}, {"doc_id": "G1"}]
    assert [r["doc_id"] for r in distinct_advisories(results, 5)] == ["G0", "G1"]
    texts = {"G0": "regular expression denial of service", "G1": "x"}
    assert precision(distinct_advisories(results, 5), class_relevance(r"redos|regular expression denial", texts)) == 0.5


def test_deep_query_helpers():
    results = [{"doc_id": "G0"}, {"doc_id": "G1"}, {"doc_id": "G2"}]
    texts = {"G0": "nothing here", "G1": "pass { noext: true } to minimatch", "G2": "noext: true again"}
    assert reciprocal_rank(results, class_relevance(r"noext: true", texts)) == 0.5  # first relevant at rank 2
    assert reciprocal_rank(results, class_relevance(r"absent", texts)) == 0.0
    assert evidence_offset("Workarounds: Pass `NoExt: true`", r"noext: true") == 19  # case-insensitive
    assert evidence_offset("no match", r"noext") is None


def test_deep_query_patterns_compile_and_queries_are_unique():
    import re

    for _, pattern in DEEP_QUERIES:
        re.compile(pattern)
    assert len({q for q, _ in DEEP_QUERIES}) == len(DEEP_QUERIES)


def test_embedding_call_retries_transient_errors_only():
    import httpx
    import pytest
    from huggingface_hub.errors import HfHubHTTPError

    from reachfix.retrieval.embeddings import _feature_extraction

    request = httpx.Request("POST", "https://router.huggingface.co/x")

    def error(status):
        return HfHubHTTPError("err", response=httpx.Response(status, request=request))

    class Flaky:
        def __init__(self, outcomes):
            self.outcomes = outcomes

        def feature_extraction(self, text, model):
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    sleeps = []
    assert _feature_extraction(Flaky([error(502), error(503), [0.1]]), "t", "m", sleep=sleeps.append) == [0.1]
    assert sleeps == [1, 2]
    with pytest.raises(HfHubHTTPError):
        _feature_extraction(Flaky([error(401)]), "t", "m", sleep=sleeps.append)  # auth errors are not retried
