"""Build the advisory-chunk vector index (Phase 6 semantic retrieval).

Each variant is an embedding model plus how chunks are fed to it, so the
choice can be measured (scripts/eval_advisory_retrieval.py):

- minilm_whole: one vector per raw chunk (MiniLM silently truncates long ones).
  all-MiniLM-L6-v2 reads 256 word-pieces and the HF endpoint silently drops
  the rest, so for long chunks only the first ~150 words count.
- minilm_windowed: each chunk split into ~110-word windows, each starting
  with the advisory's summary and packages (retrieval.windows,
  npm.advisory.embedding_prefix).
- bge_m3_whole: BAAI/bge-m3 reads up to 8192 tokens, so each chunk (at most
  802 words) is embedded whole, with the same summary/packages prefix.

Every variant produces window ids ("<chunk_id>#w<n>", one window when
unsplit), so retrieval.windows.search_chunks serves any of them. Queries
must be embedded with the variant's own model.
"""

from dataclasses import dataclass
from pathlib import Path

from huggingface_hub import InferenceClient

from ..retrieval import VectorIndex, embed_chunks, embed_texts
from ..retrieval.windows import embedding_windows
from .advisory import embedding_prefix

MINILM = "sentence-transformers/all-MiniLM-L6-v2"
BGE_M3 = "BAAI/bge-m3"
# Best-chunk cosine on scripts/calibrate_semantic_floor.py's questions (2026-10-31): on-topic 0.34-0.74,
# plainly off-topic 0.10-0.25. Off-topic tech questions ("what is npm?" 0.42) overlap the on-topic band;
# the classifier's off_topic route has to catch those. It also wrongly called 2 of the 18 on-topic ones
# off_topic (0.54, 0.52), which the second floor (above every off-topic score seen) answers anyway.
MINILM_WINDOWED_FLOOR = 0.30
MINILM_WINDOWED_OFF_TOPIC_FLOOR = 0.45


@dataclass(frozen=True)
class Variant:
    model: str
    dimensions: int
    use_prefix: bool
    max_words: int | None  # None: embed each chunk whole
    # Semantic-route similarity floor: chunks scoring below it are dropped, and a question with
    # none left is declined. Scores are model-specific, so it is calibrated per variant (None: off).
    min_score: float | None = None
    # A question the classifier calls off_topic is still answered if its best chunk reaches this
    # (the classifier sometimes refuses terse security questions). None: off_topic is final.
    off_topic_min_score: float | None = None


VARIANTS = {
    "minilm_whole": Variant(MINILM, 384, use_prefix=False, max_words=None),
    "minilm_windowed": Variant(MINILM, 384, use_prefix=True, max_words=110, min_score=MINILM_WINDOWED_FLOOR,
                               off_topic_min_score=MINILM_WINDOWED_OFF_TOPIC_FLOOR),
    "bge_m3_whole": Variant(BGE_M3, 1024, use_prefix=True, max_words=None),
}
DEFAULT_VARIANT = "minilm_windowed"


def index_path(directory: Path, variant: str) -> Path:
    return directory / f"advisory_index_{variant}"


def advisory_windows(chunks: list[dict], variant: str = DEFAULT_VARIANT) -> list[dict]:
    options = VARIANTS[variant]
    windows = []
    for chunk in chunks:
        prefix = embedding_prefix(chunk) if options.use_prefix else ""
        windows.extend(embedding_windows(chunk["chunk_id"], chunk["text"], prefix=prefix, max_words=options.max_words))
    return windows


def build_advisory_index(
    chunks: list[dict], *, client: InferenceClient, cache_root: Path, variant: str = DEFAULT_VARIANT
) -> VectorIndex:
    options = VARIANTS[variant]
    ids, vectors = embed_chunks(
        advisory_windows(chunks, variant), client=client, model_name=options.model,
        output_dimensionality=options.dimensions, cache_root=cache_root,
    )
    return VectorIndex(ids, vectors)


def embed_query(client: InferenceClient, query: str, variant: str = DEFAULT_VARIANT) -> list[float]:
    [vector] = embed_texts(client, [query], task_type="RETRIEVAL_QUERY", model_name=VARIANTS[variant].model)
    return vector
