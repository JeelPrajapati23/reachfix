"""Chunk/query embeddings: all-MiniLM-L6-v2 runs locally, other models on the Hugging Face Inference API.

The local model is fastembed's ONNX export of all-MiniLM-L6-v2. It gives the
same vectors as the HF endpoint (cosine 1.0 on the stored index), so indexes
built either way are interchangeable, and query embedding needs no HF token
or credits. Models it doesn't cover (bge-m3) go to HF, which needs HF_TOKEN.

Unlike Gemini's asymmetric embedding API (separate RETRIEVAL_QUERY/
RETRIEVAL_DOCUMENT task types), HF's plain feature-extraction endpoint has
no query/document distinction — task_type is accepted for interface
compatibility with existing call sites (search.py, pipeline.py) and
otherwise unused.
"""

import os
import threading
import time
from collections.abc import Callable

import httpx
import numpy as np
from huggingface_hub import InferenceClient
from huggingface_hub.errors import HfHubHTTPError, InferenceTimeoutError

DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_OUTPUT_DIMENSIONALITY = 384  # all-MiniLM-L6-v2's native dimension; used for cache-key namespacing only
# Models run locally with fastembed instead of on HF (fastembed knows them by the same name).
LOCAL_MODELS = frozenset({"sentence-transformers/all-MiniLM-L6-v2"})
MAX_RETRIES = 4  # transient 5xx / timeouts / dropped connections, with exponential backoff


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, (InferenceTimeoutError, httpx.TransportError)):
        return True
    status = getattr(getattr(exc, "response", None), "status_code", None)
    return isinstance(exc, HfHubHTTPError) and status is not None and status >= 500


def _feature_extraction(client: InferenceClient, text: str, model_name: str, sleep=time.sleep):
    """One embedding call, retried on transient errors (the HF router returns the odd 502)."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            return client.feature_extraction(text, model=model_name)
        except Exception as exc:
            if attempt == MAX_RETRIES or not _is_transient(exc):
                raise
            sleep(2 ** attempt)
    raise AssertionError("unreachable")


class EmbeddingClient:
    """InferenceClient's `feature_extraction`, run locally for LOCAL_MODELS and on HF for the rest.

    Local models load on first use. `local_factory` (model name -> object with
    fastembed's `embed`) is for tests.
    """

    def __init__(self, hf: InferenceClient | None = None, local_factory: Callable[[str], object] | None = None):
        self.hf = hf
        self._local_factory = local_factory or _fastembed_model
        self._local: dict[str, object] = {}
        self._lock = threading.Lock()  # API handlers run in a threadpool; load each model once

    def feature_extraction(self, text: str, model: str):
        if model in LOCAL_MODELS:
            with self._lock:
                if model not in self._local:
                    self._local[model] = self._local_factory(model)
            return np.asarray(next(iter(self._local[model].embed([text]))))
        if self.hf is None:
            raise RuntimeError(f"HF_TOKEN is not set (check .env); {model} is embedded on Hugging Face "
                               f"(only {', '.join(sorted(LOCAL_MODELS))} runs locally)")
        return self.hf.feature_extraction(text, model=model)


def _fastembed_model(name: str):
    from fastembed import TextEmbedding  # imported lazily: loading onnxruntime takes a moment

    return TextEmbedding(name)


def build_embedding_client(api_key: str | None = None) -> EmbeddingClient:
    """Local embeddings always; HF too when HF_TOKEN (or `api_key`) is set."""
    api_key = api_key or os.environ.get("HF_TOKEN")
    return EmbeddingClient(InferenceClient(token=api_key) if api_key else None)


def embed_texts(
    client: InferenceClient,
    texts: list[str],
    *,
    task_type: str,
    model_name: str = DEFAULT_EMBEDDING_MODEL,
) -> list[list[float]]:
    """Embed a batch of texts, one Inference API call per text.

    A 2D per-token result (a model without built-in pooling) is mean-pooled
    into a single vector; sentence-transformers models like the default
    already return one pooled vector per input.
    """
    vectors = []
    for text in texts:
        result = np.asarray(_feature_extraction(client, text, model_name))
        if result.ndim == 2:
            result = result.mean(axis=0)
        vectors.append(result.tolist())
    return vectors
