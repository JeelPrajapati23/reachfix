import numpy as np
import pytest

from reachfix.npm.advisory_index import BGE_M3, MINILM
from reachfix.retrieval import build_embedding_client, embed_texts
from reachfix.retrieval.embeddings import LOCAL_MODELS, EmbeddingClient


class FakeLocal:
    def __init__(self, name):
        self.name = name

    def embed(self, texts):
        return (np.array([len(t), 1.0]) for t in texts)


class FakeHF:
    def __init__(self):
        self.calls = []

    def feature_extraction(self, text, model):
        self.calls.append(model)
        return [9.0, 9.0]


def test_minilm_runs_locally_and_loads_once():
    loaded = []
    hf = FakeHF()
    client = EmbeddingClient(hf, local_factory=lambda name: loaded.append(name) or FakeLocal(name))

    vectors = embed_texts(client, ["abc", "de"], task_type="RETRIEVAL_QUERY", model_name=MINILM)

    assert vectors == [[3.0, 1.0], [2.0, 1.0]] and loaded == [MINILM] and hf.calls == []


def test_other_models_go_to_hugging_face():
    hf = FakeHF()
    client = EmbeddingClient(hf, local_factory=lambda name: pytest.fail("bge-m3 has no local model"))
    assert embed_texts(client, ["x"], task_type="RETRIEVAL_QUERY", model_name=BGE_M3) == [[9.0, 9.0]]
    assert hf.calls == [BGE_M3]


def test_a_hugging_face_model_without_a_token_says_so():
    with pytest.raises(RuntimeError, match="HF_TOKEN is not set"):
        EmbeddingClient(None).feature_extraction("x", model=BGE_M3)


def test_the_client_builds_without_a_token(monkeypatch):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    client = build_embedding_client()
    assert client.hf is None and MINILM in LOCAL_MODELS
