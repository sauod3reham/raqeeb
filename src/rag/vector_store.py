import json
from pathlib import Path
from typing import List
from src.config import VECTOR_STORE_PATH


def save_vector_store(vectors: List[dict]) -> None:
    VECTOR_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTOR_STORE_PATH.write_text(json.dumps(vectors, ensure_ascii=False, indent=2), encoding="utf-8")


def load_vector_store() -> List[dict]:
    if not VECTOR_STORE_PATH.exists():
        return []
    return json.loads(VECTOR_STORE_PATH.read_text(encoding="utf-8"))


def cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def search_vectors(query_embedding: List[float], top_k: int) -> List[dict]:
    store = load_vector_store()
    scored = []
    for item in store:
        score = cosine_similarity(query_embedding, item["embedding"])
        scored.append({"item": item, "score": score})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return [entry["item"] for entry in scored[:top_k]]
