from src.config import RAG_TOP_K
from src.rag.vector_store import search_vectors
from src.llm.client import create_embeddings


def retrieve_evidence(query: str, top_k: int | None = None) -> list[dict]:
    embedding = create_embeddings([query])[0]
    results = search_vectors(embedding, top_k=top_k or RAG_TOP_K)
    return results
