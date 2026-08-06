from src.config import MAX_CHUNK_WORDS, CHUNK_OVERLAP_WORDS
from src.rag.loaders import read_knowledge_files
from src.rag.chunking import chunk_text
from src.rag.vector_store import save_vector_store
from src.llm.client import create_embeddings


def prepare_knowledge() -> list[dict]:
    all_vectors = []
    documents = read_knowledge_files()
    for document in documents:
        chunks = chunk_text(document["text"], max_words=MAX_CHUNK_WORDS, overlap_words=CHUNK_OVERLAP_WORDS)
        embeddings = create_embeddings(chunks)
        for chunk, embedding in zip(chunks, embeddings):
            all_vectors.append(
                {
                    "source": document["source"],
                    "text": chunk,
                    "embedding": embedding,
                }
            )
    save_vector_store(all_vectors)
    return all_vectors


def ensure_vector_store() -> None:
    from src.rag.vector_store import load_vector_store

    if not load_vector_store():
        prepare_knowledge()
