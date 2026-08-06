import re
from typing import List


def clean_text(text: str) -> str:
    text = text.replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    return text


def chunk_text(text: str, max_words: int = 120, overlap_words: int = 20) -> List[str]:
    words = clean_text(text).split()
    if overlap_words >= max_words:
        raise ValueError("overlap_words must be smaller than max_words")
    step = max_words - overlap_words
    chunks = []
    for i in range(0, len(words), step):
        chunk = " ".join(words[i : i + max_words])
        chunks.append(chunk)
        if i + max_words >= len(words):
            break
    return chunks
