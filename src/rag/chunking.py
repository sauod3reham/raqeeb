import re
from typing import List


def clean_text(text: str) -> str:
    text = text.replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    return text


def chunk_text(text: str, max_words: int = 120) -> List[str]:
    words = clean_text(text).split()
    chunks = []
    for i in range(0, len(words), max_words):
        chunk = " ".join(words[i : i + max_words])
        chunks.append(chunk)
    return chunks
