from pathlib import Path
from pypdf import PdfReader
from src.config import DATA_DIR


def read_pdf_text(source) -> str:
    reader = PdfReader(str(source) if isinstance(source, Path) else source)
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n".join(pages)


def read_knowledge_files() -> list[dict]:
    knowledge = []
    paths = sorted(Path(DATA_DIR).glob("*.txt")) + sorted(Path(DATA_DIR).glob("*.pdf"))
    for path in paths:
        text = read_pdf_text(path) if path.suffix.lower() == ".pdf" else path.read_text(encoding="utf-8")
        knowledge.append({"source": path.name, "text": text})
    return knowledge
