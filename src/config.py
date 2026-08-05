import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "knowledge"
VECTOR_STORE_PATH = PROJECT_ROOT / "data" / "rag_vectors.json"
REPORTS_DIR = PROJECT_ROOT / "reports"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_VISION_MODEL = os.getenv("OPENAI_VISION_MODEL", "gpt-4o-mini")
OPENAI_EMBEDDING_MODEL = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-large")
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "4"))
MAX_CHUNK_WORDS = int(os.getenv("MAX_CHUNK_WORDS", "120"))
CURRENT_COMPLIANCE_YEAR = int(os.getenv("CURRENT_COMPLIANCE_YEAR", "2026"))
