import base64
from typing import List, Optional
from openai import OpenAI
from src.config import OPENAI_API_KEY, OPENAI_MODEL, OPENAI_VISION_MODEL, OPENAI_EMBEDDING_MODEL

_client: Optional[OpenAI] = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=OPENAI_API_KEY)
    return _client


def create_embeddings(texts: List[str]) -> List[List[float]]:
    response = get_client().embeddings.create(input=texts, model=OPENAI_EMBEDDING_MODEL)
    return [item.embedding for item in response.data]


def generate_text(prompt: str, max_tokens: int = 700) -> str:
    response = get_client().chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": "أنت مساعد امتثال متخصص في تدقيق الامتثال التنظيمي والتحول الرقمي والأمن السيبراني."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return response.choices[0].message.content.strip()


def analyze_image_evidence(image_bytes: bytes, mime_type: str, prompt: str, max_tokens: int = 500) -> str:
    encoded = base64.b64encode(image_bytes).decode("utf-8")
    data_url = f"data:{mime_type};base64,{encoded}"
    response = get_client().chat.completions.create(
        model=OPENAI_VISION_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "أنت مدقق امتثال يفحص لقطات شاشة ووثائق مصورة كأدلة إثبات. "
                    "صف بدقة ما تراه في الصورة، وحدد هل تطابق نوع الدليل المطلوب للمعيار المحدد، "
                    "وابحث عن أي تاريخ أو طابع زمني ظاهر في الصورة وحدده بوضوح."
                ),
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            },
        ],
        max_tokens=max_tokens,
        temperature=0.1,
    )
    return response.choices[0].message.content.strip()
