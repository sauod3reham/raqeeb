from typing import List, Optional
from src.rag.retriever import retrieve_evidence
from src.agent.orchestrator import analyze_with_tools


def run_audit(
    proposal_text: str,
    user_request: str,
    standard_id: Optional[str] = None,
    standard_title: Optional[str] = None,
    framework_label: Optional[str] = None,
    image_evidence_notes: Optional[List[str]] = None,
) -> dict:
    if standard_id and standard_title:
        query = f"معيار {standard_id} {standard_title} الهدف المتطلبات الرئيسية"
        evidence = retrieve_evidence(query, top_k=6)
    else:
        evidence = retrieve_evidence(user_request)

    if not evidence:
        return {
            "final_answer": (
                "لا يوجد دليل كافٍ في قاعدة المعرفة الحالية. "
                "يرجى تحديث المعلومات أو إعادة صياغة الطلب.")
        }

    combined_text = proposal_text
    if image_evidence_notes:
        images_section = "\n\n".join(
            f"[دليل مصور {i + 1}]\n{note}" for i, note in enumerate(image_evidence_notes)
        )
        combined_text = f"{combined_text}\n\n--- تحليل الأدلة المصورة المرفقة ---\n{images_section}"

    analysis = analyze_with_tools(combined_text, evidence, standard_id, standard_title, framework_label)
    header = (
        f"الإطار: {framework_label}\nالمعيار/الضابط المُدقَّق: {standard_id} - {standard_title}\n\n"
        if standard_id and standard_title
        else ""
    )
    final_answer = (
        f"{header}"
        f"تقييم الامتثال: {analysis['score']} من 100\n\n"
        f"{analysis['summary']}\n\n"
        f"المصادر المستخدمة: {', '.join({item['source'] for item in evidence})}"
    )
    return {
        "final_answer": final_answer,
        "report_csv": analysis["report_csv"],
        "evidence": evidence,
        "score": analysis["score"],
    }
