from typing import List, Optional
from src.rag.retriever import retrieve_evidence
from src.agent.orchestrator import analyze_with_tools
from src.security.prompt_guard import detect_injection
from src.security.file_validation import sanitize_plain_text, MAX_TEXT_LEN
from src.security.audit_log import log_event, new_correlation_id

BLOCKED_MESSAGE = (
    "تعذّر إتمام هذا الطلب: تم رصد نمط في المحتوى المرفوع قد يمثل محاولة للتأثير على تعليمات النظام. "
    "تم إيقاف المعالجة لأسباب أمنية. يرجى مراجعة الملف/النص المرفوع وإزالة أي تعليمات موجّهة للنظام ثم إعادة المحاولة."
)


def run_audit(
    proposal_text: str,
    user_request: str,
    standard_id: Optional[str] = None,
    standard_title: Optional[str] = None,
    framework_label: Optional[str] = None,
    image_evidence_notes: Optional[List[str]] = None,
    correlation_id: Optional[str] = None,
    user: str = "-",
    role: str = "-",
) -> dict:
    correlation_id = correlation_id or new_correlation_id()

    # Defense-in-depth: hard length caps regardless of what the UI already enforced.
    proposal_text = sanitize_plain_text(proposal_text, MAX_TEXT_LEN)
    user_request = sanitize_plain_text(user_request, 500)
    image_evidence_notes = [sanitize_plain_text(note, 3000) for note in (image_evidence_notes or [])]

    # Direct + indirect (document/image-derived) prompt-injection screening.
    injection_hits = detect_injection(proposal_text) or detect_injection(user_request)
    for note in image_evidence_notes:
        injection_hits = injection_hits or detect_injection(note)
    if injection_hits:
        log_event(
            event="prompt_injection_blocked",
            correlation_id=correlation_id,
            user=user,
            role=role,
            resource=f"standard={standard_id}",
            result="blocked",
            details=f"matched_patterns_count={len(injection_hits)}",
        )
        return {"final_answer": BLOCKED_MESSAGE, "blocked": True}

    if standard_id and standard_title:
        query = f"معيار {standard_id} {standard_title} الهدف المتطلبات الرئيسية"
        evidence = retrieve_evidence(query, top_k=6)
    else:
        evidence = retrieve_evidence(user_request)

    if not evidence:
        log_event(
            event="audit_run", correlation_id=correlation_id, user=user, role=role,
            resource=f"standard={standard_id}", result="no_evidence",
        )
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
    log_event(
        event="audit_run", correlation_id=correlation_id, user=user, role=role,
        resource=f"standard={standard_id}", result="completed",
        details=f"score={analysis['score']}",
    )
    return {
        "final_answer": final_answer,
        "report_csv": analysis["report_csv"],
        "evidence": evidence,
        "score": analysis["score"],
    }
