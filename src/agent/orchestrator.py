from typing import List, Optional
from src.llm.client import generate_text
from src.llm.prompts import build_audit_prompt
from src.agent.tool_registry import calculate_compliance_score, generate_compliance_report


def analyze_with_tools(
    proposal_text: str,
    evidence: List[dict],
    standard_id: Optional[str] = None,
    standard_title: Optional[str] = None,
    framework_label: Optional[str] = None,
) -> dict:
    prompt = build_audit_prompt(proposal_text, evidence, standard_id, standard_title, framework_label)
    summary = generate_text(prompt)

    findings = []
    for item in evidence:
        status = "compliant" if "تدقيق" not in item["text"] else "needs review"
        findings.append(
            {
                "requirement": item["source"],
                "status": status,
                "evidence": item["text"],
                "notes": "تم ربط هذا العنصر مع الطلب." if status == "compliant" else "يحتاج إلى مزيد من التحقق والضبط.",
            }
        )

    score = calculate_compliance_score(findings)
    report_csv = generate_compliance_report(findings)
    return {
        "summary": summary,
        "findings": findings,
        "score": score,
        "report_csv": report_csv,
    }
