"""Fixed, non-agentic tool set invoked directly by orchestrator code — never
selected or executed dynamically based on LLM/user output. Both functions are
pure data transforms (no filesystem/network/subprocess/eval access), which is
the allowlist boundary for this module: any future tool must keep that
property, and any tool with real side effects (write/delete/send) must
require explicit human confirmation before running (see app.py gating)."""
import csv
import io
from typing import List


def calculate_compliance_score(findings: List[dict]) -> int:
    if not findings:
        return 0
    matched = sum(1 for item in findings if item.get("status") == "compliant")
    score = int((matched / len(findings)) * 100)
    return score


def generate_compliance_report(findings: List[dict]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["requirement", "status", "evidence", "notes"],
    )
    writer.writeheader()
    for item in findings:
        writer.writerow(
            {
                "requirement": item.get("requirement", ""),
                "status": item.get("status", ""),
                "evidence": item.get("evidence", ""),
                "notes": item.get("notes", ""),
            }
        )
    return output.getvalue()
