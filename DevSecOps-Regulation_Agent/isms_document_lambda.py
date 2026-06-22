"""
ISMS 문서 분석 Lambda 경로 (document_text 기반, Step1→RAG→Step4).

OpsGuard incident 이벤트와 분리하여 lambda_router에서만 호출한다.
"""

from __future__ import annotations

from typing import Any, Dict


def run_isms_document_analysis_from_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    payload에 비어 있지 않은 document_text가 있어야 한다.
    성공 시 {"ok": True, "step": "complete", ...analyzer fields } 형태.
    """
    from main import step1_checklist_validation, step2_rag_search
    from step4_llm_analysis import Step4LLMAnalyzer
    from test_isms_rag import load_chromadb

    document_text = str(payload.get("document_text", "")).strip()
    if not document_text:
        raise ValueError("document_text is required")

    temp_path = "/tmp/isms_input.txt"
    with open(temp_path, "w", encoding="utf-8") as f:
        f.write(document_text)

    step1_items = step1_checklist_validation(temp_path)
    if not step1_items:
        return {
            "ok": True,
            "step": "step1",
            "summary": "True로 판정된 체크리스트 항목이 없습니다.",
            "findings": [],
        }

    collection = load_chromadb()
    step2_results = step2_rag_search(collection, step1_items)
    if not step2_results:
        return {
            "ok": True,
            "step": "step2",
            "summary": "검색된 규정 결과가 없습니다.",
            "findings": [],
        }

    analyzer = Step4LLMAnalyzer()
    result = analyzer.analyze(step1_items, step2_results)
    return {"ok": True, "step": "complete", **result}
