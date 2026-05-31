"""GuardDuty 이벤트 → regulation_agent.rag (프로덕션과 동일 Top-5) 공통 유틸."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Tuple

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)


def ensure_pythonpath() -> None:
    src = os.path.join(_REPO_ROOT, "src")
    for path in (_REPO_ROOT, src):
        if path not in sys.path:
            sys.path.insert(0, path)


def load_dotenv() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(os.path.join(_REPO_ROOT, ".env"))
    except ImportError:
        pass


def finding_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """process_guardduty_event 와 동일한 finding 추출."""
    raw_event = event.get("raw_event") or {}
    if isinstance(event.get("detail"), dict):
        return event["detail"]
    if isinstance(raw_event.get("detail"), dict):
        return raw_event["detail"]
    if isinstance(event.get("finding"), dict):
        return event["finding"]
    return event


def clause_id_from_row(row: Dict[str, Any]) -> str:
    meta = row.get("metadata") or {}
    return str(row.get("id") or meta.get("clause_id") or meta.get("id") or "")


def decide_level_for_event(event: Dict[str, Any]) -> tuple[int, list[str]]:
    """service.process_guardduty_event 와 동일한 level_router."""
    from level_router import decide_response_level

    finding = finding_from_event(event)
    raw_event = event.get("raw_event") or {}
    runtime_result = event.get("runtime_result") or raw_event.get("runtime_result") or {}
    decision = decide_response_level(finding=finding, runtime_result=runtime_result)
    return decision.selected_level, list(decision.reasons)


def run_guardduty_rag(
    event: Dict[str, Any],
    collection: Any,
    *,
    candidate_actions: List[str] | None = None,
) -> Tuple[str, Any, List[Dict[str, Any]], List[str]]:
    """
    service.process_guardduty_event 와 동일한 RAG 단계:
      build_guardduty_rag_query → chroma_retrieve(RETRIEVAL_TOP_K) → rerank → [:RERANK_OUTPUT_TOP_K]

    Returns:
        query_text, where_filter, ranked_rows (full row dicts), clause_ids (top-K ids)
    """
    from regulation_agent.rag import (
        RERANK_OUTPUT_TOP_K,
        RETRIEVAL_TOP_K,
        build_guardduty_rag_query,
        chroma_retrieve,
        rerank_retrieved_documents,
    )
    from regulation_agent.service import DEFAULT_CANDIDATE_ACTIONS

    finding = finding_from_event(event)
    raw_event = event.get("raw_event") or {}
    runtime_result = event.get("runtime_result") or raw_event.get("runtime_result") or {}
    actions = candidate_actions if candidate_actions is not None else DEFAULT_CANDIDATE_ACTIONS

    query_text, where_filter = build_guardduty_rag_query(
        finding=finding,
        runtime_result=runtime_result,
        candidate_actions=actions,
    )
    pool = chroma_retrieve(
        collection,
        query_text,
        where_filter=where_filter,
        top_k=RETRIEVAL_TOP_K,
    )
    ranked = rerank_retrieved_documents(query_text, finding, pool)[:RERANK_OUTPUT_TOP_K]
    clause_ids = [clause_id_from_row(r) for r in ranked if clause_id_from_row(r)]
    return query_text, where_filter, ranked, clause_ids
