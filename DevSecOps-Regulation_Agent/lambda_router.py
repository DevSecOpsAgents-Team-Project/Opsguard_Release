"""
Lambda 단일 엔트리: 이벤트 스키마에 따라 OpsGuard vs ISMS 문서분기 분기.

- OpsGuard: raw_event / incident_id(+요약·런타임) / detail(finding) 등
- ISMS: 비어 있지 않은 document_text
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)

from src.regulation_agent.lambda_handler import (
    _format_lambda_return,
    _incident_payload_from_event,
    lambda_handler as opsguard_lambda_handler,
)


def _json_preview(obj: Any, *, max_chars: int = 12000) -> str:
    """CloudWatch 용량·가독성을 위해 JSON 문자열을 잘라서 반환."""
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str, indent=2)
    except Exception:
        s = repr(obj)
    if len(s) > max_chars:
        return s[:max_chars] + f"\n... [truncated, length={len(s)}]"
    return s


def _is_opsguard_payload(payload: Dict[str, Any]) -> bool:
    """OpsGuard / Regulation Agent incident 입력인지."""
    if not isinstance(payload, dict) or not payload:
        return False
    if payload.get("raw_event") is not None:
        return True
    if payload.get("incident_id"):
        return True
    if isinstance(payload.get("detail"), dict) and payload["detail"]:
        return True
    if payload.get("finding"):
        return True
    if payload.get("incident_summary") is not None or payload.get("runtime_result") is not None:
        return True
    return False


def _is_document_payload(payload: Dict[str, Any]) -> bool:
    """ISMS 문서 분석: document_text 키가 있고 내용이 비어 있지 않음."""
    if not isinstance(payload, dict):
        return False
    if "document_text" not in payload:
        return False
    return bool(str(payload.get("document_text") or "").strip())


def lambda_handler(event: Dict[str, Any], context: Any) -> Any:
    raw = event or {}
    # 콘솔에서 선택한 테스트 이벤트가 기대와 다른지 확인용 (전체 페이로드)
    logger.info("lambda_router_incoming_event_full:\n%s", _json_preview(raw))
    payload = _incident_payload_from_event(raw)
    logger.info("lambda_router_routing_payload_full (after API GW body unwrap if any):\n%s", _json_preview(payload))

    og = _is_opsguard_payload(payload) if isinstance(payload, dict) else False
    doc = _is_document_payload(payload) if isinstance(payload, dict) else False
    logger.info(
        "lambda_router: keys=%s -> opsguard=%s document=%s",
        list(payload.keys()) if isinstance(payload, dict) else None,
        og,
        doc,
    )

    if isinstance(payload, dict) and og:
        return opsguard_lambda_handler(raw, context)

    if isinstance(payload, dict) and doc:
        try:
            from isms_document_lambda import run_isms_document_analysis_from_event

            out = run_isms_document_analysis_from_event(payload)
            code = 200 if out.get("ok") is not False else 500
            return _format_lambda_return(out, raw, status_code=code)
        except ValueError as e:
            return _format_lambda_return(
                {"ok": False, "step": "validate_input", "error": str(e)},
                raw,
                status_code=400,
            )
        except Exception as e:
            logger.exception("isms_document_pipeline")
            return _format_lambda_return(
                {
                    "ok": False,
                    "step": "isms_pipeline",
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
                raw,
                status_code=500,
            )

    if isinstance(payload, dict) and "document_text" in payload:
        return _format_lambda_return(
            {"ok": False, "step": "validate_input", "error": "document_text is required"},
            raw,
            status_code=400,
        )

    return _format_lambda_return(
        {
            "ok": False,
            "step": "validate_input",
            "error": (
                "Unrecognized event: use OpsGuard incident "
                "(incident_id, raw_event, incident_summary, …) "
                "or ISMS document analysis with non-empty document_text"
            ),
            "received_keys": list(payload.keys()) if isinstance(payload, dict) else [],
        },
        raw,
        status_code=400,
    )
