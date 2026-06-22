from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

# Chroma는 service import 시 로드됨 — 그 전에 telemetry 비활성화
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)


def _is_api_gateway_event(event: Optional[Dict[str, Any]]) -> bool:
    """API Gateway(REST/HTTP) 프록시 이벤트 여부. 콘솔 직접 테스트 JSON에는 보통 없음."""
    if not isinstance(event, dict) or not event:
        return False
    if event.get("requestContext"):
        return True
    if event.get("version") == "2.0" and ("routeKey" in event or "rawPath" in event):
        return True
    return False


def _incident_payload_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    API Gateway면 body(JSON)를 파싱해 incident payload로 쓴다.
    콘솔/Invoke 직접 테스트는 event 자체가 incident JSON.
    """
    if not _is_api_gateway_event(event):
        return dict(event or {})
    raw = event.get("body")
    if raw is None:
        return {}
    if isinstance(raw, str):
        if not raw.strip():
            return {}
        try:
            inner = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("API Gateway body JSON parse failed; using empty payload")
            return {}
    else:
        inner = raw
    return dict(inner) if isinstance(inner, dict) else {}


def _format_lambda_return(
    payload: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    *,
    status_code: int = 200,
) -> Any:
    """콘솔/Invoke: dict 그대로. API Gateway: HTTP 응답 래퍼."""
    if _is_api_gateway_event(event):
        return {
            "statusCode": status_code,
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "body": json.dumps(payload, ensure_ascii=False, default=str),
        }
    return payload


def _log_final_result(final_result: Dict[str, Any]) -> None:
    sp = final_result.get("selected_playbook") if isinstance(final_result, dict) else None
    primary = (sp or {}).get("playbook_name") if isinstance(sp, dict) else None
    logger.info(
        "lambda_final_result: type=%s keys=%s selected_level=%r schema_version=%r "
        "selected_playbook.playbook_name=%r",
        type(final_result).__name__,
        list(final_result.keys()) if isinstance(final_result, dict) else None,
        final_result.get("selected_level") if isinstance(final_result, dict) else None,
        final_result.get("schema_version") if isinstance(final_result, dict) else None,
        primary,
    )


def lambda_handler(event: Dict[str, Any], context: Any) -> Any:
    # 예전 ISMS 핸들러는 "lambda_handler: invoke start" 만 찍음 → 그 로그면 구 이미지.
    # OPSGUARD_IMAGE_TAG + 아래 문구가 보이면 이 레포의 OpsGuard(output contract) 핸들러.
    _tag = os.environ.get("OPSGUARD_IMAGE_TAG", "MISSING_ENV")
    logger.info(
        "OPSGUARD_IMAGE_TAG=%s regulation_agent_opsguard_handler: entry keys=%s",
        _tag,
        list((event or {}).keys()) if isinstance(event, dict) else None,
    )

    from .service import process_guardduty_event

    payload = _incident_payload_from_event(event or {})
    try:
        final_result = process_guardduty_event(payload)
    except Exception as exc:
        logger.exception("process_guardduty_event failed")
        err: Dict[str, Any] = {
            "status": "error",
            "error_type": type(exc).__name__,
            "message": str(exc),
        }
        return _format_lambda_return(err, event, status_code=500)

    if not isinstance(final_result, dict):
        logger.warning("process_guardduty_event returned non-dict: %s", type(final_result))
        final_result = {"status": "error", "message": "Invalid response shape", "raw": str(final_result)}

    _log_final_result(final_result)

    status = final_result.get("status")
    code = 200 if status != "error" else 500
    return _format_lambda_return(final_result, event, status_code=code)
