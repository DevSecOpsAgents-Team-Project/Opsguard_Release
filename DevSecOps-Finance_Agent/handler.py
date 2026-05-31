"""
Lambda 진입점. event.action에 따라 finance_run / get_simulation_questions / get_simulation_recommendation 실행.
event: { "action": "finance_run" | "get_simulation_questions" | "get_simulation_recommendation", ... }
"""
import json
import logging

from src.engine import finance_run
from src.regulation_simulation import get_simulation_recommendation_from_regulation
from src.simulation_questions import (
    get_simulation_questions,
    get_simulation_recommendation_for_mcp,
)

logger = logging.getLogger(__name__)


def lambda_handler(event, context=None):
    """
    event.action:
      - finance_run: event["request"]으로 비용 계산. 반환 result dict.
      - get_simulation_questions: 시뮬레이션 질문 4개 반환 (MCP용).
      - get_simulation_recommendation: event["comparison"], event["user_response"]로 추천 (playbooks에 cost_summary 없으면 비용 null).
      - get_simulation_recommendation_from_regulation: regulation_result + user_response — L2/L3 비용을 정책으로 산정 후 추천 (MCP/Slack 권장).
    """
    try:
        action = (event.get("action") or "").strip() or (event.get("httpMethod") and "finance_run")
        if not action and "request" in event:
            action = "finance_run"
        if not action and "comparison" in event and "user_response" in event:
            action = "get_simulation_recommendation"
        if not action and "mock_regulation_result" in event and "user_response" in event:
            action = "get_simulation_recommendation_from_regulation"
        if not action and "regulation_result" in event and "user_response" in event:
            action = "get_simulation_recommendation_from_regulation"

        if action == "get_simulation_questions":
            body = get_simulation_questions()
            return _response(200, body)

        if action == "finance_run":
            request = event.get("request") or event.get("body")
            if isinstance(request, str):
                request = json.loads(request)
            if not request:
                return _response(400, {"error": "missing request"})
            body = finance_run(request)
            return _response(200, body)

        if action == "get_simulation_recommendation":
            comparison = event.get("comparison") or {}
            user_response = event.get("user_response") or {}
            if isinstance(comparison, str):
                comparison = json.loads(comparison)
            if isinstance(user_response, str):
                user_response = json.loads(user_response)
            body = get_simulation_recommendation_for_mcp(comparison, user_response)
            return _response(200, body)

        if action == "get_simulation_recommendation_from_regulation":
            regulation_payload = (
                event.get("regulation_result")
                or event.get("mock_regulation_result")
                or event
            )
            user_response = event.get("user_response") or {}
            policy_version = (event.get("policy_version") or "v1.0.0").strip()
            if isinstance(user_response, str):
                user_response = json.loads(user_response)
            if isinstance(regulation_payload, str):
                regulation_payload = json.loads(regulation_payload)

            required_user_fields = ["environment", "data_sensitivity", "downtime_tolerance", "priority"]
            if not isinstance(user_response, dict):
                return _response(400, {"error": "user_response must be an object"})
            missing = [k for k in required_user_fields if k not in user_response]
            if missing:
                return _response(400, {"error": "missing user_response fields", "missing": missing})

            body = get_simulation_recommendation_from_regulation(
                regulation_payload=regulation_payload,
                user_response=user_response,
                policy_version=policy_version,
                event=event,
            )
            return _response(200, body)

        return _response(400, {"error": "unknown action", "action": action})
    except Exception as e:
        logger.exception("lambda_handler error")
        return _response(500, {"error": str(e)})


def _response(status_code: int, body: dict) -> dict:
    """API Gateway 형식 또는 직접 호출용."""
    return {
        "statusCode": status_code,
        "body": body if isinstance(body, dict) else json.loads(body) if isinstance(body, str) else {},
    }
