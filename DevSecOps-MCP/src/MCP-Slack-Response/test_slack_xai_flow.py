"""
MCP-Slack-XAI 로컬 검증 테스트
- Regulation XAI Slack 메시지 포맷
- Runtime 조치 성공/실패 Slack 메시지 포맷
- approve_l 핸들러 동기 Runtime 호출 + response_url 갱신
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# MCP-Slack-Response 모듈 경로
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from finance_bridge import (  # noqa: E402
    format_execution_result_slack_message,
    format_regulation_xai_explanation,
    parse_runtime_lambda_response,
)

RUNTIME_ROOT = HERE.parents[2] / "DevSecOps-Runtime_Agent"
sys.path.insert(0, str(RUNTIME_ROOT))

from src.dispatcher_module import ActionDispatcher  # noqa: E402


def _ok(name: str) -> None:
    print(f"  PASS  {name}")


def _fail(name: str, msg: str) -> None:
    print(f"  FAIL  {name}: {msg}")
    raise AssertionError(f"{name}: {msg}")


def test_parse_runtime_lambda_response() -> None:
    raw = json.dumps(
        {
            "execution_success": False,
            "detail": "실행할 조치가 없거나 recommended_actions가 비어 있습니다.",
            "incident_id": "gd-test-002",
        }
    )
    body = parse_runtime_lambda_response(raw)
    assert body["execution_success"] is False
    assert "gd-test-002" in body.get("incident_id", "")
    _ok("parse_runtime_lambda_response (direct JSON)")


def test_format_execution_success() -> None:
    msg = format_execution_result_slack_message(
        "gd-test-001",
        {"execution_success": True, "detail": "승인된 플레이북 조치 2건이 정상 처리되었습니다."},
    )
    assert "✅" in msg and "조치 실행 성공" in msg and "gd-test-001" in msg
    _ok("format_execution_result_slack_message (success)")


def test_format_execution_failure() -> None:
    msg = format_execution_result_slack_message(
        "gd-test-002",
        {
            "execution_success": False,
            "detail": "다음 조치가 실패했습니다:\n• `disable_access_key` (AKIA-FAKE): FAILED",
        },
    )
    assert "❌" in msg and "조치 실행 실패" in msg and "gd-test-002" in msg
    assert "disable_access_key" in msg
    _ok("format_execution_result_slack_message (failure)")


def test_format_regulation_xai() -> None:
    sample_path = HERE.parents[2] / "DevSecOps-Finance_Agent" / "samples" / "regulation_output_example.json"
    if not sample_path.exists():
        _fail("format_regulation_xai_explanation", f"sample not found: {sample_path}")

    regulation = json.loads(sample_path.read_text(encoding="utf-8"))
    regulation["justification"] = "테스트용 XAI 설명: Root 자격 증명 사용은 Level 3 격리가 필요합니다."
    regulation["reasoning_bullets"] = ["Root 계정 사용 탐지", "ISMS-P 2.4.1 위반 가능성"]
    regulation["regulations"] = [
        {
            "framework": "ISMS-P",
            "clause_id": "2.4.1",
            "clause_title": "접근권한 최소 부여",
            "why_relevant": "Root 사용은 최소 권한 원칙 위반",
        }
    ]

    xai = format_regulation_xai_explanation(regulation)
    assert "권장 대응 레벨" in xai
    assert "XAI 종합 설명" in xai
    assert "추론 요약" in xai
    assert "2.4.1" in xai
    _ok("format_regulation_xai_explanation")


def test_dispatcher_empty_targets() -> None:
    dispatcher = ActionDispatcher(dry_run=True)
    results = dispatcher.dispatch(
        {
            "incident_id": "gd-test-002",
            "scenario": "TEST",
            "recommended_actions": [
                {"action_id": "disable_access_key", "targets": []},
            ],
        }
    )
    assert len(results) == 1
    assert results[0]["status"] == "FAILED"
    assert results[0]["action_id"] == "disable_access_key"
    _ok("dispatcher empty targets → FAILED")


def test_engine_handler_execute_approved_actions() -> None:
    from src import engine_handler  # noqa: E402

    mock_results = [
        {"action_id": "disable_access_key", "target_id": "AKIA-FAKE", "status": "FAILED"},
    ]
    slack_calls: list[tuple] = []

    class FakeActions:
        def notify_execution_result_to_slack(self, incident_id, success, detail_message):
            slack_calls.append((incident_id, success, detail_message))
            return {"status": "SUCCESS"}

    with patch.object(engine_handler, "ActionDispatcher") as MockDispatcher:
        MockDispatcher.return_value.dispatch.return_value = mock_results
        with patch.object(engine_handler, "Actions", FakeActions):
            result = engine_handler._execute_approved_actions(
                {
                    "incident_id": "gd-test-002",
                    "scenario": "TEST",
                    "recommended_actions": [{"action_id": "disable_access_key", "targets": []}],
                }
            )

    assert result["execution_success"] is False
    assert result.get("detail")
    assert slack_calls and slack_calls[0][1] is False
    _ok("engine_handler _execute_approved_actions (failure path + slack notify)")


def test_approve_l_updates_response_url() -> None:
    """approve_l: Runtime 동기 호출 후 response_url에 성공/실패 메시지 POST."""
    import lambda_function as slack_lambda  # noqa: E402

    posted: list[dict] = []

    def fake_post(url, json=None, **kwargs):
        posted.append({"url": url, "json": json})
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    runtime_payload = {
        "execution_success": False,
        "detail": "• `disable_access_key` (AKIA-FAKE): FAILED — Access key not found",
        "incident_id": "gd-test-002",
        "status": "ACTION_PARTIAL_OR_FAILED",
    }
    fake_invoke_resp = {
        "Payload": MagicMock(read=lambda: json.dumps(runtime_payload).encode("utf-8")),
    }

    action_value = {
        "incident_id": "gd-test-002",
        "scenario": "TEST",
        "recommended_actions": [
            {
                "action_id": "disable_access_key",
                "targets": [{"type": "AccessKey", "id": "AKIA-FAKE", "user_name": "root"}],
            }
        ],
    }

    slack_event_body = (
        "payload="
        + json.dumps(
            {
                "user": {"username": "tester"},
                "response_url": "https://hooks.slack.com/response/test",
                "actions": [
                    {
                        "action_id": "approve_l2",
                        "value": json.dumps(action_value),
                    }
                ],
            }
        )
    )

    with patch.object(slack_lambda, "RUNTIME_ARN", "arn:aws:lambda:ap-northeast-2:123:function:runtime"):
        with patch.object(slack_lambda.requests, "post", side_effect=fake_post):
            with patch.object(slack_lambda.lambda_client, "invoke", return_value=fake_invoke_resp):
                resp = slack_lambda.lambda_handler({"body": slack_event_body}, None)

    assert resp["statusCode"] == 200
    assert len(posted) >= 2, "loading + result messages expected"

    loading = posted[0]["json"]
    assert "조치 실행 중" in loading.get("text", "")

    final = posted[-1]["json"]
    final_text = final.get("text", "")
    assert "❌" in final_text and "조치 실행 실패" in final_text
    assert "gd-test-002" in final_text
    assert final.get("replace_original") is True
    _ok("approve_l handler → response_url failure message")


def run_all() -> None:
    print("\n=== MCP-Slack-XAI 로컬 테스트 ===\n")
    tests = [
        test_parse_runtime_lambda_response,
        test_format_execution_success,
        test_format_execution_failure,
        test_format_regulation_xai,
        test_dispatcher_empty_targets,
        test_engine_handler_execute_approved_actions,
        test_approve_l_updates_response_url,
    ]
    passed = 0
    for fn in tests:
        try:
            fn()
            passed += 1
        except Exception as exc:
            print(f"\n❌ 테스트 실패: {fn.__name__}\n   {exc}\n")
            raise
    print(f"\n✅ 전체 {passed}/{len(tests)} 테스트 통과\n")


if __name__ == "__main__":
    run_all()
