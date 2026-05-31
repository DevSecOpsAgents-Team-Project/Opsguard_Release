"""수정된 코드 경로의 로그/출력 미리보기 (테스트용)."""
import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "DevSecOps-MCP" / "src" / "MCP-Slack-Response"))
sys.path.insert(0, str(ROOT / "DevSecOps-Runtime_Agent"))

SEP = "=" * 60


def section(title: str) -> None:
    print(f"\n{SEP}\n{title}\n{SEP}")


def main() -> None:
    section("[1] Dispatcher — targets 없음 (dispatcher_module.py)")
    from src.dispatcher_module import ActionDispatcher

    results = ActionDispatcher(dry_run=True).dispatch(
        {
            "incident_id": "gd-test-002",
            "scenario": "TEST",
            "recommended_actions": [{"action_id": "disable_access_key", "targets": []}],
        }
    )
    print("CloudWatch/logger 예상:")
    print("  WARNING | src.dispatcher_module | ⚠️ targets 없음 — action_id=disable_access_key")
    print("dispatch 결과:", json.dumps(results, ensure_ascii=False, indent=2))

    section("[2] Runtime engine_handler — L2/L3 조치 (engine_handler.py)")
    from src import engine_handler as eh

    class FakeActions:
        def notify_execution_result_to_slack(self, incident_id, success, detail_message):
            title = "✅ [Agent B] 조치 실행 성공" if success else "❌ [Agent B] 조치 실행 실패"
            print("CloudWatch/logger 예상:")
            print(f"  INFO | engine_handler | 🚀 [조치 실행] 슬랙 승인에 의한 L2/L3 조치 시작 (ID: {incident_id})")
            print("Slack Webhook (actions_module.notify_execution_result_to_slack):")
            print(f"  text: {title}")
            print(f"  Incident ID: {incident_id}")
            print(f"  결과: {'성공' if success else '실패'}")
            print(f"  상세: {detail_message}")
            return {"status": "SUCCESS"}

    mock_results = [
        {
            "action_id": "disable_access_key",
            "target_id": "AKIA-FAKE",
            "status": "FAILED",
            "error": "Access key not found",
        }
    ]
    with patch.object(eh, "ActionDispatcher") as mock_dispatcher:
        mock_dispatcher.return_value.dispatch.return_value = mock_results
        with patch.object(eh, "Actions", FakeActions):
            out = eh._execute_approved_actions(
                {
                    "incident_id": "gd-test-002",
                    "scenario": "TEST",
                    "recommended_actions": [
                        {"action_id": "disable_access_key", "targets": [{"id": "AKIA-FAKE"}]}
                    ],
                }
            )
    print("Runtime Lambda 반환 (MCP가 파싱):")
    print(json.dumps(
        {k: out[k] for k in ("status", "execution_success", "detail")},
        ensure_ascii=False,
        indent=2,
    ))

    section("[3] MCP approve_l — response_url 갱신 (lambda_function.py)")
    import lambda_function as slack_lambda

    posted = []

    def fake_post(url, json=None, **kwargs):
        posted.append(json or {})
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    runtime_payload = {
        "execution_success": False,
        "detail": "다음 조치가 실패했습니다:\n• `disable_access_key` (AKIA-FAKE): FAILED",
        "incident_id": "gd-test-002",
        "status": "ACTION_PARTIAL_OR_FAILED",
    }
    fake_invoke = {
        "Payload": MagicMock(read=lambda: json.dumps(runtime_payload).encode("utf-8")),
    }
    action_value = {
        "incident_id": "gd-test-002",
        "scenario": "TEST",
        "recommended_actions": [
            {"action_id": "disable_access_key", "targets": [{"id": "AKIA-FAKE"}]}
        ],
    }
    slack_body = "payload=" + json.dumps(
        {
            "user": {"username": "tester"},
            "response_url": "https://hooks.slack.com/response/test",
            "actions": [{"action_id": "approve_l2", "value": json.dumps(action_value)}],
        }
    )

    with patch.object(slack_lambda, "RUNTIME_ARN", "arn:aws:lambda:ap:123:function:runtime"):
        with patch.object(slack_lambda.requests, "post", side_effect=fake_post):
            with patch.object(slack_lambda.lambda_client, "invoke", return_value=fake_invoke):
                slack_lambda.lambda_handler({"body": slack_body}, None)

    print("CloudWatch/stdout 예상:")
    print("  🚀 [Runtime Call] 조치 실행을 위해 Runtime 람다 동기 호출 시작...")
    print('  📦 [Runtime] result: {"execution_success": false, "detail": "...", ...}')
    print("\nSlack response_url POST 순서:")
    for i, msg in enumerate(posted, 1):
        ro = msg.get("replace_original")
        text = msg.get("text", "")
        print(f"\n  --- 메시지 #{i} (replace_original={ro}) ---")
        print(text)

    section("[4] Regulation XAI — Slack 블록 텍스트 (finance_bridge.py)")
    from finance_bridge import format_regulation_xai_explanation

    sample_path = ROOT / "DevSecOps-Finance_Agent" / "samples" / "regulation_output_example.json"
    regulation = json.loads(sample_path.read_text(encoding="utf-8"))
    regulation["justification"] = "Root 자격 증명 사용 탐지 → Level 3 격리 권장"
    regulation["reasoning_bullets"] = [
        "GuardDuty Policy:IAMUser/RootCredentialUsage",
        "ISMS-P 2.4.1 매핑",
    ]
    xai = format_regulation_xai_explanation(regulation)
    print("Slack section text (일부):")
    print("*🧠 Regulation Agent (XAI) — 왜 L2/L3 플레이북을 제안했는가?*")
    print(xai)

    print(f"\n{SEP}\n완료 — 위 로그가 Lambda/Slack E2E에서도 동일 패턴으로 출력됩니다.\n{SEP}")


if __name__ == "__main__":
    main()
