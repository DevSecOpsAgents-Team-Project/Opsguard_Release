"""
XAI 한국어 로컬화 — Lambda와 동일 경로 E2E 검증

단위 테스트가 아니라 lambda_function.py 와 같은 blocks 조립까지 수행합니다.
선택: SLACK_WEBHOOK_URL 있으면 실제 Slack 전송, AWS Lambda invoke 가능 시 --aws 사용.

사용:
  cd DevSecOps-MCP/src/MCP-Slack-Response
  python test_xai_e2e.py
  python test_xai_e2e.py --post-slack
  python test_xai_e2e.py --aws --function-name YOUR_MCP_SLACK_RESPONSE_FUNCTION
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from finance_bridge import format_regulation_xai_explanation  # noqa: E402


# Slack 스크린샷과 유사한 Regulation Agent 영어 출력 (DynamoDB regulation_data)
SAMPLE_REGULATION_ENGLISH: Dict[str, Any] = {
    "incident_id": "gd-test-s3-001",
    "scenario": "S3PublicAccess",
    "incident_summary": {
        "title": "S3 bucket public access detected",
        "severity": "7.0",
    },
    "escalation_assessment": {
        "recommended_level": 2,
        "confidence": 0.8,
        "approval_notes": "This action requires approval.",
    },
    "reasoning_bullets": ["Regulatory basis for action"],
    "regulations": [
        {
            "framework": "CSA_CCM",
            "clause_id": "DSP-17",
            "clause_title": "Sensitive Data Protection",
            "why_relevant": (
                "This regulation emphasizes the need to protect sensitive data, "
                "relevant due to the public access granted to the S3 bucket."
            ),
            "excerpt": "민감 데이터는 저장·전송 시 암호화 및 접근 통제로 보호해야 한다.",
        },
        {
            "framework": "CSA_CCM",
            "clause_id": "DSP-18",
            "clause_title": "Disclosure Notification",
            "why_relevant": (
                "This regulation is relevant as it outlines the need for procedures "
                "to manage data disclosure requests, which may arise from the incident."
            ),
            "excerpt": "정보 공개·유출 통지 절차를 수립·운영해야 한다.",
        },
        {
            "framework": "CSA_CCM",
            "clause_id": "DSP-10",
            "clause_title": "Sensitive Data Transfer",
            "why_relevant": (
                "This regulation is crucial as it addresses the protection of "
                "sensitive data transfers, which is pertinent given the public access granted."
            ),
            "excerpt": "민감 정보 전송 구간에서 암호화 프로토콜을 사용해야 한다.",
        },
        {
            "framework": "CSA_CCM",
            "clause_id": "DSP-16",
            "clause_title": "Data Retention and Deletion",
            "why_relevant": (
                "This regulation is relevant as it ensures that data management "
                "practices comply with legal and business requirements."
            ),
            "excerpt": "법적·업무 요구에 맞게 데이터 보존 및 파기 정책을 운영해야 한다.",
        },
    ],
    "recommended_actions": [
        {
            "level": 2,
            "playbook_name": "S3 공개 접근 차단",
            "actions": [
                {
                    "action_id": "block_s3_public_access",
                    "targets": [{"type": "S3Bucket", "id": "test-bucket"}],
                }
            ],
        }
    ],
}


def build_xai_slack_block(regulation_data: Dict[str, Any]) -> Dict[str, Any]:
    """lambda_function.py 와 동일한 XAI section block."""
    xai_text = format_regulation_xai_explanation(regulation_data)
    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*🧠 Regulation Agent (XAI) — 왜 L2/L3 플레이북을 제안했는가?*\n{xai_text}",
        },
    }


def assert_korean_xai(xai_text: str) -> List[str]:
    errors = []
    english_markers = [
        "This action requires approval",
        "Regulatory basis for action",
        "This regulation emphasizes",
        "This regulation is relevant",
        "This regulation is crucial",
    ]
    generic_ko = [
        "규제·위협 맥락",
        "규제 근거에 따른 대응",
        "무단 접근 가능성을 줄이기 위해 제안된 조치",
    ]
    for marker in english_markers:
        if marker in xai_text:
            errors.append(f"영어 잔존: {marker!r}")
    for marker in generic_ko:
        if marker in xai_text:
            errors.append(f"뻔한 한국어 문구: {marker!r}")
    if "사건 요약" not in xai_text and "제안 플레이북" not in xai_text:
        errors.append("사건/플레이북 설명 섹션 없음")
    if "S3" not in xai_text and "공개" not in xai_text and "block_s3" not in xai_text.lower():
        if "액세스" not in xai_text and "버킷" not in xai_text:
            errors.append("구체적 대응 설명 부족")
    if not any("\uac00" <= c <= "\ud7a3" for c in xai_text):
        errors.append("한글이 전혀 없음")
    return errors


def run_local_e2e(post_slack: bool = False) -> None:
    print("=" * 60)
    print("[1] Lambda와 동일: format_regulation_xai_explanation → Slack block")
    print("=" * 60)

    block = build_xai_slack_block(SAMPLE_REGULATION_ENGLISH)
    xai_full = block["text"]["text"]
    print(xai_full)
    print()

    errors = assert_korean_xai(xai_full)
    if errors:
        print("❌ 검증 실패:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("✅ XAI 본문 한국어 로컬화 검증 통과\n")

    if post_slack:
        webhook = os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook:
            print("⚠️ SLACK_WEBHOOK_URL 없음 — Slack 전송 스킵")
            return
        import requests

        payload = {"text": "🧪 XAI E2E 테스트", "blocks": [block]}
        r = requests.post(webhook, json=payload, timeout=10)
        print(f"Slack Webhook POST status={r.status_code}")
        if r.status_code == 200:
            print("✅ Slack 채널에서 XAI 블록 확인하세요.")
        else:
            print(f"❌ Slack 오류: {r.text[:200]}")


def run_lambda_handler_mock() -> None:
    """Finance 폼 제출 분기까지 lambda_handler 실행 (DynamoDB/Finance mock)."""
    import lambda_function as lf  # noqa: E402

    print("=" * 60)
    print("[2] lambda_handler Finance 분기 mock E2E (배포 코드 경로)")
    print("=" * 60)

    incident_id = SAMPLE_REGULATION_ENGLISH["incident_id"]
    posted: List[dict] = []

    def fake_post(url, json=None, **kwargs):
        posted.append(json or {})
        m = MagicMock()
        m.status_code = 200
        return m

    comparison = {
        "playbooks": [
            {
                "level": 2,
                "playbook_name": "S3 공개 접근 차단",
                "_regulation_playbook": SAMPLE_REGULATION_ENGLISH["recommended_actions"][0],
                "_estimated_monthly_cost": 7.5,
            }
        ]
    }
    fin_data = {
        "recommended_playbook": {
            "recommended_level": 2,
            "playbook_name": "S3 공개 접근 차단",
            "reason": "비용 대비 S3 공개 차단이 적절합니다.",
        }
    }

    slack_body = "payload=" + json.dumps(
        {
            "user": {"username": "e2e-tester"},
            "response_url": "https://hooks.slack.com/services/TEST/TEST/TEST",
            "state": {
                "values": {
                    "block_env": {"select_env": {"selected_option": {"value": "Prod"}}},
                    "block_data": {"select_data": {"selected_option": {"value": "High"}}},
                    "block_downtime": {"select_downtime": {"selected_option": {"value": "Low"}}},
                    "block_priority": {"select_priority": {"selected_option": {"value": "High"}}},
                }
            },
            "actions": [
                {
                    "action_id": "submit_finance_context",
                    "value": incident_id,
                }
            ],
        }
    )

    mock_table = MagicMock()
    mock_table.get_item.return_value = {
        "Item": {"incident_id": incident_id, "regulation_data": json.dumps(SAMPLE_REGULATION_ENGLISH)}
    }

    with patch.dict(os.environ, {"FINANCE_ARN": "arn:aws:lambda:ap-northeast-2:123:function:finance"}):
        with patch.object(lf, "dynamodb") as mock_ddb:
            mock_ddb.Table.return_value = mock_table
            with patch.object(lf, "build_comparison_with_costs", return_value=comparison):
                with patch.object(lf, "invoke_simulation_recommendation", return_value=fin_data):
                    with patch.object(lf.requests, "post", side_effect=fake_post):
                        resp = lf.lambda_handler({"body": slack_body}, None)

    assert resp["statusCode"] == 200, resp

    # blocks 가 들어간 최종 Slack 메시지 찾기
    final = posted[-1]
    blocks = final.get("blocks") or []
    xai_blocks = [
        b for b in blocks
        if b.get("type") == "section"
        and "Regulation Agent (XAI)" in (b.get("text") or {}).get("text", "")
    ]
    if not xai_blocks:
        print("❌ lambda_handler blocks에 XAI section 없음")
        print(json.dumps(blocks, ensure_ascii=False, indent=2)[:1500])
        sys.exit(1)

    xai_text = xai_blocks[0]["text"]["text"]
    print(xai_text)
    print()

    errors = assert_korean_xai(xai_text)
    if errors:
        print("❌ lambda_handler 경로 검증 실패:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("✅ lambda_handler → Slack blocks XAI 한국어 검증 통과")


def run_aws_invoke(function_name: str) -> None:
    """배포된 Lambda invoke (Finance 전체는 DynamoDB 필요 — finance_bridge만 inline 테스트 payload)."""
    import boto3

    print("=" * 60)
    print(f"[3] AWS Lambda invoke: {function_name}")
    print("=" * 60)

    # approve_l 아닌 health: handler가 import 되는지만 확인하는 ping
    ping = {"ping": True}
    client = boto3.client("lambda", region_name=os.environ.get("AWS_REGION", "ap-northeast-2"))
    try:
        resp = client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(ping).encode("utf-8"),
        )
    except Exception as e:
        print(f"❌ Lambda invoke 실패 (권한/함수명 확인): {e}")
        sys.exit(1)

    raw = resp["Payload"].read().decode("utf-8")
    print(f"StatusCode={resp.get('StatusCode')} FunctionError={resp.get('FunctionError')}")
    print(f"Payload={raw[:500]}")

    # XAI 한국어는 Finance 폼 + DynamoDB 필요 → AWS에서는 Slack UI로 재현 권장
    print(
        "\nℹ️ XAI 한국어는 Finance 폼 제출 시 DynamoDB Regulation_JSON을 읽습니다.\n"
        "   배포 후: GuardDuty → Finance 폼 제출 → L2/L3 화면 XAI 섹션 확인.\n"
        "   또는 [1][2] 로컬 E2E가 Lambda 코드와 동일 경로입니다."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="XAI 한국어 Lambda 동일 경로 E2E")
    parser.add_argument("--post-slack", action="store_true", help="SLACK_WEBHOOK_URL로 실제 전송")
    parser.add_argument("--aws", action="store_true", help="AWS Lambda ping invoke")
    parser.add_argument("--function-name", default=os.environ.get("MCP_SLACK_RESPONSE_FUNCTION", ""))
    args = parser.parse_args()

    run_local_e2e(post_slack=args.post_slack)
    run_lambda_handler_mock()
    if args.aws and args.function_name:
        run_aws_invoke(args.function_name)
    elif args.aws:
        print("\n⚠️ --function-name 또는 MCP_SLACK_RESPONSE_FUNCTION 환경변수 필요")


if __name__ == "__main__":
    main()
