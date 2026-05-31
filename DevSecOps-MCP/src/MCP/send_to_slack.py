import json
import logging
import os

import requests

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "")


def send_finance_context_request(incident_id, summary_title, severity):
    if not SLACK_BOT_TOKEN or not SLACK_CHANNEL:
        missing = []
        if not SLACK_BOT_TOKEN:
            missing.append("SLACK_BOT_TOKEN")
        if not SLACK_CHANNEL:
            missing.append("SLACK_CHANNEL")
        logger.error("[MCP][SLACK] missing env: %s", ", ".join(missing))
        raise ValueError("SLACK_BOT_TOKEN, SLACK_CHANNEL 환경변수가 필요합니다.")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "📊 Finance 평가를 위한 컨텍스트 입력"}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*이벤트:* {summary_title}\n*심각도:* 🔥 {severity}\n\n정확한 대응 비용 및 우선순위 계산을 위해 아래 정보를 선택한 후 제출해 주세요."}
        },
        {"type": "divider"},
        # 1. 운영 환경
        {
            "type": "section",
            "block_id": "block_env",
            "text": {"type": "mrkdwn", "text": "*운영 환경*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_env",
                "placeholder": {"type": "plain_text", "text": "선택하세요"},
                "options": [
                    {"text": {"type": "plain_text", "text": "Production"}, "value": "production"},
                    {"text": {"type": "plain_text", "text": "Internal"}, "value": "internal"},
                    {"text": {"type": "plain_text", "text": "Dev/Test"}, "value": "dev_test"}
                ]
            }
        },
        # 2. 데이터 민감도
        {
            "type": "section",
            "block_id": "block_data",
            "text": {"type": "mrkdwn", "text": "*데이터 민감도*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_data",
                "placeholder": {"type": "plain_text", "text": "선택하세요"},
                "options": [
                    {"text": {"type": "plain_text", "text": "PII (개인정보)"}, "value": "pii"},
                    {"text": {"type": "plain_text", "text": "Internal (내부용)"}, "value": "internal"},
                    {"text": {"type": "plain_text", "text": "Public (공개)"}, "value": "public"}
                ]
            }
        },
        # 3. 서비스 일시 중단 허용 여부
        {
            "type": "section",
            "block_id": "block_downtime",
            "text": {"type": "mrkdwn", "text": "*서비스 일시 중단 허용 여부*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_downtime",
                "placeholder": {"type": "plain_text", "text": "선택하세요"},
                "options": [
                    {"text": {"type": "plain_text", "text": "Allowed (허용)"}, "value": "allowed"},
                    {"text": {"type": "plain_text", "text": "Approval Required (승인 필요)"}, "value": "approval_required"},
                    {"text": {"type": "plain_text", "text": "Not Allowed (불가)"}, "value": "not_allowed"}
                ]
            }
        },
        # 4. 보안 vs 비용 우선순위
        {
            "type": "section",
            "block_id": "block_priority",
            "text": {"type": "mrkdwn", "text": "*보안 vs 비용 우선순위*"},
            "accessory": {
                "type": "static_select",
                "action_id": "select_priority",
                "placeholder": {"type": "plain_text", "text": "선택하세요"},
                "options": [
                    {"text": {"type": "plain_text", "text": "Security First (보안 최우선)"}, "value": "security"},
                    {"text": {"type": "plain_text", "text": "Balanced (균형)"}, "value": "balanced"},
                    {"text": {"type": "plain_text", "text": "Cost Optimized (비용 최적화)"}, "value": "cost"}
                ]
            }
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🚀 Finance 계산 요청"},
                    "style": "primary",
                    "value": incident_id, # DB 조회를 위해 incident_id를 value에 심음
                    "action_id": "submit_finance_context"
                }
            ]
        }
    ]

    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    payload = {"channel": SLACK_CHANNEL, "blocks": blocks}
    logger.info(
        "[MCP][SLACK] chat.postMessage incident_id=%s channel=%s",
        incident_id,
        SLACK_CHANNEL,
    )
    resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json=payload,
        timeout=15,
    )
    try:
        body = resp.json()
    except ValueError:
        logger.error(
            "[MCP][SLACK] non-JSON response status=%s text=%s",
            resp.status_code,
            resp.text[:1000],
        )
        raise RuntimeError(f"Slack API non-JSON response HTTP {resp.status_code}") from None

    if not body.get("ok"):
        logger.error(
            "[MCP][SLACK] chat.postMessage failed incident_id=%s error=%s warning=%s",
            incident_id,
            body.get("error"),
            body.get("warning"),
        )
        raise RuntimeError(f"Slack API error: {body.get('error')}")

    logger.info(
        "[MCP][SLACK] chat.postMessage OK incident_id=%s ts=%s",
        incident_id,
        body.get("ts"),
    )

