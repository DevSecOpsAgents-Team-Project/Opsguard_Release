import json
import requests

# ⚠️ 본인의 토큰과 채널 ID를 꼭 유지해주세요!
SLACK_BOT_TOKEN = "xoxb-10299250893681-10564145647505-jVkEytMccRsYpiQahegEIPSZ"
SLACK_CHANNEL = "C0A8E9KCZ7U"

def send_approval_message(mock_json):
    incident_id = mock_json["incident_id"]
    summary = mock_json["incident_summary"]
    actions = mock_json["recommended_actions"]
    regs = mock_json["regulations"]
    
    # 규제 근거 텍스트 만들기
    reg_text = ""
    for reg in regs:
        reg_text += f"• *{reg['framework']} ({reg['clause_id']})*: {reg['clause_title']}\n"
    if not reg_text:
        reg_text = "매핑된 규제 근거 없음"

    # 1. 상단: 1.png 스타일의 상세한 컨텍스트 정보
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 보안 이벤트 요약: {summary['title']}"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*이벤트 ID:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*심각도:*\n🔥 {summary['severity']}"},
                {"type": "mrkdwn", "text": f"*대상 리소스:*\n`{summary['resource']['id']}`"},
                {"type": "mrkdwn", "text": f"*L1 사전 조치:*\n✅ {len(mock_json['executed_level1_actions'])}건 완료"}
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🔍 AI 판단 근거 (Reasoning):*\n{mock_json['reasoning_bullets'][0]}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*⚖️ 위반 의심 규제 (Regulations):*\n{reg_text}"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🛠️ 추천 대응 방안 (원하는 조치를 선택해 승인하세요):*"
            }
        }
    ]

    # 2. 하단: 2.png 스타일의 다중 선택형 대응 방안 리스트
    for action in actions:
        action_id = action["action_id"]
        level = action["level"]
        desc = action["description"]
        impact = action["expected_impact"]

        # 서버로 보낼 값 (어떤 사건의 어떤 액션을 선택했는지)
        button_value = json.dumps({"incident_id": incident_id, "action_id": action_id})

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"> *[Level {level}] `{action_id}`*\n> {desc}\n> *예상 영향도:* `{impact}`"
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": f"✅ Level {level} 승인"
                },
                "style": "primary",
                "value": button_value, 
                "action_id": f"approve_{action_id}"
            }
        })

    # 3. 전체 거절 버튼 추가
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "❌ 전체 거절 (조치 안 함)"},
                "style": "danger",
                "value": incident_id,
                "action_id": "reject_all_action"
            }
        ]
    })

    # 4. Slack API로 전송
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}"
    }
    payload = {
        "channel": SLACK_CHANNEL,
        "blocks": blocks
    }
    
    response = requests.post("https://slack.com/api/chat.postMessage", headers=headers, json=payload)
    result = response.json()
    
    if result.get("ok"):
        print("✅ 성공! 슬랙을 확인하세요.")
    else:
        print(f"❌ 실패! 이유: {result.get('error')}")

# --- 원본 JSON 데이터 (비교 테스트를 위해 추천 액션을 2개로 늘려두었습니다) ---
full_mock_data = {
  "schema_version": "1.2",
  "generated_at": "2026-02-14T09:23:35.765312+00:00",        
  "incident_id": "gd-finding-123",
  "scenario": "CredentialCompromise",
  "incident_summary": {
    "source": "guardduty",
    "title": "Access Key suspicious usage (post-L1)",        
    "severity": "5.3",
    "resource": {
      "type": "AccessKey",
      "id": "AKIA-HACKED-KEY123",
      "region": "ap-northeast-2",
      "account_id": "123456789012"
    }
  },
  "executed_level1_actions": [
    "record_finding", "notify_slack", "fetch_cloudtrail_related_events", "tag_finding_observe"
  ],
  "reasoning_bullets": [
    "The incident involves suspicious usage of an access key, indicating potential unauthorized access."
  ],
  "regulations": [
    {
      "framework": "CSA_CCM",
      "clause_id": "IAM-05",
      "clause_title": "Least Privilege"
    },
    {
      "framework": "CSA_CCM",
      "clause_id": "IAM-13",
      "clause_title": "Uniquely Identifiable Users"
    }
  ],
  "recommended_actions": [
    {
      "action_id": "disable_access_key",
      "level": 2,
      "description": "Disable the suspicious access key to prevent further unauthorized access.",
      "expected_impact": "LOW"
    },
    {
      "action_id": "delete_access_key",
      "level": 3,
      "description": "Permanently delete the key and force password reset for the user.",
      "expected_impact": "HIGH"
    }
  ]
}

# --- 실행 ---
if __name__ == "__main__":
    print("🚀 융합형 슬랙 메시지 전송을 시작합니다...")
    send_approval_message(full_mock_data)