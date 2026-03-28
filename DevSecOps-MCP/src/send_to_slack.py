import json
import requests
import os

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "")

def send_approval_message(mock_json):
    if not SLACK_BOT_TOKEN or not SLACK_CHANNEL:
        raise ValueError("SLACK_BOT_TOKEN, SLACK_CHANNEL 환경변수가 필요합니다.")
    incident_id = mock_json["incident_id"]
    summary = mock_json["incident_summary"]
    playbooks = mock_json["recommended_actions"]
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
    for pb in playbooks:
        level = pb["level"]
        pb_name = pb["playbook_name"]
        actions_list = pb["actions"] # 이 레벨에 포함된 액션들
        
        # Dispatcher가 즉시 인식할 수 있는 형태로 데이터 포맷팅
        # 이 데이터를 버튼의 'value'에 심어버립니다.
        button_payload = {
            "incident_id": incident_id,
            "scenario": mock_json["scenario"],
            "recommended_actions": actions_list # 여기에 여러 함수 정보가 들어감!
        }

        # 슬랙에 보여줄 액션 요약 (예: disable_access_key, block_ip)
        action_ids_str = ", ".join([f"`{a['action_id']}`" for a in actions_list])

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"> *[Level {level}] {pb_name}*\n> *포함된 조치:* {action_ids_str}\n> {pb['description']}\n> *영향도:* `{pb['expected_impact']}`"
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": f"L{level} 실행"},
                "style": "primary" if level == 2 else "danger",
                "value": json.dumps(button_payload),
                "action_id": f"approve_l{level}"
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
      "id": "AKIA...",
      "region": "ap-northeast-2",
      "account_id": "123456789012"
    }
  },
  "executed_level1_actions": [
    "record_finding",
    "notify_slack",
    "fetch_cloudtrail_related_events",
    "tag_finding_observe"
  ],
  "escalation_assessment": {
    "escalation_needed": True,
    "recommended_level": 2,
    "confidence": 0.9,
    "decision_questions": [
      "Do you approve escalation actions (Level 2/3) given the observed anomalous IAM access behavior?"
    ],
    "approval_notes": "Recommended actions are necessary to mitigate potential unauthorized access."
  },
  "reasoning_bullets": [
    "The incident involves suspicious usage of an access key, indicating potential unauthorized access.",
    "Regulatory requirements emphasize the need for urgent response and least privilege principles."
  ],
  "regulations": [
    {
      "framework": "CSA_CCM",
      "clause_id": "IAM-05",
      "clause_title": "Least Privilege",
      "relevance": 0.9,
      "excerpt": "Employ the least privilege principle when implementing information system access.",
      "why_relevant": "This incident highlights the need to restrict access to only necessary privileges to prevent unauthorized actions."
    },
    {
      "framework": "CSA_CCM",
      "clause_id": "IAM-13",
      "clause_title": "Uniquely Identifiable Users",
      "relevance": 0.8,
      "excerpt": "Define, implement and evaluate processes, procedures and technical measures that ensure users are identifiable through unique IDs.",
      "why_relevant": "The use of shared or compromised access keys reduces accountability and increases risk."
    }
  ],
  "recommended_actions": [
      {
          "level": 2,
          "playbook_name": "계정 권한 제한 및 관찰",
          "description": "위험 요소를 제거하고 활동을 제한합니다.",
          "actions": [ # L2 선택 시 실행될 함수들 리스트
              {
                  "action_id": "disable_access_key",
                  "targets": [
                      {"type": "AccessKey", "id": "AKIA...", "user_name": "alice"}
                    ]
            },
            {
                  "action_id": "block_ip",
                  "targets": [{"type": "IPAddress", "ip": "1.2.3.4"}]
            }
        ],
          "requires_approval": True,
          "expected_impact": "LOW"
    },
      {
          "level": 3,
          "playbook_name": "강력한 격리 및 계정 삭제",
          "description": "인프라 접근을 완전히 차단하고 자격 증명을 파괴합니다.",
          "actions": [ # L3 선택 시 실행될 함수들 리스트
              {
                  "action_id": "delete_access_key",
                  "targets": [
                      {"type": "AccessKey", "id": "AKIA...", "user_name": "alice"}
                    ]
                },
              {
                  "action_id": "detach_admin_policies",
                  "targets": [
                      {"type": "IAMUser", "user_name": "alice"}
                    ]
                }
              ],
            "requires_approval": True,
            "expected_impact": "HIGH"
          }
      ],
      "insufficient_context": False,
      "missing_context_requests": []
}

# --- 실행 ---
if __name__ == "__main__":
    print("🚀 융합형 슬랙 메시지 전송을 시작합니다...")
    send_approval_message(full_mock_data)
