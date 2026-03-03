import json
import requests

# ⚠️ 본인의 토큰과 채널 ID 유지
SLACK_BOT_TOKEN = "xoxb-10299250893681-10564145647505-jVkEytMccRsYpiQahegEIPSZ"
SLACK_CHANNEL = "C0A8E9KCZ7U"

def send_approval_message(mock_json):
    incident_id = mock_json["incident_id"]
    summary = mock_json["incident_summary"]
    playbooks = mock_json["recommended_actions"]
    regs = mock_json["regulations"]
    
    reg_text = "".join([f"• *{r['framework']} ({r['clause_id']})*: {r['clause_title']}\n" for r in regs]) or "매핑된 규제 근거 없음"

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🚨 보안 이벤트 요약: {summary['title']}"}},
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
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*🔍 AI 판단 근거:*\n{mock_json['reasoning_bullets'][0]}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*⚖️ 위반 의심 규제:*\n{reg_text}"}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*🛠️ 추천 대응 방안 (Playbook 선택):*"}}
    ]

    for pb in playbooks:
        level = pb["level"]
        # [중요] Dispatcher가 인식할 수 있는 '최종 실행용 JSON'을 버튼 value에 주입
        button_payload = {
            "incident_id": incident_id,
            "scenario": mock_json["scenario"],
            "recommended_actions": pb["actions"] # 해당 레벨의 액션 리스트만 추출
        }

        action_ids_str = ", ".join([f"`{a['action_id']}`" for a in pb["actions"]])

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": f"> *[Level {level}] {pb['playbook_name']}*\n> *조치:* {action_ids_str}\n> {pb['description']}"
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": f"L{level} 실행"},
                "style": "primary" if level == 2 else "danger",
                "value": json.dumps(button_payload), # JSON 문자열로 변환하여 저장
                "action_id": f"approve_l{level}"
            }
        })
        
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "actions",
        "elements": [{
            "type": "button", "text": {"type": "plain_text", "text": "❌ 전체 거절"},
            "style": "danger", "value": incident_id, "action_id": "reject_all_action"
        }]
    })

    response = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        json={"channel": SLACK_CHANNEL, "blocks": blocks}
    )
    print("✅ 슬랙 전송 완료" if response.json().get("ok") else f"❌ 실패: {response.json()}")

# --- 테스트용 데이터 ---
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
                      {"type": "AccessKey", "id": "AKIA...", "user_name": "alice", "ip": None, "target_bucket": None}
                    ]
            },
            {
                  "action_id": "block_ip",
                  "targets": [
                  {"type": "IPAddress", "id": None, "user_name": None, "ip": "1.2.3.4", "target_bucket": None}
                  ]
            }
        ],
          "requires_approval": True,
          "expected_impact": "LOW"
    },
      {
          "level": 3,
          "playbook_name": "강력한 격리 및 계정 삭제",
          "description": "인프라 접근을 완전히 차단하고 자격 증명을 파괴합니다.",
          "actions": [
                # 1. EC2 조치 세트
                {"action_id": "isolate_instance", "targets": [{"type": "EC2Instance", "id": "i-086b9b73e1452c8ee", "user_name": None, "ip": None, "target_bucket": None}]},
                {"action_id": "create_snapshot", "targets": [{"type": "EC2Instance", "id": "i-0d9f339409aaf1992", "user_name": None, "ip": None, "target_bucket": None}]},
                {"action_id": "backup_instance", "targets": [{"type": "EC2Instance", "id": "i-0d9f339409aaf1992", "user_name": None, "ip": None, "target_bucket": None}]},
                {"action_id": "stop_instance", "targets": [{"type": "EC2Instance", "id": "i-0d9f339409aaf1992", "user_name": None, "ip": None, "target_bucket": None}]},
                
                # 2. IAM 조치 세트
                {
                    "action_id": "disable_access_key", 
                    "targets": [{"type": "IAMUser", "id": "AKIA4FOROB5ME2C4Q3H2", "user_name": "IAM-2026-03-04-test2", "ip": None, "target_bucket": None}]
                },
                {"action_id": "detach_admin_policies", "targets": [{"type": "IAMUser", "id": None, "user_name": "IAM-2026-03-04-test2", "ip": None, "target_bucket": None}]},
                {"action_id": "disable_iam_entity", "targets": [{"type": "IAMUser", "id": None, "user_name": "IAM-2026-03-04-test1", "ip": None, "target_bucket": None}]},

                # 3. Network / WAF 조치 세트
                {"action_id": "block_ip", "targets": [{"type": "IPAddress", "id": None, "user_name": None, "ip": "1.2.3.4", "target_bucket": None}]},
                {"action_id": "enable_vpc_flow_logs", "targets": [{"type": "VPC", "id": "vpc-0be19f1f16b457b93", "user_name": None, "ip": "1.2.3.4", "target_bucket": None}]},

                # 4. S3 조치 세트
                {"action_id": "block_s3_public_access", "targets": [{"type": "S3Bucket", "id": "s3-2026-03-04-test1", "user_name": None, "ip": None, "target_bucket": None}]},
                {
                    "action_id": "enable_s3_bucket_logging", 
                    "targets": [{"type": "S3Bucket","id": "s3-2026-03-04-test1", "user_name": None, "ip": None, "target_bucket": "mcp-security-logs-bucket"}]
                }
            ],
            "requires_approval": True,
            "expected_impact": "HIGH"
          }
      ],
  "insufficient_context": False,
  "missing_context_requests": []
}

if __name__ == "__main__":
    send_approval_message(full_mock_data)