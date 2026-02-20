import json
import glob
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def load_playbooks():
    files = glob.glob('../data/regulation_output_*.json')
    playbooks = []
    # 최신 생성 순 정렬
    files.sort(key=os.path.getmtime, reverse=True)
    
    for f in files[:2]:
        with open(f, 'r', encoding='utf-8') as file:
            playbooks.append(json.load(file))
    return playbooks

def send_to_slack():
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    playbooks = load_playbooks()
    
    if not playbooks:
        print("재생할 플레이북 파일이 없습니다.")
        return

    incident = playbooks[0]['incident_summary']
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ 보안 대응 단계 선택 요청"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": f"*사건명:* {incident['title']}\n*대상:* `{incident['resource']['id']}`"
            }
        },
        {"type": "divider"}
    ]

    for idx, pb in enumerate(playbooks):
        # JSON 데이터에서 레벨 및 상세 정보 추출
        level = pb['escalation_assessment']['recommended_level']
        reg = pb['regulations'][0]
        action = pb['recommended_actions'][0]
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": f"*Option: Level {level} 대응*\n> *규제 근거:* {reg['framework']} ({reg['clause_title']})\n> *액션:* {action['description']}\n> *예상 영향:* `{action['expected_impact']}`"
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": f"Level {level} 승인"},
                "style": "primary" if level == 2 else "danger", # 레벨에 따른 버튼 색상 차별화
                "value": json.dumps({
                    "incident_id": pb['incident_id'],
                    "level": f"Level {level}",
                    "action_id": action['action_id'],
                    "target_id": action['targets'][0]['id'],
                    "framework": reg['framework']
                }),
                "action_id": f"approve_lvl_{level}"
            }
        })

    requests.post(webhook_url, json={"blocks": blocks})
    print("Slack으로 레벨별 선택지 전송 완료")

if __name__ == "__main__":
    send_to_slack()