import json
import urllib.parse
import requests

def lambda_handler(event, context):
    # 1. Slack에서 보낸 데이터 파싱 (API Gateway 프록시 연동 기준)
    body = event.get('body', '')
    parsed_body = urllib.parse.parse_qs(body)
    
    if 'payload' not in parsed_body:
        return {"statusCode": 400, "body": "Invalid payload"}
        
    slack_payload = json.loads(parsed_body['payload'][0])
    
    # 2. 어떤 버튼을 눌렀는지, 어떤 사건(incident_id)인지 파악
    action = slack_payload['actions'][0]
    action_id = action['action_id'] # 'approve_action' 또는 'reject_action'
    incident_id = action['value']   # 'gd-finding-123'
    user_name = slack_payload['user']['username']
    response_url = slack_payload['response_url'] # 슬랙 메시지를 업데이트하기 위한 전용 URL
    
    print(f"사용자 {user_name}가 {incident_id}에 대해 {action_id}를 클릭함.")

    # 3. DB에서 Playbook 조회 및 Runtime Agent 실행
    # playbook = db.get_item(Key={'incident_id': incident_id})
    if action_id == "approve_action":
        # runtime_agent.execute(playbook)
        status_text = f"✅ *{user_name}* 님에 의해 승인되어 조치가 완료되었습니다."
        # db.update_item(status="COMPLETED", log="...") # DB 로깅 (어필 포인트)
    else:
        # runtime_agent.rollback(playbook)
        status_text = f"❌ *{user_name}* 님에 의해 거절/롤백 되었습니다."
        # db.update_item(status="REJECTED", log="...") # DB 로깅
        
    # 4. 슬랙 원본 메시지 업데이트 (버튼을 없애고 결과 텍스트로 대체)
    update_message = {
        "replace_original": "true",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🚨 *보안 이벤트 처리 완료 ({incident_id})*\n{status_text}"
                }
            }
        ]
    }
    
    requests.post(response_url, json=update_message)
    
    return {
        "statusCode": 200,
        "body": "OK"
    }