import json
import os
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
    value_raw = action['value']
    
    if action_id == "reject_all_action":
        incident_id = value_raw  # 문자열
        status_text = f"❌ *{user_name}* 님에 의해 전체 거절되었습니다."
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
        return {"statusCode": 200, "body": "OK"}

    # approve_l2 또는 approve_l3
    try:
        runtime_event = json.loads(value_raw)
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": "Invalid payload value"}

    # MCP 서버 호출 (MCP URL이 환경변수로 있다면)
    MCP_APPROVE_URL = os.environ.get("MCP_APPROVE_URL")
    if MCP_APPROVE_URL:
        # MCP가 response_url로 결과 메시지를 보내므로 Lambda에서는 200만 반환
        requests.post(MCP_APPROVE_URL, json={"payload": slack_payload})
        return {"statusCode": 200, "body": "OK"}

    # Lambda에서 직접 Runtime 호출하는 경우: 실행 후 Slack 업데이트
    from dispatcher_module import lambda_handler as runtime_handler
    runtime_handler(runtime_event, None)
    status_text = f"✅ *{user_name}* 님에 의해 승인되어 조치가 완료되었습니다."
    incident_id = runtime_event.get("incident_id", "unknown")
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