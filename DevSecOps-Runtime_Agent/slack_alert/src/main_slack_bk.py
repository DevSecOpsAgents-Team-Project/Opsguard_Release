import os
import json
from slack_sdk import WebClient
from slack_sdk.socket_mode.builtin import SocketModeHandler
from dotenv import load_dotenv

load_dotenv()

# 1. 클라이언트 초기화
client = WebClient(token=os.environ.get("SLACK_BOT_TOKEN"))

def handle_interactivity(client, req, payload):
    """사용자가 버튼을 클릭했을 때 실행되는 콜백 함수"""
    
    # payload 분석
    user_name = payload['user']['name']
    action_info = payload['actions'][0]
    
    # 버튼 value에 심어둔 JSON 데이터 추출
    selection = json.loads(action_info['value'])

    # 콘솔 출력 (데이터 수신 확인)
    print("\n" + "="*50)
    print(f"📡 Socket Mode로 수신 완료!")
    print(f"Decision Received from: {user_name}")
    print(f"Selected: {selection['level']}")
    print(f"Action ID: {selection['action_id']}")
    print(f"Target Resource: {selection['target_id']}")
    print("="*50 + "\n")

    # 2. 사용자 화면 업데이트 (기존 메시지를 승인 완료 상태로 변경)
    # Socket Mode에서는 chat_update를 사용하여 메시지를 수정합니다.
    channel_id = payload['container']['channel_id']
    message_ts = payload['container']['message_ts']

    client.chat_update(
        channel=channel_id,
        ts=message_ts,
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"✅ *{user_name}* 님이 *{selection['level']}* 대응을 승인했습니다.\n> *대상:* `{selection['target_id']}`\n> *조치:* `{selection['action_id']}`\n\n_자동 대응 프로세스를 가동합니다._"
                }
            }
        ]
    )
    
    # 여기서 실제 Boto3 함수를 호출하면 됩니다!
    # run_boto3_action(selection['action_id'], selection['target_id'])

if __name__ == "__main__":
    # 필수 라이브러리: pip install slack_sdk
    if not os.environ.get("SLACK_APP_TOKEN"):
        print("❌ SLACK_APP_TOKEN이 설정되지 않았습니다.")
    else:
        # Socket Mode 핸들러 실행
        handler = SocketModeHandler(app_token=os.environ.get("SLACK_APP_TOKEN"))
        
        # 'interactive' 타입의 이벤트를 수신하면 handle_interactivity 함수 실행
        handler.connect_callback("interactive")(handle_interactivity)
        
        print("⚡ OpsGuard Socket Mode Server가 켜졌습니다. 사용자의 승인을 대기 중...")
        handler.start()