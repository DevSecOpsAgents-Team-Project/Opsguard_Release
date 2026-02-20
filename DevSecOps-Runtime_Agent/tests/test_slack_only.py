import os
import json
from src.actions_module import Actions
from dotenv import load_dotenv


import inspect
print(inspect.signature(Actions.notify_to_slack))


load_dotenv()

def run_quick_test():
    # 환경 변수 로드 확인
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("❌ 에러: SLACK_WEBHOOK_URL 환경 변수가 설정되지 않았습니다.")
        return

    print(f"🔗 연결된 Webhook URL: {webhook_url[:20]}...")

    # Actions 객체 생성 (실제 전송을 위해 dry_run=False)
    actions = Actions(dry_run=False)
    
    test_incident_id = "INC-TEST-1234"
    test_msg = "🚀 Agent B의 Slack 연동 테스트가 성공적으로 수행되었습니다!"

    print("📤 Slack 메시지 전송 시도 중...")
    result = actions.notify_to_slack(test_msg, test_incident_id)

    if result["status"] == "SUCCESS":
        print("✅ 성공: Slack 채널을 확인하세요!")
    else:
        print(f"❌ 실패: {result['details'].get('error')}")

if __name__ == "__main__":
    run_quick_test()