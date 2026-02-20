import json
import os
import sys

from src.playbooks_module import playbook_integrated_base_mitigation

# 1. 실제 샘플 파일 로드
SAMPLE_FILE = os.path.join(os.path.dirname(__file__), "sample_events", "Backdoor_Runtime_C&CActivity.B!DNS_0621c920f4d14a1ab88f7bd515bc9acc.json")

with open(SAMPLE_FILE, 'r', encoding='utf-8') as f:
    real_event = json.load(f)

# 2. Mock Actions 클래스
class MockActions:
    def notify_to_slack(self, msg, inc_id): print(f"  [Mock] Slack: {msg[:50]}...")
    def lookup_cloudtrail_events(self, user, inc_id): print(f"  [Mock] CloudTrail 수집: {user}")
    def tag_resource_with_incident(self, res_id, inc_id): print(f"  [Mock] 태깅: {res_id}")
    def create_snapshot(self, res_id, inc_id): print(f"  [Mock] 스냅샷 생성: {res_id}")

def run_real_test():
    print(f"=== 실제 샘플 테스트 시작: {SAMPLE_FILE} ===")
    mock_actions = MockActions()
    
    # 래핑: GuardDuty 포맷에 맞춰 detail 키에 넣어줌 (handler가 하는 역할)
    wrapped_event = {
        "id": real_event.get("Id"),
        "detail": real_event
    }
    
    result = playbook_integrated_base_mitigation(wrapped_event, actions=mock_actions)
    
    print("\n=== 최종 분석 결과 ===")
    print(json.dumps(result, indent=2))
    
    if result["actions_count"] == 5:
        print("\n✅ [성공] 실제 복잡한 JSON에서도 모든 리소스를 찾아내어 대응을 완료했습니다!")
    else:
        print("\n❌ [확인 필요] 일부 리소스 추출에 실패했을 수 있습니다.")

if __name__ == "__main__":
    run_real_test()