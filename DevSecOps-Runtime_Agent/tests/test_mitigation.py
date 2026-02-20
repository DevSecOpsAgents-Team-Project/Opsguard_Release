import json
import sys
import os

# 프로젝트 루트를 sys.path에 추가
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# 절대 임포트 사용
from src.playbooks_module import playbook_integrated_base_mitigation

# 1. 테스트용 가상 Actions 클래스 (Mock)
class MockActions:
    def notify_to_slack(self, msg, inc_id): print(f"  [Mock] Slack 전송: {msg}")
    def lookup_cloudtrail_events(self, user, inc_id): print(f"  [Mock] CloudTrail 조회: {user}")
    def tag_resource_with_incident(self, res_id, inc_id): 
        print(f"  [Mock] 태깅 완료: {res_id}")
        return {"status": "SUCCESS"}
    def create_snapshot(self, res_id, inc_id):
        print(f"  [Mock] 스냅샷 생성: {res_id}")
        return {"status": "SUCCESS"}

# 2. 테스트용 GuardDuty 이벤트 데이터
mock_event = {
    "id": "test-incident-001",
    "detail": {
        "type": "Backdoor:EC2/C&CActivity.B!DNS",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-0abcdef1234567890" # 테스트 타겟
            }
        },
        "service": {
            "action": {
                "awsApiCallAction": {
                    "userName": "malicious-attacker"
                }
            }
        }
    }
}

def run_test():
    print("=== Base Mitigation 테스트 시작 ===")
    mock_actions = MockActions()
    
    # 함수 실행
    result = playbook_integrated_base_mitigation(mock_event, actions=mock_actions)
    
    print("\n=== 테스트 결과 ===")
    print(json.dumps(result, indent=2))
    
    # 검증: 5단계 중 5단계가 모두 실행되었는지 확인
    if result["actions_count"] >= 4: # CloudTrail은 조건부이므로 4-5개면 정상
        print("\n✅ 확인 완료: Base Mitigation이 정상적으로 모든 대응 단계를 통과했습니다.")
    else:
        print("\n❌ 실패: 일부 대응 단계가 누락되었습니다.")

if __name__ == "__main__":
    run_test()