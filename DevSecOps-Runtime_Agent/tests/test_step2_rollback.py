import sys
import os
import boto3

# 1. 프로젝트 루트 경로를 sys.path에 추가 (src 모듈을 찾기 위함)
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from src import rollback_module

def run_test_rollback(target_incident_id):
    print(f"\n======================================================")
    print(f"🚀 [Rollback Test] 시작: Incident ID = {target_incident_id}")
    print(f"======================================================")

    # 2. 이벤트 구성 (Lambda Trigger 시뮬레이션)
    event = {
        "incident_id": target_incident_id
    }

    # 3. 롤백 핸들러 실행
    # (Context는 로컬 테스트라 None으로 넘깁니다)
    try:
        result = rollback_module.rollback_incident_handler(event, None)
    except Exception as e:
        print(f"\n❌ 롤백 핸들러 실행 중 치명적 오류 발생: {e}")
        return

    # 4. 결과 출력
    status = result.get('status')
    print(f"\n📊 [최종 결과] Status: {status}")
    print(f"   - 성공: {result.get('success', 0)} 건")
    print(f"   - 실패: {result.get('failed', 0)} 건")
    
    print("\n🔍 [상세 실행 내역]")
    details = result.get('details', [])
    
    if not details:
        print("   (실행된 롤백 액션이 없습니다. DB에 로그가 없거나, 롤백 대상이 아닐 수 있습니다.)")

    for detail in details:
        action_name = detail.get('action_name')
        res_status = detail.get('status')
        msg = detail.get('message') or detail.get('error')
        
        # 보기 좋게 아이콘 처리
        if "SUCCESS" in res_status:
            icon = "✅"
        elif "SKIPPED" in res_status:
            icon = "⏭️"
        else:
            icon = "❌"
            
        print(f"   {icon} [{action_name}] -> {res_status} : {msg}")

    print("\n======================================================")

if __name__ == "__main__":
    # 👇 [수정 필요] 방금 실행 후 DynamoDB(AgentB_Response_History)에 생긴 ID를 여기에 넣으세요!
    # 예시: "incident-20250201-190333"
    TARGET_INCIDENT_ID = "test-finding-s3-03a36842-2973-4d6f-be41-fd4940b3f71a"  
    
    if TARGET_INCIDENT_ID == "PUT_YOUR_INCIDENT_ID_HERE":
        print("⚠️  경고: 스크립트 맨 아래 'TARGET_INCIDENT_ID' 변수에 실제 ID를 입력해주세요!")
    else:
        run_test_rollback(TARGET_INCIDENT_ID)