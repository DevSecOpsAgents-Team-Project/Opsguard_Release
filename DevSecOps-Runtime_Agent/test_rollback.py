# test_rollback.py
import sys
import os
import json

# ---------------------------------------------------------
# 1. 경로 설정 (src 폴더를 인식하도록 함)
# ---------------------------------------------------------
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# ---------------------------------------------------------
# 2. 롤백 모듈 가져오기
# ---------------------------------------------------------
import rollback_module

# =========================================================
# ⚙️ [설정] 롤백할 Incident ID를 여기에 적으세요!
# =========================================================
TARGET_INCIDENT_ID = "TEST-ALL-ACTIONS-001" 
# 👆 DynamoDB 로그 테이블에서 확인한 실제 ID로 바꿔주세요.

def run_rollback():
    print(f"🔄 롤백 시작: {TARGET_INCIDENT_ID}")
    print("-" * 50)

    # 1. 롤백 핸들러에 보낼 가짜 이벤트 생성
    event = {
        "incident_id": TARGET_INCIDENT_ID
    }

    # 2. 이미 만들어둔 rollback_incident_handler 호출
    result = rollback_module.rollback_incident_handler(event, None)

    # 3. 결과 출력
    print("\n✅ 롤백 결과 리포트:")
    print(json.dumps(result, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    # 혹시 ID 입력을 깜빡했을까봐 체크
    if TARGET_INCIDENT_ID == "INCIDENT-XXXXXXXX":
        print("❌ 오류: 코드 상단의 'TARGET_INCIDENT_ID'를 실제 값으로 바꿔주세요!")
    else:
        run_rollback()
