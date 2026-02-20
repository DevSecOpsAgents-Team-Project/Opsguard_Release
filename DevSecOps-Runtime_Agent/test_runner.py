import json
import os
import sys

# src 폴더를 파이썬 경로에 추가 (모듈 import를 위해)
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from dispatcher_module import ActionDispatcher

# ==================================================
# [설정] 테스트를 위한 환경 변수 세팅
# 실제 AWS 환경 변수나, Terraform/CDK로 만든 리소스 ID를 넣으세요.
# ==================================================
os.environ["AWS_REGION"] = "ap-northeast-2"
os.environ["DB_TABLE_NAME"] = "AgentB_Response_History" # 실제 DynamoDB 테이블 이름

# WAF나 Flow Log 관련 설정 (없으면 에러날 수 있으니 더미 값이라도 넣거나 실제 값 넣기)
os.environ["WAF_IPSET_NAME"] = "OpsGuard-Block-IPSet"
os.environ["WAF_IPSET_ID"] = "657906ea-7bc5-4c48-b500-6b2686fdb9d2" # 실제 WAF IPSet ID 필요
os.environ["WAF_SCOPE"] = "REGIONAL"
os.environ["VPC_FLOW_LOG_GROUP"] = "/aws/vpc/flowlogs-test"
os.environ["VPC_FLOW_ROLE_ARN"] = "arn:aws:iam::836347236184:role/AgentB-FlowLog-Role"

def load_test_event(filename="test_event.json"):
    """JSON 파일을 읽어서 딕셔너리로 반환"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ 오류: '{filename}' 파일을 찾을 수 없습니다.")
        sys.exit(1)

def main():
    print("🚀 [TEST START] Dispatcher 통합 테스트 시작...")
    
    # 1. JSON 로드
    event_payload = load_test_event()
    print(f"📄 테스트 데이터 로드 완료 (Scenario: {event_payload.get('scenario')})")

    # 2. Dispatcher 초기화 (dry_run=False여야 실제 AWS에 반영됨!)
    # * 주의: dry_run=True로 하면 API 호출은 안 하고 로그만 찍습니다.
    dispatcher = ActionDispatcher(dry_run=False) 

    # 3. 실행
    results = dispatcher.dispatch(event_payload)

    # 4. 결과 출력
    print("\n" + "="*50)
    print("🎯 테스트 실행 결과")
    print("="*50)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print("="*50)

if __name__ == "__main__":
    main()
