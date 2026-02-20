import json
import os
import sys
from dataclasses import dataclass

# src 폴더 경로 추가
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# ⭐️ 핵심: 클래스가 아니라 'lambda_handler' 함수를 임포트합니다.
from dispatcher_module import lambda_handler

# ==================================================
# [환경 변수 설정] 
# 실제 AWS Lambda 콘솔의 '환경 변수' 설정과 동일한 역할을 합니다.
# ==================================================
os.environ["AWS_REGION"] = "ap-northeast-2"
os.environ["DB_TABLE_NAME"] = "AgentB_Response_History"
os.environ["WAF_IPSET_ID"] = "657906ea-7bc5-4c48-b500-6b2686fdb9d2" # 실제 ID
os.environ["WAF_IPSET_NAME"] = "OpsGuard-Block-IPSet"
os.environ["WAF_SCOPE"] = "REGIONAL"
os.environ["VPC_FLOW_LOG_GROUP"] = "/aws/vpc/flowlogs-test"
os.environ["VPC_FLOW_ROLE_ARN"] = "arn:aws:iam::836347236184:role/AgentB-FlowLog-Role"
os.environ["DEFAULT_S3_LOG_BUCKET"] = "mcp-security-logs-bucket"

# ==================================================
# [Mock Context] 
# AWS Lambda가 실행될 때 같이 넘겨주는 'context' 객체를 흉내냅니다.
# (보통 로그 찍을 때 request_id 같은 걸 씁니다)
# ==================================================
@dataclass
class MockContext:
    aws_request_id: str = "test-req-12345"
    function_name: str = "AgentB-Action-Handler"
    memory_limit_in_mb: int = 128
    invoked_function_arn: str = "arn:aws:lambda:ap-northeast-2:123456789012:function:AgentB"

def load_test_event(filename="test_event.json"):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ '{filename}' 파일이 없습니다.")
        sys.exit(1)

def main():
    print("🚀 [LAMBDA SIMULATION] 람다 핸들러 호출 테스트 시작...")

    # 1. Regulation Agent가 보낸 것과 똑같은 JSON 로드
    event_payload = load_test_event()
    
    # 2. 가짜 Context 생성
    context = MockContext()

    print(f"📥 입력 Event: Scenario '{event_payload.get('scenario')}'")

    # ---------------------------------------------------------
    # ⭐️ 여기가 핵심! Dispatcher 클래스가 아니라, 핸들러를 호출합니다.
    # 실제 AWS Lambda가 실행하는 방식과 100% 동일합니다.
    # ---------------------------------------------------------
    response = lambda_handler(event_payload, context)

    # 3. 결과 확인 (Lambda는 보통 statusCode와 body를 리턴합니다)
    print("\n" + "="*50)
    print("📤 Lambda 반환값 (Return)")
    print("="*50)
    
    # 보기 좋게 출력
    print(f"Status Code: {response['statusCode']}")
    
    try:
        body_json = json.loads(response['body'])
        print(json.dumps(body_json, indent=2, ensure_ascii=False))
    except:
        print(response['body'])
        
    print("="*50)

if __name__ == "__main__":
    main()