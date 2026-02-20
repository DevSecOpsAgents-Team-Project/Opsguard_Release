import logging
import uuid
import sys
import boto3
from src import playbooks_module

# 로깅 설정 (콘솔 출력용)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [TEST] %(message)s')
logger = logging.getLogger()

# ==============================================================================
# 🛠️ 테스트 환경 설정 (여기에 본인의 실제 리소스 ID를 입력하세요)
# ==============================================================================
TEST_CONFIG = {
    # [EC2] 테스트용 인스턴스 ID (중요: 운영 서버 금지)
    "EC2_INSTANCE_ID": "i-02385bd3a4ee44545", 
    
    # [S3] 테스트용 버킷 이름
    "S3_BUCKET_NAME": "test-20260201-shy",
    
    # [IAM] 테스트용 IAM 사용자 이름
    "IAM_USER_NAME": "test-20260201-shy1"
}

# ==============================================================================
# 🧪 Mock Event 생성기 (GuardDuty 이벤트 흉내내기)
# ==============================================================================

def generate_ec2_event(instance_id):
    """EC2 백도어 감지 이벤트 생성"""
    return {
        "id": f"test-finding-ec2-{uuid.uuid4()}",
        "detail": {
            "type": "Backdoor:EC2/C&CActivity.B",  # EC2 관련 Type
            "severity": 8.0,
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": instance_id
                }
            },
            # 플레이북의 find_key_recursive가 찾을 수 있도록 배치
            "instanceId": instance_id 
        }
    }

def generate_s3_event(bucket_name):
    """S3 퍼블릭 액세스 감지 이벤트 생성"""
    return {
        "id": f"test-finding-s3-{uuid.uuid4()}",
        "detail": {
            "type": "Policy:S3/BucketPublicAccessGranted", # S3 관련 Type
            "severity": 5.0,
            "resource": {
                "resourceType": "S3Bucket",
                "s3BucketDetails": [
                    {"Name": bucket_name}
                ]
            }
        }
    }

def generate_iam_event(user_name):
    """IAM 권한 남용 감지 이벤트 생성"""
    return {
        "id": f"test-finding-iam-{uuid.uuid4()}",
        "detail": {
            "type": "Policy:IAMUser/AnomalousBehavior", # IAM 관련 Type
            "severity": 7.5,
            "userName": user_name,
            "resource": {
                "resourceType": "AccessKey",
                "userName": user_name
            }
        }
    }

# ==============================================================================
# 🚀 시나리오별 테스트 실행 함수
# ==============================================================================

def run_test_ec2():
    print(f"\n{'='*60}\n[Scenario 1] EC2 Base Mitigation 테스트\n{'='*60}")
    target = TEST_CONFIG["EC2_INSTANCE_ID"]
    
    # 1. 가짜 이벤트 생성
    event = generate_ec2_event(target)
    logger.info(f"이벤트 생성됨: Type={event['detail']['type']}, Target={target}")

    # 2. 플레이북 실행
    # (주의: playbook_integrated_base_mitigation는 내부적으로 actions_module을 호출하여 실제 AWS 명령을 내립니다)
    result = playbooks_module.playbook_integrated_base_mitigation(event)

    # 3. 결과 출력
    print(f"\n📝 실행 결과: {result}")
    print("\n✅ 검증 포인트:")
    print(f"   1. AWS 콘솔 -> EC2 -> {target} -> 'Tags' 탭 확인 (IncidentID 태그 등)")
    print(f"   2. AWS 콘솔 -> EC2 -> Snapshots -> 해당 인스턴스 스냅샷 생성 여부 확인")
    print(f"   3. DynamoDB -> AgentB_Response_History 테이블에 로그 적재 확인")

def run_test_s3():
    print(f"\n{'='*60}\n[Scenario 2] S3 Base Mitigation 테스트\n{'='*60}")
    target = TEST_CONFIG["S3_BUCKET_NAME"]
    
    event = generate_s3_event(target)
    logger.info(f"이벤트 생성됨: Type={event['detail']['type']}, Target={target}")

    result = playbooks_module.playbook_integrated_base_mitigation(event)

    print(f"\n📝 실행 결과: {result}")
    print("\n✅ 검증 포인트:")
    print(f"   1. AWS 콘솔 -> S3 -> {target} -> '속성' -> 태그 확인")
    print(f"   2. AWS 콘솔 -> S3 -> {target} -> '속성' -> 서버 액세스 로깅 활성화 여부 확인")

def run_test_iam():
    print(f"\n{'='*60}\n[Scenario 3] IAM Base Mitigation 테스트\n{'='*60}")
    target = TEST_CONFIG["IAM_USER_NAME"]
    
    event = generate_iam_event(target)
    logger.info(f"이벤트 생성됨: Type={event['detail']['type']}, Target={target}")

    result = playbooks_module.playbook_integrated_base_mitigation(event)

    print(f"\n📝 실행 결과: {result}")
    print("\n✅ 검증 포인트:")
    print(f"   1. AWS 콘솔 -> IAM -> 사용자 -> {target} -> 태그 확인")
    print(f"   2. AWS 콘솔 -> IAM -> 사용자 -> {target} -> 권한 확인 (Admin 권한 분리 여부)")

# ==============================================================================
# ▶️ 메인 실행부
# ==============================================================================
if __name__ == "__main__":
    # AWS 자격 증명 확인
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        logger.info(f"AWS 연결 성공: {identity['Arn']}")
    except Exception as e:
        logger.error(f"AWS 자격 증명 오류: {e}")
        sys.exit(1)

    # 원하는 시나리오의 주석을 해제하여 실행하세요.
    run_test_ec2()
    run_test_s3()
    run_test_iam()

    print(f"\n{'='*60}\n🏁 모든 테스트 시나리오 종료\n{'='*60}")