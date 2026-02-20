# DevSecOps Agent B

AWS GuardDuty 이벤트를 자동으로 분석하고 대응하는 Lambda 함수

## 기능

- **시나리오 감지**: GuardDuty Finding 타입 기반 자동 분류
- **자동 대응**: 플레이북 기반 보안 조치 실행
  - EC2 인스턴스 격리
  - S3 퍼블릭 접근 차단
  - IP 블랙리스트 추가
- **이력 관리**: 모든 액션 DB 로깅 및 롤백 데이터 저장

## 구조

```
src/
├── engine_handler.py      # Lambda 진입점, 시나리오 감지
├── playbooks_module.py    # 시나리오별 플레이북 정의
├── actions_module.py      # AWS API 호출 액션
└── db_logger_module.py    # 액션 이력 로깅
```

## 설치

```bash
pip install -r requirements.txt
```

## 사용법

Lambda 함수로 배포 후 EventBridge에서 GuardDuty 이벤트를 수신합니다.

## 시나리오 매핑

- `EC2_ISOLATION`: UnauthorizedAccess, Backdoor, CryptoCurrency 등 → EC2 격리
- `S3_POLICY_BLOCK`: S3 Policy 변경 → 퍼블릭 접근 차단
- `IAM_POLICY_ALERT`: IAM Policy 변경 → 알림
