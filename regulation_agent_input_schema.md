# Regulation Agent 입력 데이터 스키마

## 개요

이 문서는 `e2e_test.py`에서 Regulation Agent LLM에 전달되는 모든 데이터의 JSON 스키마를 정의합니다.

---

## 전체 Payload 구조

Regulation Agent는 다음 구조의 JSON을 받습니다:

```json
{
  "schema_version": "1.1",
  "generated_at": "2024-01-15T10:30:00.000Z",
  "incident_id": "gd-finding-123",
  "incident_summary": {...},
  "executed_level1_actions": [...],
  "candidate_actions": [...],
  "severity_decision_result": {...},
  "context_chunks": [...]
}
```

---

## 1. incident_summary

**타입**: `object`  
**설명**: 사고 요약 정보

```json
{
  "source": "guardduty",
  "title": "Access Key suspicious usage (post-L1)",
  "severity": "5.3",
  "resource": {
    "type": "AccessKey",
    "id": "AKIA...",
    "region": "ap-northeast-2",
    "account_id": "123456789012"
  }
}
```

### 필드 설명

#### source (string, required)
- **설명**: 사고 소스
- **값**: `"guardduty"` (고정)
- **예시**: `"guardduty"`

#### title (string, required)
- **설명**: 사고 제목
- **예시**: `"Access Key suspicious usage (post-L1)"`

#### severity (string, required)
- **설명**: GuardDuty 심각도 점수 (문자열로 변환)
- **범위**: `"0.0"` ~ `"10.0"`
- **예시**: `"5.3"`, `"7.8"`

#### resource (object, required)
- **설명**: 영향받은 리소스 정보

##### resource.type (string, required)
- **설명**: 리소스 유형
- **예시**: `"AccessKey"`, `"EC2Instance"`, `"S3Bucket"`, `"RDSDatabase"`

##### resource.id (string, required)
- **설명**: 리소스 식별자
- **예시**: `"AKIA..."` (AccessKey ID), `"i-1234567890abcdef0"` (EC2 Instance ID)

##### resource.region (string, required)
- **설명**: AWS 리전
- **예시**: `"ap-northeast-2"`, `"us-east-1"`

##### resource.account_id (string, required)
- **설명**: AWS 계정 ID
- **예시**: `"123456789012"`

---

## 2. executed_level1_actions

**타입**: `array[string]`  
**설명**: Runtime Agent가 이미 실행한 Level 1 액션 목록

```json
[
  "record_finding",
  "notify_slack",
  "fetch_cloudtrail_related_events",
  "tag_finding_observe"
]
```

### 가능한 액션 값

- `"record_finding"`: Finding 기록
- `"notify_slack"`: Slack 알림
- `"fetch_cloudtrail_related_events"`: CloudTrail 관련 이벤트 조회
- `"tag_finding_observe"`: Finding 태깅
- 기타 Level 1 액션들

**참고**: 이 액션들은 이미 실행되었으며 변경 불가능합니다.

---

## 3. candidate_actions

**타입**: `array[string]`  
**설명**: 고려 중인 Level 2/3 후보 액션 목록 (빈 배열 가능)

```json
[
  "disable_access_key",
  "detach_admin_policies",
  "terminate_sessions",
  "isolate_instance",
  "create_snapshot"
]
```

### 가능한 액션 값

- `"disable_access_key"`: Access Key 비활성화
- `"detach_admin_policies"`: 관리자 정책 분리
- `"terminate_sessions"`: 세션 종료
- `"isolate_instance"`: 인스턴스 격리
- `"create_snapshot"`: 스냅샷 생성
- 기타 Level 2/3 액션들

**참고**: 
- 빈 배열일 수 있음
- Regulation Agent는 이 목록에서만 선택하거나, 필요시 다른 액션을 제안할 수 있음

---

## 4. severity_decision_result

**타입**: `object`  
**설명**: Severity Decision Engine + XAI의 결정 결과

```json
{
  "assigned_level": 2,
  "justification": "심각도 레벨 Level 2 (High)이 할당되었습니다.\n\n[이벤트 요인]\n- 공개 노출 (Public Exposure)\n- 권한 영향 (Privilege Impact)\n\n[규제 신호]\n- IAM-05 (CSA_CCM): 긴급 대응 필요 (Urgent Response Required)\n- SEF-07 (CSA_CCM): 보고 의무 (Reporting Obligation)",
  "triggers": {
    "event_factors": [
      "공개 노출 (Public Exposure)",
      "권한 영향 (Privilege Impact)",
      "중간 민감도 데이터 (Medium Sensitivity Data)"
    ],
    "regulatory_signals": [
      {
        "clause_id": "IAM-05",
        "doc_type": "CSA_CCM",
        "intent": "긴급 대응 필요 (Urgent Response Required)",
        "title": "Least Privilege"
      },
      {
        "clause_id": "SEF-07",
        "doc_type": "CSA_CCM",
        "intent": "보고 의무 (Reporting Obligation)",
        "title": "Security Breach Notification"
      }
    ],
    "fallback": false
  }
}
```

### 필드 설명

#### assigned_level (integer, required)
- **설명**: 결정된 심각도 레벨
- **값**: `1` (Critical), `2` (High), `3` (Medium/Low)
- **용도**: Regulation Agent가 권고 레벨 결정 시 참고

#### justification (string, required)
- **설명**: XAI 기반 결정 근거 설명
- **형식**: 다중 줄 텍스트
- **구조**:
  ```
  심각도 레벨 Level X (Critical/High/Medium)이 할당되었습니다.

  [이벤트 요인]
  - 요인1
  - 요인2

  [규제 신호]
  - clause_id (doc_type): intent
  - ...
  ```

#### triggers (object, required)
- **설명**: 결정에 영향을 미친 요인들

##### triggers.event_factors (array[string], required)
- **설명**: 보안 이벤트에서 추출된 결정 요인
- **예시**: `["공개 노출 (Public Exposure)", "권한 영향 (Privilege Impact)"]`

##### triggers.regulatory_signals (array[object], required)
- **설명**: 규제 문서에서 추출된 규제 신호 (최대 5개)
- **구조**:
  ```json
  {
    "clause_id": "IAM-05",
    "doc_type": "CSA_CCM",
    "intent": "긴급 대응 필요 (Urgent Response Required)",
    "title": "Least Privilege"
  }
  ```

##### triggers.fallback (boolean, required)
- **설명**: Fallback 조건 여부
- **값**: `true` (규제 문서 부족으로 기본값 사용), `false` (정상 결정)

**자세한 내용**: `severity_result_schema.md` 참조

---

## 5. context_chunks

**타입**: `array[object]`  
**설명**: RAG로 검색된 규제 문서 청크 목록

```json
[
  {
    "doc_type": "CSA_CCM",
    "doc_version": "v4.0",
    "clause_id": "IAM-05",
    "title": "Least Privilege",
    "category": "IAM",
    "mapping_iso27001": ["A.5.15", "A.8.2"],
    "mapping_iso27017": [],
    "content": "Control ID: IAM-05\nControl Title: Least Privilege\n[성격: Least Privilege(최소 권한), Access Control(접근 통제), Mitigation(완화)]\n\nRule: Employ the least privilege principle when implementing information system access.\n(한글 요약: 최소 권한 원칙 - 정보 시스템 접근 권한 부여 시 업무 수행에 필요한 최소한의 권한만 부여해야 한다.)\n\n[적용 시나리오]\n본 규정은 IaaS, PaaS, SaaS 등 모든 클라우드 서비스 모델에서 관리자, 개발자, 보안 담당자 등 사용자에게 시스템 접근 권한을 할당(Provisioning)하거나 변경할 때 적용됩니다. 특히 직무보다 과도한 권한이 부여된 계정(Excessive Privilege)이 식별될 때 필수적입니다.\n\n[대응 조치]\n이에 대한 보안 조치로는 사용자 직무에 필수적인 리소스에만 접근하도록 IAM 정책을 제한(restrict_access)하고, 정기적인 권한 검토를 통해 미사용 권한이나 과도한 권한을 즉시 회수(revoke_permissions)해야 합니다."
  },
  {
    "doc_type": "CSA_CCM",
    "doc_version": "v4.0",
    "clause_id": "IAM-13",
    "title": "Uniquely Identifiable Users",
    "category": "IAM",
    "mapping_iso27001": ["A.5.16"],
    "mapping_iso27017": [],
    "content": "Control ID: IAM-13\nControl Title: Uniquely Identifiable Users\n..."
  }
]
```

### 필드 설명

#### doc_type (string, required)
- **설명**: 규제 문서 유형
- **예시**: `"CSA_CCM"`, `"ISO27001"`, `"ISMS-P"`

#### doc_version (string, optional)
- **설명**: 문서 버전
- **예시**: `"v4.0"`, `"2022"`

#### clause_id (string, required)
- **설명**: 규제 조항 ID
- **예시**: `"IAM-05"`, `"SEF-07"`, `"LOG-03"`

#### title (string, required)
- **설명**: 규제 조항 제목
- **예시**: `"Least Privilege"`, `"Security Breach Notification"`

#### category (string, optional)
- **설명**: 규제 카테고리
- **예시**: `"IAM"`, `"SEF"`, `"LOG"`, `"DCS"`

#### mapping_iso27001 (array[string], optional)
- **설명**: ISO 27001 매핑
- **예시**: `["A.5.15", "A.8.2"]`
- **참고**: 빈 배열일 수 있음

#### mapping_iso27017 (array[string], optional)
- **설명**: ISO 27017 매핑
- **예시**: `["A.5.15"]`
- **참고**: 빈 배열일 수 있음

#### content (string, required)
- **설명**: 규제 조항의 전체 내용 (document 필드)
- **형식**: 다중 줄 텍스트
- **구조**:
  ```
  Control ID: IAM-05
  Control Title: Least Privilege
  [성격: ...]
  
  Rule: ...
  (한글 요약: ...)
  
  [적용 시나리오]
  ...
  
  [대응 조치]
  ...
  ```

---

## 6. 메타데이터 필드

### schema_version (string, required)
- **설명**: 스키마 버전
- **값**: `"1.1"` (현재 버전)

### generated_at (string, required)
- **설명**: 생성 시각 (ISO 8601 형식)
- **형식**: `YYYY-MM-DDTHH:mm:ss.sssZ`
- **예시**: `"2024-01-15T10:30:00.000Z"`

### incident_id (string, required)
- **설명**: 사고 식별자
- **예시**: `"gd-finding-123"`

---

## 전체 예시

```json
{
  "schema_version": "1.1",
  "generated_at": "2024-01-15T10:30:00.000Z",
  "incident_id": "gd-finding-123",
  "incident_summary": {
    "source": "guardduty",
    "title": "Access Key suspicious usage (post-L1)",
    "severity": "5.3",
    "resource": {
      "type": "AccessKey",
      "id": "AKIA...",
      "region": "ap-northeast-2",
      "account_id": "123456789012"
    }
  },
  "executed_level1_actions": [
    "record_finding",
    "notify_slack",
    "fetch_cloudtrail_related_events",
    "tag_finding_observe"
  ],
  "candidate_actions": [
    "disable_access_key",
    "detach_admin_policies",
    "terminate_sessions",
    "isolate_instance",
    "create_snapshot"
  ],
  "severity_decision_result": {
    "assigned_level": 2,
    "justification": "심각도 레벨 Level 2 (High)이 할당되었습니다.\n\n[이벤트 요인]\n- 공개 노출 (Public Exposure)\n- 권한 영향 (Privilege Impact)\n\n[규제 신호]\n- IAM-05 (CSA_CCM): 긴급 대응 필요 (Urgent Response Required)",
    "triggers": {
      "event_factors": [
        "공개 노출 (Public Exposure)",
        "권한 영향 (Privilege Impact)",
        "중간 민감도 데이터 (Medium Sensitivity Data)"
      ],
      "regulatory_signals": [
        {
          "clause_id": "IAM-05",
          "doc_type": "CSA_CCM",
          "intent": "긴급 대응 필요 (Urgent Response Required)",
          "title": "Least Privilege"
        }
      ],
      "fallback": false
    }
  },
  "context_chunks": [
    {
      "doc_type": "CSA_CCM",
      "doc_version": "v4.0",
      "clause_id": "IAM-05",
      "title": "Least Privilege",
      "category": "IAM",
      "mapping_iso27001": ["A.5.15", "A.8.2"],
      "mapping_iso27017": [],
      "content": "Control ID: IAM-05\nControl Title: Least Privilege\n..."
    },
    {
      "doc_type": "CSA_CCM",
      "doc_version": "v4.0",
      "clause_id": "IAM-13",
      "title": "Uniquely Identifiable Users",
      "category": "IAM",
      "mapping_iso27001": ["A.5.16"],
      "mapping_iso27017": [],
      "content": "Control ID: IAM-13\nControl Title: Uniquely Identifiable Users\n..."
    }
  ]
}
```

---

## 데이터 흐름

```
1. GuardDuty Finding
   ↓
2. make_mock_incident_input()
   → incident_input 생성
   ↓
3. RAG 검색 (chroma_retrieve)
   → retrieved 문서들
   ↓
4. Severity Decision + XAI
   → severity_result 생성
   ↓
5. build_context_chunks()
   → context_chunks 생성
   ↓
6. Payload 구성
   {
     ...incident_input,
     "severity_decision_result": severity_result,
     "context_chunks": context_chunks
   }
   ↓
7. Regulation Agent LLM 호출
```

---

## 필수 필드 vs 선택 필드

### 필수 필드 (Required)
- `schema_version`
- `generated_at`
- `incident_id`
- `incident_summary`
- `executed_level1_actions`
- `context_chunks`

### 선택 필드 (Optional)
- `candidate_actions` (빈 배열 가능)
- `severity_decision_result` (추가됨, 향후 필수로 전환 가능)

---

## 검증 규칙

1. **schema_version**: 반드시 `"1.1"`이어야 함
2. **generated_at**: ISO 8601 형식의 유효한 날짜/시간 문자열
3. **incident_id**: 비어있지 않은 문자열
4. **incident_summary.resource**: 모든 하위 필드 필수
5. **executed_level1_actions**: 배열 (빈 배열 가능)
6. **candidate_actions**: 배열 (빈 배열 가능)
7. **severity_decision_result.assigned_level**: 1, 2, 또는 3
8. **context_chunks**: 배열 (최소 1개 이상 권장)
9. **context_chunks[].clause_id**: 비어있지 않은 문자열
10. **context_chunks[].content**: 비어있지 않은 문자열

---

## 버전 관리

- **v1.0**: 초기 스키마 (severity_decision_result 제외)
- **v1.1** (현재): severity_decision_result 추가

---

## 관련 문서

- `severity_result_schema.md`: severity_decision_result 상세 스키마
- `테스트_방법_가이드.md`: 테스트 방법
- `병합_점검_리포트.md`: 병합 상태 리포트

