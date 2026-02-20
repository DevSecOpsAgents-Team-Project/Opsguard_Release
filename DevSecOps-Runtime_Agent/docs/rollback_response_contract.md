## Agent B – 롤백 응답 스키마(Contract) 명세서

본 문서는 Agent B의 모든 액션(Actions Module)이 반환해야 하는 표준 스키마와 D팀 `rollback_service`가 기대하는 데이터 구조를 정의합니다. 해당 계약은 `Actions Module → Playbook → Engine Handler → DynamoDB → RollbackService` 전체 경로에서 일관되게 사용되어야 합니다.

---

### 1. 액션 공통 응답 스키마 (ActionResult)

```json
{
  "action_id": "string (uuid4)",
  "incident_id": "string",
  "action_name": "string",
  "status": "SUCCESS | FAILED | RETRY | DRYRUN",
  "rollback_data": {},
  "details": {}
}
```

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| action_id | string (UUID) | 액션 고유 식별자 |
| incident_id | string | GuardDuty Incident 기준 ID |
| action_name | string | 수행된 액션 이름(예: `isolate_instance`) |
| status | enum | `SUCCESS`, `FAILED`, `RETRY`, `DRYRUN` |
| rollback_data | object | 롤백 필수 데이터 |
| details | object | 성공/실패 메시지, 추가 정보 |

---

### 2. 액션별 `rollback_data` 스키마

#### 2.1 `isolate_instance` (EC2 격리)

```json
{
  "instance_id": "string",
  "original_sg_id": ["sg-xxxx", "sg-yyyy"],
  "new_sg_id": "sg-ISOLATION"
}
```

- 격리 SG 제거 후 `original_sg_id` 목록 재부착  
- `Isolated=true` 태그 삭제(선택)

#### 2.2 `block_ip` (WAF IPSet 차단)

```json
{
  "ip_address": "1.1.1.1",
  "waf_set_id": "ipset-12345",
  "scope": "REGIONAL"
}
```

- IPSet에서 해당 IP 제거  
- `UpdateIPSet` 호출 전 `GetIPSet`으로 LockToken 재획득

#### 2.3 `create_snapshot` (EC2 볼륨 스냅샷 생성)

```json
{
  "snapshot_id": "snap-abc123",
  "volume_id": "vol-12345"
}
```

- 롤백 시 `ec2:DeleteSnapshot` 호출  
- 원본 볼륨은 변경되지 않으므로 스냅샷 삭제만 수행

---

### 3. DynamoDB 저장 형식 (`log_action → table.put_item`)

```json
{
  "HistoryID": "uuid4",
  "Timestamp": "ISO8601",
  "IncidentId": "string",
  "Scenario": "string",
  "ActionId": "string",
  "ActionName": "string",
  "RollbackData": {},
  "Details": {}
}
```

- `HistoryID`는 PK  
- `IncidentId` 기반 GSI 구성 시 Incident 단위 조회 가능  
- `ActionId` 순서 기준으로 역순 롤백 처리

---

### 4. 롤백 서비스 규칙

**4.1 Incident 단위 롤백**  
- `IncidentId`로 DynamoDB 로그 조회  
- `ActionId` 내림차순(최신 우선)으로 롤백 실행

**4.2 액션별 매핑**

| Action Name | Rollback Function |
| --- | --- |
| `isolate_instance` | `restore_security_groups` |
| `block_ip` | `remove_ip_from_ipset` |
| `create_snapshot` | `delete_snapshot` |

---

### 5. RollbackService 예시 로직

```python
def rollback_incident(incident_id):
    logs = fetch_actions_from_dynamodb(incident_id)
    for log in sorted(logs, key=lambda x: x["ActionId"], reverse=True):
        if log["ActionName"] == "isolate_instance":
            restore_security_groups(log["RollbackData"])
        elif log["ActionName"] == "block_ip":
            remove_ip_from_ipset(log["RollbackData"])
        elif log["ActionName"] == "create_snapshot":
            delete_snapshot(log["RollbackData"])
```

---

### 6. Contract 변경 규칙 (팀 간 협업 기준)

- `rollback_data` 구조 임의 변경 금지  
- 변경 필요 시 팀 B·C·D 합의 필수  
- `ActionId`, `IncidentId`는 필수 필드  
- DynamoDB 저장 스키마 변경 시 전 팀 동의 필요

---

### 7. 버전 관리

- **v1.0** — 최초 명세 (3주차)  
- **v1.1** — `isolate_instance` rollback_data 구조 고정  
- **v1.2** — 스냅샷 삭제 시나리오 추가
#️⃣ Agent B – 롤백 응답 스키마(Contract) 명세서

본 문서는 Agent B의 모든 액션(Actions Module)이 반환해야 하는 표준 스키마와
D팀이 구현하는 rollback_service가 기대하는 데이터 구조를 정의합니다.

이 스키마는

Actions Module → Playbook → Engine Handler → DynamoDB → RollbackService
모든 레이어에서 일관되게 사용되는 공통 계약(Contract) 입니다.

#️⃣ 1. 액션 공통 응답 스키마 (ActionResult)

Agent B의 모든 액션은 아래 JSON 스키마를 반환해야 한다.

{
  "action_id": "string (uuid4)",
  "incident_id": "string",
  "action_name": "string",
  "status": "SUCCESS | FAILED | RETRY | DRYRUN",
  "rollback_data": { ... },
  "details": { ... }
}

👉 필드 설명
필드	타입	설명
action_id	string (UUID)	한 액션을 고유하게 식별하기 위한 ID
incident_id	string	GuardDuty 이벤트 기준 Incident 식별자
action_name	string	수행된 액션 이름 (ex: isolate_instance)
status	enum	액션 결과 (성공/실패/재시도/드라이런)
rollback_data	object	롤백에 반드시 필요한 핵심 필드
details	object	성공/실패 메시지, 부가 정보
#️⃣ 2. 액션별 rollback_data 스키마

롤백을 위해 필수적으로 저장해야 하는 필드는 아래와 같다.

2.1 isolate_instance (EC2 격리)
📌 rollback_data
{
  "instance_id": "string",
  "original_sg_id": ["sg-xxxx", "sg-yyyy"],
  "new_sg_id": "sg-ISOLATION"
}

📌 롤백 시나리오

새로운 격리 SG(new_sg_id)를 제거

original_sg_id 배열에 있는 Security Group들을 다시 인스턴스에 부착

"Isolated=true" 태그 삭제(선택)

2.2 block_ip (WAF IPSet 차단)
📌 rollback_data
{
  "ip_address": "1.1.1.1",
  "waf_set_id": "ipset-12345",
  "scope": "REGIONAL"
}

📌 롤백 시나리오

IPSet에서 ip_address를 제거

UpdateIPSet에 LockToken 필요 → 재조회 필요함

2.3 create_snapshot (EC2 볼륨 스냅샷 생성)
📌 rollback_data
{
  "snapshot_id": "snap-abc123",
  "volume_id": "vol-12345"
}

📌 롤백 시나리오

스냅샷 삭제 (ec2:DeleteSnapshot)

원본 볼륨은 변경되지 않으므로 스냅샷 삭제만 처리

#️⃣ 3. DynamoDB 저장 형식 (log_action → table.put_item)

log_action은 아래 스키마를 DynamoDB에 저장한다:

{
  "HistoryID": "uuid4",
  "Timestamp": "ISO8601",
  "IncidentId": "string",
  "Scenario": "string",
  "ActionId": "string",
  "ActionName": "string",
  "RollbackData": { ... },
  "Details": { ... }
}

설명

HistoryID는 DynamoDB의 PK로 사용

IncidentId를 기준으로 GSI 생성하면 rollback 시 “IncidentId 기준 정렬” 가능

ActionId가 있는 덕분에 액션 수행 순서 보존 가능

롤백 시 역순(ActionId DESC)으로 실행

#️⃣ 4. 롤백 서비스가 따라야 할 규칙
✔ 4.1 Incident 단위 롤백

IncidentId로 DynamoDB에서 해당 이벤트의 모든 액션 내역 조회

ActionId 기준 내림차순 정렬 (가장 나중에 실행된 액션부터 롤백)

✔ 4.2 액션별 매핑 테이블

RollbackService는 다음 매핑을 기반으로 원복 로직을 수행해야 한다.

Action Name	Rollback Function
isolate_instance	restore_security_groups
block_ip	remove_ip_from_ipset
create_snapshot	delete_snapshot
#️⃣ 5. RollbackService 예시 로직
def rollback_incident(incident_id):
    logs = fetch_actions_from_dynamodb(incident_id)

    # 최신 액션부터 순서대로 롤백
    for log in sorted(logs, key=lambda x: x["ActionId"], reverse=True):
        if log["ActionName"] == "isolate_instance":
            restore_security_groups(log["RollbackData"])

        elif log["ActionName"] == "block_ip":
            remove_ip_from_ipset(log["RollbackData"])

        elif log["ActionName"] == "create_snapshot":
            delete_snapshot(log["RollbackData"])

#️⃣ 6. Contract 변경 규칙 (팀 간 협업 기준)

✔ rollback_data의 필드 구조는 절대 변경하지 말아야 한다.
✔ 만약 변경이 필요하면 팀 B–C–D 전체 합의가 필요하다.
✔ ActionId, IncidentId는 필수 필드이며 생략 불가.
✔ DynamoDB 저장 스키마 변경도 전체 팀 동의 필요.

#️⃣ 7. 버전 관리

v1.0 — 최초 명세 (3주차)

v1.1 — isolate_instance rollback_data 구조 고정

v1.2 — 스냅샷 삭제 시나리오 추가