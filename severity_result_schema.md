# Severity Result 전달 형식 스키마

## 개요

`severity_result`는 Severity Decision Engine + XAI의 결과를 Regulation Agent에 전달하기 위한 구조화된 데이터 형식입니다.

---

## 데이터 구조

### severity_result (최상위 객체)

```json
{
  "assigned_level": 1,
  "justification": "심각도 레벨 Level 1 (Critical)이 할당되었습니다.\n\n[이벤트 요인]\n- 공개 노출 (Public Exposure)\n- 권한 영향 (Privilege Impact)\n- 고민감도 데이터 (High Sensitivity Data)\n\n[규제 신호]\n- IAM-05 (CSA_CCM): 긴급 대응 필요 (Urgent Response Required)\n- SEF-07 (CSA_CCM): 보고 의무 (Reporting Obligation)",
  "triggers": {
    "event_factors": [
      "공개 노출 (Public Exposure)",
      "권한 영향 (Privilege Impact)",
      "고민감도 데이터 (High Sensitivity Data)",
      "침해/유출 이벤트 (Breach/Exfiltration Event)"
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

---

## 필드 설명

### assigned_level (int, required)
- **설명**: 결정된 심각도 레벨
- **값**: `1` (Critical), `2` (High), `3` (Medium/Low)
- **용도**: Regulation Agent가 권고 레벨 결정 시 참고

### justification (str, required)
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
- **용도**: Regulation Agent가 결정 근거를 이해하고 권고사항 작성 시 활용

### triggers (object, required)
- **설명**: 결정에 영향을 미친 요인들

#### event_factors (array[str], required)
- **설명**: 보안 이벤트에서 추출된 결정 요인
- **예시**: `["공개 노출 (Public Exposure)", "권한 영향 (Privilege Impact)"]`
- **용도**: Regulation Agent가 이벤트 특성을 파악하는 데 활용

#### regulatory_signals (array[object], required)
- **설명**: 규제 문서에서 추출된 규제 신호
- **최대 개수**: 5개 (상위 5개만)
- **용도**: Regulation Agent가 규제 근거를 명시할 때 활용

##### regulatory_signals[].clause_id (str, required)
- **설명**: 규제 조항 ID
- **예시**: `"IAM-05"`, `"SEF-07"`

##### regulatory_signals[].doc_type (str, required)
- **설명**: 규제 문서 유형
- **예시**: `"CSA_CCM"`, `"ISO27001"`

##### regulatory_signals[].intent (str, required)
- **설명**: 규제 의도
- **예시**: `"긴급 대응 필요 (Urgent Response Required)"`, `"보고 의무 (Reporting Obligation)"`

##### regulatory_signals[].title (str, optional)
- **설명**: 규제 조항 제목
- **예시**: `"Least Privilege"`, `"Security Breach Notification"`

#### fallback (bool, required)
- **설명**: Fallback 조건 여부
- **값**: `true` (규제 문서 부족으로 기본값 사용), `false` (정상 결정)
- **용도**: Regulation Agent가 규제 증거의 신뢰도를 판단하는 데 활용

---

## Regulation Agent 전달 방법

### 방법 1: incident_input에 추가 (권장)

`incident_input` 딕셔너리에 `severity_decision_result` 필드를 추가합니다.

```python
incident_input = {
    "schema_version": "1.1",
    "generated_at": now,
    "incident_id": "...",
    "incident_summary": {...},
    "executed_level1_actions": [...],
    "candidate_actions": [...],
    "severity_decision_result": severity_result,  # 추가
    "context_chunks": context_chunks
}
```

**장점:**
- 구조화된 입력으로 명확함
- Regulation Agent가 쉽게 접근 가능
- 타입 안정성 확보 가능

### 방법 2: context_chunks에 메타데이터로 추가

`context_chunks`의 첫 번째 항목에 메타데이터로 추가합니다.

```python
context_chunks_with_severity = [
    {
        "doc_type": "_severity_decision_metadata",
        "severity_result": severity_result
    },
    ...context_chunks
]
```

**단점:**
- context_chunks의 본래 목적과 혼재
- LLM이 혼동할 수 있음

---

## Regulation Agent 프롬프트 업데이트

`severity_decision_result`를 전달할 경우, 시스템 프롬프트에 다음을 추가해야 합니다:

```
## Severity Decision Result (Optional)
You may receive a severity_decision_result field containing:
- assigned_level: The severity level (1, 2, or 3) determined by the Severity Decision Engine
- justification: XAI-based explanation of the decision
- triggers: Event factors and regulatory signals that influenced the decision

Use this information to:
- Understand the regulatory context and decision rationale
- Strengthen your recommendations with the provided regulatory signals
- Reference specific clause IDs in your regulations field
- Consider the event factors when recommending actions

Note: The severity_decision_result is provided for context and decision support.
You should still make your own assessment based on the incident and regulatory context.
```

---

## 예시: e2e_test.py에서 사용

```python
# Severity Decision + XAI 실행
severity_result = decide_severity_level_with_xai(security_event, retrieved)

# incident_input에 추가
incident_input["severity_decision_result"] = severity_result

# Regulation Agent 호출
output = call_regulation_agent_with_validation(
    incident_input=incident_input,
    context_chunks=context_chunks,
    model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
)
```

---

## 검증 규칙

1. `assigned_level`은 반드시 1, 2, 또는 3이어야 함
2. `justification`은 비어있지 않은 문자열이어야 함
3. `triggers.event_factors`는 배열이어야 함 (빈 배열 가능)
4. `triggers.regulatory_signals`는 배열이어야 함 (빈 배열 가능)
5. `triggers.fallback`은 boolean이어야 함
6. `regulatory_signals`의 각 항목은 `clause_id`, `doc_type`, `intent`를 포함해야 함

---

## 버전 관리

- **v1.0** (현재): 기본 구조 정의
- 향후 확장 가능: 추가 메타데이터, 통계 정보 등

