# Finance Agent

> 보안 사고 대응 과정에서 플레이북 비용 계산, 대응 레벨(Level2/Level3) 추천, 사용자 시뮬레이션 질문을 담당하는 AWS Lambda 서비스입니다.

비용과 위험도를 함께 고려한 추천을 제공하며, **최종 결정은 사용자가 수행**합니다. (AI recommends, Human decides)

---

## 목차

- [아키텍처](#아키텍처)
- [주요 기능](#주요-기능)
- [Lambda Actions](#lambda-actions)
- [추천 모델](#추천-모델)
- [로컬 테스트](#로컬-테스트)

---

## 아키텍처

```
GuardDuty Event
      │
      ▼
Runtime Agent  ─── Level1 자동 대응
      │
      ▼
Regulation Agent  ─── 규제 기반 Playbook 후보 생성
      │
      ▼
Finance Agent  ─── 비용 계산 · 시뮬레이션 질문 · L2/L3 추천
      │
      ▼
MCP (Slack UI)
      │
      ▼
User Decision
```

Finance Agent는 **추천 시스템** 역할만 수행하며, 실제 대응 실행은 Runtime Agent가 담당합니다.

---

## 주요 기능

### 1. 대응 플레이북 비용 계산

보안 대응 시 발생하는 AWS 리소스 비용을 계산합니다.

**비용 드라이버**

| 드라이버 | 설명 |
|----------|------|
| CloudWatch Logs | 로그 저장 |
| S3 Storage | 조사 데이터 저장 |
| NAT Gateway Egress | 네트워크 트래픽 |
| Snapshot Storage | 디스크 스냅샷 |

### 2. 대응 레벨 추천 (L2 vs L3)

다음 요소를 기반으로 **결정론적 스코어링**으로 Level2 vs Level3를 추천합니다.

- 시스템 환경 (production / internal / dev_test)
- 데이터 민감도 (pii / internal / public)
- 서비스 중단 허용 여부 (allowed / approval_required / not_allowed)
- 보안 vs 비용 우선순위 (security / balanced / cost)

### 3. 사용자 시뮬레이션 질문

MCP를 통해 사용자에게 **4개 질문**을 제공합니다. 사용자 선택 결과는 추천 로직에 반영됩니다.

- 서비스 환경
- 데이터 민감도
- 서비스 중단 허용 여부
- 보안 vs 비용 우선순위

---

## Lambda Actions

| action | 설명 |
|--------|------|
| `finance_run` | 플레이북 비용 계산 |
| `get_simulation_questions` | 시뮬레이션 질문 4개 반환 |
| `get_simulation_recommendation` | 사용자 응답 기반 L2/L3 추천 |

---

## 추천 모델

- **결정(Decision)** → **결정론적 로직** (스코어 기반, LLM 미사용)
- **설명(Explanation)** → **LLM** (추천 이유 XAI, 사용자 친화적 메시지)

즉, **어떤 플레이북을 추천할지**는 코드로 고정되고, **이유 문장**만 LLM으로 생성합니다. (`OPENAI_API_KEY` 설정 시)

---

## 로컬 테스트

```bash
python run_mocks.py
```

**테스트 대상**

- `finance_run` — 비용 계산 파이프라인
- `get_simulation_questions` — 질문 JSON 반환
- `get_simulation_recommendation` — 사용자 응답 기반 추천 (LLM/fallback)

`.env`에 `OPENAI_API_KEY`를 설정하면 LLM으로 추천 이유가 생성되고, 없으면 결정론적 이유만 사용됩니다.

