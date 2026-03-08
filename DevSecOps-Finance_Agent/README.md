Finance Agent (AWS Lambda)

Finance Agent는 보안 사고 대응 과정에서 플레이북 비용 계산, 대응 레벨(Level2/Level3) 추천, 사용자 시뮬레이션 질문 제공을 담당하는 AWS Lambda 서비스입니다.

이 서비스는 보안 대응 비용과 위험도를 함께 고려하여 추천을 제공하며, 최종 결정은 사용자가 수행합니다.

Architecture
GuardDuty Event
      │
      ▼
Runtime Agent
      │
      └ Level1 자동 대응
            │
            ▼
Regulation Agent
      │
      └ 규제 기반 Playbook 후보 생성
            │
            ▼
Finance Agent
      │
      ├ 비용 계산
      ├ 시뮬레이션 질문 생성
      └ Level2 / Level3 추천
            │
            ▼
MCP (Slack UI)
      │
      ▼
User Decision

Finance Agent는 추천 시스템 역할만 수행하며 실제 대응 실행은 Runtime Agent가 담당합니다.

주요 기능
1. 대응 플레이북 비용 계산

보안 대응 시 발생하는 AWS 리소스 비용을 계산합니다.

주요 비용 드라이버

CloudWatch Logs

S3 Storage

NAT Gateway Egress

Snapshot Storage

2. 대응 레벨 추천

Finance Agent는 다음 요소를 기반으로 Level2 vs Level3 대응을 추천합니다.

시스템 환경

데이터 민감도

서비스 중단 허용 여부

보안 vs 비용 우선순위

추천은 deterministic scoring logic으로 수행됩니다.

3. 사용자 시뮬레이션 질문

Finance Agent는 MCP를 통해 사용자에게 다음 질문을 제공합니다.

서비스 환경

데이터 민감도

서비스 중단 허용 여부

보안 vs 비용 우선순위

사용자의 선택은 추천 로직에 반영됩니다.

Supported Actions

Finance Agent Lambda는 다음 action을 지원합니다.

action	description
finance_run	플레이북 비용 계산
get_simulation_questions	시뮬레이션 질문 반환
get_simulation_recommendation	사용자 응답 기반 추천
Deterministic Decision Model

추천 결과는 스크립트 기반 로직으로 결정됩니다.

LLM은 다음 용도로만 사용됩니다.

추천 이유 설명 (XAI)

사용자 친화적 메시지 생성

즉,

Decision → deterministic
Explanation → LLM
Local Test
python run_mocks.py

테스트 대상

finance_run

get_simulation_questions

get_simulation_recommendation

Key Design Principle

Finance Agent는 AI 기반 보안 대응 추천 시스템입니다.

AI recommends the response.
Human makes the final decision.
Documentation

세부 설계 문서는 팀 Notion에서 관리합니다.

포함 내용

JSON Schema

Pricing 계산 방식

Playbook 리소스 매핑

LLM Prompt 구조

Audit 로그 설계