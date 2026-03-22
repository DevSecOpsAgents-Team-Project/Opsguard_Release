"""
Finance Agent 로컬 검증: 사용자 응답 3종으로 LLM 추천 응답 테스트.

- 공통 입력: 사용자 제공 finance request 1개 (30일 기준)
- 사용자 응답 Mock 3종 (보안 우선 / 균형 / 비용 우선)으로 get_simulation_recommendation_for_mcp 호출
- 각각 LLM이 어떤 추천/이유를 내는지 비교 확인

실행: python run_mocks.py
"""
import json
import io
import sys
from pathlib import Path

# stdout UTF-8 강제 (Windows 등)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
try:
    import dotenv
    dotenv.load_dotenv(ROOT / ".env")
except ImportError:
    pass

from src.engine import finance_run
from src.simulation_questions import extract_recommended_playbook_from_mcp_payload, get_simulation_recommendation_for_mcp


# ---------------------------------------------------------------------------
# 공통 입력 (사용자 제공)
# ---------------------------------------------------------------------------

INPUT_FINANCE_REQUEST = {
    "schema_version": "1.0",
    "incident_id": "gd-finding-123",
    "policy_version": "v1.0.0",
    "assumptions": {
        "duration_hours": 720,
        "traffic_multiplier": 1.0,
        "region": "ap-northeast-2",
        "service_tier": "S1",
        "org_profile": "Standard",
    },
    "resource_change": {
        "cloudwatch_log_gb_per_day": 10,
        "s3_storage_gb": 100,
        "nat_egress_gb": 5,
        "snapshot_gb": 20,
    },
}

# 사용자 응답 Mock 3종 (LLM 추천 비교용)
USER_RESPONSE_1 = {
    "environment": "production",
    "data_sensitivity": "pii",
    "downtime_tolerance": "allowed",
    "priority": "security",
}
USER_RESPONSE_2 = {
    "environment": "internal",
    "data_sensitivity": "internal",
    "downtime_tolerance": "approval_required",
    "priority": "balanced",
}
USER_RESPONSE_3 = {
    "environment": "dev_test",
    "data_sensitivity": "public",
    "downtime_tolerance": "not_allowed",
    "priority": "cost",
}

USER_RESPONSES = [
    ("사용자 1: 보안 우선 (production, pii, 중단 허용, security)", USER_RESPONSE_1),
    ("사용자 2: 균형 (internal, internal, 승인 시 중단, balanced)", USER_RESPONSE_2),
    ("사용자 3: 비용 우선 (dev_test, public, 중단 불가, cost)", USER_RESPONSE_3),
]


# ---------------------------------------------------------------------------
# 플레이북 Mock 3종 (LLM 입력으로 사용)
# ---------------------------------------------------------------------------

# 예시 1: L2 저비용 vs L3 고비용, 영향 LOW vs HIGH
PLAYBOOK_MOCK_1 = {
    "playbooks": [
        {
            "level": 2,
            "playbook_name": "계정 권한 제한 및 관찰",
            "cost_summary": {"estimated_monthly_cost": 2.5},
            "expected_impact": "LOW",
        },
        {
            "level": 3,
            "playbook_name": "강력한 격리 및 계정 삭제",
            "cost_summary": {"estimated_monthly_cost": 8.0},
            "expected_impact": "HIGH",
        },
    ]
}

# 예시 2: L2/L3 비용 차이 적음, 둘 다 보통 영향
PLAYBOOK_MOCK_2 = {
    "playbooks": [
        {
            "level": 2,
            "playbook_name": "로그 보존 및 접근 제한",
            "cost_summary": {"estimated_monthly_cost": 5.0},
            "expected_impact": "MEDIUM",
        },
        {
            "level": 3,
            "playbook_name": "리소스 격리 및 포렌식 수집",
            "cost_summary": {"estimated_monthly_cost": 6.0},
            "expected_impact": "MEDIUM",
        },
    ]
}

# 예시 3: L3이 더 저렴한 경우 (L2가 리소스 많이 씀)
PLAYBOOK_MOCK_3 = {
    "playbooks": [
        {
            "level": 2,
            "playbook_name": "장기 모니터링 및 단계적 제한",
            "cost_summary": {"estimated_monthly_cost": 12.0},
            "expected_impact": "LOW",
        },
        {
            "level": 3,
            "playbook_name": "즉시 격리 및 증거 확보",
            "cost_summary": {"estimated_monthly_cost": 7.0},
            "expected_impact": "HIGH",
        },
    ]
}

PLAYBOOK_MOCKS = [
    ("예시 1: L2 저비용 vs L3 고비용", PLAYBOOK_MOCK_1),
    ("예시 2: L2/L3 비용 비슷", PLAYBOOK_MOCK_2),
    ("예시 3: L3이 더 저렴", PLAYBOOK_MOCK_3),
]


# ---------------------------------------------------------------------------
# 테스트 실행
# ---------------------------------------------------------------------------

def run_baseline_finance():
    """공통 입력으로 finance_run 1회 실행 → 비용 요약 출력 (선택적 컨텍스트)."""
    print("=== [공통 입력] finance_run (30일 기준) ===")
    r = finance_run(INPUT_FINANCE_REQUEST)
    if "error" in r:
        print(json.dumps(r, ensure_ascii=False))
    else:
        print("cost_summary:", json.dumps(r.get("cost_summary"), ensure_ascii=False))
        if r.get("top3_drivers"):
            print("top3_drivers:", r.get("top3_drivers"))
    print()


def run_llm_playbook_tests():
    """사용자 응답 3종에 대해 get_simulation_recommendation_for_mcp 호출 → LLM 응답 비교."""
    # 공통 플레이북 1개 사용 (L2 저비용 vs L3 고비용) → 사용자 응답만 바꿔가며 추천 비교
    comparison = PLAYBOOK_MOCK_1

    for label, user_response in USER_RESPONSES:
        print("---", label, "---")
        print("user_response:", json.dumps(user_response, ensure_ascii=False))
        result = get_simulation_recommendation_for_mcp(comparison, user_response)
        print("source:", (result.get("result") or {}).get("source"))
        rec = extract_recommended_playbook_from_mcp_payload(result)
        print("recommended_level:", rec.get("recommended_level"))
        print("playbook_name:", rec.get("playbook_name"))
        print("reason:", rec.get("reason", ""))
        print()


def main():
    run_baseline_finance()
    run_llm_playbook_tests()
    print("done.")


if __name__ == "__main__":
    main()
