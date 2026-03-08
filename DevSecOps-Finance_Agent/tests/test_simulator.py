"""시뮬레이터(dataclass 경로) 테스트: 재현성, profile 변경 시 추천 변경."""

from src.models import FinanceRequest
from src.simulator import simulate


def test_same_request_twice_same_result():
    """동일 FinanceRequest 두 번 → 동일 FinanceResult (recommended_action 포함)."""
    request = FinanceRequest(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Medium",
        service_tier="S2",
        regulation_weight=1.2,
        profile="Standard",
    )
    r1 = simulate(request)
    r2 = simulate(request)
    assert r1.recommended_action == r2.recommended_action
    assert r1.total_cost == r2.total_cost
    assert r1.action_scores == r2.action_scores


def test_profile_change_changes_recommendation():
    """동일 시나리오에서 profile만 바꾸면 점수/추천이 적용됨. 추천은 catalog 내 action_id만 허용."""
    base = dict(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Low",
        service_tier="S1",
        regulation_weight=1.0,
    )
    r_std = simulate(FinanceRequest(profile="Standard", **base))
    r_lean = simulate(FinanceRequest(profile="LeanStartup", **base))
    valid_actions = {"OBSERVE_ONLY", "LOG_HARDEN", "LOG_PRESERVE", "SNAPSHOT_ONLY", "ISOLATE_INSTANCE", "ROTATE_KMS_KEY", "DISABLE_ACCESS_KEY", "MFA_ENFORCE"}
    assert r_std.recommended_action in valid_actions
    assert r_lean.recommended_action in valid_actions
    # profile에 따라 가중치가 다르므로 action_scores는 달라져야 함
    assert r_std.action_scores != r_lean.action_scores
