"""
Finance Agent (Week1 + Week2) 실행 예제.
동일 입력 → 동일 출력 검증. profile 변경 시 추천 변경 확인.
"""

from .models import FinanceRequest
from .simulator import simulate

if __name__ == "__main__":
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

    result = simulate(request)
    print("=== Run 1 (profile=Standard) ===")
    print(result)
    print("recommended_action:", result.recommended_action)
    print()

    # 동일 입력 2회 실행 → 동일 결과 검증
    result2 = simulate(request)
    print("=== Run 2 (동일 입력) ===")
    print("recommended_action:", result2.recommended_action)
    assert result.recommended_action == result2.recommended_action, "동일 입력 시 동일 추천"
    print("OK: 동일 입력 → 동일 recommended_action")
    print()

    # profile만 변경 → 추천 변경 케이스 (저위험 시나리오: Low/S1)
    low_risk = FinanceRequest(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Low",
        service_tier="S1",
        regulation_weight=1.0,
        profile="Standard",
    )
    r_std = simulate(low_risk)
    request_lean = FinanceRequest(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Low",
        service_tier="S1",
        regulation_weight=1.0,
        profile="LeanStartup",
    )
    r_lean = simulate(request_lean)
    print("=== profile 변경 시 추천 변경 (Low/S1) ===")
    print("Standard  recommended_action:", r_std.recommended_action)
    print("LeanStartup recommended_action:", r_lean.recommended_action)
    if r_std.recommended_action != r_lean.recommended_action:
        print("OK: profile만 바꿔도 추천 결과가 달라짐")
