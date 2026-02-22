"""
Finance Agent (Week1 – B) 템플릿 기반 XAI 설명.
LLM 미사용, 고정 템플릿만 사용. 동일 입력 → 동일 문장.
"""

from models import FinanceRequest


def generate_xai_explanation(
    request: FinanceRequest,
    total_cost: float,
    top3_drivers: list[tuple[str, float]],
) -> str:
    """
    고정 템플릿 4파트: Assumption disclosure / Top3 drivers / Sensitivity / Trade-off.
    자유 생성 없음. 동일 입력 → 동일 문장.
    """
    d1 = f"{top3_drivers[0][0]}: ${top3_drivers[0][1]:.2f}"
    d2 = f"{top3_drivers[1][0]}: ${top3_drivers[1][1]:.2f}"
    d3 = f"{top3_drivers[2][0]}: ${top3_drivers[2][1]:.2f}"

    # 1) Assumption disclosure
    assumption = (
        f"본 시뮬레이션은 base_traffic={request.base_traffic_gb}GB, "
        f"base_log={request.base_log_gb}GB, "
        f"duration={request.duration_hours}h, "
        f"traffic_multiplier={request.traffic_multiplier}, "
        f"log_multiplier={request.log_multiplier} 기준으로 계산되었습니다."
    )
    # 2) Top3 drivers + 비용 요약
    cost_summary = (
        f"총 예상 비용은 ${total_cost:.2f} 입니다.\n\n"
        f"상위 비용 드라이버:\n"
        f"1) {d1}\n"
        f"2) {d2}\n"
        f"3) {d3}"
    )
    # 3) Sensitivity
    sensitivity = (
        "비용은 traffic_multiplier, log_multiplier, duration_hours, "
        "base_traffic_gb, base_log_gb 변경에 따라 변동됩니다."
    )
    # 4) Trade-off
    tradeoff = (
        "비용 절감 시 로그·트래픽 축소를 고려할 수 있으며, "
        "비용·리스크·가용성 간 트레이드오프가 있습니다."
    )

    return (
        f"{assumption}\n\n"
        f"{cost_summary}\n\n"
        f"Sensitivity: {sensitivity}\n\n"
        f"Trade-off: {tradeoff}"
    )
