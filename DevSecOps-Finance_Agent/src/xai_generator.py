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
    고정 템플릿으로 설명 문자열 생성. 자유 생성 없음.
    """
    d1 = f"{top3_drivers[0][0]}: ${top3_drivers[0][1]:.2f}"
    d2 = f"{top3_drivers[1][0]}: ${top3_drivers[1][1]:.2f}"
    d3 = f"{top3_drivers[2][0]}: ${top3_drivers[2][1]:.2f}"
    return (
        f"duration={request.duration_hours}시간, "
        f"traffic_multiplier={request.traffic_multiplier} 기준으로\n"
        f"총 예상 비용은 ${total_cost:.2f} 입니다.\n\n"
        f"상위 비용 드라이버:\n"
        f"1) {d1}\n"
        f"2) {d2}\n"
        f"3) {d3}\n\n"
        f"본 시뮬레이션은 base_traffic={request.base_traffic_gb}GB,\n"
        f"base_log={request.base_log_gb}GB 기준으로 계산되었습니다."
    )
