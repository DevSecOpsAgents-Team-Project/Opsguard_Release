"""
Finance Agent (Week1 + Week2) 시뮬레이션 오케스트레이션.
비용 계산 → Expected Loss → 액션 점수 → 추천 대응안.
"""

from models import FinanceRequest, FinanceResult
from cost_model import compute_cost_breakdown
from xai_generator import generate_xai_explanation
from risk_model import (
    calculate_expected_loss,
    calculate_risk_adjusted_loss,
)
from scoring_engine import compute_action_scores


def simulate(request: FinanceRequest) -> FinanceResult:
    """
    1. cost_model 호출, total_cost 계산
    2. breakdown 내림차순, Top3, xai_generator
    3. (Week2) Expected Loss, risk_adjusted_loss
    4. (Week2) 모든 액션 점수 계산, 최고 점수 액션 추천
    5. FinanceResult 반환
    """
    breakdown = compute_cost_breakdown(request)
    total_cost = sum(breakdown.values())

    sorted_items = sorted(
        breakdown.items(), key=lambda x: x[1], reverse=True
    )
    cost_breakdown_sorted = dict(sorted_items)
    top3_drivers = sorted_items[:3]

    xai_explanation = generate_xai_explanation(
        request, total_cost, top3_drivers
    )

    # Week2: Expected Loss, regulation 반영
    expected_loss = calculate_expected_loss(
        request.severity, request.service_tier
    )
    risk_adjusted_loss = calculate_risk_adjusted_loss(
        expected_loss, request.regulation_weight
    )

    # Week2: 액션별 점수, 추천
    action_scores, recommended_action = compute_action_scores(
        base_cost=total_cost,
        risk_adjusted_loss=risk_adjusted_loss,
        profile=request.profile,
    )

    return FinanceResult(
        total_cost=total_cost,
        cost_breakdown=cost_breakdown_sorted,
        top3_drivers=top3_drivers,
        xai_explanation=xai_explanation,
        expected_loss=expected_loss,
        risk_adjusted_loss=risk_adjusted_loss,
        action_scores=action_scores,
        recommended_action=recommended_action,
    )
