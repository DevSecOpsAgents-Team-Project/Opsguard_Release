"""
Finance Agent (Week1 + Week2) 시뮬레이션 진입점.
FinanceRequest → 비용/리스크/스코어 계산 → FinanceResult 반환. deterministic.
"""

import logging

from .models import FinanceRequest, FinanceResult

logger = logging.getLogger(__name__)
from .cost_model import compute_cost_breakdown
from .risk_model import calculate_expected_loss, calculate_risk_adjusted_loss
from .scoring_engine import compute_action_scores
from .xai_generator import generate_xai_explanation


def simulate(request: FinanceRequest) -> FinanceResult:
    """
    동일 입력 → 동일 출력. 비용·Expected Loss·Risk Adjusted·액션 점수·추천까지 한 번에 계산.
    """
    logger.info("시뮬레이터 실행 profile=%s severity=%s", request.profile, request.severity)
    cost_breakdown = compute_cost_breakdown(request)
    total_cost = sum(cost_breakdown.values())
    top3_drivers = sorted(
        cost_breakdown.items(), key=lambda x: -x[1]
    )[:3]

    expected_loss = calculate_expected_loss(request.severity, request.service_tier)
    risk_adjusted_loss = calculate_risk_adjusted_loss(
        expected_loss, request.regulation_weight
    )

    action_scores, recommended_action = compute_action_scores(
        total_cost, risk_adjusted_loss, request.profile
    )

    xai_explanation = generate_xai_explanation(
        request, total_cost, top3_drivers
    )

    logger.info("시뮬레이터 완료 total_cost=%.2f recommended_action=%s", total_cost, recommended_action)
    return FinanceResult(
        total_cost=total_cost,
        cost_breakdown=cost_breakdown,
        top3_drivers=top3_drivers,
        xai_explanation=xai_explanation,
        expected_loss=expected_loss,
        risk_adjusted_loss=risk_adjusted_loss,
        action_scores=action_scores,
        recommended_action=recommended_action,
    )
