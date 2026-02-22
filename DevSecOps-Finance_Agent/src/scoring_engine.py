"""
Finance Agent (Week2) Weighted Decision Score 계산.
profile 가중치로 cost/risk/availability 반영, 최적 대응안 선택.
"""

from .actions import get_actions
from .policy import PROFILE_WEIGHTS


def compute_action_scores(
    base_cost: float,
    risk_adjusted_loss: float,
    profile: str,
) -> tuple[dict[str, float], str]:
    """
    각 대응안에 대해 DecisionScore 계산 후 action_scores, recommended_action 반환.
    """
    weights = PROFILE_WEIGHTS.get(
        profile,
        PROFILE_WEIGHTS["Standard"],
    )
    w_cost = weights["cost"]
    w_risk = weights["risk"]
    w_availability = weights["availability"]

    actions = get_actions()
    scores: dict[str, float] = {}

    for action_id, spec in actions.items():
        cost_mult = spec["cost_multiplier"]
        risk_reduction_rate = spec["risk_reduction_rate"]
        availability_impact = spec["availability_impact"]

        adjusted_cost = base_cost * cost_mult
        normalized_cost = 1.0 / (1.0 + adjusted_cost)
        risk_reduction_score = risk_adjusted_loss * risk_reduction_rate
        availability_penalty = availability_impact

        decision_score = (
            w_cost * normalized_cost
            + w_risk * risk_reduction_score
            - w_availability * availability_penalty
        )
        scores[action_id] = decision_score

    recommended = max(scores.items(), key=lambda x: x[1])[0]
    return scores, recommended
