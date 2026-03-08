"""
Action scoring from policy only: action_catalog, profile_weights. Recommendation constraints applied.
Only action_ids present in action_catalog may be recommended.
"""

from .recommendation_constraints import evaluate_constraints


def compute_action_scores(
    base_cost: float,
    risk_adjusted_loss: float,
    profile: str,
    policy_bundle: dict,
    scenario_class: str,
    severity: str,
    context: dict | None = None,
) -> tuple[dict[str, float], str, list]:
    """
    Score only actions in policy action_catalog; apply recommendation_constraints to forbid some.
    Returns (action_scores, recommended_action_id, forbidden_actions_list).
    forbidden_actions_list: [{"action_id", "constraint_id", "reason_code"}].
    """
    catalog = (policy_bundle.get("action_catalog") or {}).get("actions") or {}
    profile_weights = policy_bundle.get("profile_weights") or {}
    weights = profile_weights.get(profile) or profile_weights.get("Standard") or profile_weights.get("Default") or {"cost": 0.33, "risk": 0.33, "availability": 0.34}
    w_cost = weights.get("cost", 0.33)
    w_risk = weights.get("risk", 0.33)
    w_availability = weights.get("availability", 0.34)

    ctx = {"scenario_class": scenario_class, "severity": severity, **(context or {})}
    forbidden_list, forbidden = evaluate_constraints(
        ctx,
        policy_bundle.get("recommendation_constraints") or {},
    )

    scores: dict[str, float] = {}
    for action_id, spec in catalog.items():
        if action_id in forbidden:
            continue
        if not isinstance(spec, dict):
            continue
        cost_mult = spec.get("cost_multiplier", 1.0)
        risk_reduction_rate = spec.get("risk_reduction_rate", 0.0)
        availability_impact = spec.get("availability_impact", 0.0)

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

    if not scores:
        return {}, "", forbidden_list
    recommended = max(scores.items(), key=lambda x: x[1])[0]
    return scores, recommended, forbidden_list
