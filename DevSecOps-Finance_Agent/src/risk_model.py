"""
Finance Agent (Week2) Expected Loss / Risk Adjusted Loss.
정책 기반, deterministic.
"""

from policy import SEVERITY_PROBABILITY, SERVICE_TIER_IMPACT


def calculate_expected_loss(severity: str, service_tier: str) -> float:
    """
    ExpectedLoss = Probability × Impact
    severity, service_tier는 policy 테이블에서 조회.
    """
    prob = SEVERITY_PROBABILITY.get(severity, 0.0)
    impact = SERVICE_TIER_IMPACT.get(service_tier, 0.0)
    return prob * impact


def calculate_risk_adjusted_loss(
    expected_loss: float, regulation_weight: float
) -> float:
    """risk_adjusted_loss = expected_loss * regulation_weight"""
    return expected_loss * regulation_weight
