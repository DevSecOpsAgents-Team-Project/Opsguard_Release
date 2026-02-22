"""
Finance Agent (Week1 + Week2) 입출력 모델.
dataclass 기반, deterministic, 재현 가능.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FinanceRequest:
    """비용 시뮬레이션 + 의사결정 입력 모델."""

    region: str
    duration_hours: int
    traffic_multiplier: float
    log_multiplier: float
    base_traffic_gb: float
    base_log_gb: float
    # Week2: 위험·정책·프로필
    severity: str  # Low / Medium / High
    service_tier: str  # S1 / S2 / S3
    regulation_weight: float  # 1.0 / 1.2 / 1.5
    profile: str  # MissionCritical / ComplianceGuard / LeanStartup / Standard


@dataclass
class FinanceResult:
    """비용 시뮬레이션 + 추천 출력."""

    total_cost: float
    cost_breakdown: dict[str, float]
    top3_drivers: list[tuple[str, float]]
    xai_explanation: str
    # Week2: Expected Loss, Risk Adjusted, 액션 점수, 추천
    expected_loss: float
    risk_adjusted_loss: float
    action_scores: dict[str, float]
    recommended_action: str
