"""
Finance Agent (Week2) 대응안 후보 정의.
각 액션: cost_multiplier, risk_reduction_rate, availability_impact.
"""

from typing import TypedDict


class ActionSpec(TypedDict):
    cost_multiplier: float
    risk_reduction_rate: float
    availability_impact: float


# 대응안 ID → 속성 (고정 값)
ACTIONS: dict[str, ActionSpec] = {
    "observe_only": {
        "cost_multiplier": 1.0,
        "risk_reduction_rate": 0.1,
        "availability_impact": 0.0,
    },
    "log_harden": {
        "cost_multiplier": 1.2,
        "risk_reduction_rate": 0.3,
        "availability_impact": 0.1,
    },
    "snapshot_only": {
        "cost_multiplier": 1.4,
        "risk_reduction_rate": 0.5,
        "availability_impact": 0.2,
    },
    "isolate": {
        "cost_multiplier": 1.6,
        "risk_reduction_rate": 0.8,
        "availability_impact": 0.7,
    },
}


def get_actions() -> dict[str, ActionSpec]:
    """모든 대응안 사양 반환. deterministic."""
    return dict(ACTIONS)
