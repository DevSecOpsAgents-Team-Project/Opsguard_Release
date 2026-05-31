"""Audit record type. All fields required by 3주차 A파트."""

from dataclasses import dataclass
from typing import Any

AUDIT_ENGINE_VERSION = "3.0.0"


@dataclass
class AuditRecord:
    """Single audit entry per engine run."""

    audit_id: str
    created_at: str  # ISO-8601 UTC
    engine_version: str
    policy_version: str
    policy_hash: str
    assumption_hash: str
    request: dict[str, Any]
    scores: dict[str, Any]  # impact_breakdown, likelihood, regulatory_component, profile_applied, final_score
    recommendations: dict[str, Any]  # top_actions, forbidden_actions
    insights: dict[str, list]  # top_drivers, sensitivity, tradeoffs (B파트 대비 빈 배열)

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "engine_version": self.engine_version,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "assumption_hash": self.assumption_hash,
            "request": self.request,
            "scores": self.scores,
            "recommendations": self.recommendations,
            "insights": self.insights,
        }
