"""Build one audit record from request, result, and context."""

import uuid
from datetime import datetime, timezone

from .types import AuditRecord, AUDIT_ENGINE_VERSION


def build_audit_record(
    request: dict,
    result: dict,
    *,
    policy_hash: str = "",
    assumption_hash: str = "",
    impact_breakdown: dict | None = None,
    likelihood: float = 0.0,
    regulatory_component: float = 0.0,
    profile_applied: str = "",
    final_score: float = 0.0,
    top_actions: list | None = None,
    forbidden_actions: list | None = None,
    top3_drivers: list | None = None,
) -> dict:
    """
    Build audit dict. Same input + same policy_version => same content (created_at/audit_id excepted).
    """
    policy_version = result.get("policy_version", request.get("policy_version", ""))
    top_actions = top_actions or []
    forbidden_actions = forbidden_actions or []
    impact_breakdown = impact_breakdown or {}
    top3_drivers = top3_drivers or result.get("top3_drivers", [])

    scores = {
        "impact_breakdown": impact_breakdown,
        "likelihood": likelihood,
        "regulatory_component": regulatory_component,
        "profile_applied": profile_applied,
        "final_score": final_score,
    }
    recommendations = {
        "top_actions": top_actions,
        "forbidden_actions": forbidden_actions,
    }
    insights = {
        "top_drivers": list(top3_drivers),
        "sensitivity": [],
        "tradeoffs": [],
    }

    rec = AuditRecord(
        audit_id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        engine_version=AUDIT_ENGINE_VERSION,
        policy_version=policy_version,
        policy_hash=policy_hash,
        assumption_hash=assumption_hash or result.get("assumption_hash", ""),
        request=request,
        scores=scores,
        recommendations=recommendations,
        insights=insights,
    )
    return rec.to_dict()
