"""
Finance Agent (Week2) 정책 테이블.
확률·영향·프로필 가중치만 여기에 정의. 하드코딩은 이 모듈에만 허용.
"""

# Severity → Probability
SEVERITY_PROBABILITY: dict[str, float] = {
    "Low": 0.05,
    "Medium": 0.15,
    "High": 0.35,
}

# Service Tier → Impact
SERVICE_TIER_IMPACT: dict[str, float] = {
    "S1": 10.0,
    "S2": 50.0,
    "S3": 200.0,
}

# Profile별 가중치 (cost, risk, availability)
PROFILE_WEIGHTS: dict[str, dict[str, float]] = {
    "MissionCritical": {"cost": 0.2, "risk": 0.3, "availability": 0.5},
    "ComplianceGuard": {"cost": 0.2, "risk": 0.5, "availability": 0.3},
    "LeanStartup": {"cost": 0.6, "risk": 0.3, "availability": 0.1},
    "Standard": {"cost": 0.33, "risk": 0.33, "availability": 0.34},
}
