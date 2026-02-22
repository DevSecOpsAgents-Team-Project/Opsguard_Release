"""Assumption contract: normalize and validate assumptions at runtime."""

from .errors import ContractViolation

DURATION_HOURS_ALLOWED = [1, 24, 168, 720]
TRAFFIC_MULTIPLIER_ALLOWED = [1.0, 1.5, 2.0]
REGION_ALLOWED = ["ap-northeast-2", "us-east-1"]
SERVICE_TIER_ALLOWED = ["S1", "S2", "S3"]
ORG_PROFILE_ALLOWED = ["MissionCritical", "ComplianceGuard", "LeanStartup", "Standard"]


def _to_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return None
    return None


def _to_float(v):
    if isinstance(v, (int, float)):
        return round(float(v), 2)
    if isinstance(v, str):
        try:
            return round(float(v), 2)
        except ValueError:
            return None
    return None


def normalize_and_validate_assumptions(assumptions: dict) -> dict:
    """Normalize and validate assumptions. Raises ContractViolation on error.

    - duration_hours: int (string "24" allowed)
    - traffic_multiplier: float rounded to 2 decimals (string "1.5" allowed)
    - region, service_tier, org_profile: enum control

    Returns:
        Normalized assumptions dict with correct types.
    """
    errors = []
    out = {}

    # duration_hours
    v = assumptions.get("duration_hours")
    n = _to_int(v)
    if n is None or n not in DURATION_HOURS_ALLOWED:
        errors.append({
            "field": "duration_hours",
            "code": "INVALID_VALUE",
            "message": f"duration_hours must be one of {DURATION_HOURS_ALLOWED}",
            "allowed": DURATION_HOURS_ALLOWED,
        })
    else:
        out["duration_hours"] = n

    # traffic_multiplier
    v = assumptions.get("traffic_multiplier")
    f = _to_float(v)
    if f is None or f not in TRAFFIC_MULTIPLIER_ALLOWED:
        errors.append({
            "field": "traffic_multiplier",
            "code": "INVALID_VALUE",
            "message": f"traffic_multiplier must be one of {TRAFFIC_MULTIPLIER_ALLOWED}",
            "allowed": TRAFFIC_MULTIPLIER_ALLOWED,
        })
    else:
        out["traffic_multiplier"] = round(f, 2)

    # region
    r = assumptions.get("region")
    if not isinstance(r, str) or r not in REGION_ALLOWED:
        errors.append({
            "field": "region",
            "code": "INVALID_VALUE",
            "message": f"region must be one of {REGION_ALLOWED}",
            "allowed": REGION_ALLOWED,
        })
    else:
        out["region"] = r

    # service_tier
    s = assumptions.get("service_tier")
    if not isinstance(s, str) or s not in SERVICE_TIER_ALLOWED:
        errors.append({
            "field": "service_tier",
            "code": "INVALID_VALUE",
            "message": f"service_tier must be one of {SERVICE_TIER_ALLOWED}",
            "allowed": SERVICE_TIER_ALLOWED,
        })
    else:
        out["service_tier"] = s

    # org_profile
    o = assumptions.get("org_profile")
    if not isinstance(o, str) or o not in ORG_PROFILE_ALLOWED:
        errors.append({
            "field": "org_profile",
            "code": "INVALID_VALUE",
            "message": f"org_profile must be one of {ORG_PROFILE_ALLOWED}",
            "allowed": ORG_PROFILE_ALLOWED,
        })
    else:
        out["org_profile"] = o

    if errors:
        raise ContractViolation(errors)
    return out
