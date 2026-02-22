"""
A(엔진) 요청/결과와 B(시뮬레이터) 입출력 연결.

- engine_request_to_finance_request: A가 받는 dict 요청 → B가 받는 FinanceRequest 변환
  (같은 요청이 A와 B 둘 다에 들어가도록)
- A 결과는 스키마/정책 기반 비용, B 결과는 dataclass 기반 비용+추천이라
  동일 요청에 대해 둘 다 돌려서 비교할 수 있음.
"""

from .models import FinanceRequest


def engine_request_to_finance_request(req: dict) -> FinanceRequest:
    """엔진용 요청 dict를 시뮬레이터용 FinanceRequest로 변환.

    A 스키마: assumptions (duration_hours, traffic_multiplier, region, service_tier, org_profile),
             resource_change (cloudwatch_log_gb_per_day, s3_storage_gb, nat_egress_gb, snapshot_gb).
    B 모델: region, duration_hours, traffic_multiplier, log_multiplier, base_traffic_gb, base_log_gb,
           severity, service_tier, regulation_weight, profile.

    A에 없는 필드는 기본값 사용 (severity=Medium, regulation_weight=1.2, log_multiplier=traffic_multiplier,
    base_traffic_gb=nat_egress_gb, base_log_gb=cloudwatch_log_gb_per_day * 24 등).
    """
    a = req.get("assumptions", {})
    r = req.get("resource_change", {})

    def _num(v, default: float):
        if v is None:
            return default
        try:
            return float(v) if isinstance(v, (int, float)) else float(v)
        except (TypeError, ValueError):
            return default

    def _int(v, default: int):
        if v is None:
            return default
        try:
            return int(v) if isinstance(v, (int, float)) else int(float(v))
        except (TypeError, ValueError):
            return default

    duration_hours = _int(a.get("duration_hours"), 24)
    traffic_multiplier = _num(a.get("traffic_multiplier"), 1.0)
    region = (a.get("region") or "ap-northeast-2").strip()
    service_tier = (a.get("service_tier") or "S1").strip()
    profile = (a.get("org_profile") or "Standard").strip()

    cloudwatch_per_day = _num(r.get("cloudwatch_log_gb_per_day"), 10.0)
    nat_egress_gb = _num(r.get("nat_egress_gb"), 5.0)

    return FinanceRequest(
        region=region,
        duration_hours=duration_hours,
        traffic_multiplier=traffic_multiplier,
        log_multiplier=traffic_multiplier,
        base_traffic_gb=nat_egress_gb,
        base_log_gb=cloudwatch_per_day * 24,
        severity="Medium",
        service_tier=service_tier,
        regulation_weight=1.2,
        profile=profile,
    )
