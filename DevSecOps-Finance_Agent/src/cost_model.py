"""
Finance Agent (Week1 – B) 비용 계산.
순수 Python 로직, 랜덤/전역 변수/LLM/외부 API 없음.
"""

from models import FinanceRequest

# Week1 단가 (하드코딩)
CloudWatchLogs_per_gb = 0.50
S3Storage_per_gb_hour = 0.023 / 730
VPCEgress_per_gb = 0.09


def compute_cost_breakdown(request: FinanceRequest) -> dict[str, float]:
    """
    드라이버 기반 비용 breakdown 계산.
    반환: CloudWatchLogs, VPCEgress, S3Storage 키를 가진 dict.
    """
    log_cost = (
        request.base_log_gb * request.log_multiplier * CloudWatchLogs_per_gb
    )
    traffic_cost = (
        request.base_traffic_gb
        * request.traffic_multiplier
        * VPCEgress_per_gb
    )
    storage_cost = (
        request.base_log_gb * request.duration_hours * S3Storage_per_gb_hour
    )
    return {
        "CloudWatchLogs": log_cost,
        "VPCEgress": traffic_cost,
        "S3Storage": storage_cost,
    }
