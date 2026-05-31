"""
단가 소스: 정책 JSON 또는 AWS Pricing API.
Regulation Agent에서 들어온 플레이북마다 과금 계산 시, API를 매번 호출하면 비용이 들므로
리전별 단가 캐시(TTL)로 호출 횟수를 줄임.
"""
import json
import logging
import os
import time
from typing import Protocol

logger = logging.getLogger(__name__)

PRICING_KEYS = ("cloudwatch_per_gb", "s3_per_gb", "nat_egress_per_gb", "snapshot_per_gb")
_aws_pricing_cache: dict[str, tuple[dict, float]] = {}
# 호출이 자주 없으므로 기본 24시간. 7일은 PRICING_CACHE_TTL_SECONDS=604800
DEFAULT_CACHE_TTL_SECONDS = 86400


def _load_dotenv_if_present() -> None:
    try:
        from pathlib import Path
        import dotenv
        root = Path(__file__).resolve().parent.parent
        env_path = root / ".env"
        if env_path.exists():
            dotenv.load_dotenv(env_path)
    except ImportError:
        pass


def _policy_table(policy: dict) -> dict:
    out = (policy.get("pricing_table") or {}).copy()
    for k in PRICING_KEYS:
        if k not in out or not isinstance(out[k], (int, float)):
            out[k] = 0.0
    return out


def _get_cache_ttl_seconds() -> int:
    _load_dotenv_if_present()
    s = os.environ.get("PRICING_CACHE_TTL_SECONDS", "").strip()
    if not s:
        return DEFAULT_CACHE_TTL_SECONDS
    try:
        t = int(s)
        return max(60, t) if t > 0 else DEFAULT_CACHE_TTL_SECONDS
    except ValueError:
        return DEFAULT_CACHE_TTL_SECONDS


def clear_pricing_cache() -> None:
    global _aws_pricing_cache
    _aws_pricing_cache = {}


class PricingProvider(Protocol):
    def get_pricing_table(self, region: str, policy: dict) -> dict: ...


class PolicyPricingProvider:
    """정책 JSON의 pricing_table 사용. API 호출 없음."""
    def get_pricing_table(self, region: str, policy: dict) -> dict:
        return _policy_table(policy)


class BakedPricingProvider:
    """미리 조회해 둔 단가 JSON 사용. API 호출 0. PRICING_BAKED_PATH 또는 policy/pricing_baked.json."""
    def __init__(self, path: str | None = None):
        from pathlib import Path
        if path:
            self._path = Path(path)
        else:
            self._path = Path(__file__).resolve().parent.parent / "policy" / "pricing_baked.json"
        self._data: dict[str, dict] = {}
        if self._path.exists():
            try:
                with open(self._path, encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception as e:
                logger.warning("Baked pricing load failed: %s", e)

    def get_pricing_table(self, region: str, policy: dict) -> dict:
        fallback = _policy_table(policy)
        table = self._data.get(region) or self._data.get(region.replace("-", "_"))
        if not table:
            return fallback
        out = dict(fallback)
        for k in PRICING_KEYS:
            if k in table and isinstance(table[k], (int, float)):
                out[k] = float(table[k])
        return out


def _aws_location(region: str) -> str:
    m = {
        "us-east-1": "US East (N. Virginia)",
        "ap-northeast-2": "Asia Pacific (Seoul)",
        "ap-northeast-1": "Asia Pacific (Tokyo)",
        "eu-west-1": "EU (Ireland)",
    }
    return m.get(region, "US East (N. Virginia)")


def _parse_ondemand_usd(product_str: str) -> float | None:
    try:
        data = json.loads(product_str)
        terms = (data.get("terms") or {}).get("OnDemand", {})
        for tier in terms.values():
            for dim_id, dim in (tier.get("priceDimensions") or {}).items():
                price = (dim or {}).get("pricePerUnit", {}).get("USD")
                if price is not None:
                    return float(price)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return None


def _fetch_first_price(client, service_code: str, filters: list) -> float | None:
    try:
        resp = client.get_products(ServiceCode=service_code, MaxResults=1, Filters=filters)
        for item in (resp.get("PriceList") or []):
            if isinstance(item, str):
                p = _parse_ondemand_usd(item)
                if p is not None:
                    return p
    except Exception:
        pass
    return None


def _get_cloudwatch_logs_price(client, location: str) -> float | None:
    return _fetch_first_price(
        client, "AmazonCloudWatch",
        [
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Data Payload"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
        ],
    )


def _get_s3_storage_price(client, location: str) -> float | None:
    return _fetch_first_price(
        client, "AmazonS3",
        [
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Storage"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
        ],
    )


def _get_nat_egress_price(client, location: str) -> float | None:
    return _fetch_first_price(
        client, "AmazonEC2",
        [
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "NAT Gateway"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
        ],
    )


def _get_snapshot_price(client, location: str) -> float | None:
    return _fetch_first_price(
        client, "AmazonEC2",
        [
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Storage Snapshot"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
        ],
    )


class AwsPricingProvider:
    """AWS Pricing API로 단가 조회. 리전별 TTL 캐시로 호출 절감. 실패 시 정책 단가 폴백."""
    def get_pricing_table(self, region: str, policy: dict) -> dict:
        fallback = _policy_table(policy)
        try:
            import boto3
        except ImportError:
            logger.debug("boto3 not installed, using policy pricing")
            return fallback

        now = time.monotonic()
        ttl = _get_cache_ttl_seconds()
        cached = _aws_pricing_cache.get(region)
        if cached is not None:
            table, expiry = cached
            if now < expiry:
                logger.debug("Pricing cache hit region=%s", region)
                return dict(table)
        try:
            client = boto3.client("pricing", region_name="us-east-1")
            location = _aws_location(region)
            table = dict(fallback)
            for key, fetcher in [
                ("cloudwatch_per_gb", lambda: _get_cloudwatch_logs_price(client, location)),
                ("s3_per_gb", lambda: _get_s3_storage_price(client, location)),
                ("nat_egress_per_gb", lambda: _get_nat_egress_price(client, location)),
                ("snapshot_per_gb", lambda: _get_snapshot_price(client, location)),
            ]:
                v = fetcher()
                if v is not None:
                    table[key] = round(v, 4)
            result = {k: table.get(k, 0.0) for k in PRICING_KEYS}
            _aws_pricing_cache[region] = (result, now + ttl)
            logger.debug("Pricing cache set region=%s ttl=%ds", region, ttl)
            return result
        except Exception as e:
            logger.warning("AWS Pricing API fallback to policy: %s", e)
            return fallback


def get_pricing_provider() -> PricingProvider:
    _load_dotenv_if_present()
    baked_path = os.environ.get("PRICING_BAKED_PATH", "").strip()
    use_baked = os.environ.get("USE_BAKED_PRICING", "").strip().lower() in ("true", "1", "yes")
    if use_baked or baked_path:
        return BakedPricingProvider(baked_path or None)
    use_api = os.environ.get("USE_AWS_PRICING_API", "").strip().lower() in ("true", "1", "yes")
    if use_api:
        return AwsPricingProvider()
    return PolicyPricingProvider()
