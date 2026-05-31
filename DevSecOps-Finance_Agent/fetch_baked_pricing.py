"""
한 번 실행해서 policy/pricing_baked.json 생성. 이후 USE_BAKED_PRICING=true 로 사용하면 API 호출 0.
사용: python fetch_baked_pricing.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.pricing_provider import (
    _aws_location,
    _get_cloudwatch_logs_price,
    _get_s3_storage_price,
    _get_nat_egress_price,
    _get_snapshot_price,
    PRICING_KEYS,
)

REGIONS = ["us-east-1", "ap-northeast-2", "ap-northeast-1"]


def main():
    try:
        import boto3
    except ImportError:
        print("boto3 필요: pip install boto3")
        return 1
    client = boto3.client("pricing", region_name="us-east-1")
    out = {}
    for region in REGIONS:
        location = _aws_location(region)
        table = {}
        for key, fetcher in [
            ("cloudwatch_per_gb", lambda: _get_cloudwatch_logs_price(client, location)),
            ("s3_per_gb", lambda: _get_s3_storage_price(client, location)),
            ("nat_egress_per_gb", lambda: _get_nat_egress_price(client, location)),
            ("snapshot_per_gb", lambda: _get_snapshot_price(client, location)),
        ]:
            v = fetcher()
            table[key] = round(v, 4) if v is not None else 0.0
        out[region] = table
        print(region, table)
    path = ROOT / "policy" / "pricing_baked.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("저장:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
