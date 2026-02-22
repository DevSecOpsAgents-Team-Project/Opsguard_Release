"""Policy versioning: different policy version yields different total cost."""

import json
import pytest
from pathlib import Path

from src.engine import finance_run

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"


def _load_sample():
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def policy_v1_1():
    """Create policy.v1.1.json with different pricing, then remove after tests."""
    v1_0_path = POLICY_DIR / "policy.v1.0.json"
    v1_1_path = POLICY_DIR / "policy.v1.1.json"
    with open(v1_0_path, encoding="utf-8") as f:
        policy = json.load(f)
    policy["policy_version"] = "v1.1"
    policy["approved_at"] = "2026-02-16"
    policy["pricing_table"]["cloudwatch_per_gb"] = 1.0
    with open(v1_1_path, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
    yield
    if v1_1_path.exists():
        v1_1_path.unlink()


def test_v1_0_vs_v1_1_different_cost(policy_v1_1):
    req = _load_sample()
    req["policy_version"] = "v1.0"
    result_v10 = finance_run(req)
    req["policy_version"] = "v1.1"
    result_v11 = finance_run(req)
    assert "error" not in result_v10
    assert "error" not in result_v11
    total_v10 = result_v10["cost_summary"]["estimated_monthly_cost"]
    total_v11 = result_v11["cost_summary"]["estimated_monthly_cost"]
    assert total_v10 != total_v11
