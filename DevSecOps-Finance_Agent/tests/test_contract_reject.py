"""Contract rejection: invalid duration_hours or region returns ASSUMPTION_CONTRACT_VIOLATION."""

import json
import pytest
from pathlib import Path

from src.engine import finance_run

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _load_sample():
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        return json.load(f)


def test_duration_hours_12_returns_contract_violation():
    req = _load_sample()
    req["assumptions"]["duration_hours"] = 12
    result = finance_run(req)
    assert "error" in result
    assert result["error"]["type"] == "ASSUMPTION_CONTRACT_VIOLATION"
    assert result["error"]["incident_id"] == "gd-finding-123"
    items = result["error"]["items"]
    assert any(i["field"] == "duration_hours" for i in items)


def test_region_typo_returns_contract_violation():
    req = _load_sample()
    req["assumptions"]["region"] = "ap-northeast-3"
    result = finance_run(req)
    assert "error" in result
    assert result["error"]["type"] == "ASSUMPTION_CONTRACT_VIOLATION"
    items = result["error"]["items"]
    assert any(i["field"] == "region" for i in items)
