"""Constraints from policy only: S1 high -> isolate forbidden; S3 high -> isolate allowed."""

import json
from pathlib import Path

from src.engine import finance_run

SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"


def _load(name: str) -> dict:
    with open(SCENARIOS_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def test_s1_high_severity_isolate_forbidden():
    """S1 + High severity -> ISOLATE_INSTANCE 추천 금지 (policy constraint)."""
    req = _load("01_s1_high_forbid_isolate.json")
    result = finance_run(req)
    assert "error" not in result
    assert result.get("recommendation") != "ISOLATE_INSTANCE"
    assert "ISOLATE_INSTANCE" not in (result.get("action_scores") or {})


def test_s3_high_severity_isolate_allowed():
    """S3 + High severity -> 격리 허용 (추천 후보에 포함 가능)."""
    req = _load("03_s3_high_isolate_allowed.json")
    result = finance_run(req)
    assert "error" not in result
    assert result.get("recommendation")
    assert "ISOLATE_INSTANCE" in (result.get("action_scores") or {})
