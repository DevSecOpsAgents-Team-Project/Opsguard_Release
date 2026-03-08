"""회귀 시나리오 테스트: 정책 제약·regulation weight·격리 추천 포함/미포함."""

import json
from pathlib import Path

from src.engine import finance_run

SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"


def _load(name: str) -> dict:
    with open(SCENARIOS_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def test_01_s1_high_forbid_isolate():
    """S1 + High severity -> ISOLATE_INSTANCE 추천 금지 (constraints)."""
    req = _load("01_s1_high_forbid_isolate.json")
    result = finance_run(req)
    assert "error" not in result
    assert result.get("recommendation") != "ISOLATE_INSTANCE"
    assert result.get("policy_hash")


def test_02_s1_high_allow_isolate_standby():
    """S1 + High + allow_isolate_standby -> 격리 허용 (추천 가능)."""
    req = _load("02_s1_high_allow_isolate_standby.json")
    result = finance_run(req)
    assert "error" not in result
    assert result.get("recommendation")
    assert result["recommendation"] in result.get("action_scores", {})


def test_03_s3_high_isolate_allowed():
    """S3 + High -> 격리 추천 가능 (제약 없음)."""
    req = _load("03_s3_high_isolate_allowed.json")
    result = finance_run(req)
    assert "error" not in result
    assert result.get("recommendation")
    scores = result.get("action_scores", {})
    assert "ISOLATE_INSTANCE" in scores


def test_04_s3_high_strict_audit():
    """S3 + High + strict -> policy_hash, applied_regulation_weights 반영."""
    req = _load("04_s3_high_strict_audit.json")
    result = finance_run(req)
    assert "error" not in result
    assert result.get("policy_hash")
    assert result.get("applied_regulation_weights")
    assert result.get("recommendation")
    top_actions = sorted(result.get("action_scores", {}).items(), key=lambda x: -x[1])[:3]
    action_ids = [a[0] for a in top_actions]
    assert "LOG_PRESERVE" in result.get("action_scores", {}) or "ISOLATE_INSTANCE" in result.get("action_scores", {})


def test_05_06_regulation_weight_changes_recommendation():
    """regulation weight_profile relaxed vs strict -> 적용 가중치/추천 변화."""
    relaxed = _load("05_regulation_relaxed_vs_strict.json")
    strict_req = _load("06_regulation_strict_access.json")
    r_relaxed = finance_run(relaxed)
    r_strict = finance_run(strict_req)
    assert "error" not in r_relaxed and "error" not in r_strict
    assert r_relaxed.get("applied_regulation_weights") != r_strict.get("applied_regulation_weights")
    assert r_relaxed.get("recommendation") and r_strict.get("recommendation")
