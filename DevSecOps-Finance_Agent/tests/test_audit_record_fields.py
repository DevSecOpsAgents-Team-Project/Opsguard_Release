"""Audit record: 1 record per run, required fields present."""

import json
import os
from pathlib import Path

import pytest

from src.engine import finance_run
from src.audit import build_audit_record, append_audit_record

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"


def _load_sample():
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        return json.load(f)


def test_audit_record_has_required_fields(tmp_path):
    """엔진 1회 실행 후 audit 파일에 1줄, 필수 필드 존재."""
    os.environ["AUDIT_LOG_PATH"] = str(tmp_path / "audit.jsonl")
    try:
        req = _load_sample()
        result = finance_run(req)
        assert "error" not in result
    finally:
        os.environ.pop("AUDIT_LOG_PATH", None)

    path = tmp_path / "audit.jsonl"
    assert path.exists()
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) >= 1
    record = json.loads(lines[-1])

    assert "audit_id" in record
    assert "created_at" in record
    assert "engine_version" in record
    assert "policy_version" in record
    assert "policy_hash" in record
    assert "assumption_hash" in record
    assert "request" in record
    assert "scores" in record
    assert "recommendations" in record
    assert "insights" in record

    scores = record["scores"]
    assert "impact_breakdown" in scores
    assert "likelihood" in scores
    assert "regulatory_component" in scores
    assert "profile_applied" in scores
    assert "final_score" in scores

    recs = record["recommendations"]
    assert "top_actions" in recs
    assert "forbidden_actions" in recs

    insights = record["insights"]
    assert "top_drivers" in insights
    assert "sensitivity" in insights
    assert "tradeoffs" in insights


def test_build_audit_record_structure():
    """build_audit_record returns dict with required shape."""
    request = {"incident_id": "t1", "policy_version": "v1.0.0", "assumptions": {}}
    result = {"policy_version": "v1.0.0", "assumption_hash": "a" * 64, "top3_drivers": ["a", "b", "c"]}
    record = build_audit_record(
        request,
        result,
        policy_hash="h" * 64,
        assumption_hash="a" * 64,
        top_actions=[{"action_id": "X", "rank": 1, "score": 1.0}],
        forbidden_actions=[{"action_id": "Y", "constraint_id": "c1", "reason_code": "R1"}],
    )
    assert record["audit_id"]
    assert record["created_at"]
    assert record["engine_version"]
    assert record["policy_version"] == "v1.0.0"
    assert record["policy_hash"] == "h" * 64
    assert record["recommendations"]["top_actions"]
    assert record["recommendations"]["forbidden_actions"]
    assert record["insights"]["top_drivers"] == ["a", "b", "c"]
    assert record["insights"]["sensitivity"] == []
    assert record["insights"]["tradeoffs"] == []
