"""Schema validation: request, result, audit record (optional output schema)."""

import json
import os
import pytest
from pathlib import Path

from src.validate import validate_request, validate_result, validate_audit_record
from src.engine import finance_run
from src.audit import build_audit_record

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_sample_request_passes_schema():
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        req = json.load(f)
    validate_request(req)


def test_engine_output_passes_result_schema():
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        req = json.load(f)
    result = finance_run(req)
    assert "error" not in result
    validate_result(result)


def test_result_without_xai_passes_schema():
    """Result without xai field must still validate (xai is optional)."""
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        req = json.load(f)
    result = finance_run(req)
    assert "error" not in result
    assert "xai" not in result
    assert "xai_schema_version" not in result
    validate_result(result)


def test_audit_record_passes_audit_schema():
    """Built audit record validates against audit_record.schema.json."""
    request = {"incident_id": "t1", "policy_version": "v1.0.0"}
    result = {"policy_version": "v1.0.0", "assumption_hash": "a" * 64, "top3_drivers": ["d1", "d2", "d3"]}
    record = build_audit_record(
        request,
        result,
        policy_hash="b" * 64,
        assumption_hash="a" * 64,
        top_actions=[{"action_id": "A1", "rank": 1, "score": 0.5}],
        forbidden_actions=[{"action_id": "A2", "constraint_id": "c1", "reason_code": "R1"}],
    )
    validate_audit_record(record)
