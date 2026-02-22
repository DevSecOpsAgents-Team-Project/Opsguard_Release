"""Schema validation: request sample passes, engine result passes, result without xai passes."""

import json
import pytest
from pathlib import Path

from src.validate import validate_request, validate_result
from src.engine import finance_run

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
