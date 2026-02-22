"""Reproducibility: same request twice yields identical result dict."""

import json
from pathlib import Path

from src.engine import finance_run

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_same_request_twice_identical_result():
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        req = json.load(f)
    result1 = finance_run(req)
    result2 = finance_run(req)
    assert "error" not in result1
    assert "error" not in result2
    assert result1 == result2
