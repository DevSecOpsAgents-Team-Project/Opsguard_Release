"""A 요청이 B 인풋으로 잘 들어가는지 검증 (bridge)."""

import json
from pathlib import Path

from src.bridge import engine_request_to_finance_request
from src.engine import finance_run
from src.simulator import simulate

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_same_request_to_engine_and_simulator():
    """같은 샘플 요청을 A(엔진)와 B(시뮬레이터) 둘 다에 넣을 수 있고, B는 변환된 FinanceRequest로 정상 실행된다."""
    with open(SAMPLES_DIR / "finance_request.sample.json", encoding="utf-8") as f:
        req = json.load(f)

    engine_result = finance_run(req)
    assert "error" not in engine_result

    finance_req = engine_request_to_finance_request(req)
    assert finance_req.region == req["assumptions"]["region"]
    assert finance_req.service_tier == req["assumptions"]["service_tier"]
    assert finance_req.profile == req["assumptions"]["org_profile"]

    sim_result = simulate(finance_req)
    assert sim_result.recommended_action
    assert sim_result.total_cost >= 0
