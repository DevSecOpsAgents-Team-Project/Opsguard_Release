"""
Finance Agent 단일 진입점: 인풋아웃풋 설계(엔진) + 로직(시뮬레이터) 한 번에 실행.

- run_engine_sample(): schema 기반 (dict in/out) — validate → contract → policy → pricing
- run_simulator_demo(): dataclass 기반 (FinanceRequest → FinanceResult) — 비용/리스크/스코어/추천
- run_all(): 위 두 경로 + 재현성 검증까지 한 번에 실행.
"""

import json
import logging
from pathlib import Path

from .engine import finance_run
from .models import FinanceRequest
from .simulator import simulate
from .bridge import engine_request_to_finance_request

_SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
logger = logging.getLogger(__name__)


def _load_sample_request() -> dict:
    """샘플 JSON 요청 로드 (A/B 공통 소스)."""
    path = _SAMPLES_DIR / "finance_request.sample.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_engine_sample() -> dict:
    """샘플 JSON으로 엔진(schema 경로) 실행. 반환값은 result dict."""
    logger.info("run_engine_sample 시작 (샘플 JSON)")
    req = _load_sample_request()
    out = finance_run(req)
    logger.info("run_engine_sample 완료 error=%s", "error" in out)
    return out


def run_simulator_with_engine_request(req: dict):
    """A가 받은 요청 dict를 B용 FinanceRequest로 변환해 시뮬레이터 실행. 같은 인풋이 B에 들어감."""
    finance_req = engine_request_to_finance_request(req)
    return simulate(finance_req)


def run_simulator_demo() -> None:
    """데모: FinanceRequest → simulate → 동일 입력 재현성 + profile 변경 시 추천 변경 검증."""
    logger.info("run_simulator_demo 시작")
    request = FinanceRequest(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Medium",
        service_tier="S2",
        regulation_weight=1.2,
        profile="Standard",
    )
    result = simulate(request)
    print("=== Run 1 (profile=Standard) ===")
    print("recommended_action:", result.recommended_action)
    print("total_cost:", result.total_cost)
    print()

    result2 = simulate(request)
    assert result.recommended_action == result2.recommended_action
    print("=== Run 2 (동일 입력) === OK: 동일 recommended_action")
    print()

    low_risk = FinanceRequest(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Low",
        service_tier="S1",
        regulation_weight=1.0,
        profile="Standard",
    )
    r_std = simulate(low_risk)
    request_lean = FinanceRequest(
        region="ap-northeast-2",
        duration_hours=24,
        traffic_multiplier=1.5,
        log_multiplier=1.2,
        base_traffic_gb=50,
        base_log_gb=20,
        severity="Low",
        service_tier="S1",
        regulation_weight=1.0,
        profile="LeanStartup",
    )
    r_lean = simulate(request_lean)
    print("=== profile 변경 (Standard vs LeanStartup) ===")
    print("Standard   recommended_action:", r_std.recommended_action)
    print("LeanStartup recommended_action:", r_lean.recommended_action)
    if r_std.recommended_action != r_lean.recommended_action:
        print("OK: profile만 바꿔도 추천 결과가 달라짐")
    logger.info("run_simulator_demo 완료")


def run_all() -> None:
    """같은 요청을 A→엔진, (변환 후) B→시뮬레이터에 넣어서 한 번에 실행."""
    logger.info("run_all 시작 (엔진 + 시뮬레이터, 같은 인풋 연결)")
    req = _load_sample_request()

    print("--- [1] A (엔진) 같은 요청으로 실행 ---")
    engine_result = finance_run(req)
    if "error" in engine_result:
        print("Engine error:", engine_result["error"])
    else:
        a_cost = engine_result.get("cost_summary", {}).get("estimated_monthly_cost")
        print("Engine OK. cost_summary:", engine_result.get("cost_summary"))

    print()
    print("--- [2] B (시뮬레이터) A가 받은 요청을 FinanceRequest로 변환해 인풋으로 사용 ---")
    finance_req = engine_request_to_finance_request(req)
    sim_result = simulate(finance_req)
    print("Simulator OK. recommended_action:", sim_result.recommended_action, "total_cost:", round(sim_result.total_cost, 2))
    if "error" not in engine_result:
        print("(같은 요청: A 비용", a_cost, " vs B 비용", round(sim_result.total_cost, 2), ")")

    print()
    print("--- [3] 시뮬레이터 데모 (재현성·profile 변경) ---")
    run_simulator_demo()
    print()
    print("--- run_all 완료 ---")
    logger.info("run_all 완료")


if __name__ == "__main__":
    run_all()
