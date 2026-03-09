"""
Advanced explainable validation script for Finance Agent recommendation flow.

- Baseline finance_run() execution
- Cross-comparison: 3 playbook mocks x 3 user responses = 9 test cases
- PASS/FAIL validation with explanation hints
- Safe LLM execution with rule-based fallback
- Structured XAI output: decision_trace, decision_factors, cost_comparison,
  candidate_summary, applied_rules, confidence_hint

Compatible with: finance_run, get_simulation_recommendation_for_mcp.
Do not modify src/ modules.
Run: python run_mocks_advanced.py
"""
import io
import json
import sys
from pathlib import Path

# Force UTF-8 stdout (Windows etc.)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
try:
    import dotenv
    dotenv.load_dotenv(ROOT / ".env")
except ImportError:
    pass

from src.engine import finance_run
from src.simulation_questions import get_simulation_recommendation_for_mcp

from run_mocks import (
    INPUT_FINANCE_REQUEST,
    USER_RESPONSES,
    PLAYBOOK_MOCKS,
)

# Expected recommendation level by user priority (for PASS/FAIL validation)
EXPECTED_LEVELS = {
    "security": 3,
    "balanced": 2,
    "cost": 2,
}

# Deterministic rule identifiers for auditability
RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT = "RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT"
RULE_PRODUCTION_PII_SECURITY_FORCE_L3 = "RULE_PRODUCTION_PII_SECURITY_FORCE_L3"
RULE_COST_PRIORITY_SELECT_LOWEST_COST = "RULE_COST_PRIORITY_SELECT_LOWEST_COST"
RULE_FALLBACK_LOWEST_COST = "RULE_FALLBACK_LOWEST_COST"

# Output file for optional persistence of all test results
RESULTS_OUTPUT_FILE = "mock_test_results_advanced.json"
RESULTS_OUTPUT_FILE_V2 = "mock_test_results_advanced_v2.json"


def normalize_playbooks(playbooks: list) -> list[dict]:
    """
    Safely extract level, playbook_name, estimated_monthly_cost, expected_impact
    from each candidate. Returns list of normalized candidate dicts.
    """
    out = []
    for p in playbooks or []:
        cost_summary = p.get("cost_summary") or {}
        out.append({
            "level": p.get("level"),
            "playbook_name": p.get("playbook_name", ""),
            "estimated_monthly_cost": cost_summary.get("estimated_monthly_cost"),
            "expected_impact": (p.get("expected_impact") or "").upper() or "UNKNOWN",
        })
    return out


def select_lowest_cost_playbook(normalized_playbooks: list[dict]) -> dict | None:
    """Return the normalized playbook with the lowest estimated_monthly_cost."""
    if not normalized_playbooks:
        return None
    return min(
        normalized_playbooks,
        key=lambda x: x.get("estimated_monthly_cost") if x.get("estimated_monthly_cost") is not None else float("inf"),
    )


def run_baseline_finance() -> None:
    """Run finance_run once; print cost_summary and top3_drivers (deterministic check)."""
    print("=== BASELINE FINANCE ENGINE RESULT ===")
    r = finance_run(INPUT_FINANCE_REQUEST)
    if "error" in r:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return
    print("cost_summary:", json.dumps(r.get("cost_summary", {}), ensure_ascii=False))
    print("top3_drivers:", r.get("top3_drivers", []))
    print()


def build_excluded_candidates_summary(
    excluded: list[dict], reason_template: str = "HIGH impact excluded due to downtime_tolerance=not_allowed"
) -> list[dict]:
    """Build xai.excluded_candidates list from excluded normalized playbooks."""
    return [
        {
            "level": p.get("level"),
            "playbook_name": p.get("playbook_name", ""),
            "reason": reason_template,
        }
        for p in excluded
    ]


# 규칙별 사용자용 설명 (감사/디버깅용). rule-based 시 reason은 "rule_based_decision" 고정 반환.
RULE_REASON_MESSAGES = {
    RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT: "서비스 중단이 불가한 설정이므로 고영향(HIGH) 플레이북을 제외한 뒤, 남은 후보 중에서 선택했습니다.",
    RULE_PRODUCTION_PII_SECURITY_FORCE_L3: "운영 환경이 프로덕션이고 PII 데이터이며 보안을 우선하므로, Level 3 이상의 강력한 대응 플레이북을 추천했습니다.",
    RULE_COST_PRIORITY_SELECT_LOWEST_COST: "비용 우선 설정에 따라 예상 비용이 가장 낮은 플레이북을 추천했습니다.",
    RULE_FALLBACK_LOWEST_COST: "기본 규칙에 따라 예상 비용이 가장 낮은 플레이북을 추천했습니다.",
}


def _template_reason(
    user_response: dict,
    level: int | None,
    playbook_name: str,
    estimated_monthly_cost: int | float | None,
) -> str:
    """run_mocks / simulation_questions와 동일한 reason 형식: 사용자 선택 + 예상 비용 반영 문장."""
    env = user_response.get("environment", "")
    data_sens = user_response.get("data_sensitivity", "")
    downtime = user_response.get("downtime_tolerance", "")
    priority = user_response.get("priority", "")
    cost_str = f"{estimated_monthly_cost} USD" if estimated_monthly_cost is not None else "알 수 없음"
    return (
        f"사용자 선택(환경={env}, 데이터민감도={data_sens}, 중단허용={downtime}, 우선순위={priority})과 "
        f"예상 비용({cost_str})을 반영하여 L{level} ({playbook_name})를 추천합니다."
    )


def _rule_based_reason(applied_rules: list[str]) -> str:
    """applied_rules를 사용자용 한글 설명으로 변환. 규칙이 없으면 기본 문구 반환. (폴백용)"""
    if not applied_rules:
        return "규칙에 따라 자동 추천되었습니다."
    parts = [RULE_REASON_MESSAGES[r] for r in applied_rules if r in RULE_REASON_MESSAGES]
    return " ".join(parts) if parts else "규칙에 따라 자동 추천되었습니다."


def rule_based_recommendation(playbooks: list, user_response: dict) -> dict | None:
    """
    Deterministic rule filter before LLM.
    Returns { recommended_level, playbook_name, reason, applied_rules, rule_metadata } or None.
    rule_metadata: { original_candidates, excluded_candidates, remaining_candidates, filtering_occurred }.
    """
    if not playbooks:
        return None
    normalized = normalize_playbooks(playbooks)
    downtime = user_response.get("downtime_tolerance", "")
    environment = user_response.get("environment", "")
    data_sensitivity = user_response.get("data_sensitivity", "")
    priority = user_response.get("priority", "")

    candidates = list(normalized)
    applied_rules: list[str] = []
    excluded_candidates: list[dict] = []
    filtering_occurred = False

    # Rule 1: exclude HIGH impact when downtime not allowed
    if downtime == "not_allowed":
        excluded_candidates = [p for p in candidates if (p.get("expected_impact") or "") == "HIGH"]
        candidates = [p for p in candidates if (p.get("expected_impact") or "") != "HIGH"]
        if not candidates:
            return None
        filtering_occurred = True
        applied_rules.append(RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT)

    rule_metadata = {
        "original_candidates": list(normalized),
        "excluded_candidates": excluded_candidates,
        "remaining_candidates": list(candidates),
        "filtering_occurred": filtering_occurred,
    }

    # Rule 2: production + pii + security -> force level >= 3
    if environment == "production" and data_sensitivity == "pii" and priority == "security":
        level_3_plus = [p for p in candidates if (p.get("level") or 0) >= 3]
        chosen = max(level_3_plus or candidates, key=lambda p: p.get("level") or 0)
        applied_rules.append(RULE_PRODUCTION_PII_SECURITY_FORCE_L3)
        return {
            "recommended_level": chosen.get("level"),
            "playbook_name": chosen.get("playbook_name", ""),
            "reason": "rule_based_decision",
            "applied_rules": list(applied_rules),
            "rule_metadata": rule_metadata,
        }

    # Rule 3: cost priority -> lowest cost (within candidates)
    if priority == "cost":
        chosen = select_lowest_cost_playbook(candidates)
        if chosen:
            applied_rules.append(RULE_COST_PRIORITY_SELECT_LOWEST_COST)
            return {
                "recommended_level": chosen.get("level"),
                "playbook_name": chosen.get("playbook_name", ""),
                "reason": "rule_based_decision",
                "applied_rules": list(applied_rules),
                "rule_metadata": rule_metadata,
            }

    # Rule 1 only (downtime not allowed, we filtered): pick lowest cost from remaining
    if downtime == "not_allowed" and len(candidates) < len(normalized):
        chosen = select_lowest_cost_playbook(candidates)
        if chosen:
            return {
                "recommended_level": chosen.get("level"),
                "playbook_name": chosen.get("playbook_name", ""),
                "reason": "rule_based_decision",
                "applied_rules": list(applied_rules),
                "rule_metadata": rule_metadata,
            }

    return None


def build_decision_trace(
    playbooks: list,
    user_response: dict,
    selected_playbook: dict,
    source: str,
    applied_rules: list | None = None,
    rule_metadata: dict | None = None,
    reason_alignment_warning: bool = False,
) -> list[str]:
    """
    Step-by-step trace of how the recommendation was formed.
    When rule_metadata has filtering_occurred, show original -> excluded -> remaining -> selection.
    """
    trace = []
    priority = user_response.get("priority", "")
    env = user_response.get("environment", "")
    data_sens = user_response.get("data_sensitivity", "")
    downtime = user_response.get("downtime_tolerance", "")

    trace.append(f"Input priority is {priority}")
    trace.append(f"Environment is {env}")
    trace.append(f"Data sensitivity is {data_sens}")
    trace.append(f"Downtime tolerance is {downtime}")

    meta = rule_metadata or {}
    original = meta.get("original_candidates") or normalize_playbooks(playbooks)
    excluded = meta.get("excluded_candidates", [])
    remaining = meta.get("remaining_candidates", [])
    filtering_occurred = meta.get("filtering_occurred", False)

    if filtering_occurred and (original or excluded or remaining):
        for p in original:
            cost = p.get("estimated_monthly_cost")
            cost_str = f"{cost} USD" if cost is not None else "N/A"
            trace.append(
                f"Original candidate L{p.get('level')} {p.get('playbook_name', '')} cost = {cost_str}, impact = {p.get('expected_impact', '')}"
            )
        for rule in applied_rules or []:
            if rule == RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT:
                trace.append(f"Applied rule {rule}")
                for p in excluded:
                    trace.append(
                        f"Excluded candidate L{p.get('level')} {p.get('playbook_name', '')} because impact is HIGH"
                    )
                if remaining:
                    names = ", ".join(f"L{p.get('level')} {p.get('playbook_name', '')}" for p in remaining)
                    trace.append(f"Remaining candidates: {names}")
                break
        if priority == "cost" and RULE_COST_PRIORITY_SELECT_LOWEST_COST in (applied_rules or []):
            trace.append(f"Applied rule {RULE_COST_PRIORITY_SELECT_LOWEST_COST} within remaining candidates")
    else:
        for p in original:
            cost = p.get("estimated_monthly_cost")
            cost_str = f"{cost} USD" if cost is not None else "N/A"
            trace.append(
                f"Candidate L{p.get('level')} {p.get('playbook_name', '')} cost = {cost_str}, impact = {p.get('expected_impact', '')}"
            )
        if env == "production" and data_sens == "pii" and priority == "security":
            trace.append("Production + pii + security triggers stronger control preference")
        if priority == "cost" and not filtering_occurred:
            trace.append("Cost priority: lowest cost candidate preferred")

    level = selected_playbook.get("recommended_level") or selected_playbook.get("level")
    name = selected_playbook.get("playbook_name", "")
    trace.append(f"Selected L{level} playbook: {name}")
    if reason_alignment_warning:
        trace.append("Warning: explanation text may not match the selected playbook")
    return trace


def build_decision_factors(
    playbooks: list,
    user_response: dict,
    selected_playbook: dict,
    rule_metadata: dict | None = None,
) -> dict:
    """Structured dict showing which inputs influenced the decision (system-level explainability)."""
    normalized = normalize_playbooks(playbooks)
    selected_level = selected_playbook.get("recommended_level") or selected_playbook.get("level")
    selected_name = selected_playbook.get("playbook_name", "")
    selected_cost = None
    selected_impact = None
    for p in normalized:
        if (p.get("level") == selected_level and p.get("playbook_name") == selected_name) or (
            not selected_cost and p.get("playbook_name") == selected_name
        ):
            selected_cost = p.get("estimated_monthly_cost")
            selected_impact = p.get("expected_impact")
            break

    env = user_response.get("environment", "")
    data_sens = user_response.get("data_sensitivity", "")
    downtime = user_response.get("downtime_tolerance", "")
    priority = user_response.get("priority", "")
    meta = rule_metadata or {}
    filtering_occurred = meta.get("filtering_occurred", False)

    return {
        "environment": env,
        "data_sensitivity": data_sens,
        "downtime_tolerance": downtime,
        "priority": priority,
        "selected_level": selected_level,
        "selected_cost": selected_cost,
        "selected_impact": selected_impact,
        "cost_preference_active": priority == "cost",
        "security_preference_active": priority == "security",
        "downtime_constraint_active": downtime == "not_allowed",
        "production_sensitive_context": env == "production" and data_sens == "pii",
        "selected_from_remaining_candidates": filtering_occurred,
    }


def build_cost_comparison(playbooks: list) -> dict:
    """
    Summarize all candidates with cost/impact.
    lowest_cost_level / highest_cost_level are derived from actual cost values (min/max estimated_monthly_cost).
    """
    normalized = normalize_playbooks(playbooks)
    candidates = [
        {
            "level": p.get("level"),
            "playbook_name": p.get("playbook_name", ""),
            "estimated_monthly_cost": p.get("estimated_monthly_cost"),
            "expected_impact": p.get("expected_impact", ""),
        }
        for p in normalized
    ]
    valid = [p for p in normalized if p.get("estimated_monthly_cost") is not None]
    if not valid:
        return {
            "candidates": candidates,
            "lowest_cost_level": None,
            "highest_cost_level": None,
            "lowest_cost_playbook_name": "",
            "highest_cost_playbook_name": "",
            "cost_gap": 0,
        }
    by_cost_min = min(valid, key=lambda x: x.get("estimated_monthly_cost") or float("inf"))
    by_cost_max = max(valid, key=lambda x: x.get("estimated_monthly_cost") or float("-inf"))
    costs = [p.get("estimated_monthly_cost") for p in valid]
    cost_gap = (max(costs) - min(costs)) if len(costs) >= 2 else 0.0
    return {
        "candidates": candidates,
        "lowest_cost_level": by_cost_min.get("level"),
        "highest_cost_level": by_cost_max.get("level"),
        "lowest_cost_playbook_name": by_cost_min.get("playbook_name", ""),
        "highest_cost_playbook_name": by_cost_max.get("playbook_name", ""),
        "cost_gap": round(cost_gap, 2),
    }


def build_candidate_summary(playbooks: list) -> list[str]:
    """Concise per-candidate summary strings for each playbook option."""
    normalized = normalize_playbooks(playbooks)
    return [
        f"L{p.get('level')} / {p.get('playbook_name', '')} / cost={p.get('estimated_monthly_cost')} / impact={p.get('expected_impact', '')}"
        for p in normalized
    ]


def extract_candidate_names(all_candidates: list[dict]) -> list[str]:
    """Extract playbook_name from each candidate for reason-alignment checks."""
    return [str(p.get("playbook_name", "")).strip() for p in (all_candidates or []) if p.get("playbook_name")]


def validate_reason_alignment(
    selected_playbook: dict,
    reason_text: str,
    all_candidates: list[dict],
) -> dict:
    """
    Check whether the explanation text is aligned with the selected playbook.
    Returns { "aligned": bool, "hint": str }.
    Skip check for rule-based reasons (고정 문구) or very short reasons (no LLM explanation to validate).
    """
    selected_name = (selected_playbook.get("playbook_name") or "").strip()
    reason = (reason_text or "").strip()
    if not selected_name:
        return {"aligned": True, "hint": ""}
    if not reason or reason == "rule_based_decision" or len(reason) < 20:
        return {"aligned": True, "hint": ""}
    # 규칙 기반 한글 설명이면 플레이북 이름 없어도 정합성 검사 스킵
    if any(msg in reason for msg in RULE_REASON_MESSAGES.values()):
        return {"aligned": True, "hint": ""}

    names = extract_candidate_names(all_candidates or [])
    selected_in_reason = selected_name in reason
    other_candidate_mentioned = False
    other_praised = False
    for n in names:
        if n != selected_name and n in reason:
            other_candidate_mentioned = True
            # Simple heuristic: if reason contains positive phrasing near another candidate (e.g. L2, "저렴", "적합")
            lower_reason = reason.lower()
            if "l2" in lower_reason and selected_playbook.get("recommended_level") == 3:
                other_praised = True
            if "l3" in lower_reason and selected_playbook.get("recommended_level") == 2:
                other_praised = True
            break

    if not selected_in_reason and other_candidate_mentioned:
        return {
            "aligned": False,
            "hint": f"Reason text appears to describe another playbook while the selected result is L{selected_playbook.get('recommended_level')} {selected_name}",
        }
    if other_praised and other_candidate_mentioned:
        return {
            "aligned": False,
            "hint": f"Reason text appears to describe L2 playbook while the selected result is L3" if selected_playbook.get("recommended_level") == 3 else "Reason text may praise a different candidate than the one selected",
        }
    if not selected_in_reason and len(names) > 1:
        return {
            "aligned": False,
            "hint": f"Selected playbook '{selected_name}' is not mentioned in the reason text",
        }
    return {"aligned": True, "hint": ""}


def infer_confidence_hint(
    source: str,
    applied_rules: list | None = None,
    llm_result: dict | None = None,
    fallback_used: bool = False,
) -> str:
    """
    Heuristic confidence label for demo/report.
    - high: deterministic rule
    - medium: LLM matched rule preference, or LLM without strong rule
    - low: LLM failed and fallback used
    """
    applied_rules = applied_rules or []
    if fallback_used:
        return "low"
    if source == "rule_based" and applied_rules:
        return "high"
    if source == "llm":
        return "medium"
    return "medium"


def run_llm_recommendation_safe(playbook_mock: dict, user_response: dict) -> dict:
    """
    결정(level, playbook_name)은 rule-based로 하고, reason만 LLM이 자연어로 생성.
    rule_based_recommendation으로 결정 후 get_simulation_recommendation_for_mcp에 넘겨 reason만 LLM 생성.
    rule이 없으면 결정은 recommend_level_from_user_response, reason은 LLM.
    LLM 실패 시 reason만 "rule_based_decision" 또는 템플릿으로 폴백.
    """
    playbooks = playbook_mock.get("playbooks") or []
    applied_rules: list[str] = []
    fallback_used = False
    err_msg: str | None = None
    rule_metadata = None

    # 1) 결정은 rule-based로 (있으면 사용)
    rule_rec = rule_based_recommendation(playbooks, user_response)
    if rule_rec is not None:
        applied_rules = rule_rec.get("applied_rules", [])
        rule_metadata = rule_rec.get("rule_metadata")
        # 2) 이 결정으로 reason만 LLM에 요청
        try:
            result = get_simulation_recommendation_for_mcp(
                playbook_mock,
                user_response,
                recommended_level=rule_rec.get("recommended_level"),
                playbook_name=rule_rec.get("playbook_name", ""),
            )
            rec = result.get("recommended_playbook")
            if rec and rec.get("recommended_level") is not None and rec.get("playbook_name") is not None:
                return {
                    "source": result.get("source", "llm"),
                    "recommended_playbook": rec,
                    "applied_rules": applied_rules,
                    "fallback_used": result.get("source") == "fallback",
                    "error": None,
                    "user_response": result.get("user_response", user_response),
                    "rule_metadata": rule_metadata,
                }
        except Exception as e:
            err_msg = str(e)
            fallback_used = True
        # LLM 실패 시 rule 결정 + rule_based_decision reason
        return {
            "source": "fallback",
            "recommended_playbook": {
                "recommended_level": rule_rec.get("recommended_level"),
                "playbook_name": rule_rec.get("playbook_name", ""),
                "reason": "rule_based_decision",
            },
            "applied_rules": applied_rules,
            "fallback_used": True,
            "error": err_msg,
            "user_response": user_response,
            "rule_metadata": rule_metadata,
        }

    # 3) rule 없음: 결정은 recommend_level_from_user_response, reason은 LLM
    try:
        result = get_simulation_recommendation_for_mcp(playbook_mock, user_response)
        rec = result.get("recommended_playbook")
        if rec and rec.get("recommended_level") is not None and rec.get("playbook_name") is not None:
            return {
                "source": result.get("source", "llm"),
                "recommended_playbook": rec,
                "applied_rules": [],
                "fallback_used": result.get("source") == "fallback",
                "error": None,
                "user_response": result.get("user_response", user_response),
            }
        raise ValueError("Invalid LLM output: missing recommended_level or playbook_name")
    except Exception as e:
        err_msg = str(e)
        fallback_used = True
        lowest = select_lowest_cost_playbook(normalize_playbooks(playbooks))
        if lowest:
            return {
                "source": "fallback",
                "recommended_playbook": {
                    "recommended_level": lowest.get("level", 2),
                    "playbook_name": lowest.get("playbook_name", "fallback_lowest_cost"),
                    "reason": "rule_based_decision",
                },
                "applied_rules": [RULE_FALLBACK_LOWEST_COST],
                "fallback_used": True,
                "error": err_msg,
                "user_response": user_response,
            }
        return {
            "source": "fallback",
            "recommended_playbook": {
                "recommended_level": 2,
                "playbook_name": "fallback_lowest_cost",
                "reason": "rule_based_decision",
            },
            "applied_rules": [RULE_FALLBACK_LOWEST_COST],
            "fallback_used": True,
            "error": err_msg,
            "user_response": user_response,
        }


def validate_result(
    actual_level: int | None,
    expected_level: int | None,
    priority: str,
    playbooks: list,
    selected_playbook: dict,
    applied_rules: list | None = None,
    reason_alignment: dict | None = None,
) -> tuple[str, str]:
    """
    Compare actual vs expected level. Returns (validation, hint_message).
    On FAIL, hint distinguishes: price inversion, rule-based exclusion, or explanation inconsistency.
    """
    if expected_level is None or actual_level is None:
        return "SKIP", ""
    if actual_level == expected_level:
        return "PASS", ""

    applied_rules = applied_rules or []
    reason_alignment = reason_alignment or {}
    normalized = normalize_playbooks(playbooks)
    costs_by_level = {}
    for p in normalized:
        lv = p.get("level")
        c = p.get("estimated_monthly_cost")
        if lv is not None and c is not None:
            costs_by_level[lv] = c

    # Prefer most specific hint: price inversion > rule-based exclusion > explanation inconsistency
    if costs_by_level and actual_level in costs_by_level and expected_level in costs_by_level:
        if costs_by_level.get(actual_level, float("inf")) < costs_by_level.get(expected_level, float("inf")):
            hint = (
                f"expected L{expected_level} for {priority} profile, but L{actual_level} was selected "
                f"because L{actual_level} had lower estimated cost in this scenario"
            )
            return "FAIL", hint

    if RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT in applied_rules:
        hint = (
            f"expected L{expected_level} for {priority} profile, but L{actual_level} was selected; "
            "higher-impact candidates were excluded before cost comparison due to downtime_tolerance=not_allowed"
        )
        return "FAIL", hint

    if not reason_alignment.get("aligned", True) and reason_alignment.get("hint"):
        hint = (
            f"expected L{expected_level} for {priority} profile, but L{actual_level} was selected; "
            "explanation text may not match the selected playbook"
        )
        return "FAIL", hint

    hint = (
        f"expected L{expected_level} for {priority} profile, but L{actual_level} was selected "
        "(rule or LLM preference differs from default expected level)"
    )
    return "FAIL", hint


def run_cross_tests() -> tuple[int, int, list, dict]:
    """
    Run 9 test cases; build full result with xai block; collect stats for XAI summary.
    Returns (pass_count, fail_count, all_results, xai_summary_counts).
    """
    pass_count = 0
    fail_count = 0
    all_results: list[dict] = []
    xai_summary_counts = {
        "rule_based_cases": 0,
        "llm_cases": 0,
        "fallback_cases": 0,
        "high_confidence_cases": 0,
        "medium_confidence_cases": 0,
        "low_confidence_cases": 0,
    }

    for playbook_label, playbook_mock in PLAYBOOK_MOCKS:
        playbooks = playbook_mock.get("playbooks") or []
        for user_label, user_response in USER_RESPONSES:
            print(f"=== PLAYBOOK SCENARIO: {playbook_label} ===")
            print(f"--- USER PROFILE: {user_label} ---")

            result = run_llm_recommendation_safe(playbook_mock, user_response)
            rec = result.get("recommended_playbook") or {}
            actual_level = rec.get("recommended_level")
            priority = user_response.get("priority", "balanced")
            expected_level = EXPECTED_LEVELS.get(priority)

            normalized = normalize_playbooks(playbooks)
            rule_metadata = result.get("rule_metadata")
            reason_alignment = validate_reason_alignment(rec, rec.get("reason", ""), normalized)
            validation, hint = validate_result(
                actual_level,
                expected_level,
                priority,
                playbooks,
                rec,
                applied_rules=result.get("applied_rules", []),
                reason_alignment=reason_alignment,
            )
            if validation == "PASS":
                pass_count += 1
            elif validation == "FAIL":
                fail_count += 1

            # Build selected playbook dict for XAI (level, name, cost, impact from playbooks)
            selected_for_xai = dict(rec)
            for p in normalized:
                if p.get("level") == actual_level and p.get("playbook_name") == rec.get("playbook_name", ""):
                    selected_for_xai["expected_impact"] = p.get("expected_impact")
                    selected_for_xai["estimated_monthly_cost"] = p.get("estimated_monthly_cost")
                    break

            source = result.get("source", "")
            applied_rules = result.get("applied_rules", [])
            fallback_used = result.get("fallback_used", False)
            confidence = infer_confidence_hint(
                source, applied_rules, rec, fallback_used
            )
            if source == "rule_based":
                xai_summary_counts["rule_based_cases"] += 1
            elif source == "llm":
                xai_summary_counts["llm_cases"] += 1
            else:
                xai_summary_counts["fallback_cases"] += 1
            if confidence == "high":
                xai_summary_counts["high_confidence_cases"] += 1
            elif confidence == "medium":
                xai_summary_counts["medium_confidence_cases"] += 1
            else:
                xai_summary_counts["low_confidence_cases"] += 1

            excluded_candidates = []
            if rule_metadata and rule_metadata.get("excluded_candidates"):
                excluded_candidates = build_excluded_candidates_summary(
                    rule_metadata["excluded_candidates"],
                    reason_template="HIGH impact excluded due to downtime_tolerance=not_allowed",
                )

            reason_alignment_warning = not reason_alignment.get("aligned", True)
            xai = {
                "decision_trace": build_decision_trace(
                    playbooks,
                    user_response,
                    selected_for_xai,
                    source,
                    applied_rules,
                    rule_metadata=rule_metadata,
                    reason_alignment_warning=reason_alignment_warning,
                ),
                "decision_factors": build_decision_factors(
                    playbooks, user_response, selected_for_xai, rule_metadata=rule_metadata
                ),
                "cost_comparison": build_cost_comparison(playbooks),
                "candidate_summary": build_candidate_summary(playbooks),
                "excluded_candidates": excluded_candidates,
                "applied_rules": applied_rules,
                "confidence_hint": confidence,
                "reason_alignment": {
                    "aligned": reason_alignment.get("aligned", True),
                    "hint": reason_alignment.get("hint", ""),
                },
            }

            test_case_result = {
                "playbook_scenario": playbook_label,
                "user_profile": user_label,
                "user_response": user_response,
                "result": {
                    "source": source,
                    "recommended_level": actual_level,
                    "playbook_name": rec.get("playbook_name", ""),
                    "reason": rec.get("reason", ""),
                },
                "xai": xai,
                "validation": validation,
            }
            if hint:
                test_case_result["validation_hint"] = hint

            all_results.append(test_case_result)
            print(json.dumps(test_case_result, ensure_ascii=False, indent=2))
            if validation == "FAIL" and hint:
                print(f"[FAIL hint] {hint}")
            print()

    return pass_count, fail_count, all_results, xai_summary_counts


def main() -> None:
    """Baseline run, 9 cross-tests with XAI, summary, optional save to JSON."""
    run_baseline_finance()
    total = 9
    pass_count, fail_count, all_results, xai_counts = run_cross_tests()

    print("=== TEST SUMMARY ===")
    print(f"total_cases: {total}")
    print(f"pass: {pass_count}")
    print(f"fail: {fail_count}")
    print()
    print("=== XAI SUMMARY ===")
    print(f"rule_based_cases: {xai_counts['rule_based_cases']}")
    print(f"llm_cases: {xai_counts['llm_cases']}")
    print(f"fallback_cases: {xai_counts['fallback_cases']}")
    print(f"high_confidence_cases: {xai_counts['high_confidence_cases']}")
    print(f"medium_confidence_cases: {xai_counts['medium_confidence_cases']}")
    print(f"low_confidence_cases: {xai_counts['low_confidence_cases']}")

    # Persist all test results to JSON (v2 with XAI/validation fixes)
    payload = {
        "total_cases": total,
        "pass": pass_count,
        "fail": fail_count,
        "xai_summary": xai_counts,
        "test_results": all_results,
    }
    for out_name in (RESULTS_OUTPUT_FILE, RESULTS_OUTPUT_FILE_V2):
        out_path = ROOT / out_name
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print()
            print(f"Results saved to {out_path}")
        except Exception as e:
            print()
            print(f"Could not save results to {out_path}: {e}")


if __name__ == "__main__":
    main()
