"""
MCP 시뮬레이션 추천 응답용 XAI 블록 생성 (get_simulation_recommendation_for_mcp).
run_mocks_advanced.py 와 동일한 설명 구조를 런타임 경로에서 재사용.
"""

from __future__ import annotations

RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT = "RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT"
RULE_PRODUCTION_PII_SECURITY_FORCE_L3 = "RULE_PRODUCTION_PII_SECURITY_FORCE_L3"
RULE_COST_PRIORITY_SELECT_LOWEST_COST = "RULE_COST_PRIORITY_SELECT_LOWEST_COST"
RULE_FALLBACK_LOWEST_COST = "RULE_FALLBACK_LOWEST_COST"

RULE_REASON_MESSAGES = {
    RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT: "서비스 중단이 불가한 설정이므로 고영향(HIGH) 플레이북을 제외한 뒤, 남은 후보 중에서 선택했습니다.",
    RULE_PRODUCTION_PII_SECURITY_FORCE_L3: "운영 환경이 프로덕션이고 PII 데이터이며 보안을 우선하므로, Level 3 이상의 강력한 대응 플레이북을 추천했습니다.",
    RULE_COST_PRIORITY_SELECT_LOWEST_COST: "비용 우선 설정에 따라 예상 비용이 가장 낮은 플레이북을 추천했습니다.",
    RULE_FALLBACK_LOWEST_COST: "기본 규칙에 따라 예상 비용이 가장 낮은 플레이북을 추천했습니다.",
}


def _coerce_level(level: object) -> object:
    """Slack/L2·L3 비용 매칭용: level 이 \"2\"/\"3\" 문자열이어도 candidates·UI와 일치하도록."""
    if level is None or isinstance(level, bool):
        return level
    if isinstance(level, (int, float)):
        return int(level)
    if isinstance(level, str) and level.strip().isdigit():
        return int(level.strip())
    return level


def normalize_playbooks(playbooks: list) -> list[dict]:
    out = []
    for p in playbooks or []:
        cost_summary = p.get("cost_summary") or {}
        out.append(
            {
                "level": _coerce_level(p.get("level")),
                "playbook_name": p.get("playbook_name", ""),
                "estimated_monthly_cost": cost_summary.get("estimated_monthly_cost"),
                "expected_impact": (p.get("expected_impact") or "").upper() or "UNKNOWN",
            }
        )
    return out


def build_decision_trace(
    playbooks: list,
    user_response: dict,
    selected_playbook: dict,
    source: str,
    applied_rules: list | None = None,
    rule_metadata: dict | None = None,
    reason_alignment_warning: bool = False,
) -> list[str]:
    trace: list[str] = []
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
    normalized = normalize_playbooks(playbooks)
    return [
        f"L{p.get('level')} / {p.get('playbook_name', '')} / cost={p.get('estimated_monthly_cost')} / impact={p.get('expected_impact', '')}"
        for p in normalized
    ]


def extract_candidate_names(all_candidates: list[dict]) -> list[str]:
    return [str(p.get("playbook_name", "")).strip() for p in (all_candidates or []) if p.get("playbook_name")]


def validate_reason_alignment(
    selected_playbook: dict,
    reason_text: str,
    all_candidates: list[dict],
) -> dict:
    selected_name = (selected_playbook.get("playbook_name") or "").strip()
    reason = (reason_text or "").strip()
    if not selected_name:
        return {"aligned": True, "hint": ""}
    if not reason or reason == "rule_based_decision" or len(reason) < 20:
        return {"aligned": True, "hint": ""}
    if any(msg in reason for msg in RULE_REASON_MESSAGES.values()):
        return {"aligned": True, "hint": ""}

    names = extract_candidate_names(all_candidates or [])
    selected_in_reason = selected_name in reason
    other_candidate_mentioned = False
    other_praised = False
    for n in names:
        if n != selected_name and n in reason:
            other_candidate_mentioned = True
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
            "hint": "Reason text appears to describe L2 playbook while the selected result is L3"
            if selected_playbook.get("recommended_level") == 3
            else "Reason text may praise a different candidate than the one selected",
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
    fallback_used: bool = False,
) -> str:
    applied_rules = applied_rules or []
    if fallback_used:
        return "low"
    if source == "rule_based" and applied_rules:
        return "high"
    if source == "llm":
        return "medium"
    return "medium"


def infer_applied_rules_heuristic(user_response: dict, recommended_level: int | None) -> list[str]:
    """간단 휴리스틱(런타임). run_mocks_advanced 의 전체 rule 엔진과 동일하지 않을 수 있음."""
    rules: list[str] = []
    env = user_response.get("environment")
    ds = user_response.get("data_sensitivity")
    pr = user_response.get("priority")
    dt = user_response.get("downtime_tolerance")
    if env == "production" and ds == "pii" and pr == "security" and recommended_level == 3:
        rules.append(RULE_PRODUCTION_PII_SECURITY_FORCE_L3)
    if pr == "cost":
        rules.append(RULE_COST_PRIORITY_SELECT_LOWEST_COST)
    if dt == "not_allowed":
        rules.append(RULE_DOWNTIME_NOT_ALLOWED_EXCLUDE_HIGH_IMPACT)
    return rules


def build_mcp_simulation_response(
    comparison: dict,
    user_response: dict,
    rec: dict,
    source: str,
    *,
    playbook_scenario: str = "",
    user_profile: str = "",
) -> dict:
    """
    MCP mock 과 동일한 최상위 키: playbook_scenario, user_profile, user_response, result, xai, validation.
    """
    playbooks = comparison.get("playbooks") or []
    selected_playbook = {
        "recommended_level": rec.get("recommended_level"),
        "playbook_name": rec.get("playbook_name", ""),
        "reason": rec.get("reason", ""),
    }
    normalized = normalize_playbooks(playbooks)
    applied_rules = infer_applied_rules_heuristic(user_response, rec.get("recommended_level"))
    rule_metadata: dict = {}
    reason_alignment = validate_reason_alignment(selected_playbook, rec.get("reason", ""), normalized)
    trace = build_decision_trace(
        playbooks,
        user_response,
        selected_playbook,
        source,
        applied_rules,
        rule_metadata,
        reason_alignment_warning=not reason_alignment.get("aligned", True),
    )
    factors = build_decision_factors(playbooks, user_response, selected_playbook, rule_metadata)
    cost_cmp = build_cost_comparison(playbooks)
    cand_sum = build_candidate_summary(playbooks)
    confidence = infer_confidence_hint(source, applied_rules, fallback_used=(source == "fallback"))
    validation = "PASS" if reason_alignment.get("aligned") else "REVIEW"

    scenario = playbook_scenario or (comparison or {}).get("playbook_scenario") or ""
    profile = user_profile or (comparison or {}).get("user_profile") or ""

    return {
        "playbook_scenario": scenario,
        "user_profile": profile,
        "user_response": dict(user_response),
        "result": {
            "source": source,
            "recommended_level": rec.get("recommended_level"),
            "playbook_name": rec.get("playbook_name", ""),
            "reason": rec.get("reason", ""),
        },
        "xai": {
            "decision_trace": trace,
            "decision_factors": factors,
            "cost_comparison": cost_cmp,
            "candidate_summary": cand_sum,
            "excluded_candidates": [],
            "applied_rules": applied_rules,
            "confidence_hint": confidence,
            "reason_alignment": reason_alignment,
        },
        "validation": validation,
    }
