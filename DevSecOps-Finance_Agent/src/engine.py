"""Finance Agent engine: request -> validate -> contract -> policy -> pricing -> result -> audit."""

import logging
import os
import jsonschema

from .contract import normalize_and_validate_assumptions
from .errors import ContractViolation, contract_error_response
from .policy_loader import load_policy
from .pricing import compute_costs
from .pricing_provider import get_pricing_provider
from .assumption_hash import assumption_hash
from .validate import validate_request, validate_result, validate_audit_record, should_validate_output_schema
from .risk_model import calculate_expected_loss, calculate_risk_adjusted_loss
from .scoring_engine import compute_action_scores
from .audit import build_audit_record, append_audit_record

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG_PATH = "logs/audit.jsonl"


def post_process_hook(result: dict, request: dict, context: dict) -> dict:
    """후처리 훅. 기본은 no-op. 필요 시 result 수정 후 반환."""
    return result


def finance_run(request_obj: dict) -> dict:
    """Run finance estimation pipeline.

    1) Request schema validate
    2) Normalize + contract validate (on violation return contract_error_response)
    3) Load policy (request.policy_version)
    4) Pricing compute => total + breakdown + top3
    5) Build result (no xai)
    6) Result schema validate and return (after optional post_process_hook)
    """
    incident_id = request_obj.get("incident_id", "")
    logger.info("엔진 실행 시작 incident_id=%s", incident_id)
    # 1) Request schema validate
    try:
        validate_request(request_obj)
    except jsonschema.ValidationError as e:
        logger.warning("엔진 스키마 검증 실패 incident_id=%s: %s", incident_id, str(e))
        return {
            "error": {
                "type": "SCHEMA_VALIDATION_ERROR",
                "incident_id": request_obj.get("incident_id", ""),
                "message": str(e),
            }
        }

    incident_id = request_obj["incident_id"]
    policy_version = request_obj["policy_version"]
    assumptions = request_obj["assumptions"]
    resource_change = request_obj["resource_change"]

    # 2) Normalize + contract validate
    try:
        normalized = normalize_and_validate_assumptions(assumptions)
    except ContractViolation as e:
        logger.warning("엔진 계약 위반 incident_id=%s: %s", incident_id, e.errors)
        return contract_error_response(e, incident_id)

    # 3) Load policy
    try:
        policy = load_policy(policy_version)
    except ValueError as e:
        return {
            "error": {
                "type": "POLICY_ERROR",
                "incident_id": incident_id,
                "message": str(e),
            }
        }

    # 4) Pricing (정책 단가 또는 USE_AWS_PRICING_API 시 API 호출, 리전별 캐시로 호출 절감)
    region = normalized.get("region", "us-east-1")
    pricing_table = get_pricing_provider().get_pricing_table(region, policy)
    computed = compute_costs(resource_change, normalized, pricing_table)
    duration_hours = normalized.get("duration_hours", 720)
    period_label = {1: "1h", 24: "24h", 168: "7d", 720: "30d"}.get(duration_hours, "30d")

    # 5) Build result (과금은 요청의 duration_hours 기준)
    result = {
        "schema_version": "1.0",
        "incident_id": incident_id,
        "policy_version": policy_version,
        "policy_meta": {
            "approved_by": policy.get("approved_by", ""),
            "approved_at": policy.get("approved_at", ""),
        },
        "assumption_hash": assumption_hash(normalized),
        "cost_summary": {
            "estimated_monthly_cost": computed["total"],
            "currency": policy.get("currency", "USD"),
            "period_hours": duration_hours,
            "period_label": period_label,
        },
        "driver_breakdown": _breakdown_with_why(computed["breakdown"]),
        "top3_drivers": computed["top3_drivers"],
    }

    # 5b) If policy bundle (v1.0.0): risk + recommendation from policy only
    if policy.get("policy_hash"):
        scenario_class = normalized.get("service_tier", "S1")
        severity = normalized.get("severity", "Medium")
        profile = normalized.get("org_profile", "Standard")
        reg_ctx = normalized.get("regulation_context") or {}
        weight_profile = reg_ctx.get("weight_profile", "normal")
        constraint_ctx = {"allow_isolate_standby": normalized.get("allow_isolate_standby", False)}

        expected_loss = calculate_expected_loss(
            policy.get("likelihood_table", {}),
            policy.get("impact_table", {}),
            severity,
            scenario_class,
        )
        risk_adjusted = calculate_risk_adjusted_loss(
            expected_loss,
            policy.get("regulation_weights", {}),
            weight_profile,
        )
        regulation_weights = (policy.get("regulation_weights") or {}).get(weight_profile) or {}
        action_scores, recommendation, forbidden_actions_list = compute_action_scores(
            computed["total"],
            risk_adjusted,
            profile,
            policy,
            scenario_class,
            severity,
            constraint_ctx,
        )
        result["policy_hash"] = policy["policy_hash"]
        result["applied_profile"] = profile
        result["applied_regulation_weights"] = regulation_weights
        result["recommendation"] = recommendation or ""
        result["action_scores"] = action_scores
        _audit_ctx = {
            "policy_hash": policy["policy_hash"],
            "impact_breakdown": _impact_breakdown_for_audit(policy.get("impact_table"), scenario_class),
            "likelihood": _likelihood_for_audit(policy.get("likelihood_table"), severity),
            "regulatory_component": risk_adjusted,
            "profile_applied": profile,
            "final_score": (action_scores or {}).get(recommendation, 0.0),
            "top_actions": _top_actions_list(action_scores),
            "forbidden_actions": forbidden_actions_list,
        }
    else:
        _audit_ctx = {}

    context = {"policy": policy, "normalized_assumptions": normalized, "computed": computed}
    result = post_process_hook(result, request_obj, context)

    # 6) Result schema validate
    try:
        validate_result(result)
    except jsonschema.ValidationError as e:
        return {
            "error": {
                "type": "RESULT_SCHEMA_ERROR",
                "incident_id": incident_id,
                "message": str(e),
            }
        }

    # 7) Audit: 1 record per run (success only)
    try:
        audit_record = build_audit_record(
            request_obj,
            result,
            policy_hash=_audit_ctx.get("policy_hash", ""),
            assumption_hash=result.get("assumption_hash", ""),
            impact_breakdown=_audit_ctx.get("impact_breakdown"),
            likelihood=_audit_ctx.get("likelihood", 0.0),
            regulatory_component=_audit_ctx.get("regulatory_component", 0.0),
            profile_applied=_audit_ctx.get("profile_applied", ""),
            final_score=_audit_ctx.get("final_score", 0.0),
            top_actions=_audit_ctx.get("top_actions", []),
            forbidden_actions=_audit_ctx.get("forbidden_actions", []),
            top3_drivers=result.get("top3_drivers"),
        )
        if should_validate_output_schema():
            try:
                validate_audit_record(audit_record)
            except jsonschema.ValidationError as e:
                logger.warning("Audit record schema validation failed: %s", e)
        audit_path = os.environ.get("AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH)
        append_audit_record(audit_record, audit_path)
    except Exception as e:
        logger.warning("Audit record write failed: %s", e)

    logger.info("엔진 실행 완료 incident_id=%s total=%s", incident_id, result.get("cost_summary", {}).get("estimated_monthly_cost"))
    return result


def _impact_breakdown_for_audit(impact_table: dict, scenario_class: str) -> dict:
    if not impact_table or not scenario_class:
        return {}
    v = impact_table.get(scenario_class)
    return {scenario_class: float(v)} if v is not None else {}


def _likelihood_for_audit(likelihood_table: dict, severity: str) -> float:
    if not likelihood_table or not severity:
        return 0.0
    v = likelihood_table.get(severity)
    return float(v) if v is not None else 0.0


def _top_actions_list(action_scores: dict) -> list:
    if not action_scores:
        return []
    sorted_actions = sorted(action_scores.items(), key=lambda x: -x[1])
    return [{"action_id": aid, "rank": i + 1, "score": sc} for i, (aid, sc) in enumerate(sorted_actions)]


def _breakdown_with_why(breakdown: list) -> list:
    """Add numeric 'why' explanation to each driver for explainability."""
    out = []
    for item in breakdown:
        d = dict(item)
        cost = d.get("cost", 0)
        pct = d.get("percentage", 0)
        d["why"] = f"cost={cost}, share={pct}%"
        out.append(d)
    return out
