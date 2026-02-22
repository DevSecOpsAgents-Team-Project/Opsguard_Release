"""Finance Agent engine: request -> validate -> contract -> policy -> pricing -> result."""

import jsonschema

from .contract import normalize_and_validate_assumptions
from .errors import ContractViolation, contract_error_response
from .policy_loader import load_policy
from .pricing import compute_costs
from .assumption_hash import assumption_hash
from .validate import validate_request, validate_result


# --- Extension point for B-part (XAI): A-part does not call with any implementation ---
def post_process_hook(result: dict, request: dict, context: dict) -> dict:
    """Optional hook for post-processing result (e.g. B-part can inject xai).

    A-part calls this but uses a no-op; B-part may override to add xai to result.
    Caller should use: result = post_process_hook(result, request, context).

    Args:
        result: Current result dict (without xai in A-part).
        request: Original request dict.
        context: Optional context (e.g. policy, normalized assumptions).

    Returns:
        result (unchanged in A-part).
    """
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
    # 1) Request schema validate
    try:
        validate_request(request_obj)
    except jsonschema.ValidationError as e:
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

    # 4) Pricing
    pricing_table = policy["pricing_table"]
    computed = compute_costs(resource_change, normalized, pricing_table)

    # 5) Build result (A-part does not add xai)
    result = {
        "schema_version": "1.0",
        "incident_id": incident_id,
        "policy_version": policy_version,
        "policy_meta": {
            "approved_by": policy["approved_by"],
            "approved_at": policy["approved_at"],
        },
        "assumption_hash": assumption_hash(normalized),
        "cost_summary": {
            "estimated_monthly_cost": computed["total"],
            "currency": policy["currency"],
        },
        "driver_breakdown": computed["breakdown"],
        "top3_drivers": computed["top3_drivers"],
    }

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

    return result
