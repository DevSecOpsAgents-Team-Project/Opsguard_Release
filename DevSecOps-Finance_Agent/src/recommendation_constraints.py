"""
Apply recommendation_constraints from policy only. No hardcoding.
Supports: rules[] (legacy) and constraints[] (constraint_id, when, effect, actions, reason_code).
effect: FORBID | ALLOW_ONLY | DEPRIORITIZE (and legacy forbid/allow).
"""


def get_forbidden_actions(
    constraints: dict,
    scenario_class: str,
    severity: str,
    context: dict | None = None,
) -> set[str]:
    """Return set of forbidden action_ids. Kept for backward compat."""
    _, forbidden_set = evaluate_constraints(
        {"scenario_class": scenario_class, "severity": severity, **(context or {})},
        constraints,
    )
    return forbidden_set


def evaluate_constraints(
    context: dict,
    policy_constraints: dict,
) -> tuple[list[dict], set[str]]:
    """
    Evaluate policy constraints. Returns (forbidden_actions_list, forbidden_ids_set).
    forbidden_actions_list: [{"action_id": str, "constraint_id": str, "reason_code": str}]
    All from policy file; no hardcoding.
    """
    out_list: list[dict] = []
    forbidden: set[str] = set()
    ctx = context or {}
    scenario_class = ctx.get("scenario_class", "")
    severity = ctx.get("severity", "")

    # New format: constraints[] with constraint_id, when, effect, actions, reason_code
    for c in (policy_constraints or {}).get("constraints", []):
        when = c.get("when", {})
        if not _condition_matches(when, scenario_class, severity, ctx):
            continue
        effect = (c.get("effect") or "").upper()
        actions = c.get("actions", []) or c.get("action_ids", [])
        constraint_id = c.get("constraint_id", c.get("id", ""))
        reason_code = c.get("reason_code", "POLICY_CONSTRAINT")

        if effect == "FORBID":
            for aid in actions:
                forbidden.add(aid)
                out_list.append({
                    "action_id": aid,
                    "constraint_id": constraint_id,
                    "reason_code": reason_code,
                })
        elif effect == "ALLOW_ONLY":
            # allow: remove these from forbidden (overrides previous FORBID)
            for aid in actions:
                forbidden.discard(aid)
                out_list = [x for x in out_list if x["action_id"] != aid]
        # DEPRIORITIZE: could reduce score; treat as allowed here (not forbidden)

    # Legacy format: rules[] with condition, effect forbid/allow, action_ids
    for rule in (policy_constraints or {}).get("rules", []):
        cond = rule.get("condition", rule.get("when", {}))
        if not _condition_matches(cond, scenario_class, severity, ctx):
            continue
        effect = (rule.get("effect") or "").lower()
        action_ids = rule.get("action_ids", []) or rule.get("actions", [])
        cid = rule.get("constraint_id", rule.get("id", "legacy_rule"))
        reason_code = rule.get("reason_code", "POLICY_RULE")

        if effect == "forbid":
            for aid in action_ids:
                if aid not in forbidden:
                    forbidden.add(aid)
                    out_list.append({"action_id": aid, "constraint_id": cid, "reason_code": reason_code})
        elif effect == "allow":
            for aid in action_ids:
                forbidden.discard(aid)
                out_list = [x for x in out_list if x["action_id"] != aid]

    return out_list, forbidden


def _condition_matches(cond: dict, scenario_class: str, severity: str, context: dict) -> bool:
    if not cond:
        return True
    if cond.get("scenario_class") and cond["scenario_class"] != scenario_class:
        return False
    if cond.get("severity") and cond["severity"] != severity:
        return False
    for k, v in cond.items():
        if k in ("scenario_class", "severity"):
            continue
        if context.get(k) != v:
            return False
    return True
