"""
Regulation result(= recommended_actions level2/level3) 기반으로
1) (내부) 비용 산정(L2/L3 각각)
2) (기존) get_simulation_recommendation_for_mcp로 추천 + reason 생성
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contract import normalize_and_validate_assumptions
from .pricing import compute_costs
from .pricing_provider import get_pricing_provider
from .policy_loader import load_policy
from .simulation_questions import get_simulation_recommendation_for_mcp

_DEFAULTS_PATH = Path(__file__).resolve().parent.parent / "policy" / "playbook_resource_defaults.json"

# MCP에서 전달되는 playbook_name(한글) -> policy 내부 resource defaults key 매핑
# - 매핑이 없으면 오류를 반환하도록 했습니다(잘못된 매핑은 비용 계산 오차로 직결).
PLAYBOOK_NAME_TO_DEFAULTS_KEY: dict[str, str] = {
    "계정 권한 제한 및 관찰": "playbook_iam_abuse_response",
    "강력한 격리 및 계정 삭제": "playbook_integrated_base_mitigation",
    "로그 보존 및 접근 제한": "playbook_s3_public_access",
    "리소스 격리 및 포렌식 수집": "playbook_ec2_investigation_logging",
    "장기 모니터링 및 단계적 제한": "playbook_s3_public_access",
    "즉시 격리 및 증거 확보": "playbook_ec2_isolate",
}

DEFAULTS_KEY_TO_PLAYBOOK_NAME: dict[str, str] = {
    "playbook_ec2_isolate": "즉시 격리 및 증거 확보",
    "playbook_s3_public_access": "로그 보존 및 접근 제한",
    "playbook_iam_abuse_response": "계정 권한 제한 및 관찰",
    "playbook_ec2_investigation_logging": "리소스 격리 및 포렌식 수집",
    "playbook_integrated_base_mitigation": "강력한 격리 및 계정 삭제",
}

# recommended_actions[].actions[].action_id 패턴 기반 추론
ACTION_SIGNATURE_TO_DEFAULTS_KEY: list[tuple[set[str], str]] = [
    ({"isolate_instance", "create_snapshot"}, "playbook_ec2_isolate"),
    ({"block_s3_public_access", "enable_s3_bucket_logging"}, "playbook_s3_public_access"),
    ({"disable_access_key", "block_ip"}, "playbook_iam_abuse_response"),
    ({"disable_access_key", "disable_iam_entity", "detach_admin_policies"}, "playbook_iam_abuse_response"),
    ({"create_snapshot", "tag_resource_with_incident"}, "playbook_ec2_investigation_logging"),
    ({"detach_admin_policies", "enable_s3_bucket_logging", "create_snapshot"}, "playbook_integrated_base_mitigation"),
]


def _load_playbook_resource_defaults() -> dict[str, Any]:
    try:
        with open(_DEFAULTS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load playbook defaults: {_DEFAULTS_PATH}: {e}")


@dataclass(frozen=True)
class _Candidate:
    level: int
    playbook_name: str
    expected_impact: str
    cost_monthly: float


def _extract_regulation_payload(regulation_payload: dict) -> dict:
    """
    regulation_payload는 다음 형태 중 하나일 수 있습니다.
    - { ..., "mock_regulation_result": {...} }
    - { "schema_version": ..., "recommended_actions": [...] }  (이미 mock_regulation_result 자체)
    """
    if not isinstance(regulation_payload, dict):
        raise ValueError("regulation_payload must be an object")

    if "mock_regulation_result" in regulation_payload and isinstance(regulation_payload["mock_regulation_result"], dict):
        return regulation_payload["mock_regulation_result"]
    return regulation_payload


def _extract_region_from_regulation(reg: dict) -> str | None:
    try:
        resource = (reg.get("incident_summary") or {}).get("resource") or {}
        region = resource.get("region")
        if isinstance(region, str) and region.strip():
            return region.strip()
    except Exception:
        pass
    return None


def _normalize_playbook_level(level: Any) -> int | None:
    """DynamoDB/JSON 에서 level 이 문자열 \"2\"/\"3\" 로 올 수 있음 — 비용 계산 경로에서 반드시 정규화."""
    if level is None or isinstance(level, bool):
        return None
    try:
        n = int(float(level))
    except (TypeError, ValueError):
        return None
    return n if n in (2, 3) else None


def _extract_candidates(reg: dict) -> tuple[dict, dict]:
    """
    반환:
    - (level2_candidate, level3_candidate) 각각 dict
    """
    actions = reg.get("recommended_actions") or []
    if not isinstance(actions, list):
        raise ValueError("recommended_actions must be a list")

    level2 = None
    level3 = None
    for a in actions:
        if not isinstance(a, dict):
            continue
        lvl = _normalize_playbook_level(a.get("level"))
        if lvl == 2 and level2 is None:
            level2 = a
        elif lvl == 3 and level3 is None:
            level3 = a

    if level2 is None or level3 is None:
        raise ValueError("recommended_actions must include both level=2 and level=3 candidates")

    return level2, level3


def _extract_action_ids(candidate: dict) -> set[str]:
    """
    candidate가 아래 둘 중 하나일 수 있어 방어적으로 처리합니다.
    - {"actions":[{"action_id":"..."}, ...]}
    - {"action_id":"..."}  # 단일 액션 형태
    """
    ids: set[str] = set()
    actions = candidate.get("actions")
    if isinstance(actions, list):
        for a in actions:
            if not isinstance(a, dict):
                continue
            aid = a.get("action_id")
            if isinstance(aid, str) and aid.strip():
                ids.add(aid.strip())
    else:
        aid = candidate.get("action_id")
        if isinstance(aid, str) and aid.strip():
            ids.add(aid.strip())
    return ids


def _infer_defaults_key(candidate: dict, playbook_name: str) -> str | None:
    # 1) playbook_name 기반 매핑 우선
    if playbook_name:
        by_name = PLAYBOOK_NAME_TO_DEFAULTS_KEY.get(playbook_name)
        if by_name:
            return by_name

    # 2) action_id signature 기반 추론
    action_ids = _extract_action_ids(candidate)
    if not action_ids:
        return None
    for signature, defaults_key in ACTION_SIGNATURE_TO_DEFAULTS_KEY:
        if signature.issubset(action_ids):
            return defaults_key
    return None


def _compute_cost_for_playbook(
    policy: dict,
    defaults: dict,
    playbook_defaults_key: str,
    assumptions: dict,
    *,
    region: str,
) -> float:
    playbooks = defaults.get("playbooks") or {}
    spec = playbooks.get(playbook_defaults_key) or {}
    resource_change = spec.get("resource_change") or {}
    if not resource_change:
        raise ValueError(f"Missing resource_change for defaults_key={playbook_defaults_key}")

    pricing_table = get_pricing_provider().get_pricing_table(region, policy)
    computed = compute_costs(resource_change, assumptions, pricing_table)
    return float(computed.get("total") or 0.0)


def get_simulation_recommendation_from_regulation(
    *,
    regulation_payload: dict,
    user_response: dict,
    policy_version: str,
    event: dict | None = None,
) -> dict:
    """
    MCP가 넘겨준 regulation_result(= mock_regulation_result) + user_response로부터
    L2/L3 각각 비용을 내부에서 계산한 뒤, 추천 시나리오+reason을 반환합니다.
    """
    reg = _extract_regulation_payload(regulation_payload)

    defaults = _load_playbook_resource_defaults()
    default_assumptions = defaults.get("default_assumptions") or {}
    if not default_assumptions:
        raise ValueError("playbook_resource_defaults.json missing default_assumptions")

    incident_id = reg.get("incident_id", "")
    scenario = reg.get("scenario", "")
    region = _extract_region_from_regulation(reg) or default_assumptions.get("region") or "ap-northeast-2"

    # event로 assumptions overrides를 받는 것을 허용(선택).
    overrides = {}
    if event and isinstance(event.get("assumptions"), dict):
        overrides = event["assumptions"]

    assumptions = {
        "duration_hours": overrides.get("duration_hours", default_assumptions.get("duration_hours", 720)),
        "traffic_multiplier": overrides.get("traffic_multiplier", default_assumptions.get("traffic_multiplier", 1.0)),
        "region": overrides.get("region", region),
        "service_tier": overrides.get("service_tier", default_assumptions.get("service_tier", "S1")),
        "org_profile": overrides.get("org_profile", default_assumptions.get("org_profile", "Standard")),
        # optional: normalize_and_validate_assumptions에서 허용
        "severity": overrides.get("severity", default_assumptions.get("severity", "Medium")),
    }

    try:
        normalized = normalize_and_validate_assumptions(assumptions)
    except Exception as e:
        raise ValueError(f"Invalid assumptions: {e}")

    policy = load_policy(policy_version)

    level2_raw, level3_raw = _extract_candidates(reg)
    candidates: dict[int, dict] = {2: level2_raw, 3: level3_raw}

    computed_candidates: dict[int, _Candidate] = {}
    for lvl, raw in candidates.items():
        playbook_name = str(raw.get("playbook_name") or "").strip()
        defaults_key = _infer_defaults_key(raw, playbook_name)
        if not defaults_key:
            raise ValueError(
                f"Cannot infer playbook defaults key for level={lvl}. "
                f"playbook_name='{playbook_name}', action_ids={sorted(_extract_action_ids(raw))}. "
                f"Add mapping to PLAYBOOK_NAME_TO_DEFAULTS_KEY or ACTION_SIGNATURE_TO_DEFAULTS_KEY."
            )
        if not playbook_name:
            playbook_name = DEFAULTS_KEY_TO_PLAYBOOK_NAME.get(defaults_key, defaults_key)

        expected_impact = str(raw.get("expected_impact") or "")

        cost_monthly = _compute_cost_for_playbook(
            policy=policy,
            defaults=defaults,
            playbook_defaults_key=defaults_key,
            assumptions=normalized,
            region=normalized.get("region") or region,
        )

        computed_candidates[lvl] = _Candidate(
            level=lvl,
            playbook_name=playbook_name,
            expected_impact=expected_impact,
            cost_monthly=cost_monthly,
        )

    comparison = {
        "incident_id": incident_id,
        "event_summary": scenario,
        "playbook_scenario": str(scenario or ""),
        "user_profile": (
            f"environment={user_response.get('environment')}, data_sensitivity={user_response.get('data_sensitivity')}, "
            f"downtime_tolerance={user_response.get('downtime_tolerance')}, priority={user_response.get('priority')}"
        ),
        "playbooks": [
            {
                "level": 2,
                "playbook_name": computed_candidates[2].playbook_name,
                "cost_summary": {"estimated_monthly_cost": computed_candidates[2].cost_monthly},
                "expected_impact": computed_candidates[2].expected_impact,
            },
            {
                "level": 3,
                "playbook_name": computed_candidates[3].playbook_name,
                "cost_summary": {"estimated_monthly_cost": computed_candidates[3].cost_monthly},
                "expected_impact": computed_candidates[3].expected_impact,
            },
        ],
    }

    # MCP mock 동일 형식: playbook_scenario, user_profile, result, xai, validation
    return get_simulation_recommendation_for_mcp(comparison, user_response)

