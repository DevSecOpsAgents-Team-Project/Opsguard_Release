"""
Regulation Agent 1.3 JSON → 신 Finance Agent comparison + Lambda invoke helpers.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

# Finance policy/playbook_resource_defaults.json 과 동일한 resource_change (MCP 번들용)
PLAYBOOK_RESOURCE_CHANGE: Dict[str, Dict[str, float]] = {
    "playbook_ec2_isolate": {
        "cloudwatch_log_gb_per_day": 2,
        "s3_storage_gb": 10,
        "nat_egress_gb": 5,
        "snapshot_gb": 30,
    },
    "playbook_s3_public_access": {
        "cloudwatch_log_gb_per_day": 1,
        "s3_storage_gb": 5,
        "nat_egress_gb": 0,
        "snapshot_gb": 0,
    },
    "playbook_iam_abuse_response": {
        "cloudwatch_log_gb_per_day": 0.5,
        "s3_storage_gb": 0,
        "nat_egress_gb": 0,
        "snapshot_gb": 0,
    },
    "playbook_ec2_investigation_logging": {
        "cloudwatch_log_gb_per_day": 3,
        "s3_storage_gb": 15,
        "nat_egress_gb": 2,
        "snapshot_gb": 30,
    },
    "playbook_integrated_base_mitigation": {
        "cloudwatch_log_gb_per_day": 2,
        "s3_storage_gb": 20,
        "nat_egress_gb": 3,
        "snapshot_gb": 25,
    },
}

PLAYBOOK_NAME_TO_DEFAULTS_KEY: Dict[str, str] = {
    "Credential Containment": "playbook_iam_abuse_response",
    "Access Review and Remediation": "playbook_integrated_base_mitigation",
    "Network Isolation": "playbook_ec2_isolate",
    "Network Isolation and Mitigation": "playbook_integrated_base_mitigation",
    "S3 Bucket Security Enhancement": "playbook_s3_public_access",
    "Data Compliance Review": "playbook_integrated_base_mitigation",
    "Enhanced Monitoring Setup": "playbook_s3_public_access",
    "Threat Containment and Eradication": "playbook_ec2_isolate",
    "Data Flow Restrictions": "playbook_s3_public_access",
    "Incident Isolation and Forensics": "playbook_ec2_investigation_logging",
    "Targeted Containment": "playbook_iam_abuse_response",
    "Expanded Isolation and Review": "playbook_integrated_base_mitigation",
    "계정 권한 제한 및 관찰": "playbook_iam_abuse_response",
    "강력한 격리 및 계정 삭제": "playbook_integrated_base_mitigation",
    "로그 보존 및 접근 제한": "playbook_s3_public_access",
    "리소스 격리 및 포렌식 수집": "playbook_ec2_investigation_logging",
    "즉시 격리 및 증거 확보": "playbook_ec2_isolate",
}

ACTION_SIGNATURE_TO_DEFAULTS_KEY: List[Tuple[Set[str], str]] = [
    ({"isolate_instance", "create_snapshot"}, "playbook_ec2_isolate"),
    ({"block_s3_public_access", "enable_s3_bucket_logging"}, "playbook_s3_public_access"),
    ({"disable_access_key", "block_ip"}, "playbook_iam_abuse_response"),
    ({"disable_access_key", "disable_iam_entity", "detach_admin_policies"}, "playbook_iam_abuse_response"),
    ({"create_snapshot", "tag_resource_with_incident"}, "playbook_ec2_investigation_logging"),
    (
        {"detach_admin_policies", "enable_s3_bucket_logging", "create_snapshot"},
        "playbook_integrated_base_mitigation",
    ),
]


def norm_level(lv: Any) -> Optional[int]:
    if lv is None or isinstance(lv, bool):
        return None
    try:
        n = int(float(lv))
    except (TypeError, ValueError):
        return None
    return n if n in (2, 3) else None


def _extract_action_ids(playbook: Dict[str, Any]) -> Set[str]:
    ids: Set[str] = set()
    actions = playbook.get("actions")
    if isinstance(actions, list):
        for a in actions:
            if isinstance(a, dict):
                aid = a.get("action_id")
                if isinstance(aid, str) and aid.strip():
                    ids.add(aid.strip())
    elif isinstance(playbook.get("action_id"), str):
        ids.add(playbook["action_id"].strip())
    return ids


def infer_defaults_key(playbook: Dict[str, Any]) -> Optional[str]:
    name = str(playbook.get("playbook_name") or "").strip()
    if name:
        key = PLAYBOOK_NAME_TO_DEFAULTS_KEY.get(name)
        if key:
            return key
    action_ids = _extract_action_ids(playbook)
    if not action_ids:
        return None
    for signature, defaults_key in ACTION_SIGNATURE_TO_DEFAULTS_KEY:
        if signature.issubset(action_ids):
            return defaults_key
    return None


def collect_playbook_candidates(regulation: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Regulation 1.3: recommended_actions + alternative_playbooks + selected_playbook → L2/L3 후보."""
    seen: Set[Tuple[int, str]] = set()
    out: List[Dict[str, Any]] = []

    def add(pb: Any) -> None:
        if not isinstance(pb, dict):
            return
        lvl = norm_level(pb.get("level"))
        if lvl not in (2, 3):
            return
        name = str(pb.get("playbook_name") or f"Level {lvl}")
        key = (lvl, name)
        if key in seen:
            return
        seen.add(key)
        out.append(pb)

    for pb in regulation.get("recommended_actions") or []:
        add(pb)
    for pb in regulation.get("alternative_playbooks") or []:
        add(pb)
    sp = regulation.get("selected_playbook")
    if isinstance(sp, dict):
        add(sp)

    out.sort(key=lambda x: norm_level(x.get("level")) or 99)
    return out


def _region_from_regulation(regulation: Dict[str, Any]) -> str:
    try:
        resource = (regulation.get("incident_summary") or {}).get("resource") or {}
        region = resource.get("region")
        if isinstance(region, str) and region.strip():
            return region.strip()
    except Exception:
        pass
    return "ap-northeast-2"


def parse_finance_lambda_response(raw: str) -> Tuple[int, Dict[str, Any]]:
    parsed = json.loads(raw)
    status = int(parsed.get("statusCode", 200))
    body = parsed.get("body", parsed)
    if isinstance(body, str):
        body = json.loads(body) if body.strip() else {}
    if not isinstance(body, dict):
        body = {"error": raw}
    return status, body


def invoke_finance_run(
    lambda_client: Any,
    finance_arn: str,
    *,
    incident_id: str,
    region: str,
    resource_change: Dict[str, float],
    policy_version: str = "v1.0.0",
) -> Dict[str, Any]:
    payload = {
        "action": "finance_run",
        "request": {
            "schema_version": "1.0",
            "incident_id": incident_id,
            "policy_version": policy_version,
            "assumptions": {
                "duration_hours": 720,
                "traffic_multiplier": 1.0,
                "region": region,
                "service_tier": "S1",
                "org_profile": "Standard",
            },
            "resource_change": resource_change,
        },
    }
    resp = lambda_client.invoke(
        FunctionName=finance_arn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    status, body = parse_finance_lambda_response(resp["Payload"].read().decode("utf-8"))
    if status != 200 or body.get("error"):
        err = body.get("error", body)
        raise RuntimeError(f"finance_run failed: {err}")
    return body


def build_comparison_with_costs(
    lambda_client: Any,
    finance_arn: str,
    regulation: Dict[str, Any],
    incident_id: str,
    *,
    policy_version: str = "v1.0.0",
) -> Dict[str, Any]:
    """
    Regulation 후보 플레이북마다 finance_run 호출 후 comparison.playbooks 구성.
    """
    candidates = collect_playbook_candidates(regulation)
    levels = {norm_level(pb.get("level")) for pb in candidates}
    if 2 not in levels or 3 not in levels:
        raise ValueError(
            "Regulation 결과에 Level 2·3 플레이북 후보가 모두 필요합니다. "
            f"(현재 levels={sorted(x for x in levels if x is not None)}). "
            "alternative_playbooks 와 recommended_actions 를 확인하세요."
        )

    region = _region_from_regulation(regulation)
    summary = regulation.get("incident_summary") or {}
    title = summary.get("title") or regulation.get("scenario") or "Unknown"

    playbooks_out: List[Dict[str, Any]] = []
    for pb in candidates:
        lvl = norm_level(pb.get("level"))
        if lvl is None:
            continue
        defaults_key = infer_defaults_key(pb)
        if not defaults_key:
            raise ValueError(
                f"Level {lvl} 플레이북 '{pb.get('playbook_name')}' 의 비용 프로필을 추론할 수 없습니다. "
                f"action_ids={sorted(_extract_action_ids(pb))}"
            )
        resource_change = PLAYBOOK_RESOURCE_CHANGE.get(defaults_key)
        if not resource_change:
            raise ValueError(f"Unknown defaults key: {defaults_key}")

        fin_result = invoke_finance_run(
            lambda_client,
            finance_arn,
            incident_id=incident_id,
            region=region,
            resource_change=resource_change,
            policy_version=policy_version,
        )
        cost = (fin_result.get("cost_summary") or {}).get("estimated_monthly_cost")

        playbooks_out.append(
            {
                "level": lvl,
                "playbook_name": pb.get("playbook_name") or f"Level {lvl}",
                "cost_summary": {"estimated_monthly_cost": cost},
                "expected_impact": pb.get("expected_impact") or "MEDIUM",
                "_regulation_playbook": pb,
            }
        )

    return {
        "incident_id": incident_id,
        "event_summary": title,
        "playbook_scenario": regulation.get("scenario", ""),
        "playbooks": playbooks_out,
    }


def extract_recommended_from_finance_response(fin_data: Dict[str, Any]) -> Dict[str, Any]:
    """Finance Agent 신규 응답(result.*) 또는 구형 recommended_playbook에서 추천 dict 추출."""
    if isinstance(fin_data.get("result"), dict) and fin_data["result"].get("recommended_level") is not None:
        r = fin_data["result"]
        return {
            "recommended_level": r.get("recommended_level"),
            "playbook_name": r.get("playbook_name", ""),
            "reason": r.get("reason", ""),
            "source": r.get("source", ""),
        }
    rp = fin_data.get("recommended_playbook")
    if isinstance(rp, dict):
        return rp
    return {}


def invoke_simulation_recommendation(
    lambda_client: Any,
    finance_arn: str,
    comparison: Dict[str, Any],
    user_response: Dict[str, str],
) -> Dict[str, Any]:
    payload = {
        "action": "get_simulation_recommendation",
        "comparison": {
            "incident_id": comparison.get("incident_id"),
            "event_summary": comparison.get("event_summary"),
            "playbook_scenario": comparison.get("playbook_scenario"),
            "playbooks": [
                {
                    "level": p["level"],
                    "playbook_name": p["playbook_name"],
                    "cost_summary": p.get("cost_summary"),
                    "expected_impact": p.get("expected_impact"),
                }
                for p in comparison.get("playbooks") or []
            ],
        },
        "user_response": user_response,
    }
    resp = lambda_client.invoke(
        FunctionName=finance_arn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    status, body = parse_finance_lambda_response(resp["Payload"].read().decode("utf-8"))
    if status != 200 or body.get("error"):
        err = body.get("error", body)
        raise RuntimeError(f"get_simulation_recommendation failed: {err}")
    return body


def playbooks_for_slack_ui(comparison: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Slack 버튼용: regulation 원본 플레이북 + 비용."""
    out = []
    for p in comparison.get("playbooks") or []:
        reg_pb = p.get("_regulation_playbook")
        if isinstance(reg_pb, dict):
            entry = dict(reg_pb)
        else:
            entry = {
                "level": p.get("level"),
                "playbook_name": p.get("playbook_name"),
                "actions": [],
                "expected_impact": p.get("expected_impact"),
            }
        cost = (p.get("cost_summary") or {}).get("estimated_monthly_cost")
        entry["_estimated_monthly_cost"] = cost
        out.append(entry)
    out.sort(key=lambda x: norm_level(x.get("level")) or 99)
    return out


def parse_runtime_lambda_response(raw: str) -> Dict[str, Any]:
    """Runtime Lambda invoke Payload 파싱."""
    parsed = json.loads(raw)
    body = parsed.get("body", parsed)
    if isinstance(body, str):
        body = json.loads(body) if body.strip() else {}
    if not isinstance(body, dict):
        body = {"execution_success": False, "detail": raw}
    return body


def format_execution_result_slack_message(incident_id: str, runtime_result: Dict[str, Any]) -> str:
    """Runtime 조치 결과를 Slack response_url용 텍스트로 변환."""
    success = runtime_result.get("execution_success")
    if success is None:
        success = runtime_result.get("status") == "ACTION_EXECUTED"

    detail = runtime_result.get("detail") or runtime_result.get("reason") or ""
    if not detail and runtime_result.get("results"):
        failed = [
            r for r in runtime_result["results"]
            if r.get("status") not in ("SUCCESS", "SKIPPED")
        ]
        if failed:
            detail = "\n".join(
                f"• `{r.get('action_id', '?')}` ({r.get('target_id', 'N/A')}): {r.get('status', 'UNKNOWN')}"
                for r in failed
            )
    if not detail:
        detail = "조치 실행 결과를 확인할 수 없습니다."

    if success:
        header = f"✅ *조치 실행 성공* (이벤트 ID: `{incident_id}`)"
    else:
        header = f"❌ *조치 실행 실패* (이벤트 ID: `{incident_id}`)"

    return f"{header}\n{detail}"


def _has_hangul(text: str) -> bool:
    return any("\uac00" <= ch <= "\ud7a3" for ch in text)


def _is_mostly_english(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return False
    if _has_hangul(stripped):
        return False
    alpha = sum(1 for ch in stripped if ch.isalpha())
    return alpha >= 8


_XAI_PHRASE_KO: Dict[str, str] = {
    "This action requires approval.": "본 조치는 승인이 필요합니다.",
    "Regulatory basis for action": "규제 근거에 따른 대응입니다.",
    "Explain assumptions and approval considerations.": "가정 사항 및 승인 시 고려할 사항을 검토하세요.",
    "Recommended actions are necessary to mitigate potential unauthorized access.": (
        "무단 접근 가능성을 줄이기 위해 제안된 조치가 필요합니다."
    ),
}


def _localize_xai_text(text: str) -> str:
    """XAI 본문: 이미 한국어면 그대로, 짧은 영어 관용구는 매핑, 긴 영어는 한국어 요약."""
    raw = (text or "").strip()
    if not raw:
        return ""
    if _has_hangul(raw):
        return raw
    if raw in _XAI_PHRASE_KO:
        return _XAI_PHRASE_KO[raw]
    for en, ko in _XAI_PHRASE_KO.items():
        if en.lower() in raw.lower():
            return ko
    if _is_mostly_english(raw):
        return "규제·위협 맥락을 분석한 결과, 해당 대응 조치가 필요하다고 판단했습니다."
    return raw


def _localize_regulation_why(reg: Dict[str, Any]) -> str:
    """규제 매핑 한 줄: why_relevant가 영어면 한국어 excerpt 또는 한국어 요약 사용."""
    why = (reg.get("why_relevant") or "").strip()
    excerpt = (reg.get("excerpt") or "").strip()
    cid = reg.get("clause_id", "")
    title = reg.get("clause_title", "")

    if why and _has_hangul(why):
        text = why
    elif excerpt and _has_hangul(excerpt):
        text = excerpt
    elif why:
        text = _localize_xai_text(why)
        if _is_mostly_english(text):
            text = f"`{cid}` {title} 규정상 본 위협에 대한 대응 근거로 판단했습니다."
    elif excerpt:
        text = _localize_xai_text(excerpt)
    else:
        text = f"`{cid}` {title} 규정과 관련된 조치입니다."

    if len(text) > 160:
        return text[:160] + "…"
    return text


def format_regulation_xai_explanation(regulation: Dict[str, Any]) -> str:
    """
    Regulation Agent 결과에서 Slack에 표시할 XAI(설명 가능한 AI) 요약을 만듭니다.
    reasoning_bullets, escalation_assessment, justification, regulations 필드를 활용합니다.
    Slack XAI 섹션 본문은 한국어로 표시합니다.
    """
    parts: List[str] = []

    esc = regulation.get("escalation_assessment") or {}
    if isinstance(esc, dict):
        lvl = esc.get("recommended_level")
        conf = esc.get("confidence")
        notes = esc.get("approval_notes")
        if lvl is not None:
            parts.append(f"• *권장 대응 레벨:* Level {lvl}")
        if conf is not None:
            parts.append(f"• *판단 신뢰도:* {conf}")
        if notes:
            parts.append(f"• *에스컬레이션 근거:* {_localize_xai_text(str(notes))}")

    justification = regulation.get("justification")
    if isinstance(justification, str) and justification.strip():
        parts.append(f"*XAI 종합 설명:*\n{_localize_xai_text(justification)[:1800]}")

    bullets = regulation.get("reasoning_bullets") or []
    if isinstance(bullets, list) and bullets:
        parts.append("*추론 요약:*")
        for bullet in bullets[:5]:
            if bullet:
                parts.append(f"  - {_localize_xai_text(str(bullet))}")

    regs = regulation.get("regulations") or []
    if isinstance(regs, list) and regs:
        parts.append("*규제 매핑 (왜 이 조치인가):*")
        for reg in regs[:4]:
            if not isinstance(reg, dict):
                continue
            cid = reg.get("clause_id", "")
            title = reg.get("clause_title", "")
            why = _localize_regulation_why(reg)
            parts.append(f"  - `{cid}` {title}: {why}")

    return "\n".join(parts)
