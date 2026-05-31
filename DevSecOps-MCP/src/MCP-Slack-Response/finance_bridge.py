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


_GENERIC_XAI_MARKERS = (
    "규제·위협 맥락",
    "해당 대응 조치가 필요",
    "규제 근거에 따른 대응",
    "무단 접근 가능성을 줄이기 위해 제안된 조치",
    "retrieved regulation supports",
    "listed as retrieved regulation context",
    "regulatory basis for action",
    "this action requires approval",
    "recommended actions are necessary",
    "proposed measures are needed",
    "this regulation emphasizes",
    "this regulation is relevant",
    "this regulation is crucial",
    "potential credential misuse and infrastructure impact",
    "regulatory context supports least privilege",
)


def _is_generic_xai_text(text: str) -> bool:
    lowered = (text or "").strip().lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in _GENERIC_XAI_MARKERS)


_SCENARIO_DESC_KO: Dict[str, str] = {
    "CredentialCompromise": "자격 증명(AccessKey/IAM) 이상 사용",
    "S3PublicAccess": "S3 버킷 공개 접근",
    "PrivilegeEscalation": "IAM 권한 상승·이상 API 호출",
    "SuspiciousActivity": "의심스러운 클라우드 활동",
    "Malware": "악성코드·C2 통신",
    "NetworkAnomaly": "비정상 네트워크 트래픽",
    "DataExfiltration": "데이터 유출 징후",
}


_ACTION_LABEL_KO: Dict[str, str] = {
    "disable_access_key": "액세스 키 비활성화",
    "disable_iam_entity": "IAM 사용자/역할 비활성화",
    "detach_admin_policies": "관리자 정책 분리",
    "block_ip": "의심 IP 차단",
    "block_s3_public_access": "S3 공개 접근 차단",
    "enable_s3_bucket_logging": "S3 접근 로깅 활성화",
    "isolate_instance": "EC2 격리",
    "stop_instance": "EC2 중지",
    "create_snapshot": "EBS 스냅샷(포렌식)",
    "enable_vpc_flow_logs": "VPC Flow Logs 활성화",
    "tag_resource_with_incident": "사건 태그 부여",
}


_CLAUSE_RESPONSE_HINT_KO: Dict[str, str] = {
    "IAM-05": "과도·침해 자격 증명에 대해 최소 권한 원칙에 따라 접근 권한을 축소",
    "IAM-13": "공용·식별 불가 계정 사용을 중단하고 행위 주체 추적이 가능하도록 격리",
    "LOG-03": "보안 이벤트 분류·이해관계자 통지·모니터링 강화",
    "LOG-05": "비정상 로그/행위 패턴에 대한 신속한 검토와 적시 대응",
    "LOG-11": "자격 증명·키 사용 이벤트 추적 및 감사 증적 보존",
    "IVS-03": "의심 통신에 대한 네트워크 접근 제한·가시성 확보",
    "DSP-10": "민감 정보 전송 구간 암호화·접근 통제",
    "DSP-16": "데이터 보존·파기 정책에 따른 후속 조치",
    "DSP-17": "노출·공개된 데이터에 대한 접근 통제와 보호",
    "DSP-18": "정보 공개·유출 발생 시 통지 절차 준수",
    "CEK-09": "보안 사고 후 키·암호화 통제 감사 및 컴플라이언스 검토",
}


def _action_label_ko(action_id: str) -> str:
    aid = (action_id or "").strip()
    return _ACTION_LABEL_KO.get(aid, aid.replace("_", " ") if aid else "조치")


def _target_hint(action: Dict[str, Any]) -> str:
    targets = action.get("targets") or []
    hints: List[str] = []
    for t in targets[:2]:
        if not isinstance(t, dict):
            continue
        tid = t.get("id") or t.get("ip") or t.get("target_bucket")
        if tid:
            hints.append(str(tid))
    return ", ".join(hints)


def _playbook_actions_summary_ko(playbook: Dict[str, Any]) -> str:
    actions = playbook.get("actions") or []
    parts: List[str] = []
    for action in actions[:4]:
        if not isinstance(action, dict):
            continue
        aid = str(action.get("action_id") or "")
        label = _action_label_ko(aid)
        hint = _target_hint(action)
        parts.append(f"{label}({hint})" if hint else label)
    return " → ".join(parts) if parts else "세부 조치 없음"


def _summarize_incident_ko(regulation: Dict[str, Any]) -> str:
    summary = regulation.get("incident_summary") or {}
    scenario = str(regulation.get("scenario") or "")
    resource = summary.get("resource") or {}
    rtype = str(resource.get("type") or "")
    rid = str(resource.get("id") or "").strip()
    severity = summary.get("severity")
    title = str(summary.get("title") or "").strip()

    if title and _has_hangul(title):
        base = title
    else:
        base = _SCENARIO_DESC_KO.get(scenario, "GuardDuty 보안 이벤트")
        if rid and rid.lower() not in ("n/a", "null", "none"):
            base += f" — 대상 {rtype} `{rid}`" if rtype else f" — `{rid}`"
        elif title:
            base += f" ({title[:80]})"

    if severity is not None and str(severity).strip():
        base += f" · 심각도 {severity}"
    return base


def _format_playbook_line_ko(playbook: Dict[str, Any]) -> str:
    level = playbook.get("level")
    name = str(playbook.get("playbook_name") or f"Level {level}").strip()
    desc = str(playbook.get("description") or "").strip()
    actions = _playbook_actions_summary_ko(playbook)
    if desc and _has_hangul(desc):
        return f"Level {level} `{name}`: {desc} — 실행 조치: {actions}"
    return f"Level {level} `{name}` — 실행 조치: {actions}"


def _explain_escalation_ko(regulation: Dict[str, Any]) -> str:
    esc = regulation.get("escalation_assessment") or {}
    notes = str(esc.get("approval_notes") or "").strip()
    if notes and _has_hangul(notes) and not _is_generic_xai_text(notes):
        return notes

    level = esc.get("recommended_level")
    candidates = collect_playbook_candidates(regulation)
    l2 = next((p for p in candidates if p.get("level") == 2), None)
    l3 = next((p for p in candidates if p.get("level") == 3), None)
    incident = _summarize_incident_ko(regulation)
    l1_done = regulation.get("executed_level1_actions") or []
    prefix = "Level 1(관찰·기록) 완료 후" if l1_done else "Level 1 조치 이후"

    if level == 2 and l2:
        actions = _playbook_actions_summary_ko(l2)
        extra = ""
        if l3:
            extra = (
                f" Level 3 `{l3.get('playbook_name')}`는 "
                f"{_playbook_actions_summary_ko(l3)} 등 더 강한 격리 옵션입니다."
            )
        return (
            f"{prefix}, {incident}에 추가 피해 확산을 막기 위해 "
            f"Level 2 `{l2.get('playbook_name')}`를 권장합니다. "
            f"승인 시 실행: {actions}.{extra}"
        )
    if level == 3 and l3:
        actions = _playbook_actions_summary_ko(l3)
        return (
            f"{prefix}, {incident}의 영향 범위가 넓어 Level 3 `{l3.get('playbook_name')}` "
            f"강력 격리가 필요합니다. 승인 시 실행: {actions}."
        )
    if l2:
        return f"{prefix}, {incident}에 대해 `{l2.get('playbook_name')}` 플레이북 승인이 필요합니다."
    return f"{prefix}, {incident}에 대한 Level {level or 2}/3 자동화 대응 승인이 필요합니다."


def _collect_reasoning_bullets_ko(regulation: Dict[str, Any]) -> List[str]:
    existing = [str(b).strip() for b in (regulation.get("reasoning_bullets") or []) if b]
    good = [b for b in existing if _has_hangul(b) and not _is_generic_xai_text(b)]
    if len(good) >= 2:
        seen: Set[str] = set()
        out: List[str] = []
        for b in good:
            if b not in seen:
                seen.add(b)
                out.append(b)
        return out[:5]

    bullets: List[str] = []
    incident = _summarize_incident_ko(regulation)
    if incident:
        bullets.append(f"탐지: {incident}")
    for pb in collect_playbook_candidates(regulation)[:2]:
        bullets.append(_format_playbook_line_ko(pb))
    level = (regulation.get("escalation_assessment") or {}).get("recommended_level")
    if level:
        bullets.append(f"승인 후 Level {level} 플레이북이 Agent B(Runtime)에서 자동 실행됩니다.")
    seen2: Set[str] = set()
    deduped: List[str] = []
    for b in bullets:
        if b and b not in seen2:
            seen2.add(b)
            deduped.append(b)
    return deduped[:5]


def _extract_korean_excerpt(excerpt: str) -> str:
    text = (excerpt or "").strip()
    if not text:
        return ""
    if _has_hangul(text):
        return text[:180] + ("…" if len(text) > 180 else "")
    marker = "(한글 요약:"
    if marker in text:
        start = text.index(marker) + len(marker)
        end = text.find(")", start)
        if end > start:
            return text[start:end].strip()[:180]
    return ""


def _explain_regulation_mapping_ko(reg: Dict[str, Any], regulation: Dict[str, Any]) -> str:
    why = str(reg.get("why_relevant") or "").strip()
    if why and _has_hangul(why) and not _is_generic_xai_text(why):
        return why[:220] + ("…" if len(why) > 220 else "")

    cid = str(reg.get("clause_id") or "")
    title = str(reg.get("clause_title") or "")
    excerpt_ko = _extract_korean_excerpt(str(reg.get("excerpt") or ""))
    incident = _summarize_incident_ko(regulation)
    rec_level = (regulation.get("escalation_assessment") or {}).get("recommended_level")
    candidates = collect_playbook_candidates(regulation)
    primary = next((p for p in candidates if p.get("level") == rec_level), None)
    if not primary and candidates:
        primary = candidates[0]
    actions = _playbook_actions_summary_ko(primary) if primary else ""

    hint = _CLAUSE_RESPONSE_HINT_KO.get(cid, "")
    if hint and actions:
        return f"{incident} → {hint}. 제안 조치: {actions}"
    if excerpt_ko and actions:
        return f"{incident} · `{cid}` {title}: {excerpt_ko} → {actions}"
    if hint:
        return f"{incident} → {hint}."
    if excerpt_ko:
        return f"`{cid}` {title}: {excerpt_ko}"
    if actions:
        return f"{incident}에 `{cid}` {title} 근거로 {actions} 실행을 제안합니다."
    return f"{incident}에 `{cid}` {title} 규정이 적용됩니다."


def format_regulation_xai_explanation(regulation: Dict[str, Any]) -> str:
    """
    Regulation Agent JSON에서 Slack XAI 본문을 생성합니다.
    고정 문구 치환이 아니라 사건·플레이북·규제 데이터를 조합해 한국어로 설명합니다.
    """
    parts: List[str] = []

    esc = regulation.get("escalation_assessment") or {}
    if isinstance(esc, dict):
        lvl = esc.get("recommended_level")
        conf = esc.get("confidence")
        if lvl is not None:
            parts.append(f"• *권장 대응 레벨:* Level {lvl}")
        if conf is not None:
            parts.append(f"• *판단 신뢰도:* {conf}")

    incident = _summarize_incident_ko(regulation)
    if incident:
        parts.append(f"*사건 요약:*\n{incident}")

    escalation = _explain_escalation_ko(regulation)
    if escalation:
        parts.append(f"*에스컬레이션 판단:*\n{escalation}")

    justification = regulation.get("justification")
    if (
        isinstance(justification, str)
        and justification.strip()
        and _has_hangul(justification)
        and not _is_generic_xai_text(justification)
    ):
        parts.append(f"*종합 판단:*\n{justification.strip()[:1200]}")

    playbooks = collect_playbook_candidates(regulation)
    if playbooks:
        parts.append("*제안 플레이북:*")
        for pb in playbooks[:3]:
            parts.append(f"  - {_format_playbook_line_ko(pb)}")

    bullets = _collect_reasoning_bullets_ko(regulation)
    if bullets:
        parts.append("*추론 요약:*")
        for bullet in bullets:
            parts.append(f"  - {bullet}")

    regs = regulation.get("regulations") or []
    if isinstance(regs, list) and regs:
        parts.append("*규제·조치 연결:*")
        for reg in regs[:4]:
            if not isinstance(reg, dict):
                continue
            cid = reg.get("clause_id", "")
            title = reg.get("clause_title", "")
            why = _explain_regulation_mapping_ko(reg, regulation)
            parts.append(f"  - `{cid}` {title}: {why}")

    return "\n".join(parts)
