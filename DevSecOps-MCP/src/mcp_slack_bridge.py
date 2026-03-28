"""
MCP Lambda에서 Regulation 결과를 받아 Slack 승인 메시지를 보내기 위한 브릿지 모듈.

팀원의 MCP Lambda 코드에서 regulation_result를 받은 뒤,
이 모듈의 send_slack_approval_from_regulation()을 호출하면 됩니다.
"""

import json


def _regulation_to_slack_format(regulation_result, regulation_input, event):
    """
    Regulation Agent 출력 형식을 send_approval_message가 기대하는 형식으로 변환합니다.

    Regulation 출력: recommended_actions가 [{action_id, level, description, targets, ...}, ...]
    Slack 형식: recommended_actions가 [{level, playbook_name, description, actions: [{action_id, targets}], expected_impact}, ...]

    Regulation은 액션 단위로 반환하므로, level별로 그룹핑해서 playbook 형태로 만듭니다.
    """
    if not regulation_result or not isinstance(regulation_result, dict):
        return None

    incident_summary = regulation_input.get("incident_summary", {})
    if not incident_summary:
        incident_summary = {
            "source": "guardduty",
            "title": "Unknown",
            "severity": "0",
            "resource": {"type": "Unknown", "id": "UNKNOWN", "region": "", "account_id": ""},
        }

    reg_actions = regulation_result.get("recommended_actions", [])
    regs = regulation_result.get("regulations", [])
    reasoning = regulation_result.get("reasoning_bullets", [])
    scenario = regulation_result.get("scenario", "UNKNOWN")

    # level별로 그룹핑: {2: [action1, action2], 3: [action3]}
    by_level = {}
    for ra in reg_actions:
        if not isinstance(ra, dict):
            continue
        level = ra.get("level", 2)
        if level not in by_level:
            by_level[level] = []
        by_level[level].append(ra)

    # playbook 형태로 변환
    playbooks = []
    for level in sorted(by_level.keys()):
        actions_list = by_level[level]
        first = actions_list[0]
        action_ids = [a.get("action_id", "?") for a in actions_list]
        playbook_name = f"Level {level} 대응 조치"
        description = first.get("description", "규제 기반 권고 조치")
        expected_impact = first.get("expected_impact", "MEDIUM")

        playbooks.append({
            "level": level,
            "playbook_name": playbook_name,
            "description": description,
            "actions": [{"action_id": a.get("action_id"), "targets": a.get("targets", [])} for a in actions_list],
            "requires_approval": first.get("requires_approval", True),
            "expected_impact": expected_impact,
        })

    # reasoning_bullets가 비어있을 수 있음
    if not reasoning:
        reasoning = [regulation_result.get("escalation_assessment", {}).get("approval_notes", "Regulation Agent 권고")]

    return {
        "incident_id": regulation_input.get("incident_id", "UNKNOWN"),
        "scenario": scenario,
        "incident_summary": incident_summary,
        "executed_level1_actions": regulation_input.get("executed_level1_actions", ["base_mitigation"]),
        "reasoning_bullets": reasoning,
        "regulations": regs,
        "recommended_actions": playbooks,
    }


def send_slack_approval_from_regulation(regulation_result, regulation_input, event):
    """
    MCP Lambda에서 호출하는 진입점.

    Args:
        regulation_result: Regulation Agent Lambda의 반환값 (dict)
        regulation_input: build_regulation_input()으로 만든 입력 (dict)
        event: GuardDuty 원본 이벤트 (dict, 로깅용)

    Returns:
        bool: Slack 전송 성공 여부
    """
    from send_to_slack import send_approval_message

    merged = _regulation_to_slack_format(regulation_result, regulation_input, event)
    if not merged:
        return False

    # recommended_actions가 비어있으면 Slack 메시지 의미 없음 (버튼 없음)
    if not merged.get("recommended_actions"):
        return False

    send_approval_message(merged)
    return True
