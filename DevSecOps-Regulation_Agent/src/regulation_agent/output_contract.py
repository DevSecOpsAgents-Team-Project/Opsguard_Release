"""
Final response contract: selected_playbook vs alternative_playbooks vs recommended_actions.
Keeps level-router decisions aligned with playbook lists (post-processing only).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Canonical playbook titles (abstract, consistent). Action granularity stays in actions[].action_id.
CANONICAL_PLAYBOOK_NAMES: List[str] = [
    "Credential Containment",
    "Network Isolation",
    "Network Isolation and Mitigation",
    "Access Review and Remediation",
    "S3 Bucket Security Enhancement",
    "Data Compliance Review",
    "Enhanced Monitoring Setup",
    "Threat Containment and Eradication",
    "Data Flow Restrictions",
    "Incident Isolation and Forensics",
    "Targeted Containment",
    "Expanded Isolation and Review",
]

# Aliases / noisy LLM labels → canonical
_PLAYBOOK_ALIASES: Dict[str, str] = {
    "containment playbook": "Targeted Containment",
    "isolation playbook": "Network Isolation",
    "level 2 playbook": "Targeted Containment",
    "level 3 playbook": "Network Isolation and Mitigation",
    "l2 playbook": "Targeted Containment",
    "l3 playbook": "Network Isolation and Mitigation",
    "auto converted playbook": "Targeted Containment",
    "block malicious ip": "Network Isolation",
}


def normalize_playbook_name(raw: str) -> str:
    if not raw or not str(raw).strip():
        return "Targeted Containment"
    s = str(raw).strip()
    low = s.lower()
    if low in _PLAYBOOK_ALIASES:
        return _PLAYBOOK_ALIASES[low]
    for canon in CANONICAL_PLAYBOOK_NAMES:
        if canon.lower() == low:
            return canon
    # strip action-style phrases from being used as playbook titles
    if any(
        x in low
        for x in (
            "disablement",
            "blocking",
            "access key",
            "ip address",
            "snapshot",
            "action_id",
        )
    ):
        return "Targeted Containment"
    # closest canonical by token overlap
    tokens = set(re.findall(r"[a-z0-9]+", low))
    best: Optional[str] = None
    best_score = 0
    for canon in CANONICAL_PLAYBOOK_NAMES:
        ct = set(re.findall(r"[a-z0-9]+", canon.lower()))
        score = len(tokens & ct)
        if score > best_score:
            best_score = score
            best = canon
    if best is not None and best_score > 0:
        return best
    return s[:120]


def _canonical_selected_playbook_name(
    scenario: str, selected_level: int, finding: Dict[str, Any]
) -> Optional[str]:
    """Stable primary playbook title aligned with router + scenario (output contract)."""
    if selected_level not in (2, 3):
        return None
    rt = str((finding.get("resource") or {}).get("resourceType", "")).lower()
    gd = str(finding.get("type", "")).lower()
    if "s3" in rt or "bucket" in gd:
        return "S3 Bucket Security Enhancement" if selected_level == 2 else "Data Compliance Review"
    if scenario == "CredentialCompromise":
        return "Credential Containment" if selected_level == 2 else "Access Review and Remediation"
    if scenario == "CryptoMining":
        return "Enhanced Monitoring Setup" if selected_level == 2 else "Network Isolation and Mitigation"
    if scenario == "MalwareOutbreak":
        return "Threat Containment and Eradication" if selected_level == 2 else "Network Isolation and Mitigation"
    if scenario == "DataExfiltration":
        return "Data Flow Restrictions" if selected_level == 2 else "Incident Isolation and Forensics"
    return None


def _why_not_selected(alt_level: int, selected_level: int, route_reasons: List[str]) -> str:
    hint = route_reasons[0] if route_reasons else "Router policy"
    if alt_level > selected_level:
        return f"Not selected as primary response; router committed to L{selected_level}. ({hint})"
    return f"Deferred in favor of L{selected_level} execution path. ({hint})"


def _normalize_playbook_dict(pb: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(pb)
    out["playbook_name"] = normalize_playbook_name(str(out.get("playbook_name", "")))
    return out


def iter_all_playbook_dicts(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flat list of playbook dicts for target patching."""
    out: List[Dict[str, Any]] = []
    for pb in result.get("recommended_actions") or []:
        if isinstance(pb, dict):
            out.append(pb)
    for pb in result.get("alternative_playbooks") or []:
        if isinstance(pb, dict):
            out.append(pb)
    sp = result.get("selected_playbook")
    if isinstance(sp, dict):
        out.append(sp)
    return out


def finalize_output_contract(
    result: Dict[str, Any],
    selected_level: int,
    scenario: str,
    finding: Dict[str, Any],
    candidate_actions: List[str],
    response_targets: Dict[str, Any],
    route_reasons: List[str],
) -> Dict[str, Any]:
    """
    Split LLM/rule-based recommended_actions into selected_playbook, alternative_playbooks,
    and prune recommended_actions to selected_level only. Syncs escalation_assessment.recommended_level.
    """
    result = dict(result)
    result["schema_version"] = "1.3"

    if selected_level == 1:
        result["selected_playbook"] = None
        result["alternative_playbooks"] = []
        result["recommended_actions"] = []
        return result

    playbooks_in = result.get("recommended_actions") or []
    if not isinstance(playbooks_in, list):
        playbooks_in = []

    normalized_pbs: List[Dict[str, Any]] = []
    for pb in playbooks_in:
        if isinstance(pb, dict) and pb.get("level") in (2, 3):
            normalized_pbs.append(_normalize_playbook_dict(pb))

    at_level = [p for p in normalized_pbs if int(p.get("level", 0)) == selected_level]
    others = [p for p in normalized_pbs if int(p.get("level", 0)) != selected_level]

    selected: Optional[Dict[str, Any]] = at_level[0] if at_level else None

    # Repair: wrong/missing primary playbook for router level
    if selected is None and selected_level in (2, 3):
        from .service import _build_rule_based_playbooks

        rebuilt = _build_rule_based_playbooks(finding, candidate_actions, response_targets, scenario)
        rebuilt = [_normalize_playbook_dict(x) for x in rebuilt if isinstance(x, dict)]
        cand = [p for p in rebuilt if int(p.get("level", 0)) == selected_level]
        if cand:
            selected = cand[0]
            # former others may need merge if we only had wrong level
            wrong_level = [p for p in rebuilt if int(p.get("level", 0)) != selected_level]
            for p in wrong_level:
                if p not in others:
                    others.append(p)
        else:
            ak = str((finding.get("resource") or {}).get("accessKeyDetails", {}).get("accessKeyId") or "")
            tid = ak or str(finding.get("id", "unknown"))
            # minimal stub — should be rare (keeps schema valid)
            selected = {
                "level": selected_level,
                "playbook_name": "Targeted Containment",
                "description": "Repaired playbook shell; validate actions with operations.",
                "actions": [
                    {
                        "action_id": "disable_access_key",
                        "targets": [{"type": "AccessKey", "id": tid, "user_name": None}],
                    }
                ],
                "requires_approval": True,
                "expected_impact": "MEDIUM",
            }

    # Dedupe others vs selected (by level + name)
    if selected:
        sel_key = (int(selected.get("level", 0)), selected.get("playbook_name"))
        others = [p for p in others if (int(p.get("level", 0)), p.get("playbook_name")) != sel_key]

    gd_type = str(finding.get("type", "")).lower()
    rt = str((finding.get("resource") or {}).get("resourceType", "")).lower()
    for p in others:
        if int(p.get("level", 0)) == 3 and scenario == "CredentialCompromise" and selected_level == 2:
            if "privilege" in gd_type or "privilegeescalation" in gd_type:
                p["playbook_name"] = "Access Review and Remediation"
            else:
                p["playbook_name"] = "Network Isolation"
        if int(p.get("level", 0)) == 2 and scenario == "CryptoMining" and selected_level == 3:
            p["playbook_name"] = "Enhanced Monitoring Setup"
        if int(p.get("level", 0)) == 3 and selected_level == 2 and (
            "s3" in rt or "bucket" in gd_type
        ):
            p["playbook_name"] = "Data Compliance Review"

    canon_title = _canonical_selected_playbook_name(scenario, selected_level, finding)
    if selected and canon_title:
        selected["playbook_name"] = canon_title

    alternatives: List[Dict[str, Any]] = []
    for p in others:
        alt = dict(p)
        alt["why_not_selected"] = _why_not_selected(int(p.get("level", 0)), selected_level, route_reasons)
        alternatives.append(alt)

    result["selected_playbook"] = selected
    result["alternative_playbooks"] = alternatives
    result["recommended_actions"] = [selected] if selected else []

    ea = result.get("escalation_assessment")
    if isinstance(ea, dict):
        ea = dict(ea)
        ea["recommended_level"] = selected_level if selected_level in (2, 3) else ea.get("recommended_level", 2)
        result["escalation_assessment"] = ea

    return result


def validate_output_contract(result: Dict[str, Any], selected_level: int) -> None:
    """Semantic checks; raises ValueError on violation."""
    if selected_level == 1:
        if result.get("selected_playbook") is not None:
            raise ValueError("selected_level=1 requires selected_playbook to be null")
        if result.get("recommended_actions"):
            raise ValueError("selected_level=1 requires recommended_actions to be empty")
        alts = result.get("alternative_playbooks") or []
        if alts:
            raise ValueError("selected_level=1 requires alternative_playbooks empty")
        return

    sp = result.get("selected_playbook")
    if sp is None:
        raise ValueError("selected_level in (2,3) requires selected_playbook")

    if int(sp.get("level", -1)) != selected_level:
        raise ValueError("selected_playbook.level must equal selected_level")

    for pb in result.get("recommended_actions") or []:
        if int(pb.get("level", -1)) != selected_level:
            raise ValueError("recommended_actions must only contain playbooks at selected_level")

    for pb in result.get("alternative_playbooks") or []:
        if int(pb.get("level", -1)) == selected_level:
            raise ValueError("alternative_playbooks must not duplicate selected_level")

    ea = result.get("escalation_assessment") or {}
    if isinstance(ea, dict) and ea.get("recommended_level") is not None:
        if int(ea["recommended_level"]) != selected_level:
            raise ValueError("escalation_assessment.recommended_level must match selected_level")
