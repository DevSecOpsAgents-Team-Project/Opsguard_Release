"""
Level Router 모듈

GuardDuty finding과 runtime 결과를 기반으로 Level 1/2/3을 결정하는 라우터입니다.
Level 1인 경우 RAG/Regulation Agent를 건너뛰고, Level 2/3인 경우에만 진행합니다.
"""

from typing import Dict, Any, Optional, List, NamedTuple


class LevelDecision(NamedTuple):
    """레벨 결정 결과"""
    selected_level: int  # 1|2|3
    reasons: List[str]   # 결정 근거 설명


def _safe_get(d: Dict[str, Any], path: List[str], default: Any = "") -> Any:
    """안전하게 딕셔너리에서 값을 가져옵니다."""
    cur: Any = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _to_list(x: Any) -> List[str]:
    """값을 리스트로 변환합니다."""
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x if v is not None]
    return [str(x)]


def decide_response_level(
    finding: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
) -> LevelDecision:
    """
    GuardDuty finding과 runtime 결과를 기반으로 응답 레벨을 결정합니다.
    
    Day8 MVP rule-based level router (MCP 역할을 로컬 함수로 대체)
    - severity는 참고만
    - 키워드/리소스/권한영향/반복성/확산위험 신호로 1/2/3 분기
    
    Args:
        finding: GuardDuty finding 딕셔너리
        runtime_result: Runtime Agent 결과 (tags, key_signals 등)
    
    Returns:
        LevelDecision: 선택된 레벨과 결정 근거
    """
    runtime_result = runtime_result or {}
    reasons: List[str] = []

    gd_type = str(finding.get("type", "")).lower()
    sev = float(finding.get("severity", 0) or 0)
    resource_type = _safe_get(finding, ["resource", "resourceType"], "")
    access_key_id = _safe_get(finding, ["resource", "accessKeyDetails", "accessKeyId"], "")
    iam_user = _safe_get(finding, ["resource", "accessKeyDetails", "userName"], "")

    signals = [s.lower() for s in _to_list(runtime_result.get("key_signals"))]
    tags = [t.lower() for t in _to_list(runtime_result.get("tags"))]
    
    # --- Level 1 fast-path (낮은 위험 + 단발성/약한 신호) ---
    if sev < 4.0 and not signals and not tags and not access_key_id and "accesskey" not in str(resource_type).lower():
        reasons.append(f"Low severity ({sev}) and no signals/tags → observe only.")
        return LevelDecision(1, reasons)

    # --- Level 3 trigger (확정 침해/확산/증거보존 필요) ---
    if any(k in gd_type for k in ["backdoor", "malware", "crypto", "ransom", "trojan"]):
        reasons.append("Finding type suggests active compromise/malware.")
        return LevelDecision(3, reasons)

    if any(k in signals for k in ["data exfiltration", "lateral movement", "persistence", "ongoing attack"]):
        reasons.append("Signals indicate expansion/persistence/ongoing malicious activity.")
        return LevelDecision(3, reasons)
    

    # --- Level 2 trigger (승인 기반 containment 필요) ---
    if "accesskey" in str(resource_type).lower() or access_key_id:
        reasons.append("AccessKey related event → credential misuse risk.")
        # 유출/오남용 관련 태그/시그널이 있으면 L2 강제
        if any(k in tags for k in ["credential_compromise", "key_leak", "stolen_credential"]) or \
            any(k in signals for k in ["unusual api calls", "external ip", "anomalous behavior"]):
            reasons.append("Signals/tags suggest anomalous credential usage → containment needed.")
            return LevelDecision(2, reasons)
        
    if "s3" in str(resource_type).lower() or "s3bucket" in gd_type:
        if sev >= 5.0:
            reasons.append("S3 bucket exposure/policy finding with medium+ severity → containment needed.")
            return LevelDecision(2, reasons)

    if any(k in gd_type for k in ["privilegeescalation", "excessive", "unauthorizedadminaccess"]):
        reasons.append("Privilege-impacting finding type → containment/mitigation needed.")
        return LevelDecision(2, reasons)

    # severity가 높아도 '확정 침해'가 아니면 L2로 두는 게 안전
    if sev >= 7.0:
        reasons.append(f"High severity ({sev}) but no L3 triggers → prefer L2.")
        return LevelDecision(2, reasons)

    # --- Default Level 1 (inform/observe) ---
    reasons.append("No strong indicators for containment or critical response → observe.")
    return LevelDecision(1, reasons)

