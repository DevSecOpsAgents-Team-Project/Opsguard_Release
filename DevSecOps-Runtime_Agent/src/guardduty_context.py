"""
GuardDuty finding 컨텍스트 해석 (IAM User vs EC2 instance role 임시 자격 증명).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

_TEMP_KEY_PREFIXES = ("ASIA", "AROA")


def is_instance_credential_exfiltration(finding_type: str) -> bool:
    return "instancecredentialexfiltration" in (finding_type or "").lower()


def _resource_dict(detail: Dict[str, Any]) -> Dict[str, Any]:
    resource = detail.get("resource")
    return resource if isinstance(resource, dict) else {}


def get_instance_id_from_detail(detail: Dict[str, Any]) -> Optional[str]:
    resources = _resource_dict(detail)
    inst = resources.get("instanceDetails")
    if isinstance(inst, dict):
        iid = inst.get("instanceId") or inst.get("instanceID")
        if iid:
            return str(iid)
    return None


def is_instance_role_credential_finding(
    detail: Dict[str, Any],
    finding_type: str = "",
) -> bool:
    """
    EC2 인스턴스 프로파일(Role) 임시 자격 증명 유출 finding 여부.
    accessKeyDetails.userName 은 Role 이름이며 IAM User 가 아님.
    """
    ft = finding_type or detail.get("type") or detail.get("Type") or ""
    if is_instance_credential_exfiltration(str(ft)):
        return True

    resources = _resource_dict(detail)
    if resources.get("instanceDetails"):
        if resources.get("accessKeyDetails"):
            return True

    title = str(detail.get("title") or "").lower()
    desc = str(detail.get("description") or "").lower()
    if "instance role" in title or "instance credential" in title:
        return True
    if "instance role" in desc or "ec2 instance using instance role" in desc:
        return True

    return False


def get_access_key_id_from_detail(detail: Dict[str, Any]) -> Optional[str]:
    resources = _resource_dict(detail)
    ak = resources.get("accessKeyDetails") or {}
    if isinstance(ak, dict):
        kid = ak.get("accessKeyId")
        if kid:
            return str(kid)
    return None


def is_iam_user_api_target(target: Dict[str, Any]) -> bool:
    """Dispatcher/Actions 에서 IAM User API 사용 가능 여부."""
    if target.get("principal_type") == "IAMRole":
        return False
    if target.get("principal_type") == "IAMUser":
        return True

    key_id = str(target.get("id") or target.get("access_key_id") or "")
    if key_id.startswith(_TEMP_KEY_PREFIXES):
        return False

    if target.get("instance_id"):
        return False

    return True


def iam_user_api_skip_response(action_id: str, incident_id: str, reason: str) -> Dict[str, Any]:
    from .actions_module import build_response

    return build_response(
        action_id,
        incident_id,
        "SKIPPED",
        details={"reason": reason},
    )
