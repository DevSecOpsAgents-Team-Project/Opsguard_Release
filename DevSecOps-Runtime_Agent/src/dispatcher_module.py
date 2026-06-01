import logging
import os
import json
from typing import List, Dict, Any

# 우리가 만든 모듈들 임포트
from . import actions_module as actions
from . import db_logger_module as db_logger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CONFIG = {
    "WAF_IPSET_NAME": os.environ.get("WAF_IPSET_NAME"),
    "WAF_IPSET_ID": os.environ.get("WAF_IPSET_ID"),
    "WAF_SCOPE": os.environ.get("WAF_SCOPE"),
    
    "VPC_FLOW_LOG_GROUP": os.environ.get("VPC_FLOW_LOG_GROUP"),
    "VPC_FLOW_ROLE_ARN": os.environ.get("VPC_FLOW_ROLE_ARN"),
    
    "DEFAULT_S3_LOG_BUCKET": os.environ.get("DEFAULT_S3_LOG_BUCKET")
}

IAM_ACTIONS = {
    "disable_access_key",
    "disable_iam_entity",
    "detach_admin_policies"
}

INVALID_IAM_USERS = {
    None,
    "",
    "Root",
    "root",
    "Unknown",
    "Unknown-User",
    "UNKNOWN",
}

INVALID_RESOURCE_IDS = {
    None,
    "",
    "UNKNOWN-RES",
    "Unknown-Resource",
    "unknown-resource",
    "N/A",
    "UNKNOWN",
}

# STS 임시 키(Role/연동 세션). iam:UpdateAccessKey 대상이 아님.
ASIA_ACCESS_KEY_SKIP_REASON = (
    "STS 임시 자격 증명(ASIA 접두사)은 iam:UpdateAccessKey로 비활성화할 수 없습니다. "
    "EC2 Role 세션 등 임시 credentials이므로 EC2 격리, IP 차단 등 다른 조치를 사용하세요."
)

# GuardDuty 샘플·Regulation LLM 플레이스홀더 버킷명
PLACEHOLDER_S3_BUCKET_PREFIXES = (
    "example-bucket",
    "example_bucket",
    "generatedfinding",
)

PLACEHOLDER_S3_BUCKET_SKIP_REASON = (
    "버킷 이름이 GuardDuty 샘플/플레이스홀더(example-bucket*, GeneratedFinding* 등)입니다. "
    "finding에 실제 S3 리소스가 없으면 이 조치를 건너뜁니다."
)


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    return False


def build_skipped(action_id: str, incident_id: str, reason: str):
    logger.warning("[SKIP] %s: %s", action_id, reason)
    return actions.build_response(
        action_id,
        incident_id,
        "SKIPPED",
        details={"reason": reason},
    )


def _skip_if_blank(
    action_id: str,
    incident_id: str,
    value: Any,
    field_label: str,
):
    if _is_blank(value):
        return build_skipped(action_id, incident_id, f"{field_label}이(가) 없습니다.")
    return None


def _is_placeholder_s3_bucket(bucket_name: Any) -> bool:
    if _is_blank(bucket_name):
        return False
    normalized = str(bucket_name).strip().lower()
    if normalized in INVALID_RESOURCE_IDS:
        return True
    return any(normalized.startswith(prefix) for prefix in PLACEHOLDER_S3_BUCKET_PREFIXES)


def _skip_if_placeholder_s3_bucket(
    action_id: str,
    incident_id: str,
    bucket_name: Any,
):
    if _is_placeholder_s3_bucket(bucket_name):
        return build_skipped(action_id, incident_id, PLACEHOLDER_S3_BUCKET_SKIP_REASON)
    return None


class ActionDispatcher:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run

    def dispatch(self, payload: Dict[str, Any]):
        """
        Regulation Agent로부터 받은 JSON 전체를 처리합니다.
        """
        incident_id = payload.get("incident_id")
        scenario = payload.get("scenario", "UNKNOWN")
        recommended_actions = payload.get("recommended_actions", [])

        logger.info(f"🚀 Dispatch 시작 (Incident: {incident_id}, Scenario: {scenario})")
        
        results = []

        for action_plan in recommended_actions:
            action_id = action_plan.get("action_id")
            targets = action_plan.get("targets", [])

            if not targets:
                logger.warning("⚠️ targets 없음 — action_id=%s", action_id)
                results.append({
                    "action_id": action_id,
                    "target_id": "N/A",
                    "status": "FAILED",
                    "error": "실행 대상(targets)이 없습니다.",
                })
                continue

            # 타겟이 여러 개일 수 있으므로 반복 처리
            for target in targets:
                try:
                    # 1. Action ID에 따라 적절한 핸들러 함수 매핑 및 실행
                    result = self._execute_action(action_id, target, incident_id)
                    
                    # 2. 실행 결과 DB 로깅 (Result + Rollback Data)
                    log_res = db_logger.log_action(incident_id, result, scenario)
                    
                    # 결과 수집 (API 응답용)
                    result_entry = {
                        "action_id": action_id,
                        "target_id": target.get("id") or target.get("access_key_id"),
                        "status": result.get("status"),
                        "log_status": log_res.get("status"),
                    }
                    if result.get("status") == "SKIPPED":
                        result_entry["skip_reason"] = (result.get("details") or {}).get("reason")
                    elif result.get("status") not in ("SUCCESS",):
                        result_entry["error"] = (result.get("details") or {}).get(
                            "error"
                        ) or (result.get("details") or {}).get("reason")
                    results.append(result_entry)

                except Exception as e:
                    logger.error(f"❌ Action 실행 중 치명적 오류 ({action_id}): {e}")
                    results.append({
                        "action_id": action_id, 
                        "status": "CRITICAL_ERROR", 
                        "error": str(e)
                    })

        return results

    def _execute_action(self, action_id: str, target: Dict, incident_id: str):
        """
        Action ID에 따라 JSON 타겟 정보를 actions_module 함수의 인자로 변환(Mapping)하여 호출합니다.
        """

        # IAM 액션은 실제 IAM User가 있을 때만 실행
        if action_id in IAM_ACTIONS:
            user_name = target.get("user_name")

            if user_name in INVALID_IAM_USERS:
                return build_skipped(
                    action_id,
                    incident_id,
                    f"IAM User가 아니거나 user_name이 없습니다: {user_name}",
                )

            if action_id == "disable_access_key":
                access_key_id = target.get("id") or target.get("access_key_id")

                if _is_blank(access_key_id):
                    return build_skipped(
                        action_id,
                        incident_id,
                        "disable_access_key 실행에 필요한 access_key_id가 없습니다.",
                    )

                if str(access_key_id).startswith(("i-", "vpc-", "sg-", "subnet-")):
                    return build_skipped(
                        action_id,
                        incident_id,
                        f"access_key_id가 아닌 리소스 ID가 전달되었습니다: {access_key_id}",
                    )

                if str(access_key_id).upper().startswith("ASIA"):
                    return build_skipped(
                        action_id,
                        incident_id,
                        ASIA_ACCESS_KEY_SKIP_REASON,
                    )

        # -------------------------------------------------------
        # 1. [IAM] 자격 증명 관련 액션
        # -------------------------------------------------------
        if action_id == "disable_access_key":
            # 필요 인자: user_name, access_key_id
            return actions.disable_access_key(
                user_name=target.get("user_name"),  # JSON 필드 매핑
                access_key_id=target.get("id") or target.get("access_key_id"),    # JSON 필드 매핑
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "disable_iam_entity":
            # 필요 인자: user_name
            return actions.disable_iam_entity(
                user_name=target.get("user_name"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "detach_admin_policies":
            # 필요 인자: user_name
            return actions.detach_admin_policies(
                user_name=target.get("user_name"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        # -------------------------------------------------------
        # 2. [EC2] 인스턴스 관련 액션
        # -------------------------------------------------------
        elif action_id == "isolate_instance":
            instance_id = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, instance_id, "instance_id")
            if skipped:
                return skipped
            if not str(instance_id).startswith("i-"):
                return build_skipped(
                    action_id,
                    incident_id,
                    f"EC2 instance_id 형식이 아닙니다: {instance_id}",
                )
            return actions.isolate_instance(
                instance_id=instance_id,
                incident_id=incident_id,
                dry_run=self.dry_run,
            )

        elif action_id == "stop_instance":
            instance_id = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, instance_id, "instance_id")
            if skipped:
                return skipped
            if not str(instance_id).startswith("i-"):
                return build_skipped(
                    action_id,
                    incident_id,
                    f"EC2 instance_id 형식이 아닙니다: {instance_id}",
                )
            return actions.stop_instance(
                instance_id=instance_id,
                incident_id=incident_id,
                dry_run=self.dry_run,
            )

        elif action_id == "create_snapshot":
            instance_id = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, instance_id, "instance_id")
            if skipped:
                return skipped
            if not str(instance_id).startswith("i-"):
                return build_skipped(
                    action_id,
                    incident_id,
                    f"EC2 instance_id 형식이 아닙니다: {instance_id}",
                )
            return actions.create_snapshot(
                instance_id=instance_id,
                incident_id=incident_id,
                dry_run=self.dry_run,
            )

        elif action_id == "backup_instance":
            instance_id = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, instance_id, "instance_id")
            if skipped:
                return skipped
            if not str(instance_id).startswith("i-"):
                return build_skipped(
                    action_id,
                    incident_id,
                    f"EC2 instance_id 형식이 아닙니다: {instance_id}",
                )
            return actions.backup_instance(
                instance_id=instance_id,
                incident_id=incident_id,
                dry_run=self.dry_run,
            )

        # -------------------------------------------------------
        # 3. [Network / WAF] IP 차단
        # -------------------------------------------------------
        elif action_id == "block_ip":
            ip_addr = target.get("ip") or target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, ip_addr, "source_ip")
            if skipped:
                return skipped

            missing_waf = [
                name
                for name, val in (
                    ("WAF_IPSET_ID", CONFIG["WAF_IPSET_ID"]),
                    ("WAF_IPSET_NAME", CONFIG["WAF_IPSET_NAME"]),
                    ("WAF_SCOPE", CONFIG["WAF_SCOPE"]),
                )
                if _is_blank(val)
            ]
            if missing_waf:
                return build_skipped(
                    action_id,
                    incident_id,
                    f"WAF 환경변수가 설정되지 않았습니다: {', '.join(missing_waf)}",
                )

            return actions.block_ip(
                source_ip=ip_addr,
                incident_id=incident_id,
                ipset_id=CONFIG["WAF_IPSET_ID"],
                ipset_name=CONFIG["WAF_IPSET_NAME"],
                scope=CONFIG["WAF_SCOPE"],
                dry_run=self.dry_run,
            )

        # -------------------------------------------------------
        # 4. [S3] 버킷 보안
        # -------------------------------------------------------
        elif action_id == "block_s3_public_access":
            bucket_name = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, bucket_name, "bucket_name")
            if skipped:
                return skipped
            skipped = _skip_if_placeholder_s3_bucket(action_id, incident_id, bucket_name)
            if skipped:
                return skipped
            return actions.block_s3_public_access(
                bucket_name=bucket_name,
                incident_id=incident_id,
                dry_run=self.dry_run,
            )

        elif action_id == "enable_s3_bucket_logging":
            bucket_name = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, bucket_name, "bucket_name")
            if skipped:
                return skipped
            skipped = _skip_if_placeholder_s3_bucket(action_id, incident_id, bucket_name)
            if skipped:
                return skipped

            explicit_tgt_bucket = target.get("target_bucket")
            if explicit_tgt_bucket:
                skipped = _skip_if_placeholder_s3_bucket(
                    action_id, incident_id, explicit_tgt_bucket
                )
                if skipped:
                    return skipped

            tgt_bucket = explicit_tgt_bucket or CONFIG["DEFAULT_S3_LOG_BUCKET"]
            skipped = _skip_if_blank(action_id, incident_id, tgt_bucket, "target_bucket")
            if skipped:
                return skipped

            return actions.enable_s3_bucket_logging(
                bucket_name=bucket_name,
                target_bucket=tgt_bucket,
                incident_id=incident_id,
                dry_run=self.dry_run,
            )

        # -------------------------------------------------------
        # 5. [Network] VPC Flow Log
        # -------------------------------------------------------
        elif action_id == "enable_vpc_flow_logs":
            vpc_id = target.get("id")
            skipped = _skip_if_blank(action_id, incident_id, vpc_id, "vpc_id")
            if skipped:
                return skipped
            if not str(vpc_id).startswith("vpc-"):
                return build_skipped(
                    action_id,
                    incident_id,
                    f"VPC ID 형식이 아닙니다: {vpc_id}",
                )

            missing_vpc_flow = [
                name
                for name, val in (
                    ("VPC_FLOW_LOG_GROUP", CONFIG["VPC_FLOW_LOG_GROUP"]),
                    ("VPC_FLOW_ROLE_ARN", CONFIG["VPC_FLOW_ROLE_ARN"]),
                )
                if _is_blank(val)
            ]
            if missing_vpc_flow:
                return build_skipped(
                    action_id,
                    incident_id,
                    f"VPC Flow Log 환경변수가 설정되지 않았습니다: {', '.join(missing_vpc_flow)}",
                )

            return actions.enable_vpc_flow_logs(
                vpc_id=vpc_id,
                incident_id=incident_id,
                log_group_name=CONFIG["VPC_FLOW_LOG_GROUP"],
                iam_role_arn=CONFIG["VPC_FLOW_ROLE_ARN"],
                dry_run=self.dry_run,
            )

        # -------------------------------------------------------
        # 정의되지 않은 Action 처리
        # -------------------------------------------------------
        else:
            logger.warning(f"⚠️ 정의되지 않은 Action 요청: {action_id}")
            return {
                "action_name": action_id,
                "status": "SKIPPED",
                "details": {"reason": "Not implemented in Dispatcher"}
            }

# =========================================================
# 실행 예시 (Main Lambda Handler에서 사용)
# =========================================================
def lambda_handler(event, context):
    """
    Regulation Agent가 보낸 JSON(event)을 받아서 처리하는 진입점
    """
    dispatcher = ActionDispatcher(dry_run=False) # True면 실제로 실행 안 함
    
    # event 자체가 JSON 객체라고 가정
    results = dispatcher.dispatch(event)
    
    return {
        "statusCode": 200,
        "body": json.dumps(results)
    }