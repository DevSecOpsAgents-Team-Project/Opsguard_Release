import logging
import os
import json
from typing import List, Dict, Any, Optional

# 우리가 만든 모듈들 임포트
from . import actions_module as actions
from . import db_logger_module as db_logger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_IAM_CREDENTIAL_PREFIXES = ("AKIA", "ASIA", "AROA", "AIDA")


def _resolve_iam_user_name(target: Dict[str, Any]) -> Optional[str]:
    """target.user_name 우선, 없으면 IAMUser id(액세스키 ID 제외) 사용."""
    for key in ("user_name", "userName"):
        val = target.get(key)
        if val and str(val).strip():
            return str(val).strip()
    tid = target.get("id")
    if tid and str(tid).strip():
        tid_str = str(tid).strip()
        if not tid_str.startswith(_IAM_CREDENTIAL_PREFIXES):
            return tid_str
    return None


def _iam_target_missing_response(action_id: str, incident_id: str) -> Dict[str, Any]:
    return {
        "action_name": action_id,
        "incident_id": incident_id,
        "status": "FAILED",
        "details": {
            "error": (
                "IAM user_name이 없어 실행할 수 없습니다. "
                "GuardDuty finding의 accessKeyDetails.userName 또는 target.id(IAM 사용자명)가 필요합니다."
            )
        },
    }

CONFIG = {
    "WAF_IPSET_NAME": os.environ.get("WAF_IPSET_NAME"),
    "WAF_IPSET_ID": os.environ.get("WAF_IPSET_ID"),
    "WAF_SCOPE": os.environ.get("WAF_SCOPE"),
    
    "VPC_FLOW_LOG_GROUP": os.environ.get("VPC_FLOW_LOG_GROUP"),
    "VPC_FLOW_ROLE_ARN": os.environ.get("VPC_FLOW_ROLE_ARN"),
    
    "DEFAULT_S3_LOG_BUCKET": os.environ.get("DEFAULT_S3_LOG_BUCKET")
}

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
                    results.append({
                        "action_id": action_id,
                        "target_id": target.get("id"),
                        "status": result.get("status"),
                        "log_status": log_res.get("status"),
                        "error": (result.get("details") or {}).get("error"),
                    })

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
        
        # -------------------------------------------------------
        # 1. [IAM] 자격 증명 관련 액션
        # -------------------------------------------------------
        if action_id == "disable_access_key":
            user_name = _resolve_iam_user_name(target)
            access_key_id = target.get("id")
            if not user_name or not access_key_id:
                return _iam_target_missing_response(action_id, incident_id)
            return actions.disable_access_key(
                user_name=user_name,
                access_key_id=access_key_id,
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "disable_iam_entity":
            user_name = _resolve_iam_user_name(target)
            if not user_name:
                return _iam_target_missing_response(action_id, incident_id)
            return actions.disable_iam_entity(
                user_name=user_name,
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "detach_admin_policies":
            user_name = _resolve_iam_user_name(target)
            if not user_name:
                return _iam_target_missing_response(action_id, incident_id)
            return actions.detach_admin_policies(
                user_name=user_name,
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        # -------------------------------------------------------
        # 2. [EC2] 인스턴스 관련 액션
        # -------------------------------------------------------
        elif action_id == "isolate_instance":
            # 필요 인자: instance_id
            return actions.isolate_instance(
                instance_id=target.get("id"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "stop_instance":
            return actions.stop_instance(
                instance_id=target.get("id"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "create_snapshot":
            return actions.create_snapshot(
                instance_id=target.get("id"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )
            
        elif action_id == "backup_instance":
            return actions.backup_instance(
                instance_id=target.get("id"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        # -------------------------------------------------------
        # 3. [Network / WAF] IP 차단
        # -------------------------------------------------------
        elif action_id == "block_ip":
            # JSON에 ip 필드가 없으면 id 필드를 ip로 간주
            ip_addr = target.get("ip") or target.get("id")
            
            # WAF 관련 설정은 환경변수(CONFIG)에서 주입
            return actions.block_ip(
                source_ip=ip_addr,
                incident_id=incident_id,
                ipset_id=CONFIG["WAF_IPSET_ID"],
                ipset_name=CONFIG["WAF_IPSET_NAME"],
                scope=CONFIG["WAF_SCOPE"],
                dry_run=self.dry_run
            )

        # -------------------------------------------------------
        # 4. [S3] 버킷 보안
        # -------------------------------------------------------
        elif action_id == "block_s3_public_access":
            return actions.block_s3_public_access(
                bucket_name=target.get("id"),
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        elif action_id == "enable_s3_bucket_logging":
            # 타겟 버킷이 JSON에 없으면 기본값 사용
            tgt_bucket = target.get("target_bucket", CONFIG["DEFAULT_S3_LOG_BUCKET"])
            
            return actions.enable_s3_bucket_logging(
                bucket_name=target.get("id"),
                target_bucket=tgt_bucket,
                incident_id=incident_id,
                dry_run=self.dry_run
            )

        # -------------------------------------------------------
        # 5. [Network] VPC Flow Log
        # -------------------------------------------------------
        elif action_id == "enable_vpc_flow_logs":
            return actions.enable_vpc_flow_logs(
                vpc_id=target.get("id"),
                incident_id=incident_id,
                log_group_name=CONFIG["VPC_FLOW_LOG_GROUP"], # 인프라 설정값 주입
                iam_role_arn=CONFIG["VPC_FLOW_ROLE_ARN"],    # 인프라 설정값 주입
                dry_run=self.dry_run
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
