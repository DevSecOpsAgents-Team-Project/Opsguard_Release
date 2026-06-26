# src/rollback_module.py
import logging
import boto3
import json
import os
from typing import Dict, Any, Union
from . import db_logger_module

# --- 1. 전역 설정 ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "ap-northeast-2")
TABLE_NAME = os.environ.get("DB_TABLE_NAME", "AgentB_Response_History")

try:
    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    table = dynamodb.Table(TABLE_NAME)
    
    # 클라이언트 미리 생성 (Lambda Cold Start 최적화)
    ec2_client = boto3.client('ec2', region_name=REGION)
    s3_client = boto3.client("s3", region_name=REGION)
    iam_client = boto3.client("iam", region_name=REGION)
    waf_client = boto3.client('wafv2', region_name=REGION)

    logger.info(f"DynamoDB 테이블({TABLE_NAME}) 연결 성공.")
except Exception as e:
    logger.error(f"초기화 실패: {e}")
    raise e

# --- 2. 롤백 실행 함수들 ---

def restore_instance(instance_id: str, original_sg_id: Union[str, list], **kwargs):
    logger.info(f"ROLLBACK REAL: {instance_id} 보안 그룹 복구 -> {original_sg_id}")
    groups = original_sg_id if isinstance(original_sg_id, list) else [original_sg_id]
    try:
        ec2_client.modify_instance_attribute(InstanceId=instance_id, Groups=groups)
        return {"action_name": "restore_instance", "status": "REAL_SUCCESS", "message": "SG Restored"}
    except Exception as e:
        return {"action_name": "restore_instance", "status": "REAL_FAILED", "message": str(e)}

def delete_snapshot(snapshot_id: str, **kwargs):
    logger.info(f"ROLLBACK REAL: 스냅샷 {snapshot_id} 삭제")
    try:
        ec2_client.delete_snapshot(SnapshotId=snapshot_id)
        return {"action_name": "delete_snapshot", "status": "REAL_SUCCESS", "message": "Snapshot Deleted"}
    except Exception as e:
        return {"action_name": "delete_snapshot", "status": "REAL_FAILED", "message": str(e)}

def start_instance(instance_id: str, **kwargs):
    logger.info(f"ROLLBACK: {instance_id} 인스턴스 시작")
    try:
        ec2_client.start_instances(InstanceIds=[instance_id])
        return {"action_name": "start_instance", "status": "SUCCESS", "message": "Instance started"}
    except Exception as e:
        return {"action_name": "start_instance", "status": "FAILED", "error": str(e)}

def deregister_ami(image_id: str, **kwargs):
    logger.info(f"ROLLBACK: AMI {image_id} 삭제")
    try:
        ec2_client.deregister_image(ImageId=image_id)
        return {"action_name": "deregister_ami", "status": "SUCCESS", "message": "AMI deregistered"}
    except Exception as e:
        return {"action_name": "deregister_ami", "status": "FAILED", "error": str(e)}

def unblock_s3_public_access(bucket_name: str, **kwargs):
    logger.info(f"ROLLBACK: S3 {bucket_name} 퍼블릭 차단 해제")
    try:
        s3_client.delete_public_access_block(Bucket=bucket_name)
        return {"action_name": "unblock_s3_public_access", "status": "SUCCESS", "message": "Public access block deleted"}
    except Exception as e:
        return {"action_name": "unblock_s3_public_access", "status": "FAILED", "error": str(e)}

def disable_bucket_logging(bucket_name: str, **kwargs):
    logger.info(f"ROLLBACK: S3 {bucket_name} 로깅 비활성화")
    try:
        s3_client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus={})
        return {"action_name": "disable_bucket_logging", "status": "SUCCESS", "message": "Bucket logging disabled"}
    except Exception as e:
        return {"action_name": "disable_bucket_logging", "status": "FAILED", "error": str(e)}

def enable_access_key(user_name: str, access_key_id: str, **kwargs):
    logger.info(f"ROLLBACK: IAM Key {access_key_id} 활성화")
    try:
        iam_client.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Active")
        return {"action_name": "enable_access_key", "status": "SUCCESS", "message": "Access key enabled"}
    except Exception as e:
        return {"action_name": "enable_access_key", "status": "FAILED", "error": str(e)}

def attach_policies(user_name: str, policy_arns: list, **kwargs):
    logger.info(f"ROLLBACK: IAM {user_name} 정책 재부착")
    success_cnt = 0
    try:
        for arn in policy_arns:
            iam_client.attach_user_policy(UserName=user_name, PolicyArn=arn)
            success_cnt += 1
        return {"action_name": "attach_policies", "status": "SUCCESS", "message": f"{success_cnt} policies re-attached"}
    except Exception as e:
        return {"action_name": "attach_policies", "status": "FAILED", "error": str(e)}

def delete_vpc_flow_logs(flow_log_ids: list, **kwargs):
    logger.info(f"ROLLBACK: Flow Logs {flow_log_ids} 삭제")
    try:
        ec2_client.delete_flow_logs(FlowLogIds=flow_log_ids)
        return {"action_name": "delete_vpc_flow_logs", "status": "SUCCESS", "message": "Flow logs deleted"}
    except Exception as e:
        return {"action_name": "delete_vpc_flow_logs", "status": "FAILED", "error": str(e)}

def restore_iam_entity(user_name: str, policy_name: str, deactivated_keys: list, **kwargs):
    logger.info(f"ROLLBACK: {user_name} 계정 복구")
    messages = []
    try:
        # 1. DenyAll 정책 삭제
        try:
            iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            messages.append("Policy deleted")
        except Exception as e:
            if "NoSuchEntity" in str(e):
                messages.append("Policy already gone")
            else:
                raise e

        # 2. Key 활성화
        if isinstance(deactivated_keys, str):
            deactivated_keys = [] 
        
        restored_cnt = 0
        for key_id in deactivated_keys:
            try:
                iam_client.update_access_key(UserName=user_name, AccessKeyId=key_id, Status='Active')
                restored_cnt += 1
            except Exception:
                pass
        messages.append(f"{restored_cnt} keys active")

        return {"action_name": "restore_iam_entity", "status": "REAL_SUCCESS", "message": ", ".join(messages)}
    except Exception as e:
        return {"action_name": "restore_iam_entity", "status": "REAL_FAILED", "message": str(e)}

def unblock_ip(waf_set_id: str, ip_address: str, **kwargs):
    """
    WAF IP Set에서 특정 IP를 제거합니다 (Real Implementation).
    kwargs에는 'waf_set_name'과 'scope'가 반드시 들어 있어야 합니다.
    """
    
    # 1. kwargs에서 필요한 정보 꺼내기 (block_ip에서 저장해둔 데이터)
    waf_set_name = kwargs.get("waf_set_name")
    scope = kwargs.get("scope", "REGIONAL")

    # 이름이 없으면 삭제를 못하므로 에러 처리
    if not waf_set_name:
        return {
            "action_name": "unblock_ip",
            "status": "FAILED",
            "error": "Missing 'waf_set_name' in rollback data"
        }

    try:
        # 3. 현재 IP Set 상태 가져오기 (LockToken 확보용)
        resp = waf_client.get_ip_set(
            Name=waf_set_name,
            Scope=scope,
            Id=waf_set_id
        )
        
        current_ips = resp["IPSet"]["Addresses"]
        lock_token = resp["LockToken"]
        
        # 삭제할 IP 포맷 맞추기 (/32 붙이기)
        target_cidr = f"{ip_address}/32"

        # 4. 리스트에서 IP 제거
        if target_cidr in current_ips:
            current_ips.remove(target_cidr)
        else:
            # 이미 없으면 성공으로 간주 (Idempotency)
            return {
                "action_name": "unblock_ip",
                "status": "SUCCESS",
                "message": "IP already removed"
            }

        # 5. 업데이트 반영
        waf_client.update_ip_set(
            Name=waf_set_name,
            Scope=scope,
            Id=waf_set_id,
            Addresses=current_ips,
            LockToken=lock_token
        )

        return {
            "action_name": "unblock_ip",
            "status": "SUCCESS",
            "message": f"Unblocked IP: {ip_address}"
        }

    except Exception as e:
        return {
            "action_name": "unblock_ip",
            "status": "FAILED",
            "error": str(e)
        }

# --- 3. 롤백 맵핑 ---
ROLLBACK_MAP = {
    "isolate_instance": restore_instance,
    "stop_instance": start_instance,
    "backup_instance": deregister_ami,
    "create_snapshot": delete_snapshot,
    "block_s3_public_access": unblock_s3_public_access,
    "enable_bucket_logging": disable_bucket_logging,
    "disable_access_key": enable_access_key,    
    "detach_admin_policies": attach_policies,    
    "disable_iam_entity": restore_iam_entity,      
    "enable_vpc_flow_logs": delete_vpc_flow_logs,
    "block_ip": unblock_ip,
}

# --- 4. 헬퍼 함수: 데이터 파싱 및 로직 실행 ---

def _parse_rollback_data(data):
    """DB에서 가져온 RollbackData가 문자열이면 JSON 파싱, 아니면 그대로 반환"""
    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            logger.warning(f"JSON 파싱 실패: {data}")
            return {}
    return data if isinstance(data, dict) else {}

def _execute_rollback_logic(action_name: str, rollback_data_raw: Any):
    """공통 롤백 실행 로직"""
    rollback_func = ROLLBACK_MAP.get(action_name)
    if not rollback_func:
        return {"action_name": action_name, "status": "SKIPPED", "message": "No rollback logic defined"}

    # 데이터 파싱 (String -> Dict 변환)
    rollback_data = _parse_rollback_data(rollback_data_raw)
    
    if not rollback_data:
        return {"action_name": action_name, "status": "SKIPPED", "message": "Empty RollbackData"}

    # 실행
    return rollback_func(**rollback_data)


# --- 5. 핸들러 (단일 / 일괄) ---

def rollback_handler(event, context):
    """
    [단일 롤백]
    tools/rollback_by_id.py 에서 호출됨
    Event: {"HistoryID": "...", "Timestamp": "..."}
    """
    try:
        history_id = event.get('HistoryID')
        timestamp = event.get('Timestamp')

        # 1. DB 조회
        response = table.get_item(Key={'HistoryID': history_id, 'Timestamp': timestamp})
        if 'Item' not in response:
            return {"status": "FAILED", "message": "Item not found in DB"}
        
        item = response['Item']
        
        # 🚨 [수정] Top-level 키 사용
        action_name = item.get('ActionName')
        rollback_data = item.get('RollbackData')
        incident_id = item.get('IncidentId', 'UNKNOWN')

        # 2. 로직 실행
        result = _execute_rollback_logic(action_name, rollback_data)
        
        # 3. 결과 기록
        db_logger_module.log_action(incident_id, result)
        
        return {"status": "ROLLBACK_SUCCESS", "result": result}

    except Exception as e:
        logger.error(f"단일 롤백 에러: {e}")
        return {"status": "FAILED", "message": str(e)}


def rollback_incident_handler(event, context):
    """
    [일괄 롤백]
    Event: {"incident_id": "..."}
    """
    incident_id = event.get("incident_id")
    if not incident_id:
        return {"status": "ERROR", "message": "Missing incident_id"}

    logger.info(f"일괄 롤백 시작: {incident_id}")

    try:
        # 1. 해당 Incident의 모든 로그 조회
        actions = db_logger_module.get_logs_by_incident(incident_id)
        if not actions:
            return {"status": "SUCCESS", "message": "No actions found"}

        # 2. 최신순 정렬 (역순 롤백)
        sorted_actions = sorted(actions, key=lambda x: x.get('Timestamp', ''), reverse=True)

        results = []
        success_count = 0
        fail_count = 0

        for item in sorted_actions:
            # 🚨 [수정] Top-level 키 사용
            action_name = item.get('ActionName')
            rollback_data = item.get('RollbackData')
            
            # 롤백 불필요 항목 스킵
            if action_name in ["notify_to_slack", "lookup_cloudtrail_events"]:
                continue

            try:
                res = _execute_rollback_logic(action_name, rollback_data)
                results.append(res)

                if "SUCCESS" in res.get("status", ""):
                    success_count += 1
                elif res.get("status") == "SKIPPED":
                    pass 
                else:
                    fail_count += 1
                
                # 결과 DB 저장
                db_logger_module.log_action(incident_id, res)

            except Exception as e:
                fail_count += 1
                results.append({"action": action_name, "status": "CRITICAL_ERROR", "error": str(e)})

        final_status = "SUCCESS"
        if fail_count > 0:
            final_status = "PARTIAL_SUCCESS" if success_count > 0 else "FAILED"

        return {
            "status": final_status,
            "incident_id": incident_id,
            "success": success_count,
            "failed": fail_count,
            "details": results
        }

    except Exception as e:
        logger.error(f"일괄 롤백 시스템 에러: {e}")
        return {"status": "FAILED", "message": str(e)}

# Lambda 호환용 Alias
lambda_handler = rollback_handler