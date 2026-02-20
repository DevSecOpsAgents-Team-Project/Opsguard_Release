# src/db_logger_module.py
import logging
import datetime
import uuid
import json
import os
import boto3
from boto3.dynamodb.conditions import Key # GSI 조회를 위해 필수

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# DynamoDB 테이블 초기화 (Lambda 환경 변수 사용)
TABLE_NAME = os.environ.get("DB_TABLE_NAME", "AgentB_Response_History")
COST_TABLE_NAME = os.environ.get("COST_TABLE_NAME", "MCP-Cost-Model")
DDB_REGION = os.environ.get("AWS_REGION", "ap-northeast-2")

# ========================================================================
# 1. [Write] 로그 저장 (Main 브랜치의 최신 스키마: PascalCase + JSON String)
# ========================================================================

def log_action(incident_id: str, action_result: dict, scenario: str = "UNKNOWN"):
    """
    Agent B의 모든 대응 액션 결과를 DynamoDB에 저장합니다.
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=DDB_REGION)
        table = dynamodb.Table(TABLE_NAME)
    except Exception:
        logger.error("[DB_LOGGER] DynamoDB 연결 실패. 로깅 스킵.")
        return {"status": "LOG_SKIPPED"}

    action_name = action_result.get("action_name")
    rollback_data = action_result.get("rollback_data", {})
    details = action_result.get("details", {})
    
    # 🎯 표준화된 로그 레코드
    log_entry = {
        "HistoryID": str(uuid.uuid4()),
        "Timestamp": datetime.datetime.utcnow().isoformat(),
        
        "IncidentId": incident_id,
        "Scenario": scenario,
        
        "ActionName": action_name,
        "Status": action_result.get("status", "UNKNOWN"),
        
        # [수정됨] json.dumps() 제거! -> 이제 Map(객체)으로 저장됨
        "RollbackData": rollback_data, 
        
        # [수정됨] json.dumps() 제거! -> 이제 Map(객체)으로 저장됨
        "Details": details
    }

    try:
        # 이 옵션을 추가하면, 혹시 float(소수점) 때문에 에러나는 것을 방지할 수 있습니다.
        # (DynamoDB는 기본 float을 싫어해서 Decimal로 바꿔야 하는데, boto3가 보통 처리해줌)
        # 일단은 그대로 put_item 하셔도 됩니다.
        table.put_item(Item=log_entry)
        
        logger.info(f"[DB_LOGGER] 저장 성공. Action={action_name}, HistoryID={log_entry['HistoryID']}")
        return {"status": "LOGGED", "history_id": log_entry["HistoryID"]}

    except Exception as e:
        logger.error(f"[DB_LOGGER] 저장 실패: {e}")
        return {"status": "LOG_FAILED", "message": str(e)}


# ========================================================================
# 2. [Read] 롤백 지원 (Week3-D 브랜치 기능 복구 + 스키마 호환성 처리)
# ========================================================================

def get_logs_by_incident(incident_id: str):
    """
    rollback_module.py에서 사용하는 핵심 함수입니다.
    특정 IncidentID와 관련된 모든 대응 이력을 조회합니다.
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=DDB_REGION)
        table = dynamodb.Table(TABLE_NAME)
        
        logger.info(f"IncidentID 조회 시도: {incident_id}")
        
        # GSI를 사용하여 Query 수행
        response = table.query(
            IndexName='IncidentId-Index', 
            KeyConditionExpression=Key('IncidentId').eq(incident_id)
        )
        
        items = response.get('Items', [])
        
        # 🚨 [중요] rollback_module.py 호환성 처리 🚨
        # DB에는 JSON 문자열로 저장되어 있지만, D님의 코드는 딕셔너리를 원합니다.
        # 따라서 여기서 자동으로 파싱(Parsing)해서 내보냅니다.
        
        cleaned_items = []
        for item in items:
            # 1. JSON 문자열 -> 딕셔너리 복구
            if 'RollbackData' in item and isinstance(item['RollbackData'], str):
                try:
                    item['RollbackData'] = json.loads(item['RollbackData'])
                except:
                    item['RollbackData'] = {}
                    
            if 'Details' in item and isinstance(item['Details'], str):
                try:
                    item['Details'] = json.loads(item['Details'])
                except:
                    item['Details'] = {}
            
            # 2. [구조 호환성 패치]
            # rollback_module.py가 'ActionDetails'라는 키를 찾고 있으므로,
            # 새 스키마(ActionName, RollbackData)를 구버전 구조(ActionDetails)로 포장해줍니다.
            if 'ActionDetails' not in item:
                # rollback_module.py가 리소스 ID를 찾을 수 있도록 처리
                resource_id = item.get('Details', {}).get('resource_id')
                
                item['ActionDetails'] = {
                    'action_name': item.get('ActionName'),
                    'rollback_data': item.get('RollbackData'),
                    'resource_id': resource_id,
                    # 스냅샷 ID가 있다면 Details 안에 있을 것임
                    'snapshot_id': item.get('Details', {}).get('snapshot_id')
                }
            
            cleaned_items.append(item)

        logger.info(f"조회 성공. 총 {len(cleaned_items)}개의 이력을 찾았습니다.")
        return cleaned_items
        
    except Exception as e:
        logger.error(f"IncidentID 조회 실패: {e}")
        return []


# ========================================================================
# 3. [Read] LLM 판단 지원 (Main 브랜치 기능 유지)
# ========================================================================

def get_past_incidents(resource_id: str) -> dict:
    """
    특정 리소스의 과거 경보 발생 및 오탐 이력을 조회합니다.
    (현재는 Mock 데이터를 반환하여 LLM 판단을 테스트)
    """
    logger.info(f"[DB_RETRIEVAL] 과거 이력 조회 Mock: {resource_id}")
    
    # Mock Logic
    if resource_id.startswith("i-test"):
        return {"total_incidents": 15, "false_positives": 12, "last_status": "SKIPPED"}
    
    return {"total_incidents": 5, "false_positives": 1, "last_status": "ISOLATED"}


def get_cost_model() -> dict:
    """
    LLM 판단에 필요한 AWS 액션별 비용 모델을 조회합니다.
    """
    logger.info("[DB_RETRIEVAL] 비용 모델 조회 Mock")
    
    return {
        "lambda_cost_per_exec": 0.0000002, 
        "ec2_isolate_cost_per_hour": 0.0116, 
        "waf_rule_cost_per_month": 5.0,
        "biz_downtime_cost_per_hour": 1000.00 
    }