# playbook_module.py
import uuid
import logging
import traceback
from .actions_module import Actions, build_response
from . import db_logger_module

logger = logging.getLogger()
logger.setLevel(logging.INFO)

actions_default = Actions()
RISK_THRESHOLD = 60

# =========================================================
# 🛠️ [Helper] JSON 깊은 곳에서 키 찾기 (Deep Search)
# =========================================================
def find_key_recursive(data, target_key):
    target_key = target_key.lower()
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() == target_key and v:
                return v
            result = find_key_recursive(v, target_key)
            if result: return result
    elif isinstance(data, list):
        for item in data:
            result = find_key_recursive(item, target_key)
            if result: return result
    return None

    # =========================================================
# 🛠️ [Helper] GuardDuty 이벤트에서 자동으로 키워드 추출
# =========================================================
def extract_signals_and_tags_dynamically(detail: dict) -> tuple[list, list]:
    key_signals = set()
    tags = set()

    # 1. Finding Type에서 추출 (예: "PrivilegeEscalation:IAMUser/AnomalousBehavior")
    finding_type = detail.get("type") or detail.get("Type") or ""
    if finding_type:
        # ':' 와 '/' 로 문자열을 쪼개서 각각의 단어를 추출
        parts = finding_type.replace(":", "/").split("/")
        for part in parts:
            if part.strip():
                # 카멜케이스 단어를 그대로 소문자로 변환해 시그널로 추가
                key_signals.add(part.strip().lower()) 

    # 2. Resource Type에서 태그 추출 (예: "AccessKey", "Instance")
    resource_type = find_key_recursive(detail, "resourceType")
    if resource_type:
        tags.add(str(resource_type).lower())

    # 기본 카테고리 태그 자동 분류
    finding_type_lower = finding_type.lower()
    if "iam" in finding_type_lower or "accesskey" in str(resource_type).lower():
        tags.update(["iam", "identity", "credential"])
    elif "s3" in finding_type_lower or "bucket" in str(resource_type).lower():
        tags.update(["s3", "storage"])
    elif "ec2" in finding_type_lower or "instance" in str(resource_type).lower():
        tags.update(["ec2", "compute", "network"])

    # 3. Service/Action 에서 공격 상세 정보 추출
    action_type = find_key_recursive(detail, "actionType")
    if action_type:
        key_signals.add(str(action_type).lower()) # 예: 'aws_api_call'

    api_name = find_key_recursive(detail, "api")
    if api_name:
        key_signals.add(f"api_{str(api_name).lower()}") # 예: 'api_deleteaccountpasswordpolicy'

    network_action = find_key_recursive(detail, "networkConnectionAction")
    if network_action:
        key_signals.update(["network_connection", "suspicious_ip"])
        
    port = find_key_recursive(detail, "localPortDetails")
    if port:
        key_signals.add("unusual_port")

    # set을 list로 변환하여 반환
    return list(key_signals), list(tags)

# ==========================================
# 🚨 시나리오 1: EC2 인스턴스 격리 플레이북
# ==========================================
def playbook_ec2_isolate(event: dict, actions=None):
    logger.info("플레이북 1: EC2 자동 격리 시작")
    
    if actions is None:
        actions = actions_default
    
    incident_id = event.get("id", "UNKNOWN_ID")

    try:
        details = event.get("detail", {})
        
        # 1. 데이터 추출 (Deep Search 적용)
        # instanceId 키를 가진 값을 JSON 전체에서 찾습니다.
        instance_id = find_key_recursive(details, "instanceId")

        if not instance_id:
            # 최후의 수단: 리소스 ID 필드 확인 (resource.id)
            resource = details.get("resource", {})
            if resource.get("resourceType") == "Instance":
                instance_id = resource.get("id")

        if not instance_id:
            # 그래도 없으면 에러 대신 SKIPPED 처리 (Graceful Handling)
            logger.warning(f"Instance ID를 찾을 수 없어 대응을 건너뜁니다. ID: {incident_id}")
            return {"status": "SKIPPED", "reason": "Instance ID Not Found", "incident_id": incident_id}

        gd_severity = details.get("severity", 0) 
        
        logger.info(f"타겟 인스턴스 식별됨: {instance_id}")

        # ---------------------------------------------------------
        # 🧠 [기능 1] 지능형 위험도 재평가
        # ---------------------------------------------------------
        resource_tags = actions.get_resource_tags(instance_id) 
        history_stats = {} 
        cost_info = {} 

        risk_assessment = actions.calculate_risk_score(
            severity=gd_severity,
            tags=resource_tags,
            history=history_stats,
            costs=cost_info
        )
        
        final_score = risk_assessment.get("score", 0)
        reason = risk_assessment.get("reason", "LLM 판단 불가")

        logger.info(f"🤖 LLM 위험도 평가 결과: {final_score}점. 이유: {reason}")

        if final_score < RISK_THRESHOLD:
            skip_msg = f"위험 점수 미달({final_score}점). 대응 스킵."
            logger.info(skip_msg)
            db_logger_module.log_action(incident_id, {"status": "SKIPPED", "reason": reason}, "EC2_ISOLATION")
            actions.notify_to_slack(f"[Agent B] 대응 스킵: {instance_id} (점수: {final_score})")
            return {"status": "SKIPPED", "score": final_score, "reason": reason}

        # 2. 격리 액션 실행
        isolate_result = actions.isolate_instance(instance_id, incident_id)
        
        # 3. 로깅
        isolate_result["risk_score"] = final_score
        db_logger_module.log_action(incident_id, isolate_result, "EC2_ISOLATION")

        # 4. 스냅샷
        snapshot_result = actions.create_snapshot(instance_id, incident_id)
        db_logger_module.log_action(incident_id, snapshot_result, "EC2_ISOLATION")

        # 5. 알림
        actions.notify_to_slack(f"EC2 {instance_id} 격리 완료. (위험도: {final_score}점)")
        
        return {"status": "EC2_ISOLATED_AND_LOGGED", "incident_id": incident_id, "target": instance_id, "score": final_score}

    except Exception as e:
        error_msg = f"EC2 플레이북 오류: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return {"status": "FAILED", "error": str(e), "incident_id": incident_id}


# ==========================================
# 🚨 시나리오 2: S3 퍼블릭 접근 차단 플레이북
# ==========================================
def playbook_s3_public_access(event: dict, actions=None):
    logger.info("플레이북 2: S3 퍼블릭 접근 차단 시작")

    if actions is None:
        actions = actions_default

    incident_id = event.get("id", "UNKNOWN_ID")

    try:
        details = event.get("detail", {})
        
        # 1. 데이터 추출 (Deep Search 적용)
        bucket_name = find_key_recursive(details, "bucketName")
        
        # ARN 파싱 시도 (arn:aws:s3:::bucket-name)
        if not bucket_name:
            resource_arn = details.get("resource", {}).get("arn", "")
            if ":s3:::" in resource_arn:
                bucket_name = resource_arn.split(":s3:::")[-1].split("/")[0]

        if not bucket_name:
            logger.warning(f"Bucket Name을 찾을 수 없어 대응을 건너뜁니다. ID: {incident_id}")
            return {"status": "SKIPPED", "reason": "Bucket Name Not Found", "incident_id": incident_id}

        logger.info(f"타겟 버킷 식별됨: {bucket_name}")

        block_result = actions.block_s3_public_access(bucket_name, incident_id)
        db_logger_module.log_action(incident_id, block_result, "S3_POLICY_BLOCK")
        
        actions.notify_to_slack(f"S3 {bucket_name} 퍼블릭 차단 완료.")

        return {"status": "S3_BLOCKED_AND_LOGGED", "incident_id": incident_id, "target": bucket_name}

    except Exception as e:
        error_msg = f"S3 플레이북 오류: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return {"status": "FAILED", "error": str(e), "incident_id": incident_id}

# ==========================================
# 🚨 시나리오 3: IAM 권한 악용 대응 플레이북
# ==========================================
def playbook_iam_abuse_response(event: dict, actions=None):
    logger.info("플레이북 3: IAM 권한 악용 대응 시작")

    if actions is None:
        actions = actions_default

    incident_id = event.get("id", "UNKNOWN_ID")

    try:
        details = event.get("detail", {})
        
        # 1. 데이터 추출 (Deep Search 적용)
        user_name = find_key_recursive(details, "userName")
        
        if not user_name:
            principal = find_key_recursive(details, "principalId")
            if principal and ":" in principal:
                user_name = principal.split(":")[-1]

        if not user_name:
            logger.warning(f"IAM User Name을 찾을 수 없어 대응을 건너뜁니다. ID: {incident_id}")
            return {"status": "SKIPPED", "reason": "User Name Not Found", "incident_id": incident_id}

        iam_block_result = actions.disable_iam_entity(user_name, incident_id)
        db_logger_module.log_action(incident_id, iam_block_result, "IAM_PERMISSION_ABUSE")

        actions.notify_to_slack(f"[IAM 차단 완료] {user_name} 권한 회수.")

        return {"status": "IAM_BLOCKED_AND_LOGGED", "incident_id": incident_id, "target": user_name}

    except Exception as e:
        logger.error(f"IAM 플레이북 오류: {str(e)}")
        logger.error(traceback.format_exc())
        return {"status": "FAILED", "error": str(e), "incident_id": incident_id}
    
    
# ==========================================
# 시나리오 4: EC2 조사/로그용 플레이북 (격리 없이 스냅샷 + 태그)
# ==========================================
def playbook_ec2_investigation_logging(event: dict, actions=None):
    logger.info("플레이북 4: EC2 Investigation Logging 시작")

    if actions is None:
        actions = actions_default

    incident_id = event.get("id", "UNKNOWN_ID")

    try:
        details = event.get("detail", {})

        # EC2 인스턴스 ID 추출 (기존 헬퍼 재사용)
        instance_id = find_key_recursive(details, "instanceId")

        if not instance_id:
            resource = details.get("resource", {})
            if resource.get("resourceType") == "Instance":
                instance_id = resource.get("id")

        if not instance_id:
            logger.warning(f"[INV_LOG] Instance ID를 찾을 수 없어 대응을 건너뜁니다. ID: {incident_id}")
            return {"status": "SKIPPED", "reason": "Instance ID Not Found", "incident_id": incident_id}

        logger.info(f"[INV_LOG] 조사 대상 인스턴스: {instance_id}")

        # (옵션) 위험도 평가 – 여기서는 단순히 기록용으로만 사용
        gd_severity = details.get("severity", 0)
        resource_tags = actions.get_resource_tags(instance_id)
        history_stats = {}
        cost_info = {}

        risk_assessment = actions.calculate_risk_score(
            severity=gd_severity,
            tags=resource_tags,
            history=history_stats,
            costs=cost_info
        )

        final_score = risk_assessment.get("score", 0)
        reason = risk_assessment.get("reason", "LLM 판단 불가")

        logger.info(f"[INV_LOG] LLM 평가 점수: {final_score}, 이유: {reason}")

        # 1) 스냅샷 생성
        snapshot_result = actions.create_snapshot(instance_id, incident_id)
        snapshot_result["risk_score"] = final_score
        db_logger_module.log_action(incident_id, snapshot_result, "EC2_INVESTIGATION_LOGGING")

        # 2) 인시던트 태그 부착
        tag_result = actions.tag_resource_with_incident(instance_id, incident_id)
        tag_result["risk_score"] = final_score
        db_logger_module.log_action(incident_id, tag_result, "EC2_INVESTIGATION_LOGGING")

        # 3) 알림 전송
        actions.notify_to_slack(
            f"[Investigation] EC2 {instance_id} 조사용 스냅샷 및 태그 부착 완료 (RiskScore={final_score})"
        )

        return {
            "status": "EC2_INVESTIGATION_LOGGED",
            "incident_id": incident_id,
            "target": instance_id,
            "score": final_score
        }

    except Exception as e:
        error_msg = f"EC2 Investigation 플레이북 오류: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return {"status": "FAILED", "error": str(e), "incident_id": incident_id}


# =========================================================
# Base mitigation playbook: Level1 (통합 대응)
# =========================================================
def playbook_integrated_base_mitigation(event: dict, actions=None):
    """
    S3, EC2, IAM 등 다양한 리소스 타입에 대해 최적화된 통합 대응 플레이북입니다.
    """
    # 1. Actions 인스턴스 확보 (의존성 주입 또는 기본값)
    if actions is None:
        from src.actions_module import Actions
        actions = Actions()
        
    # GuardDuty 이벤트 구조에 따른 detail 추출
    detail = event.get("detail", event) 
    finding_id = event.get("id") or detail.get("Id") or "UNKNOWN_ID"
    
    # 2. 사고 정보 기본 추출
    finding_type = detail.get("type") or detail.get("Type") or "Unknown"
    severity = detail.get("severity") or detail.get("Severity") or 0
    
    # 3. 리소스 ID 및 사용자 정보 정밀 추출
    resource_id = None
    user_name = "Unknown-User"
    resource_type = "Unknown"

    # [A] 사용자 이름 추출 (IAM 사고 대응용)
    # accessKeyDetails 내부의 userName을 우선적으로 찾음
    user_name_found = find_key_recursive(detail, "userName")
    if user_name_found:
        user_name = user_name_found

    # [B] S3 버킷 추출 (가장 에러가 많았던 부분 수정)
    # 대소문자 이슈 해결을 위해 두 가지 키 모두 검사
    resources = detail.get("resource", {}) if isinstance(detail.get("resource"), dict) else {}
    s3_details = resources.get("S3BucketDetails") or resources.get("s3BucketDetails")
    
    if s3_details:
        # 리스트인 경우
        if isinstance(s3_details, list) and len(s3_details) > 0:
            resource_id = s3_details[0].get("Name") or s3_details[0].get("name")
            resource_type = "S3"
        # 딕셔너리인 경우 (가끔 포맷이 다를 때 대응)
        elif isinstance(s3_details, dict):
            resource_id = s3_details.get("Name") or s3_details.get("name")
            resource_type = "S3"

    # [C] EC2 인스턴스 추출
    if not resource_id:
        instance_id = find_key_recursive(detail, "instanceId")
        if instance_id:
            resource_id = instance_id
            resource_type = "EC2"

    # [D] IAM 리소스 보정 (중요!)
    # IAM 관련 사고인데 resource_id를 못 찾았다면, 사용자 이름이 곧 대상 리소스임
    if "IAM" in finding_type or "Backdoor" in finding_type: # Backdoor:IAMUser 등
        if not resource_id and user_name != "Unknown-User":
            resource_id = user_name
            resource_type = "IAM"

    # 값 보정 (여전히 없으면)
    resource_id = resource_id if resource_id else "UNKNOWN-RES"

    print(f"\n🔍 [SOC-REPORT]")
    print(f" - 사고 유형: {finding_type}")
    print(f" - 위험도: {severity}")
    print(f" - 대상 사용자: {user_name}")
    print(f" - 대상 리소스: {resource_id} (타입: {resource_type})")

    # --- 대응 단계 (Actions) ---

    # [Step 1] Slack 알림
    slack_msg = (
        f"🚨 *GuardDuty 위협 감지*\n"
        f"- 유형: `{finding_type}`\n"
        f"- 심각도(Severity): `{severity}`\n"
        f"- 대상: `{resource_id}`\n"
        f"- 사용자: `{user_name}`"
    )
    actions.notify_to_slack(slack_msg, finding_id)

    # [Step 2] 사고 유형별 맞춤 대응

    # CASE A: IAM 권한 남용 (타입이 IAM이거나, 사용자가 식별된 경우)
    if resource_type == "IAM" or "IAM" in finding_type:
        if user_name != "Unknown-User":
            print(f"⚙️ [IAM-ACTION] 사용자 '{user_name}' 격리 로직 실행")
            
            # 1. 태깅 (resource_type="IAM" 명시 필수)
            tag_res = actions.tag_resource_with_incident(user_name, finding_id, resource_type="IAM")
            db_logger_module.log_action(finding_id, tag_res, "BASE_MITIGATION")

            # 2. 권한 분리
            result = actions.detach_admin_policies(user_name, finding_id)
            db_logger_module.log_action(finding_id, result, "BASE_MITIGATION")
        else:
            print(f"⚠️ [IAM-SKIP] 사용자 이름을 식별할 수 없어 대응 중단.")

    # CASE B: S3 버킷 보안 설정 위반
    elif resource_type == "S3" or "S3" in finding_type:
        if resource_id != "UNKNOWN-RES":
            print(f"⚙️ [S3-ACTION] 버킷 '{resource_id}' 보안 로깅 활성화")
            
            # 1. 태깅 (resource_type="S3" 명시 필수)
            tag_res = actions.tag_resource_with_incident(resource_id, finding_id, resource_type="S3")
            db_logger_module.log_action(finding_id, tag_res, "BASE_MITIGATION")

            # 2. 로깅 활성화
            result = actions.enable_s3_bucket_logging(resource_id, "agentb-logging-bucket", finding_id)
            db_logger_module.log_action(finding_id, result, "BASE_MITIGATION")
        else:
             print(f"⚠️ [S3-SKIP] 버킷 이름을 식별할 수 없어 대응 중단.")

    # CASE C: EC2 런타임 위협
    elif resource_type == "EC2" or (resource_id.startswith("i-") and resource_id != "i-99999999"):
        print(f"⚙️ [EC2-ACTION] 인스턴스 '{resource_id}' 증거 보존 및 태깅")
        
        # 1. 태깅
        tag_result = actions.tag_resource_with_incident(resource_id, finding_id, resource_type="EC2")
        db_logger_module.log_action(finding_id, tag_result, "BASE_MITIGATION")
        
        # 2. 스냅샷
        snap_result = actions.create_snapshot(resource_id, finding_id)
        db_logger_module.log_action(finding_id, snap_result, "BASE_MITIGATION")
        
    else:
        print(f"ℹ️ [SKIP] 정의되지 않은 리소스 타입이거나 테스트 샘플입니다. (Type: {resource_type})")

    # =================================================================
    # ★ 추가된 부분: GuardDuty 데이터에서 자동으로 힌트(키워드) 추출
    # =================================================================
    signals, generated_tags = extract_signals_and_tags_dynamically(detail)
    # =================================================================

    return {
        "status": "COMPLETED",
        "finding_id": finding_id,
        "extracted_resource": resource_id,
        "extracted_user": user_name,
        "key_signals": signals,         # 자동 추출된 시그널
        "tags": generated_tags          # 자동 추출된 태그
    }